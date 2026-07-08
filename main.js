'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const qs = require('qs');
const crypto = require('node:crypto');
const Json2iob = require('json2iob');
const { HttpCookieAgent, HttpsCookieAgent } = require('http-cookie-agent/http');
const tough = require('tough-cookie');

class SmartEq extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: 'smart-eq',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
    this.deviceArray = [];
    this.deviceModels = {}; // vin -> modelCode (HX11/HC11/HY11) from Hello API
    this.json2iob = new Json2iob(this);
    this.ignoreState = [];
    this.session = {};
    this.loginRetryTimeout = null;
    this.loginRetryDelay = 30 * 1000;   // Startwert für Retry in ms
    this.loginMaxRetryDelay = 32 * 60 * 1000; // Maximalwert für Retry in ms
    this.loginInProgress = false;
    this.userAgent =
      'Device: iPhone 8 Plus; OS-version: iOS_16.7; App-Name: smart EQ control; App-Version: 4.1.0; Build: 202305260959; Language: de_DE';
    // Hello Smart Gigya API key - eingebettet in awsapi.future.smart.com HTML,
    // stabil seit App-Version 1.x. Serverseitige Rotation würde den Login brechen.
    this.gigyaApiKey =
      '3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a';
    // Hello Smart Webview UA — awsapi.future.smart.com liefert 403 bei App-UAs.
    this.helloWebviewUserAgent =
      'Mozilla/5.0 (Linux; Android 9; ANE-LX1 Build/HUAWEIANE-L21; wv) ' +
      'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 ' +
      'Chrome/118.0.0.0 Mobile Safari/537.36';
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState('info.connection', false, true);
    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }

    this.cookieJar = new tough.CookieJar();
    const cookies = await this.getStateAsync('auth.cookies');
    if (cookies && cookies.val) {
      this.cookieJar = tough.CookieJar.fromJSON(cookies.val);
    }

    this.requestClient = axios.create({
      httpAgent: new HttpCookieAgent({ cookies: { jar: this.cookieJar } }),
      httpsAgent: new HttpsCookieAgent({ cookies: { jar: this.cookieJar }, rejectUnauthorized: false }),
    });
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.subscribeStates('*');

    if (this.config.type === 'hello') {
      this.deviceId = crypto.randomBytes(16).toString('hex');
      await this.loginHelloWithRetry();


      if (this.session.accessToken) {
        await this.getDeviceListHello();
        await this.updateDevicesHello();
        this.updateInterval = this.setInterval(async () => {
          await this.updateDevicesHello();
        }, this.config.interval * 60 * 1000);
        this.refreshTokenInterval = this.setInterval(() => {
          this.loginHello();
        }, 24 * 60 * 60 * 1000);
      }
      return;
    }
    const sessionState = await this.getStateAsync('auth.session');

    if (sessionState && sessionState.val) {
      this.log.debug('Found current session');
      this.session = JSON.parse(sessionState.val);
    }

    if (this.session.refresh_token) {
      this.log.info('Resume session from last login');
      this.log.info('If this is failing, please delte auth folder under smart-eq objects');
      await this.refreshToken();
    } else {
      this.log.info('Login with username and password');
      await this.login();
    }
    if (this.session.access_token) {
      await this.getDeviceList();
      await this.updateDevices();
      const expires_in = (this.session.expires_in - 100) * 1000 || 3600 * 1000;
      this.updateInterval = this.setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);
      this.refreshTokenInterval = this.setInterval(() => {
        this.refreshToken();
      }, expires_in);
    }
  }

  async loginHelloWithRetry() {
    if (this.loginInProgress) {
      this.log.debug('Login already in progress, skipping retry');
      return;
    }

    this.loginInProgress = true;

    try {
      await this.loginHello();

      if (this.session && this.session.accessToken) {
        this.log.info('Hello Smart login successful, resetting retry delay');
        this.loginRetryDelay = 30 * 1000;
        this.loginInProgress = false;
        return;
      }

      throw new Error('Login did not yield access token');
    } catch {
      this.log.warn(
        'Hello Smart login failed, retrying in ' + Math.round(this.loginRetryDelay / 1000) + ' seconds',
      );
    }

    this.loginInProgress = false;

    this.loginRetryTimeout = this.setTimeout(() => {
      this.loginHelloWithRetry();
    }, this.loginRetryDelay);

    this.loginRetryDelay = Math.min(this.loginRetryDelay * 2, this.loginMaxRetryDelay);
  }

  async loginHello() {
    this.log.info('Login into Hello Smart');

    // Step 1: Follow OIDC redirect chain to find context= (may be on hop 1 or 2)
    const context = await this.requestClient({
      method: 'get',
      url: 'https://awsapi.future.smart.com/login-app/api/v1/authorize?uiLocales=de-DE&uiLocales=de-DE',
      headers: {
        'upgrade-insecure-requests': '1',
        'user-agent': this.helloWebviewUserAgent,
        accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'x-requested-with': 'com.smart.hellosmart',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        // Axios followed redirects; parse context out of the final URL query string.
        const finalUrl = (res.request && res.request.path) || res.config.url;
        const parsed = qs.parse(finalUrl.split('?')[1] || '');
        return parsed;
      })
      .catch((error) => {
        this.log.error('Login failed at authorize: ' + error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        return null;
      });

    if (!context || !context.context) {
      this.log.error('Login failed: no context returned from authorize endpoint');
      this.setState('info.connection', false, true);
      return;
    }

    // Step 1.5: Bootstrap fresh Gigya session (gmid + ucid). The APK loads this
    // from the awsapi HTML at runtime; the previous adapter used hardcoded values
    // from 2023 which Gigya can invalidate serverside without warning.
    const gigyaIds = await this.bootstrapGigyaSession();
    if (!gigyaIds) {
      this.log.error('Login failed: Gigya session bootstrap failed');
      this.setState('info.connection', false, true);
      return;
    }
    const gigyaCookie =
      `gmid=${gigyaIds.gmid}; ucid=${gigyaIds.ucid}; hasGmid=ver4; ` +
      `gig_bootstrap_${this.gigyaApiKey}=auth_ver4`;

    // Step 2: Post Gigya login
    const loginResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://auth.smart.com/accounts.login',
      headers: {
        'user-agent': this.helloWebviewUserAgent,
        'content-type': 'application/x-www-form-urlencoded',
        accept: '*/*',
        origin: 'https://app.id.smart.com',
        'x-requested-with': 'com.smart.hellosmart',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
        cookie: gigyaCookie,
      },
      data: {
        loginID: this.config.username,
        password: this.config.password,
        sessionExpiration: '2592000',
        targetEnv: 'jssdk',
        include: 'profile,data,emails,subscriptions,preferences,',
        includeUserInfo: 'true',
        loginMode: 'standard',
        lang: 'de',
        APIKey: this.gigyaApiKey,
        source: 'showScreenSet',
        sdk: 'js_latest',
        authMode: 'cookie',
        pageURL: 'https://app.id.smart.com/login?gig_ui_locales=de-DE',
        sdkBuild: '15482',
        format: 'json',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        return null;
      });
    if (!loginResponse) {
      this.log.error('Login failed #1');
      this.setState('info.connection', false, true);

      return;
    }

    // Gigya returns HTTP 200 even on wrong credentials; surface the code.
    if (loginResponse.errorCode && loginResponse.errorCode !== 0) {
      this.log.error(
        'Gigya login error code=' + loginResponse.errorCode + ' message=' + loginResponse.errorMessage,
      );
      this.setState('info.connection', false, true);
      return;
    }
    if (!loginResponse.sessionInfo) {
      this.log.error('Login failed no session found');
      this.setState('info.connection', false, true);
      this.log.error(JSON.stringify(loginResponse));
      return;
    }

    // Step 3: Continue OIDC to get the OAuth access_token. Axios follows redirects
    // so the token ends up in the final URL's query string.
    const authorizeCookie =
      gigyaCookie + `; glt_${this.gigyaApiKey}=${loginResponse.sessionInfo.login_token}`;
    this.gtokens = await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url:
        'https://auth.smart.com/oidc/op/v1.0/' +
        this.gigyaApiKey +
        '/authorize/continue?context=' +
        context.context +
        '&login_token=' +
        loginResponse.sessionInfo.login_token,
      headers: {
        'upgrade-insecure-requests': '1',
        'user-agent': this.helloWebviewUserAgent,
        accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'x-requested-with': 'com.smart.hellosmart',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
        cookie: authorizeCookie,
      },
    })
      .then((res) => {
        this.log.debug(res.request.path);
        // access_token may be in query OR fragment depending on OIDC response mode.
        const finalUrl = (res.request && res.request.path) || '';
        const [queryPart, fragmentPart] = finalUrl.split('#');
        const query = qs.parse((queryPart.split('?')[1] || ''));
        const fragment = qs.parse(fragmentPart || '');
        const tokens = { ...fragment, ...query };
        if (!tokens.access_token) {
          this.log.error('Login failed #2');
          this.setState('info.connection', false, true);
          this.log.error(res.request.path);
          return;
        }
        this.log.debug(JSON.stringify(res.data));

        return tokens;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
    if (!this.gtokens || !this.gtokens.access_token) {
      this.setState('info.connection', false, true);
      return;
    }
    await this.getCurrentToken();
    this.log.info('Login successful');
  }

  /**
   * Fetch a fresh Gigya socialize session (gmid + ucid). Required so that the
   * subsequent accounts.login is accepted. The pysmarthashtag reference and the
   * Hello Smart 2.2.0 APK both go through this step; hardcoded values expire.
   */
  async bootstrapGigyaSession() {
    return await this.requestClient({
      method: 'get',
      url:
        'https://socialize.eu1.gigya.com/socialize.getIDs' +
        '?APIKey=' + this.gigyaApiKey + '&format=json&includeTicket=true',
      headers: {
        'user-agent': this.helloWebviewUserAgent,
        accept: '*/*',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
        'x-requested-with': 'com.smart.hellosmart',
      },
    })
      .then((res) => {
        this.log.debug('Gigya socialize.getIDs ' + JSON.stringify(res.data));
        if (!res.data || res.data.errorCode !== 0 || !res.data.gmid) {
          this.log.error('Gigya bootstrap failed: ' + JSON.stringify(res.data));
          return null;
        }
        return { gmid: res.data.gmid, ucid: res.data.ucid || '' };
      })
      .catch((error) => {
        this.log.error('Gigya bootstrap request failed: ' + error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        return null;
      });
  }
  async getCurrentToken() {
    const params = { identity_type: 'smart' };
    const url = '/auth/account/session/secure';
    const data = {
      accessToken: this.gtokens.access_token,
    };
    // Special case: at this point session.accessToken is still empty because we're
    // exchanging the OAuth token for it, so buildHelloHeaders returns no auth header.
    const headers = this.buildHelloHeaders('POST', url, params, data);
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: this.getHelloApiBase() + url,
      headers: headers,
      data: data,
      params: params,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.data) {
          this.session = res.data.data;
        }
        this.setState('info.connection', true, true);
      })
      .catch((error) => {
        this.log.error(error);
        this.setState('info.connection', false, true);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  creasteSignatureHello(nonce, params, timestamp, method, url, post) {
    const md5 = post
      ? crypto.createHash('md5').update(JSON.stringify(post)).digest('base64')
      : '1B2M2Y8AsgTpgAmY7PhCfg==';
    const payload = `application/json;responseformat=3
x-api-signature-nonce:${nonce}
x-api-signature-version:1.0

${qs.stringify(params)}
${md5}
${timestamp}
${method}
${url}`;

    const secret = Buffer.from('NzRlNzQ2OWFmZjUwNDJiYmJlZDdiYmIxYjM2YzE1ZTk=', 'base64');
    const result = crypto.createHmac('sha1', secret).update(payload).digest('base64');
    return result;
  }

  /**
   * Build the full x-signature header set for Hello Smart API calls.
   * Centralized so the header shape stays consistent across every call.
   * @param {string} method HTTP method in uppercase
   * @param {string} url path portion signed together with params (leading slash)
   * @param {object} params query params (may be empty object)
   * @param {object|null} [body=null] JSON body if any; MD5 is derived from JSON.stringify
   * @returns {object} header object ready for axios
   */
  buildHelloHeaders(method, url, params, body) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const sign = this.creasteSignatureHello(nonce, params, timestamp, method, url, body || undefined);
    // The 2.2.0 APK reads x-client-id from SharedPreferences after login; when the
    // session response carries it, use it. Fallback keeps the previously working
    // hardcoded Huawei device value so existing installs don't break.
    const clientId = (this.session && this.session.clientId) || 'UAWEI0000APP00ANELX123AV10090080';
    const headers = {
      'x-app-id': 'SmartAPPEU',
      accept: 'application/json;responseformat=3',
      'x-agent-type': 'android',
      'x-device-type': 'mobile',
      'x-operator-code': 'SMART',
      'x-device-identifier': this.deviceId,
      'x-env-type': 'production',
      'x-version': 'smartNew',
      'accept-language': 'en_US',
      'content-type': 'application/json; charset=utf-8',
      'x-api-signature-version': '1.0',
      'x-api-signature-nonce': nonce,
      'x-client-id': clientId,
      'x-device-manufacture': 'HUAWEI',
      'x-device-brand': 'ANE-LX1',
      'x-device-model': 'ANE-LX1',
      'x-device-release-date': '',
      'x-agent-version': '9',
      'user-agent': 'okhttp/4.11.0',
      'x-signature': sign,
      'x-timestamp': timestamp,
    };
    if (this.session && this.session.accessToken) {
      headers.authorization = this.session.accessToken;
    }
    return headers;
  }

  /**
   * Return the API base host for a given VIN.
   *
   * The APK routes based on the per-vehicle field `proprietaryPlatform` (String
   * "0" or "1") which the /device-platform/user/vehicle/secure response includes
   * for each vehicle. See:
   *   - smali_classes3/com/ecarx/open/unify/iov/iovdo.smali:1748
   *     getServiceENVByVin() reads TcVehicleProfile.proprietaryPlatform
   *   - smali_classes3/com/baselinelibrary/utils/ComUtils.smali:277
   *     exchangerHost() picks gen1SingleAuthPrefix vs gen2SingleAuthPrefix
   *     from a server-provided HostConfigBean based on this flag
   *   - smali_classes3/com/baselinelibrary/entity/TcVehicleProfile.smali:68
   *     proprietaryPlatform:String is a first-class field on the vehicle object
   *
   * The static decompilation only shows that a switch exists — the actual host
   * ("api" vs "apiv2") comes from a serverside HostConfigBean that the client
   * caches in SharedPreferences under `host_config_key`. pysmarthashtag observed
   * live traffic and found that Gen2 vehicles (smart #5, proprietaryPlatform=="1")
   * land on `apiv2.ecloudeu.com` while Gen1 vehicles stay on `api.ecloudeu.com`.
   *
   * We route by the same flag. Fallback for smart #5 (modelCode HY11) even when
   * proprietaryPlatform is missing, since pysmarthashtag confirms the mapping.
   *
   * Session / vehicle-list calls happen before we know which vehicle is which,
   * so pass vin=null to get the classic host for those.
   */
  getHelloApiBase(vin) {
    if (vin && this.deviceModels) {
      const meta = this.deviceModels[vin];
      // meta may be a bare modelCode string (backwards compat) or a metadata object.
      if (meta && typeof meta === 'object') {
        if (meta.proprietaryPlatform === '1') return 'https://apiv2.ecloudeu.com';
        if (meta.proprietaryPlatform === '0') return 'https://api.ecloudeu.com';
        // proprietaryPlatform missing — fall back to modelCode heuristic
        if (meta.modelCode === 'HY11') return 'https://apiv2.ecloudeu.com';
      } else if (meta === 'HY11') {
        return 'https://apiv2.ecloudeu.com';
      }
    }
    return 'https://api.ecloudeu.com';
  }
  async getDeviceListHello() {
    const params = { needSharedCar: 1, userId: this.session.userId };
    const url = '/device-platform/user/vehicle/secure';
    const headers = this.buildHelloHeaders('GET', url, params);
    await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: this.getHelloApiBase() + url,
      headers: headers,
      params: params,
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (!res.data || !res.data.data || res.data.data.list === 0) {
          this.log.warn('No vehicles found');
          return;
        }
        this.log.info('Found ' + res.data.data.list.length + ' vehicles');
        for (const device of res.data.data.list) {
          const vin = device.vin;
          this.deviceArray.push(vin);
          const modelCode = this.detectModelCode(device);
          // Store the full routing metadata per VIN. proprietaryPlatform is a
          // per-vehicle string flag from /device-platform/user/vehicle/secure
          // that decides whether follow-up calls go to api.ecloudeu.com (Gen1,
          // value "0") or apiv2.ecloudeu.com (Gen2, value "1"). See the smali
          // trail in getHelloApiBase()'s docstring.
          const proprietaryPlatform =
            device.proprietaryPlatform !== undefined && device.proprietaryPlatform !== null
              ? String(device.proprietaryPlatform)
              : undefined;
          this.deviceModels[vin] = { modelCode, proprietaryPlatform };
          const modelLabel = this.modelCodeToLabel(modelCode);
          const name = (device.modelName || 'smart') + ' ' + (device.plateNo || vin) + (modelLabel ? ' (' + modelLabel + ')' : '');
          this.log.info(
            'Vehicle ' + vin + ' identified as ' + (modelLabel || 'unknown model') +
              ' proprietaryPlatform=' + (proprietaryPlatform === undefined ? 'missing' : proprietaryPlatform) +
              ' -> host=' + this.getHelloApiBase(vin),
          );

          await this.setObjectNotExistsAsync(vin, {
            type: 'device',
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(vin + '.remote', {
            type: 'channel',
            common: {
              name: 'Remote Controls',
            },
            native: {},
          });

          const remoteArray = this.getRemoteCommandsForModel(modelCode);
          remoteArray.forEach((remote) => {
            this.setObjectNotExists(vin + '.remote.' + remote.command, {
              type: 'state',
              common: {
                name: remote.name || '',
                type: remote.type || 'boolean',
                role: remote.role || 'boolean',
                def: remote.def !== undefined ? remote.def : false,
                write: true,
                read: true,
              },
              native: {},
            });
          });
        }
      })
      .catch((error) => {
        this.log.error('Failed to get vehicles ');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  /**
   * Extract the modelCode from the vehicle-list response. The 2.2.0 APK uses
   * `modelCode` (see GSVVehicleInfo.smali). Some older builds and pysmarthashtag
   * observed `seriesCodeVs` — we accept both to be defensive.
   */
  detectModelCode(device) {
    if (!device) return '';
    const raw = device.modelCode || device.seriesCodeVs || device.modelType || device.model || '';
    const upper = String(raw).toUpperCase();
    if (upper.includes('HX11')) return 'HX11';
    if (upper.includes('HC11')) return 'HC11';
    if (upper.includes('HY11')) return 'HY11';
    return upper;
  }

  modelCodeToLabel(modelCode) {
    if (modelCode === 'HX11') return 'smart #1';
    if (modelCode === 'HC11') return 'smart #3';
    if (modelCode === 'HY11') return 'smart #5';
    return '';
  }

  /**
   * Return the datapoint definitions for remote commands offered per model.
   * Commands common to all models: conditioner / lock / seatheat / charging / refresh.
   * HY11 (#5) additionally supports window and frunk according to the APK's
   * ControlsViewModel (RWS_2_1_0_2 and frunk_open response codes).
   */
  getRemoteCommandsForModel(modelCode) {
    const base = [
      { command: 'conditioner', name: 'True = Start, False = Stop' },
      { command: 'conditioner_temp', name: 'Target temperature in °C (16..30)', type: 'number', role: 'value.temperature', def: 20 },
      { command: 'lock', name: 'True = Lock, False = Unlock' },
      { command: 'seatheat', name: 'True = On, False = Off' },
      { command: 'seatheat_level', name: 'Seat heating level 0..3', type: 'number', role: 'level', def: 3 },
      { command: 'charging', name: 'True = Start, False = Stop' },
      { command: 'refresh', name: 'True = Refresh' },
    ];
    if (modelCode === 'HY11') {
      base.push({ command: 'window', name: 'True = Ventilate windows, False = Close' });
      base.push({ command: 'frunk', name: 'True = Open frunk' });
    }
    return base;
  }
  async updateDevicesHello() {
    for (const vin of this.deviceArray) {
      const params = { latest: true, target: '', userId: this.session.userId };
      const url = '/remote-control/vehicle/status/' + vin;
      const headers = this.buildHelloHeaders('GET', url, params);
      await this.requestClient({
        method: 'get',
        maxBodyLength: Infinity,
        url: this.getHelloApiBase(vin) + url,
        headers: headers,
        params: params,
      })
        .then(async (res) => {
          this.log.debug(JSON.stringify(res.data));
          if (res.data.code === '1402') {
            await this.getCurrentToken();
            return;
          }
          if (!res.data || !res.data.data || !res.data.data.vehicleStatus) {
            const meta = this.deviceModels[vin] || {};
            this.log.warn(
              'No vehicleStatus in response for ' + vin +
                ' (model=' + (meta.modelCode || 'unknown') +
                ', proprietaryPlatform=' + (meta.proprietaryPlatform === undefined ? 'missing' : meta.proprietaryPlatform) +
                ', host=' + this.getHelloApiBase(vin) +
                '). Response code=' + (res.data && res.data.code) +
                ' message=' + (res.data && res.data.message),
            );
            return;
          }
          const data = res.data.data.vehicleStatus;

          const forceIndex = null;
          const preferedArrayName = null;

          this.json2iob.parse(vin + '.status', data, {
            forceIndex: forceIndex,
            preferedArrayName: preferedArrayName,
            channelName: 'Status',
          });
        })
        .catch((error) => {
          this.log.error('Failed to get vehicles ');
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
    }
  }

  /**
   * Build the remote-control payload sent as PUT body to /remote-control/vehicle/telematics/{vin}.
   * Command semantics come from the 2.2.0 APK ControlsViewModel + GSVIOVService.
   * Returns null when the command is unknown so the caller can log and abort.
   *
   * Payload shape stays flat (creator/command/serviceId/serviceParameters/timestamp)
   * per the smali JSON schema — the app builds an identical structure for all models.
   *
   * @param {string} vin Vehicle VIN (used to pick model-specific quirks)
   * @param {string} command Adapter command key (conditioner/lock/seatheat/charging/window/frunk)
   * @param {boolean|number|string} value Desired new state value
   */
  buildHelloRemotePayload(vin, command, value) {
    const now = Date.now();
    const meta = this.deviceModels[vin] || {};
    const modelCode = (meta && typeof meta === 'object' ? meta.modelCode : meta) || '';

    if (command === 'conditioner') {
      // Read the target temperature from the setpoint state if user configured one.
      const temp = this._syncGetNumericState(vin + '.remote.conditioner_temp', 20);
      const tempStr = Number(temp).toFixed(1);
      return {
        command: value ? 'start' : 'stop',
        creator: 'tc',
        operationScheduling: {
          duration: 180,
          interval: 0,
          occurs: 1,
          recurrentOperation: false,
        },
        serviceId: 'RCE_2',
        serviceParameters: [
          { key: 'rce.conditioner', value: '1' },
          { key: 'rce.temp', value: tempStr },
        ],
        timestamp: now,
      };
    }

    if (command === 'charging') {
      // APK sends serviceId "RCS" (uppercase) via GSVIOVService.smali line 1964.
      // The pysmarthashtag observation "rcs" (lowercase) is not what the app does.
      // Keep uppercase, matching the app. Command flag is always "start" — start
      // vs stop is signalled via serviceParameters (rcs.restart / rcs.terminate).
      return {
        command: 'start',
        creator: 'tc',
        operationScheduling: {
          duration: 0,
          interval: 0,
          occurs: 1,
          recurrentOperation: false,
        },
        serviceId: 'RCS',
        serviceParameters: [
          { key: 'operation', value: '1' },
          { key: value ? 'rcs.restart' : 'rcs.terminate', value: '1' },
        ],
        timestamp: now,
      };
    }

    if (command === 'seatheat') {
      const level = this._syncGetNumericState(vin + '.remote.seatheat_level', 3);
      // Clamp to the APK's accepted range (0..3, per ClimateControl in pysmarthashtag).
      const clamped = Math.max(0, Math.min(3, Math.round(Number(level) || 0)));
      return {
        command: value ? 'start' : 'stop',
        creator: 'tc',
        operationScheduling: {
          duration: 0,
          interval: 0,
          occurs: 1,
          recurrentOperation: false,
        },
        serviceId: 'RCE_2',
        serviceParameters: [
          { key: 'rce.heat', value: 'front-left' },
          { key: 'rce.level', value: String(clamped) },
        ],
        timestamp: now,
      };
    }

    if (command === 'lock') {
      return {
        command: 'start',
        creator: 'tc',
        operationScheduling: {
          duration: 0,
          interval: 0,
          occurs: 1,
          recurrentOperation: false,
        },
        serviceId: value ? 'RDL_2' : 'RDU_2',
        serviceParameters: [{ key: 'door', value: 'all' }],
        timestamp: now,
      };
    }

    // HY11 (#5) exclusive commands — see ControlsViewModel.smali (RWS + frunk_open).
    if (command === 'window' && modelCode === 'HY11') {
      return {
        command: value ? 'start' : 'stop',
        creator: 'tc',
        operationScheduling: {
          duration: 0,
          interval: 0,
          occurs: 1,
          recurrentOperation: false,
        },
        serviceId: 'RWS_2',
        serviceParameters: [{ key: 'window', value: 'all' }],
        timestamp: now,
      };
    }
    if (command === 'frunk' && modelCode === 'HY11') {
      return {
        command: 'start',
        creator: 'tc',
        operationScheduling: {
          duration: 0,
          interval: 0,
          occurs: 1,
          recurrentOperation: false,
        },
        serviceId: 'frunk_open',
        serviceParameters: [],
        timestamp: now,
      };
    }
    return null;
  }

  /**
   * Read a numeric state synchronously-ish. ioBroker states are async but we
   * cache the last known value on the instance to avoid awaiting inside the
   * payload builder (which lets it stay a plain function).
   */
  _syncGetNumericState(id, fallback) {
    if (!this._numericStateCache) this._numericStateCache = {};
    const cached = this._numericStateCache[id];
    if (typeof cached === 'number' && !Number.isNaN(cached)) return cached;
    // Fire-and-forget: refresh cache in background so next call has it.
    this.getStateAsync(id).then((s) => {
      if (s && s.val !== null && s.val !== undefined && !Number.isNaN(Number(s.val))) {
        this._numericStateCache[id] = Number(s.val);
      }
    }).catch(() => { /* state may not exist yet, fall back below */ });
    return fallback;
  }

  async login() {
    if (!this.config.otp) {
      const [code_verifier, codeChallenge] = this.getCodeChallenge();
      this.session.code_verifier = code_verifier;
      this.session.resume = await this.requestClient({
        method: 'get',
        url:
          'https://id.mercedes-benz.com/as/authorization.oauth2?client_id=70d89501-938c-4bec-82d0-6abb550b0825&response_type=code&scope=openid+profile+email+phone+ciam-uid+offline_access&redirect_uri=https://oneapp.microservice.smart.mercedes-benz.com&acr_values=mfa&code_challenge=' +
          codeChallenge +
          '&code_challenge_method=S256',
        headers: {
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'de-de',
          'User-Agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
        },
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          return qs.parse(res.request.path.split('?')[1]).resume;
        })
        .catch((error) => {
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
        });

      await this.requestClient({
        method: 'post',
        url: 'https://id.mercedes-benz.com/ciam/auth/login/user',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/plain, */*',
          'User-Agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
          Referer: 'https://id.mercedes-benz.com/ciam/auth/login',
          'Accept-Language': 'de-de',
        },
        data: JSON.stringify({
          username: this.config.username,
        }),
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
        })
        .catch((error) => {
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
        });

      await this.requestClient({
        method: 'post',
        url: 'https://id.mercedes-benz.com/ciam/auth/login/pass',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/plain, */*',
          'User-Agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
          Referer: 'https://id.mercedes-benz.com/ciam/auth/login',
          'Accept-Language': 'de-de',
        },
        data: JSON.stringify({
          username: this.config.username,
          password: this.config.password,
          rememberMe: true,
        }),
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          if (res.data.result === 'GOTO_LOGIN_OTP') {
            this.log.warn('Please enter the OTP code from the mail in the adapter settings and and save.');
          }
        })
        .catch((error) => {
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
        });

      this.setState('auth.session', JSON.stringify(this.session), true);
      this.setState('auth.cookies', JSON.stringify(this.cookieJar.toJSON()), true);
    } else {
      const token = await this.requestClient({
        method: 'post',
        url: 'https://id.mercedes-benz.com/ciam/auth/login/otp',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/plain, */*',
          'User-Agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.',
          Referer: 'https://id.mercedes-benz.com/ciam/auth/login',
          'Accept-Language': 'de-de',
        },
        data: JSON.stringify({
          password: this.config.otp,
          rememberMe: false,
          username: this.config.username,
        }),
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          return res.data.token;
        })
        .catch(async (error) => {
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
          this.log.error(
            'Failed to login via OTP. Please enter the OTP code from the mail in the adapter settings and and save.',
          );
          const adapterConfig = 'system.adapter.' + this.name + '.' + this.instance;
          const obj = await this.getForeignObjectAsync(adapterConfig);
          if (obj.native && obj.native.otp) {
            obj.native.otp = '';
            this.setForeignObject(adapterConfig, obj);
          }
        });
      if (!token) {
        this.log.error('Missing token');
        return;
      }
      const code = await this.requestClient({
        method: 'post',
        url: 'https://id.mercedes-benz.com' + this.session.resume,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json, text/plain, */*',
          'User-Agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
          Referer: 'https://id.mercedes-benz.com/ciam/auth/login',
          'Accept-Language': 'de-de',
        },
        data: 'token=' + token,
        maxRedirects: 0,
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          return qs.parse(res.request.path.split('?')[1]).code;
        })
        .catch((error) => {
          if (error.response && error.response.status === 302) {
            return qs.parse(error.response.headers.location.split('?')[1]).code;
          }
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
        });

      await this.requestClient({
        method: 'post',
        url: 'https://id.mercedes-benz.com/as/token.oauth2',
        headers: {
          Accept: '*/*',
          'User-Agent': 'sOAF/202108260942 CFNetwork/978.0.7 Darwin/18.7.0',
          'Accept-Language': 'de-de',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        data:
          'grant_type=authorization_code&code=' +
          code +
          '&code_verifier=' +
          this.session.code_verifier +
          '&redirect_uri=https://oneapp.microservice.smart.mercedes-benz.com&client_id=70d89501-938c-4bec-82d0-6abb550b0825',
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          if (res.data) {
            this.session = res.data;
            this.setState('auth.session', JSON.stringify(this.session), true);
            this.setState('info.connection', true, true);
          }
        })
        .catch((error) => {
          this.log.error(error);
          if (error.response) {
            this.log.error(JSON.stringify(error.response.data));
          }
        });
    }
  }
  getCodeChallenge() {
    const chars = '0123456789abcdef';
    let result = '';
    for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    let hash = crypto.createHash('sha256').update(result).digest('base64');
    hash = hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    return [result, hash];
  }
  async getDeviceList() {
    await this.requestClient({
      method: 'get',
      url: 'https://oneapp.microservice.smart.mercedes-benz.com/seqc/v0/users/current',
      headers: {
        accept: '*/*',
        'accept-language': 'de-DE;q=1.0',
        authorization: 'Bearer ' + this.session.access_token,
        'x-applicationname': '70d89501-938c-4bec-82d0-6abb550b0825',
        'user-agent': this.userAgent,
        guid: '280C6B55-F179-4428-88B6-E0CCF5C22A7C',
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (!res.data || !res.data.licensePlates || res.data.licensePlates.length === 0) {
          this.log.warn('No vehicles found');
          return;
        }
        for (const device of res.data.licensePlates) {
          const vin = device.fin;
          this.deviceArray.push(vin);
          const name = device.licensePlate;

          await this.setObjectNotExistsAsync(vin, {
            type: 'device',
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(vin + '.remote', {
            type: 'channel',
            common: {
              name: 'Remote Controls',
            },
            native: {},
          });

          const remoteArray = [{ command: 'precond', name: 'True = Start, False = Stop' }];
          remoteArray.forEach((remote) => {
            this.setObjectNotExists(vin + '.remote.' + remote.command, {
              type: 'state',
              common: {
                name: remote.name || '',
                type: remote.type || 'boolean',
                role: remote.role || 'boolean',
                write: true,
                read: true,
              },
              native: {},
            });
          });

          await this.requestClient({
            method: 'get',
            url:
              'https://oneapp.microservice.smart.mercedes-benz.com/seqc/v0/vehicles/' +
              vin +
              '/init-data?requestedData=BOTH&countryCode=DE&locale=de-DE',
            headers: {
              accept: '*/*',
              'accept-language': 'de-DE;q=1.0',
              authorization: 'Bearer ' + this.session.access_token,
              'x-applicationname': '70d89501-938c-4bec-82d0-6abb550b0825',
              'user-agent': this.userAgent,
              guid: '280C6B55-F179-4428-88B6-E0CCF5C22A7C',
            },
          })
            .then(async (res) => {
              this.log.debug(JSON.stringify(res.data));
              this.json2iob.parse(vin, res.data);
            })
            .catch((error) => {
              this.log.error('Failed to get vehicles');
              this.log.error(error);
              error.response && this.log.error(JSON.stringify(error.response.data));
            });
        }
      })
      .catch((error) => {
        this.log.error('Failed to get user current');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async updateDevices() {
    const statusArray = [
      {
        path: '',
        url: 'https://oneapp.microservice.smart.mercedes-benz.com/seqc/v0/vehicles/$vin/refresh-data',
      },
    ];

    const headers = {
      accept: '*/*',
      'accept-language': 'de-DE;q=1.0',
      authorization: 'Bearer ' + this.session.access_token,
      'x-applicationname': '70d89501-938c-4bec-82d0-6abb550b0825',
      'user-agent': this.userAgent,
      guid: '280C6B55-F179-4428-88B6-CB7EF6908D75',
    };
    this.deviceArray.forEach(async (vin) => {
      statusArray.forEach(async (element) => {
        if (this.ignoreState.includes(element.path)) {
          return;
        }
        const url = element.url.replace('$vin', vin);

        await this.requestClient({
          method: 'get',
          url: url,
          headers: headers,
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            const data = res.data;

            const forceIndex = null;
            const preferedArrayName = null;

            this.json2iob.parse(vin + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 401 error. Refresh Token in 60 seconds');
                this.refreshTokenTimeout && this.clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = this.setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);

                return;
              }
            }
            this.log.error(url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      });
    });
  }
  async refreshToken() {
    await this.requestClient({
      method: 'post',
      url: 'https://id.mercedes-benz.com/as/token.oauth2',
      headers: {
        Accept: '*/*',
        'User-Agent': 'sOAF/202305260959 CFNetwork/1240.0.4 Darwin/20.6.0',
        'Accept-Language': 'de-de',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: {
        grant_type: 'refresh_token',
        refresh_token: this.session.refresh_token,
        redirect_uri: 'https://oneapp.microservice.smart.mercedes-benz.com',
        client_id: '70d89501-938c-4bec-82d0-6abb550b0825',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data) {
          this.session = res.data;
          this.setState('auth.session', JSON.stringify(this.session), true);
          this.setState('info.connection', true, true);
        }
      })
      .catch((error) => {
        this.log.error('refresh token failed');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.error('Start relogin in 1min');
        this.reLoginTimeout = this.setTimeout(async () => {
          await this.setStateAsync('auth.session', '{}', true);
          const adapterConfig = 'system.adapter.' + this.name + '.' + this.instance;
          const obj = await this.getForeignObjectAsync(adapterConfig);
          if (obj.native && obj.native.otp) {
            obj.native.otp = '';
            this.setForeignObject(adapterConfig, obj);
          }
        }, 1000 * 60 * 1);
      });
  }
  sleep(ms) {
    return new Promise((resolve) => this.setTimeout(resolve, ms));
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && this.clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && this.clearTimeout(this.refreshTokenTimeout);
      this.loginRetryTimeout && this.clearTimeout(this.loginRetryTimeout);
      this.updateInterval && this.clearInterval(this.updateInterval);
      this.refreshTokenInterval && this.clearInterval(this.refreshTokenInterval);
      callback();
    } catch {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        if (id.split('.')[3] !== 'remote') {
          return;
        }
        const deviceId = id.split('.')[2];
        const command = id.split('.')[4];
        let value;
        let data;

        if (this.config.type === 'hello') {
          if (command === 'refresh') {
            await this.updateDevicesHello();
            return;
          }
          // Setpoint-only commands: they change what conditioner / seatheat send,
          // but must not fire a request on their own. Ack, cache, and skip.
          if (command === 'conditioner_temp' || command === 'seatheat_level') {
            if (!this._numericStateCache) this._numericStateCache = {};
            if (state.val !== null && state.val !== undefined && !Number.isNaN(Number(state.val))) {
              this._numericStateCache[id] = Number(state.val);
            }
            await this.setStateAsync(id, state.val, true);
            return;
          }

          const payload = this.buildHelloRemotePayload(deviceId, command, state.val);
          if (!payload) {
            this.log.warn('Unknown remote command for Hello Smart: ' + command);
            return;
          }
          this.log.debug(JSON.stringify(payload));
          const url = '/remote-control/vehicle/telematics/' + deviceId;
          const headers = {
            ...this.buildHelloHeaders('PUT', url, {}, payload),
            'x-vehicle-identifier': deviceId,
            'content-type': 'application/json; charset=UTF-8',
          };
          await this.requestClient({
            method: 'put',
            url: this.getHelloApiBase(deviceId) + url,
            headers: headers,
            data: payload,
          })
            .then(async (res) => {
              this.log.debug(JSON.stringify(res.data));
              if (res.data.code === '1402') {
                await this.getCurrentToken();
                await this.requestClient(res.config)
                  .then((res) => {
                    this.log.info(JSON.stringify(res.data));
                  })
                  .catch((error) => {
                    this.log.error(error);
                    if (error.response) {
                      this.log.error(JSON.stringify(error.response.data));
                    }
                  });
                return;
              }
              this.log.info(JSON.stringify(res.data));
            })
            .catch((error) => {
              this.log.error(error);
              if (error.response) {
                this.log.error(JSON.stringify(error.response.data));
              }
            });
        } else {
          if (command === 'precond') {
            value = state.val ? 'start' : 'stop';
            data = {
              type: 'immediate',
            };
          }
          const url =
            'https://oneapp.microservice.smart.mercedes-benz.com/seqc/v0/vehicles/' +
            deviceId +
            '/' +
            command +
            '/' +
            value;
          this.log.debug(JSON.stringify(data));
          this.log.debug(url);
          await this.requestClient({
            method: 'post',
            url: url,
            headers: {
              'content-type': 'application/json',
              accept: '*/*',
              authorization: 'Bearer ' + this.session.access_token,
              'x-applicationname': '70d89501-938c-4bec-82d0-6abb550b0825',
              'accept-language': 'de-DE;q=1.0',
              'user-agent': this.userAgent,
              guid: '280C6B55-F179-4428-88B6-6F824694BF1B',
            },
            data: data,
          })
            .then((res) => {
              this.log.info(JSON.stringify(res.data));
              return res.data;
            })
            .catch((error) => {
              this.log.error(error);
              if (error.response) {
                this.log.error(JSON.stringify(error.response.data));
              }
            });
        }
        this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
        this.refreshTimeout = this.setTimeout(async () => {
          if (this.config.type === 'hello') {
            await this.updateDevicesHello();
          } else {
            await this.updateDevices();
          }
        }, 10 * 1000);
      } else {
        if (id.endsWith('.position.latitude') || id.endsWith('.position.longitude')) {
          if (state.val) {
            await this.setObjectNotExistsAsync(id + 'Conv', {
              type: 'state',
              common: {
                name: 'Converted',
                type: 'number',
                role: 'value.gps',
                read: true,
                write: false,
              },
              native: {},
            });
            await this.setStateAsync(id + 'Conv', Number(state.val) / 3600000.0, true);
          }
        }

        // const resultDict = { chargingStatus: "precond" };
        // const idArray = id.split(".");
        // const stateName = idArray[idArray.length - 1];
        // const vin = id.split(".")[2];
        // if (resultDict[stateName]) {
        //     let value = true;
        //     if (!state.val || state.val === "INVALID" || state.val === "NOT_CHARGING" || state.val === "ERROR" || state.val === "UNLOCKED") {
        //         value = false;
        //     }
        //     await this.setStateAsync(vin + ".remote." + resultDict[stateName], value, true);
        // }
      }
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new SmartEq(options);
} else {
  // otherwise start the instance directly
  new SmartEq();
}
