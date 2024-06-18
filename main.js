'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const qs = require('qs');
const crypto = require('crypto');
const Json2iob = require('json2iob');
const { wrapper } = require('axios-cookiejar-support');
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
    this.json2iob = new Json2iob(this);
    this.ignoreState = [];
    this.session = {};
    this.userAgent =
      'Device: iPhone 8 Plus; OS-version: iOS_16.7; App-Name: smart EQ control; App-Version: 4.1.0; Build: 202305260959; Language: de_DE';
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

    this.requestClient = wrapper(axios.create({ jar: this.cookieJar }));
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.subscribeStates('*');

    if (this.config.type === 'hello') {
      this.deviceId = crypto.randomBytes(16).toString('hex');
      await this.loginHello();

      if (this.session.accessToken) {
        await this.getDeviceListHello();
        await this.updateDevicesHello();
        this.updateInterval = setInterval(async () => {
          await this.updateDevicesHello();
        }, this.config.interval * 60 * 1000);
        this.refreshTokenInterval = setInterval(() => {
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
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);
      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, expires_in);
    }
  }
  async loginHello() {
    this.log.info('Login into Hello Smart');
    const context = await this.requestClient({
      method: 'get',
      url: 'https://awsapi.future.smart.com/login-app/api/v1/authorize?uiLocales=de-DE&uiLocales=de-DE',
      headers: {
        'upgrade-insecure-requests': '1',
        'user-agent':
          'Mozilla/5.0 (Linux; Android 9; ANE-LX1 Build/HUAWEIANE-L21; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/118.0.0.0 Mobile Safari/537.36',
        accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'x-requested-with': 'com.smart.hellosmart',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
      },
    }).then((res) => {
      this.log.debug(JSON.stringify(res.data));
      return qs.parse(res.request.path.split('?')[1]);
    });

    const loginResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://auth.smart.com/accounts.login',
      headers: {
        'user-agent':
          'Mozilla/5.0 (Linux; Android 9; ANE-LX1 Build/HUAWEIANE-L21; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/118.0.0.0 Mobile Safari/537.36',
        'content-type': 'application/x-www-form-urlencoded',
        accept: '*/*',
        origin: 'https://app.id.smart.com',
        'x-requested-with': 'com.smart.hellosmart',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
        cookie:
          'gmid=gmid.ver4.AcbHPqUK5Q.xOaWPhRTb7gy-6-GUW6cxQVf_t7LhbmeabBNXqqqsT6dpLJLOWCGWZM07EkmfM4j.u2AMsCQ9ZsKc6ugOIoVwCgryB2KJNCnbBrlY6pq0W2Ww7sxSkUa9_WTPBIwAufhCQYkb7gA2eUbb6EIZjrl5mQ.sc3; ucid=hPzasmkDyTeHN0DinLRGvw; hasGmid=ver4; gig_bootstrap_3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a=auth_ver4',
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
        riskContext:
          '{"b0":41187,"b1":[0,2,3,1],"b2":4,"b3":["-23|0.383","-81.33333587646484|0.236"],"b4":3,"b5":1,"b6":"Mozilla/5.0 (Linux; Android 9; ANE-LX1 Build/HUAWEIANE-L21; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/118.0.0.0 Mobile Safari/537.36","b7":[],"b8":"16:33:26","b9":-60,"b10":null,"b11":false,"b12":{"charging":true,"chargingTime":null,"dischargingTime":null,"level":0.58},"b13":[5,"360|760|24",false,true]}',
        APIKey: '3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a',
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
      });
    if (!loginResponse) {
      this.log.error('Login failed #1');
      this.setState('info.connection', false, true);

      return;
    }

    if (!loginResponse.sessionInfo) {
      this.log.error('Login failed no session found');
      this.setState('info.connection', false, true);
      this.log.error(JSON.stringify(loginResponse));
      return;
    }
    this.gtokens = await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url:
        'https://auth.smart.com/oidc/op/v1.0/3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a/authorize/continue?context=' +
        context.context +
        '&login_token=' +
        loginResponse.sessionInfo.login_token,
      headers: {
        'upgrade-insecure-requests': '1',
        'user-agent':
          'Mozilla/5.0 (Linux; Android 9; ANE-LX1 Build/HUAWEIANE-L21; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/118.0.0.0 Mobile Safari/537.36',
        accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'x-requested-with': 'com.smart.hellosmart',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'accept-language': 'de-DE,de;q=0.9,en-DE;q=0.8,en-US;q=0.7,en;q=0.6',
        cookie:
          'gmid=gmid.ver4.AcbHPqUK5Q.xOaWPhRTb7gy-6-GUW6cxQVf_t7LhbmeabBNXqqqsT6dpLJLOWCGWZM07EkmfM4j.u2AMsCQ9ZsKc6ugOIoVwCgryB2KJNCnbBrlY6pq0W2Ww7sxSkUa9_WTPBIwAufhCQYkb7gA2eUbb6EIZjrl5mQ.sc3; ucid=hPzasmkDyTeHN0DinLRGvw; hasGmid=ver4; gig_bootstrap_3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a=auth_ver4; glt_3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a=' +
          loginResponse.sessionInfo.login_token,
      },
    })
      .then((res) => {
        this.log.debug(res.request.path);
        const tokens = qs.parse(res.request.path.split('?')[1]);
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
    await this.getCurrentToken();
    this.log.info('Login successful');
  }
  async getCurrentToken() {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const params = { identity_type: 'smart' };
    const method = 'POST';
    const url = '/auth/account/session/secure';
    const data = {
      accessToken: this.gtokens.access_token,
    };
    const sign = this.creasteSignatureHello(nonce, params, timestamp, method, url, data);
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://api.ecloudeu.com/auth/account/session/secure',
      headers: {
        'x-app-id': 'SmartAPPEU',
        accept: 'application/json;responseformat=3',
        'x-agent-type': 'android',
        'x-device-type': 'mobile',
        'x-operator-code': 'SMART',
        'x-device-identifier': this.deviceId,
        'x-env-type': 'production',
        'x-version': 'smartNew',
        'accept-language': 'en_US',
        'x-api-signature-version': '1.0',
        'x-api-signature-nonce': nonce,
        'x-device-manufacture': 'HUAWEI',
        'x-device-brand': 'ANE-LX1',
        'x-device-model': 'ANE-LX1',
        'x-device-release-date': '',
        'x-agent-version': '9',
        'content-type': 'application/json; charset=utf-8',
        'user-agent': 'okhttp/4.11.0',
        'x-signature': sign,
        'x-timestamp': timestamp,
      },
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
  async getDeviceListHello() {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const params = { needSharedCar: 1, userId: this.session.userId };
    const method = 'GET';
    const url = '/device-platform/user/vehicle/secure';
    const sign = this.creasteSignatureHello(nonce, params, timestamp, method, url);
    await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://api.ecloudeu.com' + url,
      headers: {
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
        authorization: this.session.accessToken,
        'x-client-id': 'UAWEI0000APP00ANELX123AV10090080',
        'user-agent': 'okhttp/4.11.0',
        'x-signature': sign,
        'x-timestamp': timestamp,
      },
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
          const name = device.modelName + ' ' + device.plateNo;

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

          const remoteArray = [
            { command: 'conditioner', name: 'True = Start, False = Stop' },
            { command: 'lock', name: 'True = Lock, False = Unlock' },
            { command: 'seatheat', name: 'True = On, False = Off' },
            { command: 'charging', name: 'True = On, False = Off' },
            { command: 'refresh', name: 'True = Refresh' },
          ];
          remoteArray.forEach((remote) => {
            this.setObjectNotExists(vin + '.remote.' + remote.command, {
              type: 'state',
              common: {
                name: remote.name || '',
                type: remote.type || 'boolean',
                role: remote.role || 'boolean',
                def: false,
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
  async updateDevicesHello() {
    for (const vin of this.deviceArray) {
      const timestamp = Date.now();
      const nonce = crypto.randomBytes(16).toString('hex');
      const params = { latest: true, target: '', userId: this.session.userId };
      const method = 'GET';
      const url = '/remote-control/vehicle/status/' + vin;
      const sign = this.creasteSignatureHello(nonce, params, timestamp, method, url);
      await this.requestClient({
        method: 'get',
        maxBodyLength: Infinity,
        url: 'https://api.ecloudeu.com' + url,
        headers: {
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
          authorization: this.session.accessToken,
          'x-client-id': 'UAWEI0000APP00ANELX123AV10090080',
          'user-agent': 'okhttp/4.11.0',
          'x-signature': sign,
          'x-timestamp': timestamp,
        },
        params: params,
      })
        .then(async (res) => {
          this.log.debug(JSON.stringify(res.data));
          if (res.data.code === '1402') {
            await this.getCurrentToken();
            return;
          }
          if (!res.data || !res.data.data || !res.data.data.vehicleStatus) {
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
        jar: this.cookieJar,
        withCredentials: true,
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
        jar: this.cookieJar,
        withCredentials: true,
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

      const token = await this.requestClient({
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
        jar: this.cookieJar,
        withCredentials: true,
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
        jar: this.cookieJar,
        withCredentials: true,
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
        jar: this.cookieJar,
        withCredentials: true,
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
        jar: this.cookieJar,
        withCredentials: true,
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
    let hash = '';
    let result = '';
    const chars = '0123456789abcdef';
    result = '';
    for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    hash = crypto.createHash('sha256').update(result).digest('base64');
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
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
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
        this.reLoginTimeout = setTimeout(async () => {
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
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
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
          let payload = {};
          if (command === 'conditioner') {
            payload = {
              command: state.val ? 'start' : 'stop',
              creator: 'tc',
              operationScheduling: {
                duration: 180,
                interval: 0,
                occurs: 1,
                recurrentOperation: false,
              },
              serviceId: 'RCE_2',
              serviceParameters: [
                {
                  key: 'rce.conditioner',
                  value: '1',
                },
                {
                  key: 'rce.temp',
                  value: '20.0',
                },
              ],
              timestamp: Date.now(),
            };
          }
          if (command === 'charging') {
            payload = {
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
                {
                  key: 'operation',
                  value: '1',
                },
                {
                  key: state.val ? 'rcs.restart' : 'rcs.terminate',
                  value: '1',
                },
              ],
              timestamp: Date.now(),
            };
          }
          if (command === 'seatheat') {
            payload = {
              command: state.val ? 'start' : 'stop',
              creator: 'tc',
              operationScheduling: {
                duration: 0,
                interval: 0,
                occurs: 1,
                recurrentOperation: false,
              },
              serviceId: 'RCE_2',
              serviceParameters: [
                {
                  key: 'rce.heat',
                  value: 'front-left',
                },
                {
                  key: 'rce.level',
                  value: '3',
                },
              ],
              timestamp: Date.now(),
            };
          }
          if (command === 'lock') {
            payload = {
              command: 'start',
              creator: 'tc',
              operationScheduling: {
                duration: 0,
                interval: 0,
                occurs: 1,
                recurrentOperation: false,
              },
              serviceId: state.val ? 'RDL_2' : 'RDU_2',
              serviceParameters: [
                {
                  key: 'door',
                  value: 'all',
                },
              ],
              timestamp: Date.now(),
            };
          }
          this.log.debug(JSON.stringify(payload));
          const timestamp = Date.now();
          const nonce = crypto.randomBytes(16).toString('hex');
          const params = {};
          const method = 'PUT';
          const url = '/remote-control/vehicle/telematics/' + deviceId;

          const sign = this.creasteSignatureHello(nonce, params, timestamp, method, url, payload);
          await this.requestClient({
            method: 'put',
            url: 'https://api.ecloudeu.com' + url,
            headers: {
              'x-app-id': 'SmartAPPEU',
              accept: 'application/json;responseformat=3',
              'x-agent-type': 'android',
              'x-device-type': 'mobile',
              'x-operator-code': 'SMART',
              'x-device-identifier': this.deviceId,
              'x-env-type': 'production',
              'x-version': 'smartNew',
              'accept-language': 'en_US',
              'x-api-signature-version': '1.0',
              'x-api-signature-nonce': nonce,
              authorization: this.session.accessToken,
              'x-client-id': 'UAWEI0000APP00ANELX123AV10090080',
              'x-vehicle-identifier': deviceId,
              'content-type': 'application/json; charset=UTF-8',
              'user-agent': 'okhttp/4.11.0',
              'x-signature': sign,
              'x-timestamp': timestamp,
            },
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
        this.refreshTimeout && clearTimeout(this.refreshTimeout);
        this.refreshTimeout = setTimeout(async () => {
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
