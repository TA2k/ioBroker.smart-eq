"use strict";

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
const qs = require("qs");
const crypto = require("crypto");
const Json2iob = require("./lib/json2iob");
const { wrapper } = require("axios-cookiejar-support");
const tough = require("tough-cookie");

class SmartEq extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "smart-eq",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
        this.deviceArray = [];
        this.json2iob = new Json2iob(this);
        this.ignoreState = [];
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        this.cookieJar = new tough.CookieJar();
        this.requestClient = wrapper(axios.create({ jar: this.cookieJar }));
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.session = {};
        this.subscribeStates("*");

        await this.login();

        if (this.session.access_token) {
            await this.getDeviceList();
            await this.updateDevices();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, this.config.interval * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, this.session.expires_in * 1000);
        }
    }
    async login() {
        const [code_verifier, codeChallenge] = this.getCodeChallenge();
        const resume = await this.requestClient({
            method: "get",
            url:
                "https://id.mercedes-benz.com/as/authorization.oauth2?client_id=70d89501-938c-4bec-82d0-6abb550b0825&response_type=code&scope=openid+profile+email+phone+ciam-uid+offline_access&redirect_uri=https://oneapp.microservice.smart.com&code_challenge=" +
                codeChallenge +
                "&code_challenge_method=S256",
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "de-de",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            },
            jar: this.cookieJar,
            withCredentials: true,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                return qs.parse(res.request.path.split("?")[1]).resume;
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });

        await this.requestClient({
            method: "post",
            url: "https://id.mercedes-benz.com/ciam/auth/login/user",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                Referer: "https://id.mercedes-benz.com/ciam/auth/login",
                "Accept-Language": "de-de",
            },
            jar: this.cookieJar,
            withCredentials: true,
            data: JSON.stringify({
                username: this.config.username,
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });

        const token = await this.requestClient({
            method: "post",
            url: "https://id.mercedes-benz.com/ciam/auth/login/pass",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                Referer: "https://id.mercedes-benz.com/ciam/auth/login",
                "Accept-Language": "de-de",
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
                return res.data.token;
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });
        if (!token) {
            this.log.error("Login failed, token empty");
            return;
        }
        const code = await this.requestClient({
            method: "post",
            url: "https://id.mercedes-benz.com" + resume,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                Referer: "https://id.mercedes-benz.com/ciam/auth/login",
                "Accept-Language": "de-de",
            },
            jar: this.cookieJar,
            withCredentials: true,
            data: "token=" + token,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                return qs.parse(res.request.path.split("?")[1]).code;
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });

        await this.requestClient({
            method: "post",
            url: "https://id.mercedes-benz.com/as/token.oauth2",
            headers: {
                Accept: "*/*",
                "User-Agent": "sOAF/202108260942 CFNetwork/978.0.7 Darwin/18.7.0",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            jar: this.cookieJar,
            withCredentials: true,
            data:
                "grant_type=authorization_code&code=" + code + "&code_verifier=" + code_verifier + "&redirect_uri=https://oneapp.microservice.smart.com&client_id=70d89501-938c-4bec-82d0-6abb550b0825",
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });
    }
    getCodeChallenge() {
        let hash = "";
        let result = "";
        const chars = "0123456789abcdef";
        result = "";
        for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
        hash = crypto.createHash("sha256").update(result).digest("base64");
        hash = hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        return [result, hash];
    }
    async getDeviceList() {
        await this.requestClient({
            method: "get",
            url: "https://oneapp.microservice.smart.com/seqc/v0/users/current",
            headers: {
                accept: "*/*",
                "accept-language": "de-DE;q=1.0",
                authorization: "Bearer " + this.session.access_token,
                "x-applicationname": "70d89501-938c-4bec-82d0-6abb550b0825",
                "user-agent": "Device: iPhone 6; OS-version: iOS_12.5.1; App-Name: smart EQ control; App-Version: 3.0; Build: 202108260942; Language: de_DE",
                guid: "280C6B55-F179-4428-88B6-E0CCF5C22A7C",
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));

                for (const device of res.data.licensePlates) {
                    const vin = device.fin;
                    this.deviceArray.push(vin);
                    const name = device.licensePlate;

                    await this.setObjectNotExistsAsync(vin, {
                        type: "device",
                        common: {
                            name: name,
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(vin + ".remote", {
                        type: "channel",
                        common: {
                            name: "Remote Controls",
                        },
                        native: {},
                    });

                    const remoteArray = [{ command: "precond", name: "True = Start, False = Stop" }];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(vin + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "boolean",
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    });

                    await this.requestClient({
                        method: "get",
                        url: "https://oneapp.microservice.smart.com/seqc/v0/vehicles/" + vin + "/init-data?requestedData=BOTH&countryCode=DE&locale=de-DE",
                        headers: {
                            accept: "*/*",
                            "accept-language": "de-DE;q=1.0",
                            authorization: "Bearer " + this.session.access_token,
                            "x-applicationname": "70d89501-938c-4bec-82d0-6abb550b0825",
                            "user-agent": "Device: iPhone 6; OS-version: iOS_12.5.1; App-Name: smart EQ control; App-Version: 3.0; Build: 202108260942; Language: de_DE",
                            guid: "280C6B55-F179-4428-88B6-E0CCF5C22A7C",
                        },
                    })
                        .then(async (res) => {
                            this.log.debug(JSON.stringify(res.data));
                            this.json2iob.parse(vin, res.data);
                        })
                        .catch((error) => {
                            this.log.error(error);
                            error.response && this.log.error(JSON.stringify(error.response.data));
                        });
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateDevices() {
        const statusArray = [
            {
                path: "",
                url: "https://oneapp.microservice.smart.com/seqc/v0/vehicles/$vin/refresh-data",
            },
        ];

        const headers = {
            accept: "*/*",
            "accept-language": "de-DE;q=1.0",
            authorization: "Bearer " + this.session.access_token,
            "x-applicationname": "70d89501-938c-4bec-82d0-6abb550b0825",
            "user-agent": "Device: iPhone 6; OS-version: iOS_12.5.1; App-Name: smart EQ control; App-Version: 3.0; Build: 202108260942; Language: de_DE",
            guid: "280C6B55-F179-4428-88B6-CB7EF6908D75",
        };
        this.deviceArray.forEach(async (vin) => {
            statusArray.forEach(async (element) => {
                if (this.ignoreState.includes(element.path)) {
                    return;
                }
                const url = element.url.replace("$vin", vin);

                await this.requestClient({
                    method: "get",
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

                        this.json2iob.parse(vin + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName });
                    })
                    .catch((error) => {
                        if (error.response) {
                            if (error.response.status === 401) {
                                error.response && this.log.debug(JSON.stringify(error.response.data));
                                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
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
            method: "post",
            url: "https://id.mercedes-benz.com/as/token.oauth2",
            headers: {
                Accept: "*/*",
                "User-Agent": "sOAF/202108260942 CFNetwork/978.0.7 Darwin/18.7.0",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: "grant_type=refresh_token&client_id=70d89501-938c-4bec-82d0-6abb550b0825&refresh_token=" + this.session.refresh_token,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error("refresh token failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error("Start relogin in 1min");
                this.reLoginTimeout = setTimeout(() => {
                    this.login();
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
            this.setState("info.connection", false, true);
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
                if (id.split(".")[3] !== "remote") {
                    return;
                }
                const deviceId = id.split(".")[2];
                const command = id.split(".")[4];
                let value;
                let data;
                if (command === "precond") {
                    value = state.val ? "start" : "stop";
                    data = {
                        type: "immediate",
                    };
                }
                const url = "https://oneapp.microservice.smart.com/seqc/v0/vehicles/" + deviceId + "/" + command + "/" + value;
                this.log.debug(JSON.stringify(data));
                this.log.debug(url);
                await this.requestClient({
                    method: "post",
                    url: url,
                    headers: {
                        "content-type": "application/json",
                        accept: "*/*",
                        authorization: "Bearer " + this.session.access_token,
                        "x-applicationname": "70d89501-938c-4bec-82d0-6abb550b0825",
                        "accept-language": "de-DE;q=1.0",
                        "user-agent": "Device: iPhone 6; OS-version: iOS_12.5.1; App-Name: smart EQ control; App-Version: 3.0; Build: 202108260942; Language: de_DE",
                        guid: "280C6B55-F179-4428-88B6-6F824694BF1B",
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
                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(async () => {
                    await this.updateDevices();
                }, 10 * 1000);
            } else {
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
