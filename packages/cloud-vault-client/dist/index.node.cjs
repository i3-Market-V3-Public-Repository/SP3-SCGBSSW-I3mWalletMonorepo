"use strict";var t=require("crypto"),e=require("worker_threads"),s=require("axios"),i=require("axios-retry"),a=require("events"),o=require("eventsource"),n=require("dotenv");function r(t){return t&&t.__esModule?t:{default:t}}var u=r(s),h=r(i),l=r(o);class c{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(e){const s=t.randomBytes(16),i=t.createCipheriv(this.alg,this.key,s),a=Buffer.concat([i.update(e),i.final()]),o=i.getAuthTag();return Buffer.concat([s,o,a])}decrypt(e){const s=e.subarray(0,16),i=e.subarray(16,32),a=e.subarray(32),o=t.createDecipheriv(this.alg,this.key,s);return o.setAuthTag(i),Buffer.concat([o.update(a),o.final()])}}if(!e.isMainThread&&"object"==typeof e.workerData&&"scrypt-thread"===e.workerData._name){const{passwordOrKey:C,opts:R}=e.workerData;async function O(e,s){const i={...s.alg_options,maxmem:256*s.alg_options.N*s.alg_options.r},a="string"==typeof e?e:e.export(),o=new Promise(((e,o)=>{t.scrypt(a,s.salt,s.derived_key_length,i,((t,s)=>{null!==t&&o(t),e(s)}))}));return await o}O(C,R).then((t=>{e.parentPort?.postMessage(t)})).catch((t=>{throw t instanceof Error?t:new Error(t)}))}class d{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,s){this.username=t,this.derivationOptions=s,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:s,enc:i}=this.derivationOptions,a=p(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),o=await w(t,{...e,salt:a}),n=p(s.salt_hashing_algorithm,s.salt_pattern,{username:this.username}),r=p(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),[u,h]=await Promise.all([w(o,{...s,salt:n}),w(o,{...i,salt:r})]);this._authKey=u,this._encKey=new c(h,i.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function p(e,s,i){let a="";for(const t in i)a=s.replace(t,i[t]);return t.createHash(e).update(a).digest()}async function w(s,i){return await new Promise(((a,o)=>{const n={_name:"scrypt-thread",passwordOrKey:s,opts:i},r=new e.Worker(__filename,{workerData:n});r.on("message",(e=>{a(t.createSecretKey(e))})),r.on("error",(t=>{o(t)})),r.on("messageerror",(t=>{o(t)}))}))}class m extends Error{data;message;constructor(t,e,s){super(t,s),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof m)return t;if(t instanceof Object&&"Event"===t.constructor.name)return new m("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof s.AxiosError){const e=t.response?.data;switch(e.name){case"no-storage":return new m("no-uploaded-storage",void 0);case"invalid-credentials":return new m("invalid-credentials",void 0);case"invalid-timestamp":return new m("invalid-timestamp",void 0);case"quota-exceeded":return new m("quota-exceeded",e.description);case"unauthorized":case"not-registered":return new m("unauthorized",void 0)}const s={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new m("http-connection-error",s)}if(t instanceof Error){const e=new m("error",t,{cause:t.cause});return e.stack=t.stack,e}return new m("unknown",t)}}class g{axios;defaultCallOptions;defaultUrl;_stop;ongoingRequests;constructor(t){this._stop=!1,this.axios=this.getAxiosInstance(t?.retryOptions),this.defaultCallOptions=t?.defaultCallOptions,this.defaultUrl=t?.defaultUrl,this.ongoingRequests={}}getAxiosInstance(t){const e=u.default.create();return void 0!==t?.retries&&h.default(e,{retries:t.retries,retryDelay:()=>t.retryDelay,retryCondition:t=>!this._stop&&i.isNetworkOrIdempotentRequestError(t)}),e}async waitForOngoingRequestsToFinsh(t){const e=void 0!==t?t:this.defaultUrl;if(void 0===e)throw new m("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url oof the uploads you want to wait to finish"});if(void 0!==this.ongoingRequests[e])for(const t of this.ongoingRequests[e])try{await t}catch(t){}}async stop(){this._stop=!0;for(const t in this.ongoingRequests)await this.waitForOngoingRequestsToFinsh(t).catch();this._stop=!1}async request(t,e,s,i){const a={"Content-Type":"application/json"};if(void 0!==i?.bearerToken&&(a.Authorization="Bearer "+i.bearerToken),this._stop)throw new m("http-request-canceled",{request:{method:t.toUpperCase(),url:e,headers:a,data:s}});"post"!==t&&"put"!==t||!0!==i?.sequentialPost||await this.waitForOngoingRequestsToFinsh(e).catch(),this.ongoingRequests[e]=[];const o="post"===t||"put"===t?this.axios[t](e,s,{headers:a}):this.axios[t](e,{headers:a}),n=this.ongoingRequests[e].push(o)-1,r=await o.catch((t=>{throw m.from(t)})),u=i?.beforeUploadFinish;if(void 0!==u&&await u(r.data),n===this.ongoingRequests[e].length-1)this.ongoingRequests[e].pop();else{let t=n;do{delete this.ongoingRequests[e][n],t--}while(void 0===this.ongoingRequests[e][t])}if(0===this.ongoingRequests[e].length&&delete this.ongoingRequests[e],void 0!==i?.responseStatus&&r.status!==i.responseStatus)throw new m("validation",{description:`Received HTTP status ${r.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return r.data}async delete(t,e){const s="string"==typeof t?t:this.defaultUrl;if(void 0===s)throw new m("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});const i="string"!=typeof t?t:e;return await this.request("delete",s,void 0,i)}async get(t,e){const s="string"==typeof t?t:this.defaultUrl;if(void 0===s)throw new m("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});const i="string"!=typeof t?t:e;return await this.request("get",s,void 0,i)}async post(t,e,s){let i,a,o;if("string"==typeof t?(i=t,a=e,o=s):(i=this.defaultUrl,a=t,o=e),void 0===i)throw new m("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});return await this.request("post",i,a,o)}async put(t,e,s){let i,a,o;if("string"==typeof t?(i=t,a=e,o=s):(i=this.defaultUrl,a=t,o=e),void 0===i)throw new m("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});return await this.request("put",i,a,o)}}n.config();const f=(t,e)=>{let s=`Invalid value for ${t}. `;return void 0!==e&&(s+=`Allowed values are ${e} `),s},v=["0","false","FALSE"],y=["1","true","FALSE"],_=v.concat(y);!function(t,e){const s=void 0===(i=process.env[t])?"":i;var i;e=e??{};const a=e?.isBoolean??!1;if(a&&(e={...e,allowedValues:_}),""===s){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(f(t,e.allowedValues.join(", ")))}if(a&&y.includes(s))return!0;if(a&&v.includes(s))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(s))throw new RangeError(f(t,e.allowedValues.join(", ")))}("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const E="v"+"2.5.9".split(".")[0],I={NOT_INITIALIZED:0,INITIALIZED:1,LOGGED_IN:2,CONNECTED:3};function T(t,e){switch(m.from(e).message){case"invalid-credentials":case"unauthorized":return I.INITIALIZED;case"sse-connection-error":return t>=I.LOGGED_IN?I.LOGGED_IN:I.INITIALIZED;default:return t}}class q extends a.EventEmitter{timestamp;token;name;opts;serverRootUrl;serverPrefix;serverUrl;wellKnownCvsConfigurationPromise;wellKnownCvsConfiguration;_state;_initialized;vaultRequest;keyManager;es;constructor(e,s){super({captureRejections:!0}),this.name=s?.name??t.randomBytes(16).toString("hex"),this.opts=s;const i=new URL(e);this.serverRootUrl=i.origin,this.serverPrefix=i.pathname.endsWith("/")?i.pathname.slice(0,-1):i.pathname,this.serverUrl=this.serverRootUrl+this.serverPrefix,this._state=I.NOT_INITIALIZED,this._initialized=this.init()}get initialized(){return new Promise(((t,e)=>{this._initialized.then((()=>{t()})).catch((()=>{this._initialized=this.init().then((()=>{t()})).catch((t=>{e(t)}))}))}))}get state(){return this._state}set state(t){if(t<I.NOT_INITIALIZED||t>I.CONNECTED)throw new Error("invalid state");if(t-this._state>1||this.state-t>1)throw new Error("steps MUST be passed one by one");if(this._state!==t){switch(t){case I.NOT_INITIALIZED:delete this.wellKnownCvsConfigurationPromise,delete this.wellKnownCvsConfiguration,this._initialized=new Promise(((t,e)=>{e(new m("not-initialized",void 0))}));break;case I.INITIALIZED:this._state===I.LOGGED_IN&&(delete this.keyManager,delete this.vaultRequest,delete this.token,delete this.timestamp,this.es?.close(),delete this.es)}this._state=t,this.emit("state-changed",this._state)}}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){this.wellKnownCvsConfigurationPromise=q.getWellKnownCvsConfiguration(this.serverRootUrl+this.serverPrefix,{retries:28800,retryDelay:3e3}),this.wellKnownCvsConfiguration=await this.wellKnownCvsConfigurationPromise.promise.catch((t=>{throw new m("not-initialized",t)})),this.state=I.INITIALIZED}async initEventSourceClient(){if(this.state!==I.LOGGED_IN)throw new Error("cannot be called if not logged in");const t=this.wellKnownCvsConfiguration.vault_configuration[E].events_endpoint;this.es=new l.default(t,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);void 0===e.timestamp?this.emit("empty-storage"):e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp)),this.state=I.CONNECTED})),this.es.addEventListener("storage-updated",(t=>{this.vaultRequest.waitForOngoingRequestsToFinsh().finally((()=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})).catch((t=>{}))})),this.es.addEventListener("storage-deleted",(t=>{this.vaultRequest.waitForOngoingRequestsToFinsh().finally((()=>{this.logout(),this.emit("storage-deleted")})).catch((t=>{}))})),this.es.onerror=t=>{this.state=T(this.state,t)}}async initKeyManager(t,e){const s=this.wellKnownCvsConfiguration;this.keyManager=new d(t,e,s.vault_configuration[E].key_derivation),await this.keyManager.initialized}logout(){this.state<I.LOGGED_IN||(this.state===I.CONNECTED&&(this.state=I.LOGGED_IN),this.state=I.INITIALIZED)}close(){this.logout(),this.vaultRequest?.stop().catch((()=>{})),this.wellKnownCvsConfigurationPromise?.stop(),this.wellKnownCvsConfigurationPromise?.promise.catch((()=>{})),this.state=I.NOT_INITIALIZED}async login(t,e,s){this.state===I.NOT_INITIALIZED&&await this.initialized,await this.initKeyManager(t,e);const i={username:t,authkey:this.keyManager.authKey},a=new g({retryOptions:this.opts?.defaultRetryOptions}),o=this.wellKnownCvsConfiguration,n=await a.post(o.vault_configuration.v2.token_endpoint,i,{responseStatus:200});this.token=n.token,this.vaultRequest=new g({retryOptions:this.opts?.defaultRetryOptions,defaultCallOptions:{bearerToken:this.token,sequentialPost:!0},defaultUrl:o.vault_configuration.v2.vault_endpoint}),this.timestamp=s,this.state=I.LOGGED_IN,await this.initEventSourceClient()}async getRemoteStorageTimestamp(){if(this.state<I.LOGGED_IN)throw new m("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;try{await this.vaultRequest.waitForOngoingRequestsToFinsh();const e=new g({retryOptions:this.opts?.defaultRetryOptions}),s=await e.get(t.vault_configuration[E].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<s.timestamp&&(this.timestamp=s.timestamp),s.timestamp}catch(t){throw this.state=T(this.state,t),t}}async getStorage(){if(this.state<I.LOGGED_IN)throw new m("unauthorized",void 0);const t=Date.now();this.emit("sync-start",t);try{const e=this.vaultRequest;await e.waitForOngoingRequestsToFinsh();const s=await e.get({bearerToken:this.token,responseStatus:200});if(s.timestamp<(this.timestamp??0))throw new m("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const i=this.keyManager.encKey.decrypt(Buffer.from(s.ciphertext,"base64url"));return this.timestamp=s.timestamp,this.emit("sync-stop",t,Date.now()),{storage:i,timestamp:s.timestamp}}catch(e){throw this.emit("sync-stop",t,Date.now()),this.state=T(this.state,e),m.from(e)}}async updateStorage(t,e=!1,s){if(this.state<I.LOGGED_IN)throw new m("unauthorized",void 0);const i=Date.now();this.emit("sync-start",i);try{if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new m("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const s={ciphertext:this.keyManager.encKey.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},a=this.vaultRequest,o=await a.post(s,{bearerToken:this.token,responseStatus:201,beforeUploadFinish:async t=>{this.timestamp=t.timestamp}});return this.emit("sync-stop",i,Date.now()),o.timestamp}catch(t){throw this.emit("sync-stop",i,Date.now()),this.state=T(this.state,t),m.from(t)}}async deleteStorage(){if(this.state<I.LOGGED_IN)throw new m("unauthorized",void 0);try{const t=this.vaultRequest;await t.stop(),await t.delete({bearerToken:this.token,responseStatus:204}),this.logout()}catch(t){throw t instanceof m&&"unauthorized"===t.message&&this.logout(),t}}async getServerPublicKey(){await this.initialized;const t=this.wellKnownCvsConfiguration,e=new g({retryOptions:this.opts?.defaultRetryOptions});return(await e.get(t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}static getWellKnownCvsConfiguration(t,e){const s=new g({retryOptions:e}),i=s.get(t+"/.well-known/cvs-configuration",{responseStatus:200});return{stop:s.stop,promise:i}}static async computeAuthKey(t,e,s,i){const a=q.getWellKnownCvsConfiguration(t,i),o=await a.promise,n=new d(e,s,o.vault_configuration[E].key_derivation);return await n.initialized,n.authKey}}exports.KeyManager=d,exports.Request=g,exports.SecretKey=c,exports.VAULT_STATE=I,exports.VaultClient=q,exports.VaultError=m,exports.checkErrorType=function(t,e){return t.message===e},exports.deriveKey=w;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uL3NyYy90cy9zZWNyZXQta2V5LnRzIiwiLi4vc3JjL3RzL3NjcnlwdC10aHJlYWQudHMiLCIuLi9zcmMvdHMva2V5LW1hbmFnZXIudHMiLCIuLi9zcmMvdHMvZXJyb3IudHMiLCIuLi9zcmMvdHMvcmVxdWVzdC50cyIsIi4uL3NyYy90cy9jb25maWcvcGFyc2VQcm9jZXNzRW52VmFyLnRzIiwiLi4vc3JjL3RzL2NvbmZpZy9pbmRleC50cyIsIi4uL3NyYy90cy92YXVsdC1zdGF0ZS50cyIsIi4uL3NyYy90cy92YXVsdC1jbGllbnQudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbIlNlY3JldEtleSIsImtleSIsImFsZyIsImNvbnN0cnVjdG9yIiwidGhpcyIsImVuY3J5cHQiLCJpbnB1dCIsIml2IiwicmFuZG9tQnl0ZXMiLCJjaXBoZXIiLCJjcmVhdGVDaXBoZXJpdiIsImVuY3J5cHRlZCIsIkJ1ZmZlciIsImNvbmNhdCIsInVwZGF0ZSIsImZpbmFsIiwidGFnIiwiZ2V0QXV0aFRhZyIsImRlY3J5cHQiLCJzdWJhcnJheSIsImNpcGhlcnRleHQiLCJkZWNpcGhlciIsImNyZWF0ZURlY2lwaGVyaXYiLCJzZXRBdXRoVGFnIiwiaXNNYWluVGhyZWFkIiwid29ya2VyRGF0YSIsIl9uYW1lIiwicGFzc3dvcmRPcktleSIsIm9wdHMiLCJhc3luYyIsInNjcnlwdFRocmVhZCIsInNjcnlwdE9wdGlvbnMiLCJhbGdfb3B0aW9ucyIsIm1heG1lbSIsIk4iLCJyIiwicGFzc3dvcmQiLCJleHBvcnQiLCJrZXlQcm9taXNlIiwiUHJvbWlzZSIsInJlc29sdmUiLCJyZWplY3QiLCJzY3J5cHQiLCJzYWx0IiwiZGVyaXZlZF9rZXlfbGVuZ3RoIiwiZXJyIiwidGhlbiIsImRlcml2ZWRLZXkiLCJwYXJlbnRQb3J0IiwicG9zdE1lc3NhZ2UiLCJjYXRjaCIsIkVycm9yIiwiS2V5TWFuYWdlciIsIl9lbmNLZXkiLCJfYXV0aEtleSIsInVzZXJuYW1lIiwiZGVyaXZhdGlvbk9wdGlvbnMiLCJpbml0aWFsaXplZCIsIl9pbml0aWFsaXplZCIsImluaXQiLCJtYXN0ZXIiLCJhdXRoIiwiZW5jIiwibWFzdGVyU2FsdCIsIl9zYWx0Iiwic2FsdF9oYXNoaW5nX2FsZ29yaXRobSIsInNhbHRfcGF0dGVybiIsIm1hc3RlcktleSIsImRlcml2ZUtleSIsImF1dGhTYWx0IiwiZW5jU2FsdCIsImF1dGhLZXkiLCJlbmNLZXkiLCJhbGwiLCJlbmNfYWxnb3JpdGhtIiwiY2F1c2UiLCJ0b1N0cmluZyIsImhhc2hBbGdvcml0aG0iLCJzYWx0UGF0dGVybiIsInJlcGxhY2VtZW50cyIsInNhbHRTdHJpbmciLCJzZWFyY2hWYWx1ZSIsInJlcGxhY2UiLCJjcmVhdGVIYXNoIiwiZGlnZXN0Iiwid29ya2VyIiwiV29ya2VyIiwiX19maWxlbmFtZSIsIm9uIiwiY3JlYXRlU2VjcmV0S2V5IiwiVmF1bHRFcnJvciIsImRhdGEiLCJtZXNzYWdlIiwib3B0aW9ucyIsInN1cGVyIiwibmFtZSIsInN0YXRpYyIsImVycm9yIiwiT2JqZWN0IiwiQXhpb3NFcnJvciIsInJlc3BvbnNlIiwidW5kZWZpbmVkIiwiZGVzY3JpcHRpb24iLCJ2YXVsdENvbm5FcnJvciIsInJlcXVlc3QiLCJtZXRob2QiLCJjb25maWciLCJ0b0xvY2FsZVVwcGVyQ2FzZSIsInVybCIsImhlYWRlcnMiLCJzdGF0dXMiLCJ2YXVsdEVycm9yIiwic3RhY2siLCJSZXF1ZXN0IiwiYXhpb3MiLCJkZWZhdWx0Q2FsbE9wdGlvbnMiLCJkZWZhdWx0VXJsIiwiX3N0b3AiLCJvbmdvaW5nUmVxdWVzdHMiLCJnZXRBeGlvc0luc3RhbmNlIiwicmV0cnlPcHRpb25zIiwiYXhpb3NJbnN0YW5jZSIsImNyZWF0ZSIsInJldHJpZXMiLCJheGlvc1JldHJ5IiwicmV0cnlEZWxheSIsInJldHJ5Q29uZGl0aW9uIiwiaXNOZXR3b3JrT3JJZGVtcG90ZW50UmVxdWVzdEVycm9yIiwidXJsMiIsInByb21pc2UiLCJ3YWl0Rm9yT25nb2luZ1JlcXVlc3RzVG9GaW5zaCIsInJlcXVlc3RCb2R5IiwiYmVhcmVyVG9rZW4iLCJBdXRob3JpemF0aW9uIiwidG9VcHBlckNhc2UiLCJzZXF1ZW50aWFsUG9zdCIsInJlcXVlc3RQcm9taXNlIiwiaW5kZXgiLCJwdXNoIiwicmVzIiwiZnJvbSIsImJlZm9yZVVwbG9hZEZpbmlzaCIsImxlbmd0aCIsInBvcCIsImkiLCJyZXNwb25zZVN0YXR1cyIsInVybE9yT3B0aW9ucyIsInVybE9yUmVxdWVzdEJvZHkiLCJyZXF1ZXN0Qm9keU9yT3B0aW9ucyIsImxvYWRFbnZGaWxlIiwiaW52YWxpZE1zZyIsInZhcm5hbWUiLCJ2YWx1ZXMiLCJyZXQiLCJib29sZWFuRmFsc2VBbGxvd2VkVmFsdWVzIiwiYm9vbGVhblRydWVBbGxvd2VkVmFsdWVzIiwiYm9vbGVhbkFsbG93ZWRWYWx1ZXMiLCJ2YXJOYW1lIiwidmFsdWUiLCJhIiwicHJvY2VzcyIsImVudiIsImlzQm9vbGVhbiIsImFsbG93ZWRWYWx1ZXMiLCJkZWZhdWx0VmFsdWUiLCJpbmNsdWRlcyIsIlJhbmdlRXJyb3IiLCJqb2luIiwicGFyc2VQcm9jY2Vzc0VudlZhciIsImFwaVZlcnNpb24iLCJzcGxpdCIsIlZBVUxUX1NUQVRFIiwiTk9UX0lOSVRJQUxJWkVEIiwiSU5JVElBTElaRUQiLCJMT0dHRURfSU4iLCJDT05ORUNURUQiLCJzdGF0ZUZyb21FcnJvciIsImN1cnJlbnRTdGF0ZSIsIlZhdWx0Q2xpZW50IiwiRXZlbnRFbWl0dGVyIiwidGltZXN0YW1wIiwidG9rZW4iLCJzZXJ2ZXJSb290VXJsIiwic2VydmVyUHJlZml4Iiwic2VydmVyVXJsIiwid2VsbEtub3duQ3ZzQ29uZmlndXJhdGlvblByb21pc2UiLCJ3ZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiX3N0YXRlIiwidmF1bHRSZXF1ZXN0Iiwia2V5TWFuYWdlciIsImVzIiwiY2FwdHVyZVJlamVjdGlvbnMiLCJVUkwiLCJvcmlnaW4iLCJwYXRobmFtZSIsImVuZHNXaXRoIiwic2xpY2UiLCJyZWFzb24iLCJzdGF0ZSIsIm5ld1N0YXRlIiwiY2xvc2UiLCJlbWl0IiwiZXZlbnROYW1lIiwiYXJncyIsImxpc3RlbmVyIiwib25jZSIsImdldFdlbGxLbm93bkN2c0NvbmZpZ3VyYXRpb24iLCJlc1VybCIsInZhdWx0X2NvbmZpZ3VyYXRpb24iLCJldmVudHNfZW5kcG9pbnQiLCJFdmVudFNvdXJjZSIsImRlZmF1bHQiLCJhZGRFdmVudExpc3RlbmVyIiwiZSIsIm1zZyIsIkpTT04iLCJwYXJzZSIsImZpbmFsbHkiLCJsb2dvdXQiLCJvbmVycm9yIiwiY3ZzQ29uZiIsImtleV9kZXJpdmF0aW9uIiwic3RvcCIsImluaXRLZXlNYW5hZ2VyIiwicmVxQm9keSIsImF1dGhrZXkiLCJkZWZhdWx0UmV0cnlPcHRpb25zIiwicG9zdCIsInYyIiwidG9rZW5fZW5kcG9pbnQiLCJ2YXVsdF9lbmRwb2ludCIsImluaXRFdmVudFNvdXJjZUNsaWVudCIsImdldCIsInRpbWVzdGFtcF9lbmRwb2ludCIsInN0YXJ0VHMiLCJEYXRlIiwibm93Iiwic3RvcmFnZSIsImZvcmNlIiwicmVtb3RlVGltZXN0YW1wIiwiZ2V0UmVtb3RlU3RvcmFnZVRpbWVzdGFtcCIsImxvY2FsVGltZXN0YW1wIiwiZGVsZXRlIiwicmVnaXN0cmF0aW9uX2NvbmZpZ3VyYXRpb24iLCJwdWJsaWNfandrX2VuZHBvaW50IiwiandrIiwidHlwZSJdLCJtYXBwaW5ncyI6ImdRQUdhQSxFQUNNQyxJQUNSQyxJQUVUQyxZQUFhRixFQUFnQkMsR0FDM0JFLEtBQUtILElBQU1BLEVBQ1hHLEtBQUtGLElBQU1BLENBQ1osQ0FFREcsUUFBU0MsR0FFUCxNQUFNQyxFQUFLQyxjQUFZLElBR2pCQyxFQUFTQyxFQUFBQSxlQUFlTixLQUFLRixJQUFLRSxLQUFLSCxJQUFLTSxHQUc1Q0ksRUFBWUMsT0FBT0MsT0FBTyxDQUFDSixFQUFPSyxPQUFPUixHQUFRRyxFQUFPTSxVQUd4REMsRUFBTVAsRUFBT1EsYUFH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
