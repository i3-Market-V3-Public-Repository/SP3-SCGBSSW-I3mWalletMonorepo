import{randomBytes as t,createCipheriv as e,createDecipheriv as s,scrypt as i,createHash as a,createSecretKey as o}from"crypto";import{isMainThread as n,workerData as r,parentPort as h,Worker as u}from"worker_threads";import l,{AxiosError as d}from"axios";import c from"axios-retry";import{EventEmitter as p}from"events";import w from"eventsource";import{config as m}from"dotenv";class f{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(s){const i=t(16),a=e(this.alg,this.key,i),o=Buffer.concat([a.update(s),a.final()]),n=a.getAuthTag();return Buffer.concat([i,n,o])}decrypt(t){const e=t.subarray(0,16),i=t.subarray(16,32),a=t.subarray(32),o=s(this.alg,this.key,e);return o.setAuthTag(i),Buffer.concat([o.update(a),o.final()])}}if(!n&&"object"==typeof r&&"scrypt-thread"===r._name){const{passwordOrKey:t,opts:e}=r;(async function(t,e){const s={...e.alg_options,maxmem:256*e.alg_options.N*e.alg_options.r},a="string"==typeof t?t:t.export(),o=new Promise(((t,o)=>{i(a,e.salt,e.derived_key_length,s,((e,s)=>{null!==e&&o(e),t(s)}))}));return await o})(t,e).then((t=>{h?.postMessage(t)})).catch((t=>{throw t instanceof Error?t:new Error(t)}))}class g{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,s){this.username=t,this.derivationOptions=s,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:s,enc:i}=this.derivationOptions,a=v(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),o=await y(t,{...e,salt:a}),n=v(s.salt_hashing_algorithm,s.salt_pattern,{username:this.username}),r=v(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),[h,u]=await Promise.all([y(o,{...s,salt:n}),y(o,{...i,salt:r})]);this._authKey=h,this._encKey=new f(u,i.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function v(t,e,s){let i="";for(const t in s)i=e.replace(t,s[t]);return a(t).update(i).digest()}async function y(t,e){return await new Promise(((s,i)=>{const a=new u("./dist/esm/index.node.js",{workerData:{_name:"scrypt-thread",passwordOrKey:t,opts:e}});a.on("message",(t=>{s(o(t))})),a.on("error",(t=>{i(t)})),a.on("messageerror",(t=>{i(t)}))}))}class _ extends Error{data;message;constructor(t,e,s){super(t,s),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof _)return t;if(t instanceof Object&&"Event"===t.constructor.name)return new _("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof d){const e=t.response?.data;switch(e.name){case"no-storage":return new _("no-uploaded-storage",void 0);case"invalid-credentials":return new _("invalid-credentials",void 0);case"quota-exceeded":return new _("quota-exceeded",e.description);case"unauthorized":case"not-registered":return new _("unauthorized",void 0)}const s={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new _("http-connection-error",s)}if(t instanceof Error){const e=new _("error",t,{cause:t.cause});return e.stack=t.stack,e}return new _("unknown",t)}}function T(t,e){return t.message===e}class E{axios;defaultCallOptions;defaultUrl;_stop;uploading;constructor(t){this._stop=!1,this.axios=this.getAxiosInstance(t?.retryOptions),this.defaultCallOptions=t?.defaultCallOptions,this.defaultUrl=t?.defaultUrl,this.uploading={}}getAxiosInstance(t){const e=l.create();return void 0!==t?.retries&&c(e,{retries:t.retries,retryDelay:()=>t.retryDelay,retryCondition:()=>this._stop}),e}async waitForUploadsToFinsh(t){const e=void 0!==t?t:this.defaultUrl;if(void 0===e)throw new _("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url oof the uploads you want to wait to finish"});if(void 0!==this.uploading[e])for(const t of this.uploading[e])try{await t}catch(t){}}async stop(){this._stop=!0;for(const t in this.uploading)await this.waitForUploadsToFinsh(t).catch();this._stop=!1}async get(t,e){const s="string"==typeof t?t:this.defaultUrl;if(void 0===s)throw new _("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});const i="string"!=typeof t?t:e,a={"Content-Type":"application/json"};if(void 0!==i?.bearerToken&&(a.Authorization="Bearer "+i.bearerToken),this._stop)throw new _("http-request-canceled",{request:{method:"GET",url:s,headers:a}});const o=await this.axios.get(s,{headers:a}).catch((t=>{throw _.from(t)}));if(void 0!==i?.responseStatus&&o.status!==i.responseStatus)throw new _("validation",{description:`Received HTTP status ${o.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return o.data}async delete(t,e){const s="string"==typeof t?t:this.defaultUrl;if(void 0===s)throw new _("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});const i="string"!=typeof t?t:e,a={"Content-Type":"application/json"};if(void 0!==i?.bearerToken&&(a.Authorization="Bearer "+i.bearerToken),this._stop)throw new _("http-request-canceled",{request:{method:"DELETE",url:s,headers:a}});const o=await this.axios.delete(s,{headers:a}).catch((t=>{throw _.from(t)}));if(void 0!==i?.responseStatus&&o.status!==i.responseStatus)throw new _("validation",{description:`Received HTTP status ${o.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return o.data}async upload(t,e,s,i){const a={"Content-Type":"application/json"};if(void 0!==i?.bearerToken&&(a.Authorization="Bearer "+i.bearerToken),this._stop)throw new _("http-request-canceled",{request:{method:t.toUpperCase(),url:e,headers:a,data:s}});!0===i?.sequentialPost&&await this.waitForUploadsToFinsh(e).catch(),this.uploading[e]=[];const o=this.axios[t](e,s,{headers:a}),n=this.uploading[e].push(o)-1,r=await o.catch((t=>{throw _.from(t)}));if(n===this.uploading[e].length-1)this.uploading[e].pop();else{let t=n;do{delete this.uploading[e][n],t--}while(void 0===this.uploading[e][t])}if(0===this.uploading[e].length&&delete this.uploading[e],void 0!==i?.responseStatus&&r.status!==i.responseStatus)throw new _("validation",{description:`Received HTTP status ${r.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return r.data}async post(t,e,s){let i,a,o;if("string"==typeof t?(i=t,a=e,o=s):(i=this.defaultUrl,a=t,o=e),void 0===i)throw new _("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});return await this.upload("post",i,a,o)}async put(t,e,s){let i,a,o;if("string"==typeof t?(i=t,a=e,o=s):(i=this.defaultUrl,a=t,o=e),void 0===i)throw new _("error",new Error("no url or defaultUrl provided"),{cause:"you should create the Request object with a defaultUrl or pass the url to the HTTP method"});return await this.upload("put",i,a,o)}}m();const I=(t,e)=>{let s=`Invalid value for ${t}. `;return void 0!==e&&(s+=`Allowed values are ${e} `),s},C=["0","false","FALSE"],k=["1","true","FALSE"],O=C.concat(k);function N(t,e){const s=void 0===(i=process.env[t])?"":i;var i;const a=(e=e??{})?.isBoolean??!1;if(a&&(e={...e,allowedValues:O}),""===s){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(I(t,e.allowedValues.join(", ")))}if(a&&k.includes(s))return!0;if(a&&C.includes(s))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(s))throw new RangeError(I(t,e.allowedValues.join(", ")));return s}N("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const D="v"+N("npm_package_version",{defaultValue:"0.0.1"})[0],K={NOT_INITIALIZED:0,INITIALIZED:1,LOGGED_IN:2,CONNECTED:3};function U(t,e){switch(_.from(e).message){case"invalid-credentials":case"unauthorized":return K.INITIALIZED;case"sse-connection-error":return t>=K.LOGGED_IN?K.LOGGED_IN:K.INITIALIZED;default:return t}}class z extends p{timestamp;token;name;opts;serverUrl;wellKnownCvsConfigurationPromise;wellKnownCvsConfiguration;_state;_initialized;vaultRequest;keyManager;es;constructor(e,s){super({captureRejections:!0}),this.name=s?.name??t(16).toString("hex"),this.opts=s,this.serverUrl=e,this._state=K.NOT_INITIALIZED,this._initialized=this.init()}get initialized(){return new Promise(((t,e)=>{this._initialized.then((()=>{t()})).catch((()=>{this._initialized=this.init().then((()=>{t()})).catch((t=>{e(t)}))}))}))}get state(){return this._state}set state(t){if(t<K.NOT_INITIALIZED||t>K.CONNECTED)throw new Error("invalid state");if(t-this._state>1||this.state-t>1)throw new Error("steps MUST be passed one by one");if(this._state!==t){switch(t){case K.NOT_INITIALIZED:delete this.wellKnownCvsConfigurationPromise,delete this.wellKnownCvsConfiguration,this._initialized=new Promise(((t,e)=>{e(new _("not-initialized",void 0))}));break;case K.INITIALIZED:this._state===K.LOGGED_IN&&(delete this.keyManager,delete this.vaultRequest,delete this.token,delete this.timestamp);break;case K.LOGGED_IN:this._state===K.CONNECTED&&(this.es?.close(),delete this.es)}this._state=t,this.emit("state-changed",this._state)}}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){this.wellKnownCvsConfigurationPromise=z.getWellKnownCvsConfiguration(this.serverUrl,{retries:28800,retryDelay:3e3}),this.wellKnownCvsConfiguration=await this.wellKnownCvsConfigurationPromise.promise.catch((t=>{throw new _("not-initialized",t)})),this.state=K.INITIALIZED}async initEventSourceClient(){if(this.state!==K.LOGGED_IN)throw new Error("cannot be called if not logged in");const t=this.wellKnownCvsConfiguration,e=this.serverUrl+t.vault_configuration[D].events_endpoint;this.es=new w(e,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);void 0!==e.timestamp&&e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp)),this.state=K.CONNECTED})),this.es.addEventListener("storage-updated",(t=>{this.vaultRequest.waitForUploadsToFinsh().finally((()=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})).catch((t=>{}))})),this.es.addEventListener("storage-deleted",(t=>{this.vaultRequest.waitForUploadsToFinsh().finally((()=>{this.logout(),this.emit("storage-deleted")})).catch((t=>{}))})),this.es.onerror=t=>{this.state=U(this.state,t)}}async initKeyManager(t,e){const s=this.wellKnownCvsConfiguration;this.keyManager=new g(t,e,s.vault_configuration[D].key_derivation),await this.keyManager.initialized}logout(){this.state<K.LOGGED_IN||(this.state===K.CONNECTED&&(this.state=K.LOGGED_IN),this.state=K.INITIALIZED)}close(){this.logout(),this.wellKnownCvsConfigurationPromise?.stop(),this.wellKnownCvsConfigurationPromise?.promise.catch((()=>{})),this.state=K.NOT_INITIALIZED}async login(t,e,s){this.state===K.NOT_INITIALIZED&&await this.initialized,await this.initKeyManager(t,e);const i={username:t,authkey:this.keyManager.authKey},a=new E({retryOptions:this.opts?.defaultRetryOptions}),o=this.wellKnownCvsConfiguration,n=await a.post(this.serverUrl+o.vault_configuration.v2.token_endpoint,i,{responseStatus:200});this.token=n.token,this.vaultRequest=new E({retryOptions:this.opts?.defaultRetryOptions,defaultCallOptions:{bearerToken:this.token,sequentialPost:!0},defaultUrl:this.serverUrl+o.vault_configuration.v2.vault_endpoint}),this.timestamp=s,this.state=K.LOGGED_IN,await this.initEventSourceClient()}async getRemoteStorageTimestamp(){if(this.state<K.LOGGED_IN)throw new _("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;try{await this.vaultRequest.waitForUploadsToFinsh();const e=new E({retryOptions:this.opts?.defaultRetryOptions}),s=await e.get(this.serverUrl+t.vault_configuration[D].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<s.timestamp&&(this.timestamp=s.timestamp),s.timestamp}catch(t){throw this.state=U(this.state,t),t}}async getStorage(){if(this.state<K.LOGGED_IN)throw new _("unauthorized",void 0);const t=Date.now();this.emit("sync-start",t);try{const e=this.vaultRequest;await e.waitForUploadsToFinsh();const s=await e.get({bearerToken:this.token,responseStatus:200});if(s.timestamp<(this.timestamp??0))throw new _("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const i=this.keyManager.encKey.decrypt(Buffer.from(s.ciphertext,"base64url"));return this.timestamp=s.timestamp,this.emit("sync-stop",t,Date.now()),{storage:i,timestamp:s.timestamp}}catch(e){throw this.emit("sync-stop",t,Date.now()),this.state=U(this.state,e),_.from(e)}}async updateStorage(t,e=!1,s){if(this.state<K.LOGGED_IN)throw new _("unauthorized",void 0);const i=Date.now();this.emit("sync-start",i);try{if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new _("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const s={ciphertext:this.keyManager.encKey.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},a=this.vaultRequest,o=await a.post(s,{bearerToken:this.token,responseStatus:201});return this.timestamp=o.timestamp,this.emit("sync-stop",i,Date.now()),this.timestamp}catch(t){throw this.emit("sync-stop",i,Date.now()),this.state=U(this.state,t),_.from(t)}}async deleteStorage(){if(this.state<K.LOGGED_IN)throw new _("unauthorized",void 0);try{const t=this.vaultRequest;await t.stop(),await t.delete({bearerToken:this.token,responseStatus:204}),this.logout()}catch(t){throw t instanceof _&&"unauthorized"===t.message&&this.logout(),t}}async getServerPublicKey(){await this.initialized;const t=this.wellKnownCvsConfiguration,e=new E({retryOptions:this.opts?.defaultRetryOptions});return(await e.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}static getWellKnownCvsConfiguration(t,e){const s=new E({retryOptions:e}),i=s.get(t+"/.well-known/cvs-configuration",{responseStatus:200});return{stop:s.stop,promise:i}}static async computeAuthKey(t,e,s,i){const a=z.getWellKnownCvsConfiguration(t,i),o=await a.promise,n=new g(e,s,o.vault_configuration[D].key_derivation);return await n.initialized,n.authKey}}export{g as KeyManager,E as Request,f as SecretKey,K as VAULT_STATE,z as VaultClient,_ as VaultError,T as checkErrorType,y as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NlY3JldC1rZXkudHMiLCIuLi8uLi9zcmMvdHMvc2NyeXB0LXRocmVhZC50cyIsIi4uLy4uL3NyYy90cy9rZXktbWFuYWdlci50cyIsIi4uLy4uL3NyYy90cy9lcnJvci50cyIsIi4uLy4uL3NyYy90cy9yZXF1ZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LXN0YXRlLnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiU2VjcmV0S2V5Iiwia2V5IiwiYWxnIiwiY29uc3RydWN0b3IiLCJ0aGlzIiwiZW5jcnlwdCIsImlucHV0IiwiaXYiLCJyYW5kb21CeXRlcyIsImNpcGhlciIsImNyZWF0ZUNpcGhlcml2IiwiZW5jcnlwdGVkIiwiQnVmZmVyIiwiY29uY2F0IiwidXBkYXRlIiwiZmluYWwiLCJ0YWciLCJnZXRBdXRoVGFnIiwiZGVjcnlwdCIsInN1YmFycmF5IiwiY2lwaGVydGV4dCIsImRlY2lwaGVyIiwiY3JlYXRlRGVjaXBoZXJpdiIsInNldEF1dGhUYWciLCJpc01haW5UaHJlYWQiLCJ3b3JrZXJEYXRhIiwiX25hbWUiLCJwYXNzd29yZE9yS2V5Iiwib3B0cyIsImFzeW5jIiwic2NyeXB0T3B0aW9ucyIsImFsZ19vcHRpb25zIiwibWF4bWVtIiwiTiIsInIiLCJwYXNzd29yZCIsImV4cG9ydCIsImtleVByb21pc2UiLCJQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsInNjcnlwdCIsInNhbHQiLCJkZXJpdmVkX2tleV9sZW5ndGgiLCJlcnIiLCJzY3J5cHRUaHJlYWQiLCJ0aGVuIiwiZGVyaXZlZEtleSIsInBhcmVudFBvcnQiLCJwb3N0TWVzc2FnZSIsImNhdGNoIiwiRXJyb3IiLCJLZXlNYW5hZ2VyIiwiX2VuY0tleSIsIl9hdXRoS2V5IiwidXNlcm5hbWUiLCJkZXJpdmF0aW9uT3B0aW9ucyIsImluaXRpYWxpemVkIiwiX2luaXRpYWxpemVkIiwiaW5pdCIsIm1hc3RlciIsImF1dGgiLCJlbmMiLCJtYXN0ZXJTYWx0IiwiX3NhbHQiLCJzYWx0X2hhc2hpbmdfYWxnb3JpdGhtIiwic2FsdF9wYXR0ZXJuIiwibWFzdGVyS2V5IiwiZGVyaXZlS2V5IiwiYXV0aFNhbHQiLCJlbmNTYWx0IiwiYXV0aEtleSIsImVuY0tleSIsImFsbCIsImVuY19hbGdvcml0aG0iLCJjYXVzZSIsInRvU3RyaW5nIiwiaGFzaEFsZ29yaXRobSIsInNhbHRQYXR0ZXJuIiwicmVwbGFjZW1lbnRzIiwic2FsdFN0cmluZyIsInNlYXJjaFZhbHVlIiwicmVwbGFjZSIsImNyZWF0ZUhhc2giLCJkaWdlc3QiLCJ3b3JrZXIiLCJXb3JrZXIiLCJvbiIsImNyZWF0ZVNlY3JldEtleSIsIlZhdWx0RXJyb3IiLCJkYXRhIiwibWVzc2FnZSIsIm9wdGlvbnMiLCJzdXBlciIsIm5hbWUiLCJzdGF0aWMiLCJlcnJvciIsIk9iamVjdCIsIkF4aW9zRXJyb3IiLCJyZXNwb25zZSIsInVuZGVmaW5lZCIsImRlc2NyaXB0aW9uIiwidmF1bHRDb25uRXJyb3IiLCJyZXF1ZXN0IiwibWV0aG9kIiwiY29uZmlnIiwidG9Mb2NhbGVVcHBlckNhc2UiLCJ1cmwiLCJoZWFkZXJzIiwic3RhdHVzIiwidmF1bHRFcnJvciIsInN0YWNrIiwiY2hlY2tFcnJvclR5cGUiLCJ0eXBlIiwiUmVxdWVzdCIsImF4aW9zIiwiZGVmYXVsdENhbGxPcHRpb25zIiwiZGVmYXVsdFVybCIsIl9zdG9wIiwidXBsb2FkaW5nIiwiZ2V0QXhpb3NJbnN0YW5jZSIsInJldHJ5T3B0aW9ucyIsImF4aW9zSW5zdGFuY2UiLCJjcmVhdGUiLCJyZXRyaWVzIiwiYXhpb3NSZXRyeSIsInJldHJ5RGVsYXkiLCJyZXRyeUNvbmRpdGlvbiIsInVybDIiLCJwcm9taXNlIiwid2FpdEZvclVwbG9hZHNUb0ZpbnNoIiwidXJsT3JPcHRpb25zIiwiYmVhcmVyVG9rZW4iLCJBdXRob3JpemF0aW9uIiwicmVzIiwiZ2V0IiwiZnJvbSIsInJlc3BvbnNlU3RhdHVzIiwiZGVsZXRlIiwicmVxdWVzdEJvZHkiLCJ0b1VwcGVyQ2FzZSIsInNlcXVlbnRpYWxQb3N0IiwicG9zdFByb21pc2UiLCJpbmRleCIsInB1c2giLCJsZW5ndGgiLCJwb3AiLCJpIiwidXJsT3JSZXF1ZXN0Qm9keSIsInJlcXVlc3RCb2R5T3JPcHRpb25zIiwidXBsb2FkIiwibG9hZEVudkZpbGUiLCJpbnZhbGlkTXNnIiwidmFybmFtZSIsInZhbHVlcyIsInJldCIsImJvb2xlYW5GYWxzZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuVHJ1ZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuQWxsb3dlZFZhbHVlcyIsInBhcnNlUHJvY2Nlc3NFbnZWYXIiLCJ2YXJOYW1lIiwidmFsdWUiLCJhIiwicHJvY2VzcyIsImVudiIsImlzQm9vbGVhbiIsImFsbG93ZWRWYWx1ZXMiLCJkZWZhdWx0VmFsdWUiLCJpbmNsdWRlcyIsIlJhbmdlRXJyb3IiLCJqb2luIiwiYXBpVmVyc2lvbiIsIlZBVUxUX1NUQVRFIiwiTk9UX0lOSVRJQUxJWkVEIiwiSU5JVElBTElaRUQiLCJMT0dHRURfSU4iLCJDT05ORUNURUQiLCJzdGF0ZUZyb21FcnJvciIsImN1cnJlbnRTdGF0ZSIsIlZhdWx0Q2xpZW50IiwiRXZlbnRFbWl0dGVyIiwidGltZXN0YW1wIiwidG9rZW4iLCJzZXJ2ZXJVcmwiLCJ3ZWxsS25vd25DdnNDb25maWd1cmF0aW9uUHJvbWlzZSIsIndlbGxLbm93bkN2c0NvbmZpZ3VyYXRpb24iLCJfc3RhdGUiLCJ2YXVsdFJlcXVlc3QiLCJrZXlNYW5hZ2VyIiwiZXMiLCJjYXB0dXJlUmVqZWN0aW9ucyIsInJlYXNvbiIsInN0YXRlIiwibmV3U3RhdGUiLCJjbG9zZSIsImVtaXQiLCJldmVudE5hbWUiLCJhcmdzIiwibGlzdGVuZXIiLCJvbmNlIiwiZ2V0V2VsbEtub3duQ3ZzQ29uZmlndXJhdGlvbiIsImN2c0NvbmYiLCJlc1VybCIsInZhdWx0X2NvbmZpZ3VyYXRpb24iLCJldmVudHNfZW5kcG9pbnQiLCJFdmVudFNvdXJjZSIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwibXNnIiwiSlNPTiIsInBhcnNlIiwiZmluYWxseSIsImxvZ291dCIsIm9uZXJyb3IiLCJrZXlfZGVyaXZhdGlvbiIsInN0b3AiLCJpbml0S2V5TWFuYWdlciIsInJlcUJvZHkiLCJhdXRoa2V5IiwiZGVmYXVsdFJldHJ5T3B0aW9ucyIsInBvc3QiLCJ2MiIsInRva2VuX2VuZHBvaW50IiwidmF1bHRfZW5kcG9pbnQiLCJpbml0RXZlbnRTb3VyY2VDbGllbnQiLCJ0aW1lc3RhbXBfZW5kcG9pbnQiLCJzdGFydFRzIiwiRGF0ZSIsIm5vdyIsInN0b3JhZ2UiLCJmb3JjZSIsInJlbW90ZVRpbWVzdGFtcCIsImdldFJlbW90ZVN0b3JhZ2VUaW1lc3RhbXAiLCJsb2NhbFRpbWVzdGFtcCIsInJlZ2lzdHJhdGlvbl9jb25maWd1cmF0aW9uIiwicHVibGljX2p3a19lbmRwb2ludCIsImp3ayJdLCJtYXBwaW5ncyI6ImtZQUdhQSxFQUNNQyxJQUNSQyxJQUVUQyxZQUFhRixFQUFnQkMsR0FDM0JFLEtBQUtILElBQU1BLEVBQ1hHLEtBQUtGLElBQU1BLENBQ1osQ0FFREcsUUFBU0MsR0FFUCxNQUFNQyxFQUFLQyxFQUFZLElBR2pCQyxFQUFTQyxFQUFlTixLQUFLRixJQUFLRSxLQUFLSCxJQUFLTSxHQUc1Q0ksRUFBWUMsT0FBT0MsT0FBTyxDQUFDSixFQUFPSyxPQUFPUixHQUFRRyxFQUFPTSxVQUd4REMsRUFBTVAsRUFBT1EsYUFHbkIsT0FBT0wsT0FBT0MsT0FBTyxDQUFDTixFQUFJUyxFQUFLTCxHQUNoQyxDQUVETyxRQUFTWixHQUVQLE1BQU1DLEVBQUtELEVBQU1hLFNBQVMsRUFBRyxJQUN2QkgsRUFBTVYsRUFBTWEsU0FBUyxHQUFJLElBQ3pCQyxFQUFhZCxFQUFN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
