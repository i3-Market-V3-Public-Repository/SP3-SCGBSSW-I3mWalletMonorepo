import{randomBytes as t,createCipheriv as e,createDecipheriv as s,scrypt as i,createHash as a,createSecretKey as n}from"crypto";import{isMainThread as o,workerData as r,parentPort as c,Worker as u}from"worker_threads";import h,{AxiosError as l}from"axios";import{EventEmitter as d}from"events";import p from"eventsource";import{config as m}from"dotenv";class w{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(s){const i=t(16),a=e(this.alg,this.key,i),n=Buffer.concat([a.update(s),a.final()]),o=a.getAuthTag();return Buffer.concat([i,o,n])}decrypt(t){const e=t.subarray(0,16),i=t.subarray(16,32),a=t.subarray(32),n=s(this.alg,this.key,e);return n.setAuthTag(i),Buffer.concat([n.update(a),n.final()])}}if(!o&&"object"==typeof r&&"scrypt-thread"===r._name){const{passwordOrKey:t,opts:e}=r;(async function(t,e){const s={...e.alg_options,maxmem:256*e.alg_options.N*e.alg_options.r},a="string"==typeof t?t:t.export(),n=new Promise(((t,n)=>{i(a,e.salt,e.derived_key_length,s,((e,s)=>{null!==e&&n(e),t(s)}))}));return await n})(t,e).then((t=>{c?.postMessage(t)})).catch((t=>{throw t instanceof Error?t:new Error(t)}))}class g{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,s){this.username=t,this.derivationOptions=s,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:s,enc:i}=this.derivationOptions,a=f(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),n=await v(t,{...e,salt:a}),o=f(s.salt_hashing_algorithm,s.salt_pattern,{username:this.username}),r=f(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),[c,u]=await Promise.all([v(n,{...s,salt:o}),v(n,{...i,salt:r})]);this._authKey=c,this._encKey=new w(u,i.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function f(t,e,s){let i="";for(const t in s)i=e.replace(t,s[t]);return a(t).update(i).digest()}async function v(t,e){return await new Promise(((s,i)=>{const a=new u("./dist/esm/index.node.js",{workerData:{_name:"scrypt-thread",passwordOrKey:t,opts:e}});a.on("message",(t=>{s(n(t))})),a.on("error",(t=>{i(t)})),a.on("messageerror",(t=>{i(t)}))}))}class y extends Error{data;message;constructor(t,e,s){super(t,s),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof y)return t;if(t instanceof Object&&"Event"===t.constructor.name)return new y("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof l){const e=t.response?.data;switch(e.name){case"no-storage":return new y("no-uploaded-storage",void 0);case"invalid-credentials":return new y("invalid-credentials",void 0);case"quota-exceeded":return new y("quota-exceeded",e.description);case"unauthorized":case"not-registered":return new y("unauthorized",void 0)}const s={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new y("http-connection-error",s)}if(t instanceof Error){const e=new y("error",t,{cause:t.cause});return e.stack=t.stack,e}return new y("unknown",t)}}function _(t,e){return t.message===e}var T={get:async function(t,e){const s={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(s.Authorization="Bearer "+e.bearerToken);const i=await h.get(t,{headers:s}).catch((t=>{throw y.from(t)}));if(void 0!==e?.responseStatus&&i.status!==e.responseStatus)throw new y("validation",{description:`Received HTTP status ${i.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return i.data},post:async function(t,e,s){const i={"Content-Type":"application/json"};void 0!==s?.bearerToken&&(i.Authorization="Bearer "+s.bearerToken);const a=await h.post(t,e,{headers:i}).catch((t=>{throw y.from(t)}));if(void 0!==s?.responseStatus&&a.status!==s.responseStatus)throw new y("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${s.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},put:async function(t,e,s){const i={"Content-Type":"application/json"};void 0!==s?.bearerToken&&(i.Authorization="Bearer "+s.bearerToken);const a=await h.put(t,e,{headers:i}).catch((t=>{throw y.from(t)}));if(void 0!==s?.responseStatus&&a.status!==s.responseStatus)throw new y("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${s.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},delete:async function(t,e){const s={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(s.Authorization="Bearer "+e.bearerToken);const i=await h.delete(t,{headers:s}).catch((t=>{throw y.from(t)}));if(void 0!==e?.responseStatus&&i.status!==e.responseStatus)throw new y("validation",{description:`Received HTTP status ${i.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return i.data}};m();const I=(t,e)=>{let s=`Invalid value for ${t}. `;return void 0!==e&&(s+=`Allowed values are ${e} `),s},k=["0","false","FALSE"],E=["1","true","FALSE"],C=k.concat(E);function z(t,e){const s=void 0===(i=process.env[t])?"":i;var i;const a=(e=e??{})?.isBoolean??!1;if(a&&(e={...e,allowedValues:C}),""===s){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(I(t,e.allowedValues.join(", ")))}if(a&&E.includes(s))return!0;if(a&&k.includes(s))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(s))throw new RangeError(I(t,e.allowedValues.join(", ")));return s}z("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const K="v"+z("npm_package_version",{defaultValue:"0.0.1"})[0],N={NOT_INITIALIZED:0,INITIALIZED:1,LOGGED_IN:2,CONNECTED:3};function S(t,e){switch(y.from(e).message){case"invalid-credentials":case"unauthorized":return N.INITIALIZED;case"sse-connection-error":return t>=N.LOGGED_IN?N.LOGGED_IN:N.INITIALIZED;default:return t}}class D extends d{timestamp;token;name;serverUrl;wellKnownCvsConfiguration;_state;_initialized;keyManager;es;constructor(e,s){super({captureRejections:!0}),this.name=s??t(16).toString("hex"),this.serverUrl=e,this._state=N.NOT_INITIALIZED,this._initialized=this.init()}get initialized(){return new Promise(((t,e)=>{this._initialized.then((()=>{t()})).catch((()=>{this._initialized=this.init().then((()=>{t()})),this._initialized.catch((t=>{e(t)}))}))}))}get state(){return this._state}set state(t){this._state!==t&&(this._state=t,this._state<N.LOGGED_IN&&(this.token=void 0),this.emit("state-changed",this._state))}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){this.wellKnownCvsConfiguration=await D.getWellKnownCvsConfiguration(this.serverUrl).catch((t=>{throw new y("not-initialized",t)})),this.state=N.INITIALIZED}async initEventSourceClient(){if(this.state<N.LOGGED_IN)throw new Error("cannot be called if not logged in");if(this.state>=N.CONNECTED)return;const t=this.wellKnownCvsConfiguration;this.es=new p(this.serverUrl+t.vault_configuration[K].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.state=N.CONNECTED})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.logout(),this.emit("storage-deleted")})),this.es.onerror=t=>{this.state=S(this.state,t)}}async initKeyManager(t,e){this.state===N.NOT_INITIALIZED&&await this.initialized;const s=this.wellKnownCvsConfiguration;this.keyManager=new g(t,e,s.vault_configuration[K].key_derivation),await this.keyManager.initialized}logout(){this.es?.close(),this.state=N.LOGGED_IN,this.token=void 0,this.state=N.INITIALIZED}async login(t,e){this.state===N.INITIALIZED&&await this.initialized,await this.initKeyManager(t,e);const s={username:t,authkey:this.keyManager.authKey},i=this.wellKnownCvsConfiguration,a=await T.post(this.serverUrl+i.vault_configuration.v2.token_endpoint,s,{responseStatus:200});this.token=a.token,this.state=N.LOGGED_IN,await this.initEventSourceClient()}async getRemoteStorageTimestamp(){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;try{const e=await T.get(this.serverUrl+t.vault_configuration[K].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<e.timestamp&&(this.timestamp=e.timestamp),e.timestamp}catch(t){throw this.state=S(this.state,t),t}}async getStorage(){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const t=Date.now();this.emit("sync-start",t);try{const e=this.wellKnownCvsConfiguration,s=await T.get(this.serverUrl+e.vault_configuration[K].vault_endpoint,{bearerToken:this.token,responseStatus:200});if(s.timestamp<(this.timestamp??0))throw new y("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const i=this.keyManager.encKey.decrypt(Buffer.from(s.ciphertext,"base64url"));return this.timestamp=s.timestamp,this.emit("sync-stop",t,Date.now()),{storage:i,timestamp:s.timestamp}}catch(e){throw this.emit("sync-stop",t,Date.now()),this.state=S(this.state,e),y.from(e)}}async updateStorage(t,e=!1){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const s=Date.now();this.emit("sync-start",s);try{if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new y("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const i=this.wellKnownCvsConfiguration,a={ciphertext:this.keyManager.encKey.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},n=await T.post(this.serverUrl+i.vault_configuration[K].vault_endpoint,a,{bearerToken:this.token,responseStatus:201});return this.timestamp=n.timestamp,this.emit("sync-stop",s,Date.now()),this.timestamp}catch(t){throw this.emit("sync-stop",s,Date.now()),this.state=S(this.state,t),y.from(t)}}async deleteStorage(){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;try{await T.delete(this.serverUrl+t.vault_configuration[K].vault_endpoint,{bearerToken:this.token,responseStatus:204}),delete this.timestamp,this.logout()}catch(t){throw t instanceof y&&"unauthorized"===t.message&&(this.token=void 0,this.state=N.INITIALIZED),t}}async getServerPublicKey(){await this.initialized;const t=this.wellKnownCvsConfiguration;return(await T.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}static async getWellKnownCvsConfiguration(t){return await T.get(t+"/.well-known/cvs-configuration",{responseStatus:200})}static async computeAuthKey(t,e,s){const i=await D.getWellKnownCvsConfiguration(t),a=new g(e,s,i.vault_configuration[K].key_derivation);return await a.initialized,a.authKey}}export{g as KeyManager,w as SecretKey,N as VAULT_STATE,D as VaultClient,y as VaultError,_ as checkErrorType,v as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NlY3JldC1rZXkudHMiLCIuLi8uLi9zcmMvdHMvc2NyeXB0LXRocmVhZC50cyIsIi4uLy4uL3NyYy90cy9rZXktbWFuYWdlci50cyIsIi4uLy4uL3NyYy90cy9lcnJvci50cyIsIi4uLy4uL3NyYy90cy9yZXF1ZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LXN0YXRlLnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiU2VjcmV0S2V5Iiwia2V5IiwiYWxnIiwiY29uc3RydWN0b3IiLCJ0aGlzIiwiZW5jcnlwdCIsImlucHV0IiwiaXYiLCJyYW5kb21CeXRlcyIsImNpcGhlciIsImNyZWF0ZUNpcGhlcml2IiwiZW5jcnlwdGVkIiwiQnVmZmVyIiwiY29uY2F0IiwidXBkYXRlIiwiZmluYWwiLCJ0YWciLCJnZXRBdXRoVGFnIiwiZGVjcnlwdCIsInN1YmFycmF5IiwiY2lwaGVydGV4dCIsImRlY2lwaGVyIiwiY3JlYXRlRGVjaXBoZXJpdiIsInNldEF1dGhUYWciLCJpc01haW5UaHJlYWQiLCJ3b3JrZXJEYXRhIiwiX25hbWUiLCJwYXNzd29yZE9yS2V5Iiwib3B0cyIsImFzeW5jIiwic2NyeXB0T3B0aW9ucyIsImFsZ19vcHRpb25zIiwibWF4bWVtIiwiTiIsInIiLCJwYXNzd29yZCIsImV4cG9ydCIsImtleVByb21pc2UiLCJQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsInNjcnlwdCIsInNhbHQiLCJkZXJpdmVkX2tleV9sZW5ndGgiLCJlcnIiLCJzY3J5cHRUaHJlYWQiLCJ0aGVuIiwiZGVyaXZlZEtleSIsInBhcmVudFBvcnQiLCJwb3N0TWVzc2FnZSIsImNhdGNoIiwiRXJyb3IiLCJLZXlNYW5hZ2VyIiwiX2VuY0tleSIsIl9hdXRoS2V5IiwidXNlcm5hbWUiLCJkZXJpdmF0aW9uT3B0aW9ucyIsImluaXRpYWxpemVkIiwiX2luaXRpYWxpemVkIiwiaW5pdCIsIm1hc3RlciIsImF1dGgiLCJlbmMiLCJtYXN0ZXJTYWx0IiwiX3NhbHQiLCJzYWx0X2hhc2hpbmdfYWxnb3JpdGhtIiwic2FsdF9wYXR0ZXJuIiwibWFzdGVyS2V5IiwiZGVyaXZlS2V5IiwiYXV0aFNhbHQiLCJlbmNTYWx0IiwiYXV0aEtleSIsImVuY0tleSIsImFsbCIsImVuY19hbGdvcml0aG0iLCJjYXVzZSIsInRvU3RyaW5nIiwiaGFzaEFsZ29yaXRobSIsInNhbHRQYXR0ZXJuIiwicmVwbGFjZW1lbnRzIiwic2FsdFN0cmluZyIsInNlYXJjaFZhbHVlIiwicmVwbGFjZSIsImNyZWF0ZUhhc2giLCJkaWdlc3QiLCJ3b3JrZXIiLCJXb3JrZXIiLCJvbiIsImNyZWF0ZVNlY3JldEtleSIsIlZhdWx0RXJyb3IiLCJkYXRhIiwibWVzc2FnZSIsIm9wdGlvbnMiLCJzdXBlciIsIm5hbWUiLCJzdGF0aWMiLCJlcnJvciIsIk9iamVjdCIsIkF4aW9zRXJyb3IiLCJyZXNwb25zZSIsInVuZGVmaW5lZCIsImRlc2NyaXB0aW9uIiwidmF1bHRDb25uRXJyb3IiLCJyZXF1ZXN0IiwibWV0aG9kIiwiY29uZmlnIiwidG9Mb2NhbGVVcHBlckNhc2UiLCJ1cmwiLCJoZWFkZXJzIiwic3RhdHVzIiwidmF1bHRFcnJvciIsInN0YWNrIiwiY2hlY2tFcnJvclR5cGUiLCJ0eXBlIiwiZ2V0IiwiYmVhcmVyVG9rZW4iLCJBdXRob3JpemF0aW9uIiwicmVzIiwiYXhpb3MiLCJmcm9tIiwicmVzcG9uc2VTdGF0dXMiLCJwb3N0IiwicmVxdWVzdEJvZHkiLCJwdXQiLCJkZWxldGUiLCJsb2FkRW52RmlsZSIsImludmFsaWRNc2ciLCJ2YXJuYW1lIiwidmFsdWVzIiwicmV0IiwiYm9vbGVhbkZhbHNlQWxsb3dlZFZhbHVlcyIsImJvb2xlYW5UcnVlQWxsb3dlZFZhbHVlcyIsImJvb2xlYW5BbGxvd2VkVmFsdWVzIiwicGFyc2VQcm9jY2Vzc0VudlZhciIsInZhck5hbWUiLCJ2YWx1ZSIsImEiLCJwcm9jZXNzIiwiZW52IiwiaXNCb29sZWFuIiwiYWxsb3dlZFZhbHVlcyIsImRlZmF1bHRWYWx1ZSIsImluY2x1ZGVzIiwiUmFuZ2VFcnJvciIsImpvaW4iLCJhcGlWZXJzaW9uIiwiVkFVTFRfU1RBVEUiLCJOT1RfSU5JVElBTElaRUQiLCJJTklUSUFMSVpFRCIsIkxPR0dFRF9JTiIsIkNPTk5FQ1RFRCIsInN0YXRlRnJvbUVycm9yIiwiY3VycmVudFN0YXRlIiwiVmF1bHRDbGllbnQiLCJFdmVudEVtaXR0ZXIiLCJ0aW1lc3RhbXAiLCJ0b2tlbiIsInNlcnZlclVybCIsIndlbGxLbm93bkN2c0NvbmZpZ3VyYXRpb24iLCJfc3RhdGUiLCJrZXlNYW5hZ2VyIiwiZXMiLCJjYXB0dXJlUmVqZWN0aW9ucyIsInJlYXNvbiIsInN0YXRlIiwibmV3U3RhdGUiLCJlbWl0IiwiZXZlbnROYW1lIiwiYXJncyIsImxpc3RlbmVyIiwib25jZSIsImdldFdlbGxLbm93bkN2c0NvbmZpZ3VyYXRpb24iLCJjdnNDb25mIiwiRXZlbnRTb3VyY2UiLCJ2YXVsdF9jb25maWd1cmF0aW9uIiwiZXZlbnRzX2VuZHBvaW50IiwiYWRkRXZlbnRMaXN0ZW5lciIsImUiLCJtc2ciLCJKU09OIiwicGFyc2UiLCJsb2dvdXQiLCJvbmVycm9yIiwia2V5X2Rlcml2YXRpb24iLCJjbG9zZSIsImluaXRLZXlNYW5hZ2VyIiwicmVxQm9keSIsImF1dGhrZXkiLCJ2MiIsInRva2VuX2VuZHBvaW50IiwiaW5pdEV2ZW50U291cmNlQ2xpZW50IiwidGltZXN0YW1wX2VuZHBvaW50Iiwic3RhcnRUcyIsIkRhdGUiLCJub3ciLCJ2YXVsdF9lbmRwb2ludCIsInN0b3JhZ2UiLCJmb3JjZSIsInJlbW90ZVRpbWVzdGFtcCIsImdldFJlbW90ZVN0b3JhZ2VUaW1lc3RhbXAiLCJsb2NhbFRpbWVzdGFtcCIsInJlZ2lzdHJhdGlvbl9jb25maWd1cmF0aW9uIiwicHVibGljX2p3a19lbmRwb2ludCIsImp3ayJdLCJtYXBwaW5ncyI6InVXQUdhQSxFQUNNQyxJQUNSQyxJQUVUQyxZQUFhRixFQUFnQkMsR0FDM0JFLEtBQUtILElBQU1BLEVBQ1hHLEtBQUtGLElBQU1BLENBQ1osQ0FFREcsUUFBU0MsR0FFUCxNQUFNQyxFQUFLQyxFQUFZLElBR2pCQyxFQUFTQyxFQUFlTixLQUFLRixJQUFLRSxLQUFLSCxJQUFLTSxHQUc1Q0ksRUFBWUMsT0FBT0MsT0FBTyxDQUFDSixFQUFPSyxPQUFPUixHQUFRRyxFQUFPTSxVQUd4REMsRUFBTVAsRUFBT1EsYUFHbkIsT0FBT0wsT0FBT0MsT0FBTyxDQUFDTixFQUFJUyxFQUFLTCxHQUNoQyxDQUVETyxRQUFTWixHQUVQLE1BQU1DLEVBQUtELEVBQU1hLFNBQVMsRUFBRyxJQUN2QkgsRUFBTVYsRUFBTWEsU0FBUyxHQUFJLElBQ3pCQyxFQUFhZCxFQUFNYSxTQUFTLElBRzVCRSxFQUFXQyxFQUFpQmxCLEtBQUtGLElBQUtFLEtBQUtILElBQUtNLEdBSXRELE9BSEFjLEVBQVNFLFdBQVdQLEdBR2JKLE9BQU9DLE9BQU8sQ0FBQ1EsRUFBU1AsT0FBT00sR0FBYUMsRUFBU04sU0FDN0QsRUMvQkgsSUFBS1MsR0FBc0MsaUJBQWZDLEdBQWdELGtCQUFyQkEsRUFBV0MsTUFBMkIsQ0FDM0YsTUFBTUMsY0FBRUEsRUFBYUMsS0FBRUEsR0FBU0gsR0FFaENJLGVBQTZCRixFQUFtQ0MsR0FDOUQsTUFBTUUsRUFBK0IsSUFDaENGLEVBQUtHLFlBQ1JDLE9BQVEsSUFBTUosRUFBS0csWUFBWUUsRUFBSUwsRUFBS0csWUFBWUcsR0FFaERDLEVBQXFDLGlCQUFsQlIsRUFBOEJBLEVBQWdCQSxFQUFjUyxTQUMvRUMsRUFBMkIsSUFBSUMsU0FBUSxDQUFDQyxFQUFTQyxLQUNyREMsRUFBT04sRUFBVVAsRUFBS2MsS0FBTWQsRUFBS2UsbUJBQW9CYixHQUFlLENBQUNjLEVBQUsz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
