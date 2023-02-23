import{randomBytes as t,createCipheriv as e,createDecipheriv as s,scrypt as i,createHash as a,createSecretKey as n}from"crypto";import{isMainThread as o,parentPort as r,workerData as c,Worker as u}from"worker_threads";import h,{AxiosError as l}from"axios";import{EventEmitter as d}from"events";import p from"eventsource";import{config as m}from"dotenv";class w{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(s){const i=t(16),a=e(this.alg,this.key,i),n=Buffer.concat([a.update(s),a.final()]),o=a.getAuthTag();return Buffer.concat([i,o,n])}decrypt(t){const e=t.subarray(0,16),i=t.subarray(16,32),a=t.subarray(32),n=s(this.alg,this.key,e);return n.setAuthTag(i),Buffer.concat([n.update(a),n.final()])}}if(!o){const{passwordOrKey:t,opts:e}=c;(async function(t,e){const s={...e.alg_options,maxmem:256*e.alg_options.N*e.alg_options.r},a="string"==typeof t?t:t.export(),n=new Promise(((t,n)=>{i(a,e.salt,e.derived_key_length,s,((e,s)=>{null!==e&&n(e),t(s)}))}));return await n})(t,e).then((t=>{r?.postMessage(t)})).catch((t=>{throw t instanceof Error?t:new Error(t)}))}class g{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,s){this.username=t,this.derivationOptions=s,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:s,enc:i}=this.derivationOptions,a=f(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),n=await v(t,{...e,salt:a}),o=f(s.salt_hashing_algorithm,s.salt_pattern,{username:this.username}),r=f(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),[c,u]=await Promise.all([v(n,{...s,salt:o}),v(n,{...i,salt:r})]);this._authKey=c,this._encKey=new w(u,i.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function f(t,e,s){let i="";for(const t in s)i=e.replace(t,s[t]);return a(t).update(i).digest()}async function v(t,e){return await new Promise(((s,i)=>{const a=new u("./dist/esm/index.node.js",{workerData:{passwordOrKey:t,opts:e}});a.on("message",(t=>{s(n(t))})),a.on("error",(t=>{i(t)})),a.on("messageerror",(t=>{i(t)}))}))}class y extends Error{data;message;constructor(t,e,s){super(t,s),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof y)return t;if(t instanceof Object&&"Event"===t.constructor.name)return new y("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof l){const e=t.response?.data;switch(e.name){case"no-storage":return new y("no-uploaded-storage",void 0);case"invalid-credentials":return new y("invalid-credentials",void 0);case"quota-exceeded":return new y("quota-exceeded",e.description);case"unauthorized":case"not-registered":return new y("unauthorized",void 0)}const s={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new y("http-connection-error",s)}if(t instanceof Error){const e=new y("error",t,{cause:t.cause});return e.stack=t.stack,e}return new y("unknown",t)}}function _(t,e){return t.message===e}var T={get:async function(t,e){const s={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(s.Authorization="Bearer "+e.bearerToken);const i=await h.get(t,{headers:s}).catch((t=>{throw y.from(t)}));if(void 0!==e?.responseStatus&&i.status!==e.responseStatus)throw new y("validation",{description:`Received HTTP status ${i.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return i.data},post:async function(t,e,s){const i={"Content-Type":"application/json"};void 0!==s?.bearerToken&&(i.Authorization="Bearer "+s.bearerToken);const a=await h.post(t,e,{headers:i}).catch((t=>{throw y.from(t)}));if(void 0!==s?.responseStatus&&a.status!==s.responseStatus)throw new y("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${s.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},put:async function(t,e,s){const i={"Content-Type":"application/json"};void 0!==s?.bearerToken&&(i.Authorization="Bearer "+s.bearerToken);const a=await h.put(t,e,{headers:i}).catch((t=>{throw y.from(t)}));if(void 0!==s?.responseStatus&&a.status!==s.responseStatus)throw new y("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${s.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},delete:async function(t,e){const s={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(s.Authorization="Bearer "+e.bearerToken);const i=await h.delete(t,{headers:s}).catch((t=>{throw y.from(t)}));if(void 0!==e?.responseStatus&&i.status!==e.responseStatus)throw new y("validation",{description:`Received HTTP status ${i.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return i.data}};m();const I=(t,e)=>{let s=`Invalid value for ${t}. `;return void 0!==e&&(s+=`Allowed values are ${e} `),s},k=["0","false","FALSE"],E=["1","true","FALSE"],C=k.concat(E);function z(t,e){const s=void 0===(i=process.env[t])?"":i;var i;const a=(e=e??{})?.isBoolean??!1;if(a&&(e={...e,allowedValues:C}),""===s){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(I(t,e.allowedValues.join(", ")))}if(a&&E.includes(s))return!0;if(a&&k.includes(s))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(s))throw new RangeError(I(t,e.allowedValues.join(", ")));return s}z("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const K="v"+z("npm_package_version",{defaultValue:"0.0.1"})[0],N={NOT_INITIALIZED:0,INITIALIZED:1,LOGGED_IN:2,CONNECTED:3};function S(t,e){switch(y.from(e).message){case"invalid-credentials":case"unauthorized":return N.INITIALIZED;case"sse-connection-error":return t>=N.LOGGED_IN?N.LOGGED_IN:N.INITIALIZED;default:return t}}class D extends d{timestamp;token;name;serverUrl;wellKnownCvsConfiguration;_state;_initialized;keyManager;es;constructor(e,s){super({captureRejections:!0}),this.name=s??t(16).toString("hex"),this.serverUrl=e,this._state=N.NOT_INITIALIZED,this._initialized=this.init()}get initialized(){return new Promise(((t,e)=>{this._initialized.then((()=>{t()})).catch((()=>{this._initialized=this.init().then((()=>{t()})),this._initialized.catch((t=>{e(t)}))}))}))}get state(){return this._state}set state(t){this._state!==t&&(this._state=t,this._state<N.LOGGED_IN&&(this.token=void 0),this.emit("state-changed",this._state))}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){this.wellKnownCvsConfiguration=await D.getWellKnownCvsConfiguration(this.serverUrl).catch((t=>{throw new y("not-initialized",t)})),this.state=N.INITIALIZED}async initEventSourceClient(){if(this.state<N.LOGGED_IN)throw new Error("cannot be called if not logged in");if(this.state>=N.CONNECTED)return;const t=this.wellKnownCvsConfiguration;this.es=new p(this.serverUrl+t.vault_configuration[K].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.state=N.CONNECTED})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.logout(),this.emit("storage-deleted")})),this.es.onerror=t=>{this.state=S(this.state,t)}}async initKeyManager(t,e){this.state===N.NOT_INITIALIZED&&await this.initialized;const s=this.wellKnownCvsConfiguration;this.keyManager=new g(t,e,s.vault_configuration[K].key_derivation),await this.keyManager.initialized}logout(){this.es?.close(),this.state=N.LOGGED_IN,this.token=void 0,this.state=N.INITIALIZED}async login(t,e){this.state===N.INITIALIZED&&await this.initialized,await this.initKeyManager(t,e);const s={username:t,authkey:this.keyManager.authKey},i=this.wellKnownCvsConfiguration,a=await T.post(this.serverUrl+i.vault_configuration.v2.token_endpoint,s,{responseStatus:200});this.token=a.token,this.state=N.LOGGED_IN,await this.initEventSourceClient()}async getRemoteStorageTimestamp(){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;try{const e=await T.get(this.serverUrl+t.vault_configuration[K].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<e.timestamp&&(this.timestamp=e.timestamp),e.timestamp}catch(t){throw this.state=S(this.state,t),t}}async getStorage(){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const t=Date.now();this.emit("sync-start",t);try{const e=this.wellKnownCvsConfiguration,s=await T.get(this.serverUrl+e.vault_configuration[K].vault_endpoint,{bearerToken:this.token,responseStatus:200});if(s.timestamp<(this.timestamp??0))throw new y("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const i=this.keyManager.encKey.decrypt(Buffer.from(s.ciphertext,"base64url"));return this.timestamp=s.timestamp,this.emit("sync-stop",t,Date.now()),{storage:i,timestamp:s.timestamp}}catch(e){throw this.emit("sync-stop",t,Date.now()),this.state=S(this.state,e),y.from(e)}}async updateStorage(t,e=!1){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const s=Date.now();this.emit("sync-start",s);try{if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new y("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const i=this.wellKnownCvsConfiguration,a={ciphertext:this.keyManager.encKey.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},n=await T.post(this.serverUrl+i.vault_configuration[K].vault_endpoint,a,{bearerToken:this.token,responseStatus:201});return this.timestamp=n.timestamp,this.emit("sync-stop",s,Date.now()),this.timestamp}catch(t){throw this.emit("sync-stop",s,Date.now()),this.state=S(this.state,t),y.from(t)}}async deleteStorage(){if(this.state<N.LOGGED_IN)throw new y("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;try{await T.delete(this.serverUrl+t.vault_configuration[K].vault_endpoint,{bearerToken:this.token,responseStatus:204}),delete this.timestamp,this.logout()}catch(t){throw t instanceof y&&"unauthorized"===t.message&&(this.token=void 0,this.state=N.INITIALIZED),t}}async getServerPublicKey(){await this.initialized;const t=this.wellKnownCvsConfiguration;return(await T.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}static async getWellKnownCvsConfiguration(t){return await T.get(t+"/.well-known/cvs-configuration",{responseStatus:200})}static async computeAuthKey(t,e,s){const i=await D.getWellKnownCvsConfiguration(t),a=new g(e,s,i.vault_configuration[K].key_derivation);return await a.initialized,a.authKey}}export{g as KeyManager,w as SecretKey,N as VAULT_STATE,D as VaultClient,y as VaultError,_ as checkErrorType,v as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NlY3JldC1rZXkudHMiLCIuLi8uLi9zcmMvdHMvc2NyeXB0LXRocmVhZC50cyIsIi4uLy4uL3NyYy90cy9rZXktbWFuYWdlci50cyIsIi4uLy4uL3NyYy90cy9lcnJvci50cyIsIi4uLy4uL3NyYy90cy9yZXF1ZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LXN0YXRlLnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiU2VjcmV0S2V5Iiwia2V5IiwiYWxnIiwiY29uc3RydWN0b3IiLCJ0aGlzIiwiZW5jcnlwdCIsImlucHV0IiwiaXYiLCJyYW5kb21CeXRlcyIsImNpcGhlciIsImNyZWF0ZUNpcGhlcml2IiwiZW5jcnlwdGVkIiwiQnVmZmVyIiwiY29uY2F0IiwidXBkYXRlIiwiZmluYWwiLCJ0YWciLCJnZXRBdXRoVGFnIiwiZGVjcnlwdCIsInN1YmFycmF5IiwiY2lwaGVydGV4dCIsImRlY2lwaGVyIiwiY3JlYXRlRGVjaXBoZXJpdiIsInNldEF1dGhUYWciLCJpc01haW5UaHJlYWQiLCJwYXNzd29yZE9yS2V5Iiwib3B0cyIsIndvcmtlckRhdGEiLCJhc3luYyIsInNjcnlwdE9wdGlvbnMiLCJhbGdfb3B0aW9ucyIsIm1heG1lbSIsIk4iLCJyIiwicGFzc3dvcmQiLCJleHBvcnQiLCJrZXlQcm9taXNlIiwiUHJvbWlzZSIsInJlc29sdmUiLCJyZWplY3QiLCJzY3J5cHQiLCJzYWx0IiwiZGVyaXZlZF9rZXlfbGVuZ3RoIiwiZXJyIiwic2NyeXB0VGhyZWFkIiwidGhlbiIsImRlcml2ZWRLZXkiLCJwYXJlbnRQb3J0IiwicG9zdE1lc3NhZ2UiLCJjYXRjaCIsIkVycm9yIiwiS2V5TWFuYWdlciIsIl9lbmNLZXkiLCJfYXV0aEtleSIsInVzZXJuYW1lIiwiZGVyaXZhdGlvbk9wdGlvbnMiLCJpbml0aWFsaXplZCIsIl9pbml0aWFsaXplZCIsImluaXQiLCJtYXN0ZXIiLCJhdXRoIiwiZW5jIiwibWFzdGVyU2FsdCIsIl9zYWx0Iiwic2FsdF9oYXNoaW5nX2FsZ29yaXRobSIsInNhbHRfcGF0dGVybiIsIm1hc3RlcktleSIsImRlcml2ZUtleSIsImF1dGhTYWx0IiwiZW5jU2FsdCIsImF1dGhLZXkiLCJlbmNLZXkiLCJhbGwiLCJlbmNfYWxnb3JpdGhtIiwiY2F1c2UiLCJ0b1N0cmluZyIsImhhc2hBbGdvcml0aG0iLCJzYWx0UGF0dGVybiIsInJlcGxhY2VtZW50cyIsInNhbHRTdHJpbmciLCJzZWFyY2hWYWx1ZSIsInJlcGxhY2UiLCJjcmVhdGVIYXNoIiwiZGlnZXN0Iiwid29ya2VyIiwiV29ya2VyIiwib24iLCJjcmVhdGVTZWNyZXRLZXkiLCJWYXVsdEVycm9yIiwiZGF0YSIsIm1lc3NhZ2UiLCJvcHRpb25zIiwic3VwZXIiLCJuYW1lIiwic3RhdGljIiwiZXJyb3IiLCJPYmplY3QiLCJBeGlvc0Vycm9yIiwicmVzcG9uc2UiLCJ1bmRlZmluZWQiLCJkZXNjcmlwdGlvbiIsInZhdWx0Q29ubkVycm9yIiwicmVxdWVzdCIsIm1ldGhvZCIsImNvbmZpZyIsInRvTG9jYWxlVXBwZXJDYXNlIiwidXJsIiwiaGVhZGVycyIsInN0YXR1cyIsInZhdWx0RXJyb3IiLCJzdGFjayIsImNoZWNrRXJyb3JUeXBlIiwidHlwZSIsImdldCIsImJlYXJlclRva2VuIiwiQXV0aG9yaXphdGlvbiIsInJlcyIsImF4aW9zIiwiZnJvbSIsInJlc3BvbnNlU3RhdHVzIiwicG9zdCIsInJlcXVlc3RCb2R5IiwicHV0IiwiZGVsZXRlIiwibG9hZEVudkZpbGUiLCJpbnZhbGlkTXNnIiwidmFybmFtZSIsInZhbHVlcyIsInJldCIsImJvb2xlYW5GYWxzZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuVHJ1ZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuQWxsb3dlZFZhbHVlcyIsInBhcnNlUHJvY2Nlc3NFbnZWYXIiLCJ2YXJOYW1lIiwidmFsdWUiLCJhIiwicHJvY2VzcyIsImVudiIsImlzQm9vbGVhbiIsImFsbG93ZWRWYWx1ZXMiLCJkZWZhdWx0VmFsdWUiLCJpbmNsdWRlcyIsIlJhbmdlRXJyb3IiLCJqb2luIiwiYXBpVmVyc2lvbiIsIlZBVUxUX1NUQVRFIiwiTk9UX0lOSVRJQUxJWkVEIiwiSU5JVElBTElaRUQiLCJMT0dHRURfSU4iLCJDT05ORUNURUQiLCJzdGF0ZUZyb21FcnJvciIsImN1cnJlbnRTdGF0ZSIsIlZhdWx0Q2xpZW50IiwiRXZlbnRFbWl0dGVyIiwidGltZXN0YW1wIiwidG9rZW4iLCJzZXJ2ZXJVcmwiLCJ3ZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiX3N0YXRlIiwia2V5TWFuYWdlciIsImVzIiwiY2FwdHVyZVJlamVjdGlvbnMiLCJyZWFzb24iLCJzdGF0ZSIsIm5ld1N0YXRlIiwiZW1pdCIsImV2ZW50TmFtZSIsImFyZ3MiLCJsaXN0ZW5lciIsIm9uY2UiLCJnZXRXZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiY3ZzQ29uZiIsIkV2ZW50U291cmNlIiwidmF1bHRfY29uZmlndXJhdGlvbiIsImV2ZW50c19lbmRwb2ludCIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwibXNnIiwiSlNPTiIsInBhcnNlIiwibG9nb3V0Iiwib25lcnJvciIsImtleV9kZXJpdmF0aW9uIiwiY2xvc2UiLCJpbml0S2V5TWFuYWdlciIsInJlcUJvZHkiLCJhdXRoa2V5IiwidjIiLCJ0b2tlbl9lbmRwb2ludCIsImluaXRFdmVudFNvdXJjZUNsaWVudCIsInRpbWVzdGFtcF9lbmRwb2ludCIsInN0YXJ0VHMiLCJEYXRlIiwibm93IiwidmF1bHRfZW5kcG9pbnQiLCJzdG9yYWdlIiwiZm9yY2UiLCJyZW1vdGVUaW1lc3RhbXAiLCJnZXRSZW1vdGVTdG9yYWdlVGltZXN0YW1wIiwibG9jYWxUaW1lc3RhbXAi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
