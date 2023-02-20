import{randomBytes as t,createCipheriv as e,createDecipheriv as i,createHash as n,scrypt as a,createSecretKey as s}from"crypto";import o,{AxiosError as r}from"axios";import{EventEmitter as u}from"events";import c from"eventsource";import{config as h}from"dotenv";class l{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(i){const n=t(16),a=e(this.alg,this.key,n),s=Buffer.concat([a.update(i),a.final()]),o=a.getAuthTag();return Buffer.concat([n,o,s])}decrypt(t){const e=t.subarray(0,16),n=t.subarray(16,32),a=t.subarray(32),s=i(this.alg,this.key,e);return s.setAuthTag(n),Buffer.concat([s.update(a),s.final()])}}class d{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,i){this.username=t,this.derivationOptions=i,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:i,enc:n}=this.derivationOptions,a=m(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),s=await p(t,{...e,salt:a}),o=m(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),r=m(n.salt_hashing_algorithm,n.salt_pattern,{username:this.username}),[u,c]=await Promise.all([p(s,{...i,salt:o}),p(s,{...n,salt:r})]);this._authKey=u,this._encKey=new l(c,n.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function m(t,e,i){let a="";for(const t in i)a=e.replace(t,i[t]);return n(t).update(a).digest()}async function p(t,e){const i={...e.alg_options,maxmem:256*e.alg_options.N*e.alg_options.r},n="string"==typeof t?t:t.export(),o=new Promise(((t,o)=>{a(n,e.salt,e.derived_key_length,i,((e,i)=>{null!==e&&o(e),t(s(i))}))}));return await o}class w extends Error{data;message;constructor(t,e,i){super(t,i),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof w)return t;if(t instanceof Object&&"Event"===t.constructor.name)return new w("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof r){if("Unauthorized"===t.response?.data.name)return new w("unauthorized",void 0);if(404===t.response?.status&&"no storage"===t.response.data.name)return new w("no-uploaded-storage",void 0);if(404===t.response?.status&&"invalid credentials"===t.response.data.name)return new w("invalid-credentials",void 0);const e={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new w("http-connection-error",e)}if(t instanceof Error){const e=new w("error",t,{cause:t.cause});return e.stack=t.stack,e}return new w("unknown",t)}}function g(t,e){return t.message===e}var v={get:async function(t,e){const i={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(i.Authorization="Bearer "+e.bearerToken);const n=await o.get(t,{headers:i}).catch((t=>{throw w.from(t)}));if(void 0!==e?.responseStatus&&n.status!==e.responseStatus)throw new w("validation",{description:`Received HTTP status ${n.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return n.data},post:async function(t,e,i){const n={"Content-Type":"application/json"};void 0!==i?.bearerToken&&(n.Authorization="Bearer "+i.bearerToken);const a=await o.post(t,e,{headers:n}).catch((t=>{throw w.from(t)}));if(void 0!==i?.responseStatus&&a.status!==i.responseStatus)throw new w("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},put:async function(t,e,i){const n={"Content-Type":"application/json"};void 0!==i?.bearerToken&&(n.Authorization="Bearer "+i.bearerToken);const a=await o.put(t,e,{headers:n}).catch((t=>{throw w.from(t)}));if(void 0!==i?.responseStatus&&a.status!==i.responseStatus)throw new w("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},delete:async function(t,e){const i={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(i.Authorization="Bearer "+e.bearerToken);const n=await o.delete(t,{headers:i}).catch((t=>{throw w.from(t)}));if(void 0!==e?.responseStatus&&n.status!==e.responseStatus)throw new w("validation",{description:`Received HTTP status ${n.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return n.data}};h();const f=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},y=["0","false","FALSE"],k=["1","true","FALSE"],_=y.concat(k);function z(t,e){const i=void 0===(n=process.env[t])?"":n;var n;const a=(e=e??{})?.isBoolean??!1;if(a&&(e={...e,allowedValues:_}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(f(t,e.allowedValues.join(", ")))}if(a&&k.includes(i))return!0;if(a&&y.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(f(t,e.allowedValues.join(", ")));return i}z("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const T="v"+z("npm_package_version",{defaultValue:"0.0.1"})[0];class S extends u{timestamp;token;name;serverUrl;wellKnownCvsConfiguration;_initialized;keyManager;es;constructor(e,i){super({captureRejections:!0}),this.name=i??t(16).toString("hex"),this.serverUrl=e,this._initialized=this.init()}get initialized(){return new Promise(((t,e)=>{this._initialized.then((()=>{t()})).catch((()=>{this._initialized=this.init().then((()=>{t()})).catch((t=>{e(t)}))}))}))}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){this.wellKnownCvsConfiguration=await S.getWellKnownCvsConfiguration(this.serverUrl).catch((t=>{throw new w("not-initialized",t)})),void 0!==this.token&&await this.initEventSourceClient().catch((t=>{throw w.from(t)}))}async initEventSourceClient(){if(void 0===this.token)throw new w("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;this.es=new c(this.serverUrl+t.vault_configuration[T].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.emit("connected",e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.logout(),this.emit("storage-deleted")})),this.es.onerror=t=>{this.emitError(t)}}emitError(t){const e=w.from(t);switch(e.message){case"unauthorized":this.logout(),this.emit("logged-out");break;case"sse-connection-error":this.emit("connection-error",e);break;default:this.emit("error",e)}}async initKeyManager(t,e){await this.initialized;const i=this.wellKnownCvsConfiguration;this.keyManager=new d(t,e,i.vault_configuration[T].key_derivation),await this.keyManager.initialized}logout(){this.es?.close(),this.token=void 0,this.emit("logged-out")}async login(t,e,i){if(await this.initialized,await this.initKeyManager(t,e),void 0===i){const e={username:t,authkey:this.keyManager.authKey},i=this.wellKnownCvsConfiguration,n=await v.post(this.serverUrl+i.vault_configuration.v2.token_endpoint,e,{responseStatus:200});this.token=n.token}else this.token=i;await this.initEventSourceClient().catch((t=>{throw w.from(t)}))}async getRemoteStorageTimestamp(){if(await this.initialized,void 0===this.token)throw new w("unauthorized",void 0);const t=this.wellKnownCvsConfiguration,e=await v.get(this.serverUrl+t.vault_configuration[T].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<e.timestamp&&(this.timestamp=e.timestamp),e.timestamp}async getStorage(){if(await this.initialized,void 0===this.token||void 0===this.keyManager)throw new w("unauthorized",void 0);try{const t=this.wellKnownCvsConfiguration,e=await v.get(this.serverUrl+t.vault_configuration[T].vault_endpoint,{bearerToken:this.token,responseStatus:200});if(e.timestamp<(this.timestamp??0))throw new w("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const i=this.keyManager.encKey.decrypt(Buffer.from(e.ciphertext,"base64url"));return this.timestamp=e.timestamp,{storage:i,timestamp:e.timestamp}}catch(t){throw w.from(t)}}async updateStorage(t,e=!1){if(await this.initialized,void 0===this.token||void 0===this.keyManager)throw new w("unauthorized",void 0);if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new w("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const i=this.wellKnownCvsConfiguration;if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}const n={ciphertext:this.keyManager.encKey.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},a=await v.post(this.serverUrl+i.vault_configuration[T].vault_endpoint,n,{bearerToken:this.token,responseStatus:201});return this.timestamp=a.timestamp,this.timestamp}async deleteStorage(){if(await this.initialized,void 0===this.token)throw new w("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;await v.delete(this.serverUrl+t.vault_configuration[T].vault_endpoint,{bearerToken:this.token,responseStatus:204}),delete this.timestamp,this.logout()}async getServerPublicKey(){await this.initialized;const t=this.wellKnownCvsConfiguration;return(await v.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}static async getWellKnownCvsConfiguration(t){return await v.get(t+"/.well-known/cvs-configuration",{responseStatus:200})}static async computeAuthKey(t,e,i){const n=await S.getWellKnownCvsConfiguration(t),a=new d(e,i,n.vault_configuration[T].key_derivation);return await a.initialized,a.authKey}}export{d as KeyManager,l as SecretKey,S as VaultClient,w as VaultError,g as checkErrorType,p as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NlY3JldC1rZXkudHMiLCIuLi8uLi9zcmMvdHMva2V5LW1hbmFnZXIudHMiLCIuLi8uLi9zcmMvdHMvZXJyb3IudHMiLCIuLi8uLi9zcmMvdHMvcmVxdWVzdC50cyIsIi4uLy4uL3NyYy90cy9jb25maWcvcGFyc2VQcm9jZXNzRW52VmFyLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZpZy9pbmRleC50cyIsIi4uLy4uL3NyYy90cy92YXVsdC1jbGllbnQudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbIlNlY3JldEtleSIsImtleSIsImFsZyIsImNvbnN0cnVjdG9yIiwidGhpcyIsImVuY3J5cHQiLCJpbnB1dCIsIml2IiwicmFuZG9tQnl0ZXMiLCJjaXBoZXIiLCJjcmVhdGVDaXBoZXJpdiIsImVuY3J5cHRlZCIsIkJ1ZmZlciIsImNvbmNhdCIsInVwZGF0ZSIsImZpbmFsIiwidGFnIiwiZ2V0QXV0aFRhZyIsImRlY3J5cHQiLCJzdWJhcnJheSIsImNpcGhlcnRleHQiLCJkZWNpcGhlciIsImNyZWF0ZURlY2lwaGVyaXYiLCJzZXRBdXRoVGFnIiwiS2V5TWFuYWdlciIsIl9lbmNLZXkiLCJfYXV0aEtleSIsInVzZXJuYW1lIiwiZGVyaXZhdGlvbk9wdGlvbnMiLCJpbml0aWFsaXplZCIsIl9pbml0aWFsaXplZCIsInBhc3N3b3JkIiwib3B0cyIsImluaXQiLCJhc3luYyIsIm1hc3RlciIsImF1dGgiLCJlbmMiLCJtYXN0ZXJTYWx0IiwiX3NhbHQiLCJzYWx0X2hhc2hpbmdfYWxnb3JpdGhtIiwic2FsdF9wYXR0ZXJuIiwibWFzdGVyS2V5IiwiZGVyaXZlS2V5Iiwic2FsdCIsImF1dGhTYWx0IiwiZW5jU2FsdCIsImF1dGhLZXkiLCJlbmNLZXkiLCJQcm9taXNlIiwiYWxsIiwiZW5jX2FsZ29yaXRobSIsIkVycm9yIiwiY2F1c2UiLCJleHBvcnQiLCJ0b1N0cmluZyIsImhhc2hBbGdvcml0aG0iLCJzYWx0UGF0dGVybiIsInJlcGxhY2VtZW50cyIsInNhbHRTdHJpbmciLCJzZWFyY2hWYWx1ZSIsInJlcGxhY2UiLCJjcmVhdGVIYXNoIiwiZGlnZXN0IiwicGFzc3dvcmRPcktleSIsInNjcnlwdE9wdGlvbnMiLCJhbGdfb3B0aW9ucyIsIm1heG1lbSIsIk4iLCJyIiwia2V5UHJvbWlzZSIsInJlc29sdmUiLCJyZWplY3QiLCJzY3J5cHQiLCJkZXJpdmVkX2tleV9sZW5ndGgiLCJlcnIiLCJjcmVhdGVTZWNyZXRLZXkiLCJWYXVsdEVycm9yIiwiZGF0YSIsIm1lc3NhZ2UiLCJvcHRpb25zIiwic3VwZXIiLCJuYW1lIiwic3RhdGljIiwiZXJyb3IiLCJPYmplY3QiLCJBeGlvc0Vycm9yIiwicmVzcG9uc2UiLCJ1bmRlZmluZWQiLCJzdGF0dXMiLCJ2YXVsdENvbm5FcnJvciIsInJlcXVlc3QiLCJtZXRob2QiLCJjb25maWciLCJ0b0xvY2FsZVVwcGVyQ2FzZSIsInVybCIsImhlYWRlcnMiLCJ2YXVsdEVycm9yIiwic3RhY2siLCJjaGVja0Vycm9yVHlwZSIsInR5cGUiLCJnZXQiLCJiZWFyZXJUb2tlbiIsIkF1dGhvcml6YXRpb24iLCJyZXMiLCJheGlvcyIsImNhdGNoIiwiZnJvbSIsInJlc3BvbnNlU3RhdHVzIiwiZGVzY3JpcHRpb24iLCJwb3N0IiwicmVxdWVzdEJvZHkiLCJwdXQiLCJkZWxldGUiLCJsb2FkRW52RmlsZSIsImludmFsaWRNc2ciLCJ2YXJuYW1lIiwidmFsdWVzIiwicmV0IiwiYm9vbGVhbkZhbHNlQWxsb3dlZFZhbHVlcyIsImJvb2xlYW5UcnVlQWxsb3dlZFZhbHVlcyIsImJvb2xlYW5BbGxvd2VkVmFsdWVzIiwicGFyc2VQcm9jY2Vzc0VudlZhciIsInZhck5hbWUiLCJ2YWx1ZSIsImEiLCJwcm9jZXNzIiwiZW52IiwiaXNCb29sZWFuIiwiYWxsb3dlZFZhbHVlcyIsImRlZmF1bHRWYWx1ZSIsImluY2x1ZGVzIiwiUmFuZ2VFcnJvciIsImpvaW4iLCJhcGlWZXJzaW9uIiwiVmF1bHRDbGllbnQiLCJFdmVudEVtaXR0ZXIiLCJ0aW1lc3RhbXAiLCJ0b2tlbiIsInNlcnZlclVybCIsIndlbGxLbm93bkN2c0NvbmZpZ3VyYXRpb24iLCJrZXlNYW5hZ2VyIiwiZXMiLCJjYXB0dXJlUmVqZWN0aW9ucyIsInRoZW4iLCJyZWFzb24iLCJlbWl0IiwiZXZlbnROYW1lIiwiYXJncyIsIm9uIiwibGlzdGVuZXIiLCJvbmNlIiwiZ2V0V2VsbEtub3duQ3ZzQ29uZmlndXJhdGlvbiIsImluaXRFdmVudFNvdXJjZUNsaWVudCIsImN2c0NvbmYiLCJFdmVudFNvdXJjZSIsInZhdWx0X2NvbmZpZ3VyYXRpb24iLCJldmVudHNfZW5kcG9pbnQiLCJhZGRFdmVudExpc3RlbmVyIiwiZSIsIm1zZyIsIkpTT04iLCJwYXJzZSIsImxvZ291dCIsIm9uZXJyb3IiLCJlbWl0RXJyb3IiLCJrZXlfZGVyaXZhdGlvbiIsImNsb3NlIiwiaW5pdEtleU1hbmFnZXIiLCJyZXFCb2R5IiwiYXV0aGtleSIsInYyIiwidG9rZW5fZW5kcG9pbnQiLCJ0aW1lc3RhbXBfZW5kcG9pbnQiLCJ2YXVsdF9lbmRwb2ludCIsInN0b3JhZ2UiLCJmb3JjZSIsImxvY2FsVGltZXN0YW1wIiwicmVtb3RlVGltZXN0YW1wIiwiZ2V0UmVtb3RlU3RvcmFnZVRpbWVzdGFtcCIsInJlZ2lzdHJhdGlvbl9jb25maWd1cmF0aW9uIiwicHVibGljX2p3a19lbmRwb2ludCIsImp3ayJdLCJtYXBwaW5ncyI6IjZRQUdhQSxFQUNNQyxJQUNSQyxJQUVUQyxZQUFhRixFQUFnQkMsR0FDM0JFLEtBQUtILElBQU1BLEVBQ1hHLEtBQUtGLElBQU1BLENBQ1osQ0FFREcsUUFBU0MsR0FFUCxNQUFNQyxFQUFLQyxFQUFZLElBR2pCQyxFQUFTQyxFQUFlTixLQUFLRixJQUFLRSxLQUFLSCxJQUFLTSxHQUc1Q0ksRUFBWUMsT0FBT0MsT0FBTyxDQUFDSixFQUFPSyxPQUFPUixHQUFRRyxFQUFPTSxVQUd4REMsRUFBTVAsRUFBT1EsYUFH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
