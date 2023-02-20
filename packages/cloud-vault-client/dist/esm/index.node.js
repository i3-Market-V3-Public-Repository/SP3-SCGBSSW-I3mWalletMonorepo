import{randomBytes as t,createCipheriv as e,createDecipheriv as i,createHash as n,scrypt as a,createSecretKey as s}from"crypto";import o,{AxiosError as r}from"axios";import{EventEmitter as u}from"events";import c from"eventsource";import{config as h}from"dotenv";class l{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(i){const n=t(16),a=e(this.alg,this.key,n),s=Buffer.concat([a.update(i),a.final()]),o=a.getAuthTag();return Buffer.concat([n,o,s])}decrypt(t){const e=t.subarray(0,16),n=t.subarray(16,32),a=t.subarray(32),s=i(this.alg,this.key,e);return s.setAuthTag(n),Buffer.concat([s.update(a),s.final()])}}class d{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,i){this.username=t,this.derivationOptions=i,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:i,enc:n}=this.derivationOptions,a=m(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),s=await p(t,{...e,salt:a}),o=m(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),r=m(n.salt_hashing_algorithm,n.salt_pattern,{username:this.username}),[u,c]=await Promise.all([p(s,{...i,salt:o}),p(s,{...n,salt:r})]);this._authKey=u,this._encKey=new l(c,n.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function m(t,e,i){let a="";for(const t in i)a=e.replace(t,i[t]);return n(t).update(a).digest()}async function p(t,e){const i={...e.alg_options,maxmem:256*e.alg_options.N*e.alg_options.r},n="string"==typeof t?t:t.export(),o=new Promise(((t,o)=>{a(n,e.salt,e.derived_key_length,i,((e,i)=>{null!==e&&o(e),t(s(i))}))}));return await o}class w extends Error{data;message;constructor(t,e,i){super(t,i),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof w)return t;if(t instanceof Event)return new w("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof r){if("Unauthorized"===t.response?.data.name)return new w("unauthorized",void 0);if(404===t.response?.status&&"no storage"===t.response.data.name)return new w("no-uploaded-storage",void 0);if(404===t.response?.status&&"invalid credentials"===t.response.data.name)return new w("invalid-credentials",void 0);const e={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new w("http-connection-error",e)}if(t instanceof Error){const e=new w("error",t,{cause:t.cause});return e.stack=t.stack,e}return new w("unknown",t)}}function g(t,e){return t.message===e}var v={get:async function(t,e){const i={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(i.Authorization="Bearer "+e.bearerToken);const n=await o.get(t,{headers:i}).catch((t=>{throw w.from(t)}));if(void 0!==e?.responseStatus&&n.status!==e.responseStatus)throw new w("validation",{description:`Received HTTP status ${n.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return n.data},post:async function(t,e,i){const n={"Content-Type":"application/json"};void 0!==i?.bearerToken&&(n.Authorization="Bearer "+i.bearerToken);const a=await o.post(t,e,{headers:n}).catch((t=>{throw w.from(t)}));if(void 0!==i?.responseStatus&&a.status!==i.responseStatus)throw new w("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},put:async function(t,e,i){const n={"Content-Type":"application/json"};void 0!==i?.bearerToken&&(n.Authorization="Bearer "+i.bearerToken);const a=await o.put(t,e,{headers:n}).catch((t=>{throw w.from(t)}));if(void 0!==i?.responseStatus&&a.status!==i.responseStatus)throw new w("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},delete:async function(t,e){const i={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(i.Authorization="Bearer "+e.bearerToken);const n=await o.delete(t,{headers:i}).catch((t=>{throw w.from(t)}));if(void 0!==e?.responseStatus&&n.status!==e.responseStatus)throw new w("validation",{description:`Received HTTP status ${n.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return n.data}};h();const f=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},y=["0","false","FALSE"],k=["1","true","FALSE"],_=y.concat(k);function z(t,e){const i=void 0===(n=process.env[t])?"":n;var n;const a=(e=e??{})?.isBoolean??!1;if(a&&(e={...e,allowedValues:_}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(f(t,e.allowedValues.join(", ")))}if(a&&k.includes(i))return!0;if(a&&y.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(f(t,e.allowedValues.join(", ")));return i}z("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const T="v"+z("npm_package_version",{defaultValue:"0.0.1"})[0];class S extends u{timestamp;token;name;serverUrl;wellKnownCvsConfiguration;_initialized;keyManager;es;constructor(e,i){super({captureRejections:!0}),this.name=i??t(16).toString("hex"),this.serverUrl=e,this._initialized=this.init()}get initialized(){return new Promise(((t,e)=>{this._initialized.then((()=>{t()})).catch((()=>{this._initialized=this.init().then((()=>{t()})).catch((t=>{e(t)}))}))}))}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){this.wellKnownCvsConfiguration=await S.getWellKnownCvsConfiguration(this.serverUrl).catch((t=>{throw new w("not-initialized",t)})),void 0!==this.token&&await this.initEventSourceClient().catch((t=>{throw w.from(t)}))}async initEventSourceClient(){if(void 0===this.token)throw new w("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;this.es=new c(this.serverUrl+t.vault_configuration[T].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.emit("connected",e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.logout(),this.emit("storage-deleted")})),this.es.onerror=t=>{this.emitError(t)}}emitError(t){const e=w.from(t);switch(e.message){case"unauthorized":this.logout(),this.emit("logged-out");break;case"sse-connection-error":this.emit("connection-error",e);break;default:this.emit("error",e)}}async initKeyManager(t,e){await this.initialized;const i=this.wellKnownCvsConfiguration;this.keyManager=new d(t,e,i.vault_configuration[T].key_derivation),await this.keyManager.initialized}logout(){this.es?.close(),this.token=void 0,this.emit("logged-out")}async login(t,e,i){if(await this.initialized,await this.initKeyManager(t,e),void 0===i){const e={username:t,authkey:this.keyManager.authKey},i=this.wellKnownCvsConfiguration,n=await v.post(this.serverUrl+i.vault_configuration.v2.token_endpoint,e,{responseStatus:200});this.token=n.token}else this.token=i;await this.initEventSourceClient().catch((t=>{throw w.from(t)}))}async getRemoteStorageTimestamp(){if(await this.initialized,void 0===this.token)throw new w("unauthorized",void 0);const t=this.wellKnownCvsConfiguration,e=await v.get(this.serverUrl+t.vault_configuration[T].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<e.timestamp&&(this.timestamp=e.timestamp),e.timestamp}async getStorage(){if(await this.initialized,void 0===this.token||void 0===this.keyManager)throw new w("unauthorized",void 0);try{const t=this.wellKnownCvsConfiguration,e=await v.get(this.serverUrl+t.vault_configuration[T].vault_endpoint,{bearerToken:this.token,responseStatus:200});if(e.timestamp<(this.timestamp??0))throw new w("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const i=this.keyManager.encKey.decrypt(Buffer.from(e.ciphertext,"base64url"));return this.timestamp=e.timestamp,{storage:i,timestamp:e.timestamp}}catch(t){throw w.from(t)}}async updateStorage(t,e=!1){if(await this.initialized,void 0===this.token||void 0===this.keyManager)throw new w("unauthorized",void 0);if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new w("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const i=this.wellKnownCvsConfiguration;if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}const n={ciphertext:this.keyManager.encKey.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},a=await v.post(this.serverUrl+i.vault_configuration[T].vault_endpoint,n,{bearerToken:this.token,responseStatus:201});return this.timestamp=a.timestamp,this.timestamp}async deleteStorage(){if(await this.initialized,void 0===this.token)throw new w("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;await v.delete(this.serverUrl+t.vault_configuration[T].vault_endpoint,{bearerToken:this.token,responseStatus:204}),delete this.timestamp,this.logout()}async getServerPublicKey(){await this.initialized;const t=this.wellKnownCvsConfiguration;return(await v.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}static async getWellKnownCvsConfiguration(t){return await v.get(t+"/.well-known/cvs-configuration",{responseStatus:200})}static async computeAuthKey(t,e,i){const n=await S.getWellKnownCvsConfiguration(t),a=new d(e,i,n.vault_configuration[T].key_derivation);return await a.initialized,a.authKey}}export{d as KeyManager,l as SecretKey,S as VaultClient,w as VaultError,g as checkErrorType,p as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NlY3JldC1rZXkudHMiLCIuLi8uLi9zcmMvdHMva2V5LW1hbmFnZXIudHMiLCIuLi8uLi9zcmMvdHMvZXJyb3IudHMiLCIuLi8uLi9zcmMvdHMvcmVxdWVzdC50cyIsIi4uLy4uL3NyYy90cy9jb25maWcvcGFyc2VQcm9jZXNzRW52VmFyLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZpZy9pbmRleC50cyIsIi4uLy4uL3NyYy90cy92YXVsdC1jbGllbnQudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbIlNlY3JldEtleSIsImtleSIsImFsZyIsImNvbnN0cnVjdG9yIiwidGhpcyIsImVuY3J5cHQiLCJpbnB1dCIsIml2IiwicmFuZG9tQnl0ZXMiLCJjaXBoZXIiLCJjcmVhdGVDaXBoZXJpdiIsImVuY3J5cHRlZCIsIkJ1ZmZlciIsImNvbmNhdCIsInVwZGF0ZSIsImZpbmFsIiwidGFnIiwiZ2V0QXV0aFRhZyIsImRlY3J5cHQiLCJzdWJhcnJheSIsImNpcGhlcnRleHQiLCJkZWNpcGhlciIsImNyZWF0ZURlY2lwaGVyaXYiLCJzZXRBdXRoVGFnIiwiS2V5TWFuYWdlciIsIl9lbmNLZXkiLCJfYXV0aEtleSIsInVzZXJuYW1lIiwiZGVyaXZhdGlvbk9wdGlvbnMiLCJpbml0aWFsaXplZCIsIl9pbml0aWFsaXplZCIsInBhc3N3b3JkIiwib3B0cyIsImluaXQiLCJhc3luYyIsIm1hc3RlciIsImF1dGgiLCJlbmMiLCJtYXN0ZXJTYWx0IiwiX3NhbHQiLCJzYWx0X2hhc2hpbmdfYWxnb3JpdGhtIiwic2FsdF9wYXR0ZXJuIiwibWFzdGVyS2V5IiwiZGVyaXZlS2V5Iiwic2FsdCIsImF1dGhTYWx0IiwiZW5jU2FsdCIsImF1dGhLZXkiLCJlbmNLZXkiLCJQcm9taXNlIiwiYWxsIiwiZW5jX2FsZ29yaXRobSIsIkVycm9yIiwiY2F1c2UiLCJleHBvcnQiLCJ0b1N0cmluZyIsImhhc2hBbGdvcml0aG0iLCJzYWx0UGF0dGVybiIsInJlcGxhY2VtZW50cyIsInNhbHRTdHJpbmciLCJzZWFyY2hWYWx1ZSIsInJlcGxhY2UiLCJjcmVhdGVIYXNoIiwiZGlnZXN0IiwicGFzc3dvcmRPcktleSIsInNjcnlwdE9wdGlvbnMiLCJhbGdfb3B0aW9ucyIsIm1heG1lbSIsIk4iLCJyIiwia2V5UHJvbWlzZSIsInJlc29sdmUiLCJyZWplY3QiLCJzY3J5cHQiLCJkZXJpdmVkX2tleV9sZW5ndGgiLCJlcnIiLCJjcmVhdGVTZWNyZXRLZXkiLCJWYXVsdEVycm9yIiwiZGF0YSIsIm1lc3NhZ2UiLCJvcHRpb25zIiwic3VwZXIiLCJuYW1lIiwic3RhdGljIiwiZXJyb3IiLCJFdmVudCIsIkF4aW9zRXJyb3IiLCJyZXNwb25zZSIsInVuZGVmaW5lZCIsInN0YXR1cyIsInZhdWx0Q29ubkVycm9yIiwicmVxdWVzdCIsIm1ldGhvZCIsImNvbmZpZyIsInRvTG9jYWxlVXBwZXJDYXNlIiwidXJsIiwiaGVhZGVycyIsInZhdWx0RXJyb3IiLCJzdGFjayIsImNoZWNrRXJyb3JUeXBlIiwidHlwZSIsImdldCIsImJlYXJlclRva2VuIiwiQXV0aG9yaXphdGlvbiIsInJlcyIsImF4aW9zIiwiY2F0Y2giLCJmcm9tIiwicmVzcG9uc2VTdGF0dXMiLCJkZXNjcmlwdGlvbiIsInBvc3QiLCJyZXF1ZXN0Qm9keSIsInB1dCIsImRlbGV0ZSIsImxvYWRFbnZGaWxlIiwiaW52YWxpZE1zZyIsInZhcm5hbWUiLCJ2YWx1ZXMiLCJyZXQiLCJib29sZWFuRmFsc2VBbGxvd2VkVmFsdWVzIiwiYm9vbGVhblRydWVBbGxvd2VkVmFsdWVzIiwiYm9vbGVhbkFsbG93ZWRWYWx1ZXMiLCJwYXJzZVByb2NjZXNzRW52VmFyIiwidmFyTmFtZSIsInZhbHVlIiwiYSIsInByb2Nlc3MiLCJlbnYiLCJpc0Jvb2xlYW4iLCJhbGxvd2VkVmFsdWVzIiwiZGVmYXVsdFZhbHVlIiwiaW5jbHVkZXMiLCJSYW5nZUVycm9yIiwiam9pbiIsImFwaVZlcnNpb24iLCJWYXVsdENsaWVudCIsIkV2ZW50RW1pdHRlciIsInRpbWVzdGFtcCIsInRva2VuIiwic2VydmVyVXJsIiwid2VsbEtub3duQ3ZzQ29uZmlndXJhdGlvbiIsImtleU1hbmFnZXIiLCJlcyIsImNhcHR1cmVSZWplY3Rpb25zIiwidGhlbiIsInJlYXNvbiIsImVtaXQiLCJldmVudE5hbWUiLCJhcmdzIiwib24iLCJsaXN0ZW5lciIsIm9uY2UiLCJnZXRXZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiaW5pdEV2ZW50U291cmNlQ2xpZW50IiwiY3ZzQ29uZiIsIkV2ZW50U291cmNlIiwidmF1bHRfY29uZmlndXJhdGlvbiIsImV2ZW50c19lbmRwb2ludCIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwibXNnIiwiSlNPTiIsInBhcnNlIiwibG9nb3V0Iiwib25lcnJvciIsImVtaXRFcnJvciIsImtleV9kZXJpdmF0aW9uIiwiY2xvc2UiLCJpbml0S2V5TWFuYWdlciIsInJlcUJvZHkiLCJhdXRoa2V5IiwidjIiLCJ0b2tlbl9lbmRwb2ludCIsInRpbWVzdGFtcF9lbmRwb2ludCIsInZhdWx0X2VuZHBvaW50Iiwic3RvcmFnZSIsImZvcmNlIiwibG9jYWxUaW1lc3RhbXAiLCJyZW1vdGVUaW1lc3RhbXAiLCJnZXRSZW1vdGVTdG9yYWdlVGltZXN0YW1wIiwicmVnaXN0cmF0aW9uX2NvbmZpZ3VyYXRpb24iLCJwdWJsaWNfandrX2VuZHBvaW50IiwiandrIl0sIm1hcHBpbmdzIjoiNlFBR2FBLEVBQ01DLElBQ1JDLElBRVRDLFlBQWFGLEVBQWdCQyxHQUMzQkUsS0FBS0gsSUFBTUEsRUFDWEcsS0FBS0YsSUFBTUEsQ0FDWixDQUVERyxRQUFTQyxHQUVQLE1BQU1DLEVBQUtDLEVBQVksSUFHakJDLEVBQVNDLEVBQWVOLEtBQUtGLElBQUtFLEtBQUtILElBQUtNLEdBRzVDSSxFQUFZQyxPQUFPQyxPQUFPLENBQUNKLEVBQU9LLE9BQU9SLEdBQVFHLEVBQU9NLFVBR3hEQyxFQUFNUCxFQUFPUSxhQUdu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
