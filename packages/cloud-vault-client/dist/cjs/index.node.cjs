"use strict";Object.defineProperty(exports,"__esModule",{value:!0});var t=require("crypto"),e=require("axios"),i=require("events"),r=require("eventsource"),s=require("dotenv");function a(t){return t&&"object"==typeof t&&"default"in t?t:{default:t}}var n=a(e),o=a(r);class l{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(e){const i=t.randomBytes(16),r=t.createCipheriv(this.alg,this.key,i),s=Buffer.concat([r.update(e),r.final()]),a=r.getAuthTag();return Buffer.concat([i,a,s])}decrypt(e){const i=e.subarray(0,16),r=e.subarray(16,32),s=e.subarray(32),a=t.createDecipheriv(this.alg,this.key,i);return a.setAuthTag(r),Buffer.concat([a.update(s),a.final()])}}class u{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,i){this.username=t,this.derivationOptions=i,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:i,enc:r}=this.derivationOptions,s=h(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),a=await d(t,{...e,salt:s}),n=h(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),o=h(r.salt_hashing_algorithm,r.salt_pattern,{username:this.username}),[u,c]=await Promise.all([d(a,{...i,salt:n}),d(a,{...r,salt:o})]);this._authKey=u,this._encKey=new l(c,r.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function h(e,i,r){let s="";for(const t in r)s=i.replaceAll(t,r[t]);return t.createHash(e).update(s).digest()}async function d(e,i){const r={...i.alg_options,maxmem:256*i.alg_options.N*i.alg_options.r},s="string"==typeof e?e:e.export(),a=new Promise(((e,a)=>{t.scrypt(s,i.salt,i.derived_key_length,r,((i,r)=>{null!==i&&a(i),e(t.createSecretKey(r))}))}));return await a}s.config();const c=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},m=["0","false","FALSE"],g=["1","true","FALSE"],p=m.concat(g);function f(t,e){const i=void 0===(r=process.env[t])?"":r;var r;const s=(e=e??{})?.isBoolean??!1;if(s&&(e={...e,allowedValues:p}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(c(t,e.allowedValues.join(", ")))}if(s&&g.includes(i))return!0;if(s&&m.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(c(t,e.allowedValues.join(", ")));return i}f("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const v="v"+f("npm_package_version",{defaultValue:"0.0.1"})[0];class y extends i.EventEmitter{timestamp;token;name;serverUrl;username;password;keyManager;wellKnownCvsConfiguration;defaultEvents;initialized;es;constructor(e,i,r,s){super({captureRejections:!0}),this.name=s??t.randomBytes(16).toString("hex"),this.serverUrl=e,this.username=i,this.password=r,this.defaultEvents={connected:"connected",close:"close","login-required":"login-required","storage-updated":"storage-updated","storage-deleted":"storage-deleted",conflict:"conflict",error:"error"},this.initialized=this.init()}async init(){try{await this.getWellKnownCvsConfiguration()}catch(t){return this.emitError(t),!1}const t=this.wellKnownCvsConfiguration;this.keyManager=new u(this.username,this.password,t.vault_configuration[v].key_derivation);try{await this.keyManager.initialized}catch(t){return this.emitError(t),!1}return delete this.password,!0}emitError(t){t instanceof e.AxiosError&&void 0!==t.response?"Unauthorized"===t.response.data.name?(this.logout(),this.emit(this.defaultEvents["login-required"])):this.emit(this.defaultEvents.error,t.response):this.emit(this.defaultEvents.error,t)}async getWellKnownCvsConfiguration(){const t=await n.default.get(this.serverUrl+"/.well-known/cvs-configuration");this.wellKnownCvsConfiguration=t.data}async initEventSourceClient(){if(void 0===this.token)throw new Error("Cannot subscribe to events without login first");const t=this.wellKnownCvsConfiguration;this.es=new o.default(this.serverUrl+t.vault_configuration[v].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.onmessage=t=>{console.log(t)},this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.emit(this.defaultEvents.connected,e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit(this.defaultEvents["storage-updated"],this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.close(),this.emit(this.defaultEvents["storage-deleted"])})),this.es.onerror=t=>{this.emitError(t)}}close(){this.logout(),this.emit(this.defaultEvents.close)}async getAuthKey(){if(!await this.initialized)try{await this.init()}catch(t){return this.emitError(t),null}return this.keyManager.authKey}async login(){if(!await this.initialized)try{await this.init()}catch(t){return this.emitError(t),!1}const t={username:this.username,authkey:this.keyManager.authKey};try{const e=this.wellKnownCvsConfiguration,i=await n.default.post(this.serverUrl+e.vault_configuration.v2.token_endpoint,t);if(200!==i.status)return this.emitError(i),!1;const r=i.data;return this.token=r.token,await this.initEventSourceClient(),!0}catch(t){return this.emitError(t),!1}}logout(){this.token=void 0,this.es?.close()}async getRemoteStorageTimestamp(){try{if(void 0===this.token)return this.emit(this.defaultEvents["login-required"]),null;const t=this.wellKnownCvsConfiguration,e=await n.default.get(this.serverUrl+t.vault_configuration[v].timestamp_endpoint,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});return 200!==e.status?(this.emitError(e),null):((this.timestamp??0)<e.data.timestamp&&(this.timestamp=e.data.timestamp),e.data.timestamp)}catch(t){return this.emitError(t),null}}async getStorage(){try{if(void 0===this.token)return this.emit(this.defaultEvents["login-required"]),null;const t=this.wellKnownCvsConfiguration,e=this.keyManager.encKey,i=await n.default.get(this.serverUrl+t.vault_configuration[v].vault_endpoint,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});if(200!==i.status)return this.emitError(i),null;if(i.data.timestamp<(this.timestamp??0))return this.emitError(new Error("Received timestamp is older than the latest one published")),null;const r=e.decrypt(Buffer.from(i.data.ciphertext,"base64url"));return this.timestamp=i.data.timestamp,{storage:r,timestamp:i.data.timestamp}}catch(t){return this.emitError(t),null}}async updateStorage(t,e=!1){try{if(void 0===this.token)return this.emit(this.defaultEvents["login-required"]),!1;if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)return this.emit(this.defaultEvents.conflict),!1;const i=this.wellKnownCvsConfiguration,r=this.keyManager.encKey;if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}const s={ciphertext:r.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},a=await n.default.post(this.serverUrl+i.vault_configuration[v].vault_endpoint,s,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});return 201!==a.status?(this.emitError(a),!1):(this.timestamp=a.data.timestamp,!0)}catch(t){this.emitError(t)}return!1}async deleteStorage(){try{if(void 0===this.token)return this.logout(),this.emit(this.defaultEvents["login-required"]),!1;const t=this.wellKnownCvsConfiguration,e=await n.default.delete(this.serverUrl+t.vault_configuration[v].vault_endpoint,{headers:{Authorization:"Bearer "+this.token}});return 204!==e.status?(this.emitError(e),!1):(this.emit(this.defaultEvents["storage-deleted"]),delete this.timestamp,this.close(),!0)}catch(t){this.emitError(t)}return!1}async getServerPublicKey(){try{await this.getWellKnownCvsConfiguration();const t=this.wellKnownCvsConfiguration,e=await n.default.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint);return 200!==e.status?(this.emitError(e),null):e.data.jwk}catch(t){return this.emitError(t),null}}}exports.KeyManager=u,exports.SecretKey=l,exports.VaultClient=y,exports.deriveKey=d;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9zZWNyZXQta2V5LnRzIiwiLi4vLi4vc3JjL3RzL2tleS1tYW5hZ2VyLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiU2VjcmV0S2V5Iiwia2V5IiwiYWxnIiwiY29uc3RydWN0b3IiLCJ0aGlzIiwiZW5jcnlwdCIsImlucHV0IiwiaXYiLCJyYW5kb21CeXRlcyIsImNpcGhlciIsImNyZWF0ZUNpcGhlcml2IiwiZW5jcnlwdGVkIiwiQnVmZmVyIiwiY29uY2F0IiwidXBkYXRlIiwiZmluYWwiLCJ0YWciLCJnZXRBdXRoVGFnIiwiZGVjcnlwdCIsInN1YmFycmF5IiwiY2lwaGVydGV4dCIsImRlY2lwaGVyIiwiY3JlYXRlRGVjaXBoZXJpdiIsInNldEF1dGhUYWciLCJLZXlNYW5hZ2VyIiwiX2VuY0tleSIsIl9hdXRoS2V5IiwidXNlcm5hbWUiLCJkZXJpdmF0aW9uT3B0aW9ucyIsImluaXRpYWxpemVkIiwiX2luaXRpYWxpemVkIiwicGFzc3dvcmQiLCJvcHRzIiwiaW5pdCIsImFzeW5jIiwibWFzdGVyIiwiYXV0aCIsImVuYyIsIm1hc3RlclNhbHQiLCJfc2FsdCIsInNhbHRfaGFzaGluZ19hbGdvcml0aG0iLCJzYWx0X3BhdHRlcm4iLCJtYXN0ZXJLZXkiLCJkZXJpdmVLZXkiLCJzYWx0IiwiYXV0aFNhbHQiLCJlbmNTYWx0IiwiYXV0aEtleSIsImVuY0tleSIsIlByb21pc2UiLCJhbGwiLCJlbmNfYWxnb3JpdGhtIiwiRXJyb3IiLCJjYXVzZSIsImV4cG9ydCIsInRvU3RyaW5nIiwiaGFzaEFsZ29yaXRobSIsInNhbHRQYXR0ZXJuIiwicmVwbGFjZW1lbnRzIiwic2FsdFN0cmluZyIsInNlYXJjaFZhbHVlIiwicmVwbGFjZUFsbCIsImNyZWF0ZUhhc2giLCJkaWdlc3QiLCJwYXNzd29yZE9yS2V5Iiwic2NyeXB0T3B0aW9ucyIsImFsZ19vcHRpb25zIiwibWF4bWVtIiwiTiIsInIiLCJrZXlQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsInNjcnlwdCIsImRlcml2ZWRfa2V5X2xlbmd0aCIsImVyciIsImNyZWF0ZVNlY3JldEtleSIsImxvYWRFbnZGaWxlIiwiaW52YWxpZE1zZyIsInZhcm5hbWUiLCJ2YWx1ZXMiLCJyZXQiLCJ1bmRlZmluZWQiLCJib29sZWFuRmFsc2VBbGxvd2VkVmFsdWVzIiwiYm9vbGVhblRydWVBbGxvd2VkVmFsdWVzIiwiYm9vbGVhbkFsbG93ZWRWYWx1ZXMiLCJwYXJzZVByb2NjZXNzRW52VmFyIiwidmFyTmFtZSIsIm9wdGlvbnMiLCJ2YWx1ZSIsImEiLCJwcm9jZXNzIiwiZW52IiwiaXNCb29sZWFuIiwiYWxsb3dlZFZhbHVlcyIsImRlZmF1bHRWYWx1ZSIsImluY2x1ZGVzIiwiUmFuZ2VFcnJvciIsImpvaW4iLCJhcGlWZXJzaW9uIiwiVmF1bHRDbGllbnQiLCJFdmVudEVtaXR0ZXIiLCJ0aW1lc3RhbXAiLCJ0b2tlbiIsIm5hbWUiLCJzZXJ2ZXJVcmwiLCJrZXlNYW5hZ2VyIiwid2VsbEtub3duQ3ZzQ29uZmlndXJhdGlvbiIsImRlZmF1bHRFdmVudHMiLCJlcyIsInN1cGVyIiwiY2FwdHVyZVJlamVjdGlvbnMiLCJjb25uZWN0ZWQiLCJjbG9zZSIsImNvbmZsaWN0IiwiZXJyb3IiLCJnZXRXZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiZW1pdEVycm9yIiwiY3ZzQ29uZiIsInZhdWx0X2NvbmZpZ3VyYXRpb24iLCJrZXlfZGVyaXZhdGlvbiIsIkF4aW9zRXJyb3IiLCJyZXNwb25zZSIsImRhdGEiLCJsb2dvdXQiLCJlbWl0IiwicmVzIiwiYXhpb3MiLCJnZXQiLCJFdmVudFNvdXJjZSIsImV2ZW50c19lbmRwb2ludCIsImhlYWRlcnMiLCJBdXRob3JpemF0aW9uIiwib25tZXNzYWdlIiwibXNnIiwiY29uc29sZSIsImxvZyIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwiSlNPTiIsInBhcnNlIiwib25lcnJvciIsInJlcUJvZHkiLCJhdXRoa2V5IiwicG9zdCIsInYyIiwidG9rZW5fZW5kcG9pbnQiLCJzdGF0dXMiLCJib2R5IiwiaW5pdEV2ZW50U291cmNlQ2xpZW50IiwidGltZXN0YW1wX2VuZHBvaW50IiwidmF1bHRfZW5kcG9pbnQiLCJzdG9yYWdlIiwiZnJvbSIsImZvcmNlIiwicmVtb3RlVGltZXN0YW1wIiwiZ2V0UmVtb3RlU3RvcmFnZVRpbWVzdGFtcCIsInJlcXVlc3RCb2R5IiwiZGVsZXRlIiwicmVnaXN0cmF0aW9uX2NvbmZpZ3VyYXRpb24iLCJwdWJsaWNfandrX2VuZHBvaW50IiwiandrIl0sIm1hcHBpbmdzIjoiZ1JBR2FBLEVBQ01DLElBQ1JDLElBRVRDLFlBQWFGLEVBQWdCQyxHQUMzQkUsS0FBS0gsSUFBTUEsRUFDWEcsS0FBS0YsSUFBTUEsQ0FDWixDQUVERyxRQUFTQyxHQUVQLE1BQU1DLEVBQUtDLGNBQVksSUFHakJDLEVBQVNDLEVBQUFBLGVBQWVOLEtBQUtGLElBQUtFLEtBQUtILElBQUtNLEdBRzVDSSxFQUFZQyxPQUFPQyxPQUFPLENBQUNKLEVBQU9LLE9BQU9SLEdBQVFHLEVBQU9NLFVBR3hEQyxFQUFNUCxFQUFPUSxhQUduQixPQUFPTCxPQUFPQyxPQUFPLENBQUNOLEVBQUlTLEVBQUtMLEdBQ2hDLENBRURPLFFBQVNaLEdBRVAsTUFBTUMsRUFBS0QsRUFBTWEsU0FBUyxFQUFHLElBQ3ZCSCxFQUFNVixFQUFNYSxTQUFTLEdBQUksSUFDekJDLEVBQWFkLEVBQU1hLFNBQVMsSUFHNUJFLEVBQVdDLEVBQUFBLGlCQUFpQmxCLEtBQUtGLElBQUtFLEtBQUtILElBQUtNLEdBSXRELE9BSEFjLEVBQVNFLFdBQVdQLEdBR2JKLE9BQU9DLE9BQU8sQ0FBQ1EsRUFBU1AsT0FBT00sR0FBYUMsRUFBU04sU0FDN0QsUUMx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
