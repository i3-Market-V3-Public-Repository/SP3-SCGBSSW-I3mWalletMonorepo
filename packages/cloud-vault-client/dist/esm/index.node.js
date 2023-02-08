import{randomBytes as t,createCipheriv as e,createDecipheriv as i,createHash as s,scrypt as a,createSecretKey as r}from"crypto";import n,{AxiosError as o}from"axios";import{EventEmitter as l}from"events";import u from"eventsource";import{config as h}from"dotenv";class d{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(i){const s=t(16),a=e(this.alg,this.key,s),r=Buffer.concat([a.update(i),a.final()]),n=a.getAuthTag();return Buffer.concat([s,n,r])}decrypt(t){const e=t.subarray(0,16),s=t.subarray(16,32),a=t.subarray(32),r=i(this.alg,this.key,e);return r.setAuthTag(s),Buffer.concat([r.update(a),r.final()])}}class c{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,i){this.username=t,this.derivationOptions=i,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:i,enc:s}=this.derivationOptions,a=m(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),r=await g(t,{...e,salt:a}),n=m(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),o=m(s.salt_hashing_algorithm,s.salt_pattern,{username:this.username}),[l,u]=await Promise.all([g(r,{...i,salt:n}),g(r,{...s,salt:o})]);this._authKey=l,this._encKey=new d(u,s.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function m(t,e,i){let a="";for(const t in i)a=e.replace(t,i[t]);return s(t).update(a).digest()}async function g(t,e){const i={...e.alg_options,maxmem:256*e.alg_options.N*e.alg_options.r},s="string"==typeof t?t:t.export(),n=new Promise(((t,n)=>{a(s,e.salt,e.derived_key_length,i,((e,i)=>{null!==e&&n(e),t(r(i))}))}));return await n}h();const p=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},f=["0","false","FALSE"],v=["1","true","FALSE"],w=f.concat(v);function y(t,e){const i=void 0===(s=process.env[t])?"":s;var s;const a=(e=e??{})?.isBoolean??!1;if(a&&(e={...e,allowedValues:w}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(p(t,e.allowedValues.join(", ")))}if(a&&v.includes(i))return!0;if(a&&f.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(p(t,e.allowedValues.join(", ")));return i}y("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const E="v"+y("npm_package_version",{defaultValue:"0.0.1"})[0];class _ extends l{timestamp;token;name;serverUrl;username;password;keyManager;wellKnownCvsConfiguration;defaultEvents;initialized;es;constructor(e,i,s,a){super({captureRejections:!0}),this.name=a??t(16).toString("hex"),this.serverUrl=e,this.username=i,this.password=s,this.defaultEvents={connected:"connected",close:"close","login-required":"login-required","storage-updated":"storage-updated","storage-deleted":"storage-deleted",conflict:"conflict",error:"error"},this.initialized=this.init()}async init(){try{await this.getWellKnownCvsConfiguration()}catch(t){return this.emitError(t),!1}const t=this.wellKnownCvsConfiguration;this.keyManager=new c(this.username,this.password,t.vault_configuration[E].key_derivation);try{await this.keyManager.initialized}catch(t){return this.emitError(t),!1}return delete this.password,!0}emitError(t){if(t instanceof o)if("Unauthorized"===t.response?.data.name)this.logout(),this.emit(this.defaultEvents["login-required"]);else{const e={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};this.emit(this.defaultEvents.error,e)}else this.emit(this.defaultEvents.error,t)}async getWellKnownCvsConfiguration(){const t=await n.get(this.serverUrl+"/.well-known/cvs-configuration");this.wellKnownCvsConfiguration=t.data}async initEventSourceClient(){if(void 0===this.token)throw new Error("Cannot subscribe to events without login first");const t=this.wellKnownCvsConfiguration;this.es=new u(this.serverUrl+t.vault_configuration[E].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.onmessage=t=>{console.log(t)},this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.emit(this.defaultEvents.connected,e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit(this.defaultEvents["storage-updated"],this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.close(),this.emit(this.defaultEvents["storage-deleted"])})),this.es.onerror=t=>{this.emitError(t)}}close(){this.logout(),this.emit(this.defaultEvents.close)}async getAuthKey(){if(!await this.initialized)try{await this.init()}catch(t){return this.emitError(t),null}return this.keyManager.authKey}async login(){if(!await this.initialized)try{await this.init()}catch(t){return this.emitError(t),!1}const t={username:this.username,authkey:this.keyManager.authKey};try{const e=this.wellKnownCvsConfiguration,i=await n.post(this.serverUrl+e.vault_configuration.v2.token_endpoint,t);if(200!==i.status)return this.emitError(i),!1;const s=i.data;return this.token=s.token,await this.initEventSourceClient(),!0}catch(t){return this.emitError(t),!1}}logout(){this.token=void 0,this.es?.close()}async getRemoteStorageTimestamp(){try{if(void 0===this.token)return this.emit(this.defaultEvents["login-required"]),null;const t=this.wellKnownCvsConfiguration,e=await n.get(this.serverUrl+t.vault_configuration[E].timestamp_endpoint,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});return 200!==e.status?(this.emitError(e),null):((this.timestamp??0)<e.data.timestamp&&(this.timestamp=e.data.timestamp),e.data.timestamp)}catch(t){return this.emitError(t),null}}async getStorage(){try{if(void 0===this.token)return this.emit(this.defaultEvents["login-required"]),null;const t=this.wellKnownCvsConfiguration,e=this.keyManager.encKey,i=await n.get(this.serverUrl+t.vault_configuration[E].vault_endpoint,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});if(200!==i.status)return this.emitError(i),null;if(i.data.timestamp<(this.timestamp??0))return this.emitError(new Error("Received timestamp is older than the latest one published")),null;const s=e.decrypt(Buffer.from(i.data.ciphertext,"base64url"));return this.timestamp=i.data.timestamp,{storage:s,timestamp:i.data.timestamp}}catch(t){return this.emitError(t),null}}async updateStorage(t,e=!1){try{if(void 0===this.token)return this.emit(this.defaultEvents["login-required"]),!1;if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)return this.emit(this.defaultEvents.conflict),!1;const i=this.wellKnownCvsConfiguration,s=this.keyManager.encKey;if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}const a={ciphertext:s.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},r=await n.post(this.serverUrl+i.vault_configuration[E].vault_endpoint,a,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});return 201!==r.status?(this.emitError(r),!1):(this.timestamp=r.data.timestamp,!0)}catch(t){this.emitError(t)}return!1}async deleteStorage(){try{if(void 0===this.token)return this.logout(),this.emit(this.defaultEvents["login-required"]),!1;const t=this.wellKnownCvsConfiguration,e=await n.delete(this.serverUrl+t.vault_configuration[E].vault_endpoint,{headers:{Authorization:"Bearer "+this.token}});return 204!==e.status?(this.emitError(e),!1):(this.emit(this.defaultEvents["storage-deleted"]),delete this.timestamp,this.close(),!0)}catch(t){this.emitError(t)}return!1}async getServerPublicKey(){try{await this.getWellKnownCvsConfiguration();const t=this.wellKnownCvsConfiguration,e=await n.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint);return 200!==e.status?(this.emitError(e),null):e.data.jwk}catch(t){return this.emitError(t),null}}}export{c as KeyManager,d as SecretKey,_ as VaultClient,g as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NlY3JldC1rZXkudHMiLCIuLi8uLi9zcmMvdHMva2V5LW1hbmFnZXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL3BhcnNlUHJvY2Vzc0VudlZhci50cyIsIi4uLy4uL3NyYy90cy9jb25maWcvaW5kZXgudHMiLCIuLi8uLi9zcmMvdHMvdmF1bHQtY2xpZW50LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJTZWNyZXRLZXkiLCJrZXkiLCJhbGciLCJjb25zdHJ1Y3RvciIsInRoaXMiLCJlbmNyeXB0IiwiaW5wdXQiLCJpdiIsInJhbmRvbUJ5dGVzIiwiY2lwaGVyIiwiY3JlYXRlQ2lwaGVyaXYiLCJlbmNyeXB0ZWQiLCJCdWZmZXIiLCJjb25jYXQiLCJ1cGRhdGUiLCJmaW5hbCIsInRhZyIsImdldEF1dGhUYWciLCJkZWNyeXB0Iiwic3ViYXJyYXkiLCJjaXBoZXJ0ZXh0IiwiZGVjaXBoZXIiLCJjcmVhdGVEZWNpcGhlcml2Iiwic2V0QXV0aFRhZyIsIktleU1hbmFnZXIiLCJfZW5jS2V5IiwiX2F1dGhLZXkiLCJ1c2VybmFtZSIsImRlcml2YXRpb25PcHRpb25zIiwiaW5pdGlhbGl6ZWQiLCJfaW5pdGlhbGl6ZWQiLCJwYXNzd29yZCIsIm9wdHMiLCJpbml0IiwiYXN5bmMiLCJtYXN0ZXIiLCJhdXRoIiwiZW5jIiwibWFzdGVyU2FsdCIsIl9zYWx0Iiwic2FsdF9oYXNoaW5nX2FsZ29yaXRobSIsInNhbHRfcGF0dGVybiIsIm1hc3RlcktleSIsImRlcml2ZUtleSIsInNhbHQiLCJhdXRoU2FsdCIsImVuY1NhbHQiLCJhdXRoS2V5IiwiZW5jS2V5IiwiUHJvbWlzZSIsImFsbCIsImVuY19hbGdvcml0aG0iLCJFcnJvciIsImNhdXNlIiwiZXhwb3J0IiwidG9TdHJpbmciLCJoYXNoQWxnb3JpdGhtIiwic2FsdFBhdHRlcm4iLCJyZXBsYWNlbWVudHMiLCJzYWx0U3RyaW5nIiwic2VhcmNoVmFsdWUiLCJyZXBsYWNlIiwiY3JlYXRlSGFzaCIsImRpZ2VzdCIsInBhc3N3b3JkT3JLZXkiLCJzY3J5cHRPcHRpb25zIiwiYWxnX29wdGlvbnMiLCJtYXhtZW0iLCJOIiwiciIsImtleVByb21pc2UiLCJyZXNvbHZlIiwicmVqZWN0Iiwic2NyeXB0IiwiZGVyaXZlZF9rZXlfbGVuZ3RoIiwiZXJyIiwiY3JlYXRlU2VjcmV0S2V5IiwibG9hZEVudkZpbGUiLCJpbnZhbGlkTXNnIiwidmFybmFtZSIsInZhbHVlcyIsInJldCIsInVuZGVmaW5lZCIsImJvb2xlYW5GYWxzZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuVHJ1ZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuQWxsb3dlZFZhbHVlcyIsInBhcnNlUHJvY2Nlc3NFbnZWYXIiLCJ2YXJOYW1lIiwib3B0aW9ucyIsInZhbHVlIiwiYSIsInByb2Nlc3MiLCJlbnYiLCJpc0Jvb2xlYW4iLCJhbGxvd2VkVmFsdWVzIiwiZGVmYXVsdFZhbHVlIiwiaW5jbHVkZXMiLCJSYW5nZUVycm9yIiwiam9pbiIsImFwaVZlcnNpb24iLCJWYXVsdENsaWVudCIsIkV2ZW50RW1pdHRlciIsInRpbWVzdGFtcCIsInRva2VuIiwibmFtZSIsInNlcnZlclVybCIsImtleU1hbmFnZXIiLCJ3ZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiZGVmYXVsdEV2ZW50cyIsImVzIiwic3VwZXIiLCJjYXB0dXJlUmVqZWN0aW9ucyIsImNvbm5lY3RlZCIsImNsb3NlIiwiY29uZmxpY3QiLCJlcnJvciIsImdldFdlbGxLbm93bkN2c0NvbmZpZ3VyYXRpb24iLCJlbWl0RXJyb3IiLCJjdnNDb25mIiwidmF1bHRfY29uZmlndXJhdGlvbiIsImtleV9kZXJpdmF0aW9uIiwiQXhpb3NFcnJvciIsInJlc3BvbnNlIiwiZGF0YSIsImxvZ291dCIsImVtaXQiLCJ2YXVsdENvbm5FcnJvciIsInJlcXVlc3QiLCJtZXRob2QiLCJjb25maWciLCJ0b0xvY2FsZVVwcGVyQ2FzZSIsInVybCIsImhlYWRlcnMiLCJzdGF0dXMiLCJyZXMiLCJheGlvcyIsImdldCIsIkV2ZW50U291cmNlIiwiZXZlbnRzX2VuZHBvaW50IiwiQXV0aG9yaXphdGlvbiIsIm9ubWVzc2FnZSIsIm1zZyIsImNvbnNvbGUiLCJsb2ciLCJhZGRFdmVudExpc3RlbmVyIiwiZSIsIkpTT04iLCJwYXJzZSIsIm9uZXJyb3IiLCJyZXFCb2R5IiwiYXV0aGtleSIsInBvc3QiLCJ2MiIsInRva2VuX2VuZHBvaW50IiwiYm9keSIsImluaXRFdmVudFNvdXJjZUNsaWVudCIsInRpbWVzdGFtcF9lbmRwb2ludCIsInZhdWx0X2VuZHBvaW50Iiwic3RvcmFnZSIsImZyb20iLCJmb3JjZSIsInJlbW90ZVRpbWVzdGFtcCIsImdldFJlbW90ZVN0b3JhZ2VUaW1lc3RhbXAiLCJyZXF1ZXN0Qm9keSIsImRlbGV0ZSIsInJlZ2lzdHJhdGlvbl9jb25maWd1cmF0aW9uIiwicHVibGljX2p3a19lbmRwb2ludCIsImp3ayJdLCJtYXBwaW5ncyI6IjZRQUdhQSxFQUNNQyxJQUNSQyxJQUVUQyxZQUFhRixFQUFnQkMsR0FDM0JFLEtBQUtILElBQU1BLEVBQ1hHLEtBQUtGLElBQU1BLENBQ1osQ0FFREcsUUFBU0MsR0FFUCxNQUFNQyxFQUFLQyxFQUFZLElBR2pCQyxFQUFTQyxFQUFlTixLQUFLRixJQUFLRSxLQUFLSCxJQUFLTSxHQUc1Q0ksRUFBWUMsT0FBT0MsT0FBTyxDQUFDSixFQUFPSyxPQUFPUixHQUFRRyxFQUFPTSxVQUd4REMsRUFBTVAsRUFBT1EsYUFHbkIsT0FBT0wsT0FBT0MsT0FBTyxDQUFDTixFQUFJUyxFQUFLTCxHQUNoQyxDQUVETyxRQUFTWixHQUVQLE1BQU1DLEVBQUtELEVBQU1hLFNBQVMsRUFBRyxJQUN2QkgsRUFBTVYsRUFBTWEsU0FBUyxHQUFJLElBQ3pCQyxFQUFhZCxFQUFNYSxTQUFTLElBRzVCRSxFQUFXQyxFQUFpQmxCLEtBQUtGLElBQUtFLEtBQUtILElBQUtNLEdBSXRELE9BSEFjLEVBQVNFLFdBQVdQLEdB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
