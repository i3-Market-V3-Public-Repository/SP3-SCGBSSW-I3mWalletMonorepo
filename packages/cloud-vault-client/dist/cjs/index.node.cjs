"use strict";Object.defineProperty(exports,"__esModule",{value:!0});var t=require("crypto"),e=require("axios"),i=require("events"),a=require("eventsource"),s=require("dotenv");function n(t){return t&&"object"==typeof t&&"default"in t?t:{default:t}}var o=n(e),r=n(a);class u{key;alg;constructor(t,e){this.key=t,this.alg=e}encrypt(e){const i=t.randomBytes(16),a=t.createCipheriv(this.alg,this.key,i),s=Buffer.concat([a.update(e),a.final()]),n=a.getAuthTag();return Buffer.concat([i,n,s])}decrypt(e){const i=e.subarray(0,16),a=e.subarray(16,32),s=e.subarray(32),n=t.createDecipheriv(this.alg,this.key,i);return n.setAuthTag(a),Buffer.concat([n.update(s),n.final()])}}class c{_encKey;_authKey;username;derivationOptions;initialized;_initialized;constructor(t,e,i){this.username=t,this.derivationOptions=i,this._initialized=!1,this.initialized=this.init(e)}async init(t){const{master:e,auth:i,enc:a}=this.derivationOptions,s=h(e.salt_hashing_algorithm,e.salt_pattern,{username:this.username}),n=await l(t,{...e,salt:s}),o=h(i.salt_hashing_algorithm,i.salt_pattern,{username:this.username}),r=h(a.salt_hashing_algorithm,a.salt_pattern,{username:this.username}),[c,d]=await Promise.all([l(n,{...i,salt:o}),l(n,{...a,salt:r})]);this._authKey=c,this._encKey=new u(d,a.enc_algorithm),this._initialized=!0}get authKey(){if(!this._initialized)throw new Error("Unable to get authKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._authKey.export().toString("base64url")}get encKey(){if(!this._initialized)throw new Error("Unable to get encKey. KeyManager not initialized",{cause:"You may have forgotten to await keymanager.initialized or just to login"});return this._encKey}}function h(e,i,a){let s="";for(const t in a)s=i.replace(t,a[t]);return t.createHash(e).update(s).digest()}async function l(e,i){const a={...i.alg_options,maxmem:256*i.alg_options.N*i.alg_options.r},s="string"==typeof e?e:e.export(),n=new Promise(((e,n)=>{t.scrypt(s,i.salt,i.derived_key_length,a,((i,a)=>{null!==i&&n(i),e(t.createSecretKey(a))}))}));return await n}class d extends Error{data;message;constructor(t,e,i){super(t,i),this.name="VaultError",this.data=e,this.message=t}static from(t){if(t instanceof d)return t;if(t instanceof Event)return new d("sse-connection-error",t,{cause:"Likely issues connecting to the events endpoint of the cloud vault server"});if(t instanceof e.AxiosError){if("Unauthorized"===t.response?.data.name)return new d("unauthorized",void 0);if(404===t.response?.status&&"no storage"===t.response.data.name)return new d("no-uploadded-storage",void 0);const e={request:{method:t.config?.method?.toLocaleUpperCase(),url:t.config?.url,headers:t.config?.headers,data:t.config?.data},response:{status:t.response?.status,headers:t.response?.headers,data:t.response?.data}};return new d("http-connection-error",e)}if(t instanceof Error){const e=new d("error",t,{cause:t.cause});return e.stack=t.stack,e}return new d("unknown",t)}}var p={get:async function(t,e){const i={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(i.Authorization="Bearer "+e.bearerToken);const a=await o.default.get(t,{headers:i}).catch((t=>{throw d.from(t)}));if(void 0!==e?.responseStatus&&a.status!==e.responseStatus)throw new d("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data},post:async function(t,e,i){const a={"Content-Type":"application/json"};void 0!==i?.bearerToken&&(a.Authorization="Bearer "+i.bearerToken);const s=await o.default.post(t,e,{headers:a}).catch((t=>{throw d.from(t)}));if(void 0!==i?.responseStatus&&s.status!==i.responseStatus)throw new d("validation",{description:`Received HTTP status ${s.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return s.data},put:async function(t,e,i){const a={"Content-Type":"application/json"};void 0!==i?.bearerToken&&(a.Authorization="Bearer "+i.bearerToken);const s=await o.default.put(t,e,{headers:a}).catch((t=>{throw d.from(t)}));if(void 0!==i?.responseStatus&&s.status!==i.responseStatus)throw new d("validation",{description:`Received HTTP status ${s.status} does not match the expected one (${i.responseStatus})`},{cause:"HTTP status does not match the expected one"});return s.data},delete:async function(t,e){const i={"Content-Type":"application/json"};void 0!==e?.bearerToken&&(i.Authorization="Bearer "+e.bearerToken);const a=await o.default.delete(t,{headers:i}).catch((t=>{throw d.from(t)}));if(void 0!==e?.responseStatus&&a.status!==e.responseStatus)throw new d("validation",{description:`Received HTTP status ${a.status} does not match the expected one (${e.responseStatus})`},{cause:"HTTP status does not match the expected one"});return a.data}};s.config();const m=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},w=["0","false","FALSE"],g=["1","true","FALSE"],v=w.concat(g);function f(t,e){const i=void 0===(a=process.env[t])?"":a;var a;const s=(e=e??{})?.isBoolean??!1;if(s&&(e={...e,allowedValues:v}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(m(t,e.allowedValues.join(", ")))}if(s&&g.includes(i))return!0;if(s&&w.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(m(t,e.allowedValues.join(", ")));return i}f("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const y="v"+f("npm_package_version",{defaultValue:"0.0.1"})[0];class k extends i.EventEmitter{timestamp;token;name;serverUrl;username;password;keyManager;wellKnownCvsConfiguration;initialized;es;constructor(e,i,a,s){super({captureRejections:!0}),this.name=s??t.randomBytes(16).toString("hex"),this.serverUrl=e,this.username=i,this.password=a,this.initialized=this.init()}emit(t,...e){return super.emit(t,...e)}on(t,e){return super.on(t,e)}once(t,e){return super.once(t,e)}async init(){try{await this.getWellKnownCvsConfiguration();const t=this.wellKnownCvsConfiguration;this.keyManager=new c(this.username,this.password,t.vault_configuration[y].key_derivation),await this.keyManager.initialized,delete this.password}catch(t){throw d.from(t)}}async getWellKnownCvsConfiguration(){this.wellKnownCvsConfiguration=await p.get(this.serverUrl+"/.well-known/cvs-configuration",{responseStatus:200})}async initEventSourceClient(){if(void 0===this.token)throw new d("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;this.es=new r.default(this.serverUrl+t.vault_configuration[y].events_endpoint,{headers:{Authorization:"Bearer "+this.token}}),this.es.onmessage=t=>{console.log(t)},this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.timestamp=e.timestamp,this.emit("connected",e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{delete this.timestamp,this.logout(),this.emit("storage-deleted")})),this.es.onerror=t=>{this.emitError(t)}}emitError(t){const e=d.from(t);switch(e.message){case"unauthorized":this.logout(),this.emit("logged-out");break;case"sse-connection-error":this.emit("connection-error",e);break;default:this.emit("error",e)}}logout(){this.es?.close(),this.token=void 0,this.emit("logged-out")}async getAuthKey(){return await this.initialized.catch((t=>{throw new d("not-initialized",t)})),this.keyManager.authKey}async login(){await this.initialized.catch((t=>{throw new d("not-initialized",t)}));const t={username:this.username,authkey:this.keyManager.authKey},e=this.wellKnownCvsConfiguration,i=await p.post(this.serverUrl+e.vault_configuration.v2.token_endpoint,t,{responseStatus:200});this.token=i.token,await this.initEventSourceClient().catch((t=>{throw d.from(t)}))}async getRemoteStorageTimestamp(){if(await this.initialized.catch((t=>{throw new d("not-initialized",t)})),void 0===this.token)throw new d("unauthorized",void 0);const t=this.wellKnownCvsConfiguration,e=await p.get(this.serverUrl+t.vault_configuration[y].timestamp_endpoint,{bearerToken:this.token,responseStatus:200});return(this.timestamp??0)<e.timestamp&&(this.timestamp=e.timestamp),e.timestamp}async getStorage(){if(await this.initialized.catch((t=>{throw new d("not-initialized",t)})),void 0===this.token)throw new d("unauthorized",void 0);try{const t=this.wellKnownCvsConfiguration,e=this.keyManager.encKey,i=await p.get(this.serverUrl+t.vault_configuration[y].vault_endpoint,{bearerToken:this.token,responseStatus:200});if(i.timestamp<(this.timestamp??0))throw new d("validation",{description:"WEIRD!!! Received timestamp is older than the one received in previous events"});const a=e.decrypt(Buffer.from(i.ciphertext,"base64url"));return this.timestamp=i.timestamp,{storage:a,timestamp:i.timestamp}}catch(t){throw d.from(t)}}async updateStorage(t,e=!1){if(await this.initialized.catch((t=>{throw new d("not-initialized",t)})),void 0===this.token)throw new d("unauthorized",void 0);if(void 0!==this.timestamp&&(t.timestamp??0)<this.timestamp)throw new d("conflict",{localTimestamp:t.timestamp,remoteTimestamp:this.timestamp});const i=this.wellKnownCvsConfiguration,a=this.keyManager.encKey;if(e){const e=await this.getRemoteStorageTimestamp();t.timestamp=null!==e?e:void 0}const s={ciphertext:a.encrypt(t.storage).toString("base64url"),timestamp:t.timestamp},n=await p.post(this.serverUrl+i.vault_configuration[y].vault_endpoint,s,{bearerToken:this.token,responseStatus:201});this.timestamp=n.timestamp}async deleteStorage(){if(await this.initialized.catch((t=>{throw new d("not-initialized",t)})),void 0===this.token)throw new d("unauthorized",void 0);const t=this.wellKnownCvsConfiguration;await p.delete(this.serverUrl+t.vault_configuration[y].vault_endpoint,{bearerToken:this.token,responseStatus:204}),delete this.timestamp,this.logout()}async getServerPublicKey(){await this.getWellKnownCvsConfiguration();const t=this.wellKnownCvsConfiguration;return(await p.get(this.serverUrl+t.registration_configuration.public_jwk_endpoint,{responseStatus:200})).jwk}}exports.KeyManager=c,exports.SecretKey=u,exports.VaultClient=k,exports.deriveKey=l;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9zZWNyZXQta2V5LnRzIiwiLi4vLi4vc3JjL3RzL2tleS1tYW5hZ2VyLnRzIiwiLi4vLi4vc3JjL3RzL2Vycm9yLnRzIiwiLi4vLi4vc3JjL3RzL3JlcXVlc3QudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL3BhcnNlUHJvY2Vzc0VudlZhci50cyIsIi4uLy4uL3NyYy90cy9jb25maWcvaW5kZXgudHMiLCIuLi8uLi9zcmMvdHMvdmF1bHQtY2xpZW50LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJTZWNyZXRLZXkiLCJrZXkiLCJhbGciLCJjb25zdHJ1Y3RvciIsInRoaXMiLCJlbmNyeXB0IiwiaW5wdXQiLCJpdiIsInJhbmRvbUJ5dGVzIiwiY2lwaGVyIiwiY3JlYXRlQ2lwaGVyaXYiLCJlbmNyeXB0ZWQiLCJCdWZmZXIiLCJjb25jYXQiLCJ1cGRhdGUiLCJmaW5hbCIsInRhZyIsImdldEF1dGhUYWciLCJkZWNyeXB0Iiwic3ViYXJyYXkiLCJjaXBoZXJ0ZXh0IiwiZGVjaXBoZXIiLCJjcmVhdGVEZWNpcGhlcml2Iiwic2V0QXV0aFRhZyIsIktleU1hbmFnZXIiLCJfZW5jS2V5IiwiX2F1dGhLZXkiLCJ1c2VybmFtZSIsImRlcml2YXRpb25PcHRpb25zIiwiaW5pdGlhbGl6ZWQiLCJfaW5pdGlhbGl6ZWQiLCJwYXNzd29yZCIsIm9wdHMiLCJpbml0IiwiYXN5bmMiLCJtYXN0ZXIiLCJhdXRoIiwiZW5jIiwibWFzdGVyU2FsdCIsIl9zYWx0Iiwic2FsdF9oYXNoaW5nX2FsZ29yaXRobSIsInNhbHRfcGF0dGVybiIsIm1hc3RlcktleSIsImRlcml2ZUtleSIsInNhbHQiLCJhdXRoU2FsdCIsImVuY1NhbHQiLCJhdXRoS2V5IiwiZW5jS2V5IiwiUHJvbWlzZSIsImFsbCIsImVuY19hbGdvcml0aG0iLCJFcnJvciIsImNhdXNlIiwiZXhwb3J0IiwidG9TdHJpbmciLCJoYXNoQWxnb3JpdGhtIiwic2FsdFBhdHRlcm4iLCJyZXBsYWNlbWVudHMiLCJzYWx0U3RyaW5nIiwic2VhcmNoVmFsdWUiLCJyZXBsYWNlIiwiY3JlYXRlSGFzaCIsImRpZ2VzdCIsInBhc3N3b3JkT3JLZXkiLCJzY3J5cHRPcHRpb25zIiwiYWxnX29wdGlvbnMiLCJtYXhtZW0iLCJOIiwiciIsImtleVByb21pc2UiLCJyZXNvbHZlIiwicmVqZWN0Iiwic2NyeXB0IiwiZGVyaXZlZF9rZXlfbGVuZ3RoIiwiZXJyIiwiY3JlYXRlU2VjcmV0S2V5IiwiVmF1bHRFcnJvciIsImRhdGEiLCJtZXNzYWdlIiwib3B0aW9ucyIsInN1cGVyIiwibmFtZSIsInN0YXRpYyIsImVycm9yIiwiRXZlbnQiLCJBeGlvc0Vycm9yIiwicmVzcG9uc2UiLCJ1bmRlZmluZWQiLCJzdGF0dXMiLCJ2YXVsdENvbm5FcnJvciIsInJlcXVlc3QiLCJtZXRob2QiLCJjb25maWciLCJ0b0xvY2FsZVVwcGVyQ2FzZSIsInVybCIsImhlYWRlcnMiLCJ2YXVsdEVycm9yIiwic3RhY2siLCJnZXQiLCJiZWFyZXJUb2tlbiIsIkF1dGhvcml6YXRpb24iLCJyZXMiLCJheGlvcyIsImNhdGNoIiwiZnJvbSIsInJlc3BvbnNlU3RhdHVzIiwiZGVzY3JpcHRpb24iLCJwb3N0IiwicmVxdWVzdEJvZHkiLCJwdXQiLCJkZWxldGUiLCJsb2FkRW52RmlsZSIsImludmFsaWRNc2ciLCJ2YXJuYW1lIiwidmFsdWVzIiwicmV0IiwiYm9vbGVhbkZhbHNlQWxsb3dlZFZhbHVlcyIsImJvb2xlYW5UcnVlQWxsb3dlZFZhbHVlcyIsImJvb2xlYW5BbGxvd2VkVmFsdWVzIiwicGFyc2VQcm9jY2Vzc0VudlZhciIsInZhck5hbWUiLCJ2YWx1ZSIsImEiLCJwcm9jZXNzIiwiZW52IiwiaXNCb29sZWFuIiwiYWxsb3dlZFZhbHVlcyIsImRlZmF1bHRWYWx1ZSIsImluY2x1ZGVzIiwiUmFuZ2VFcnJvciIsImpvaW4iLCJhcGlWZXJzaW9uIiwiVmF1bHRDbGllbnQiLCJFdmVudEVtaXR0ZXIiLCJ0aW1lc3RhbXAiLCJ0b2tlbiIsInNlcnZlclVybCIsImtleU1hbmFnZXIiLCJ3ZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiZXMiLCJjYXB0dXJlUmVqZWN0aW9ucyIsImVtaXQiLCJldmVudE5hbWUiLCJhcmdzIiwib24iLCJsaXN0ZW5lciIsIm9uY2UiLCJnZXRXZWxsS25vd25DdnNDb25maWd1cmF0aW9uIiwiY3ZzQ29uZiIsInZhdWx0X2NvbmZpZ3VyYXRpb24iLCJrZXlfZGVyaXZhdGlvbiIsIkV2ZW50U291cmNlIiwiZXZlbnRzX2VuZHBvaW50Iiwib25tZXNzYWdlIiwibXNnIiwiY29uc29sZSIsImxvZyIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwiSlNPTiIsInBhcnNlIiwibG9nb3V0Iiwib25lcnJvciIsImVtaXRFcnJvciIsImNsb3NlIiwicmVxQm9keSIsImF1dGhrZXkiLCJ2MiIsInRva2VuX2VuZHBvaW50IiwiaW5pdEV2ZW50U291cmNlQ2xpZW50IiwidGltZXN0YW1wX2VuZHBvaW50IiwidmF1bHRfZW5kcG9pbnQiLCJzdG9yYWdlIiwiZm9yY2UiLCJsb2NhbFRpbWVzdGFtcCIsInJlbW90ZVRpbWVzdGFtcCIsImdldFJlbW90ZVN0b3JhZ2VUaW1lc3RhbXAiLCJyZWdpc3RyYXRpb25fY29uZmlndXJhdGlvbiIsInB1YmxpY19qd2tfZW5kcG9pbnQiLCJqd2siXSwibWFwcGluZ3MiOiJnUkFHYUEsRUFDTUMsSUFDUkMsSUFFVEMsWUFBYUYsRUFBZ0JDLEdBQzNCRSxLQUFLSCxJQUFNQSxFQUNYRyxLQUFLRixJQUFNQSxDQUNaLENBRURHLFFBQVNDLEdBRVAsTUFBTUMsRUFBS0MsY0FBWSxJQUdqQkMsRUFBU0MsRUFBQUEsZUFBZU4sS0FBS0YsSUFBS0UsS0FBS0gsSUFBS00sR0FHNUNJLEVBQVlDLE9BQU9DLE9BQU8sQ0FBQ0osRUFBT0ssT0FBT1IsR0FBUUcsRUFBT00sVUFHeERDLEVBQU1QLEVBQU9RLGFBR25CLE9BQU9MLE9BQU9DLE9BQU8sQ0FB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