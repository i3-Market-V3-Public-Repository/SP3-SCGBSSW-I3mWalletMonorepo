import t,{AxiosError as e}from"axios";import i from"eventsource";import{randomBytes as s,scrypt as r,createSecretKey as a}from"node:crypto";import{EventEmitter as o}from"node:events";import{config as n}from"dotenv";n();const l=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},h=["0","false","FALSE"],u=["1","true","FALSE"],d=h.concat(u);function c(t,e){const i=void 0===(s=process.env[t])?"":s;var s;const r=(e=e??{})?.isBoolean??!1;if(r&&(e={...e,allowedValues:d}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(l(t,e.allowedValues.join(", ")))}if(r&&u.includes(i))return!0;if(r&&h.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(l(t,e.allowedValues.join(", ")));return i}c("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const m="v"+c("npm_package_version",{defaultValue:"0.0.1"})[0];class p extends o{timestamp;token;name;serverUrl;vaultPath;publicKeyPath;es;constructor(t,e){super(),this.name=e??s(16).toString("hex"),this.serverUrl=t,this.vaultPath=`/api/${m}/vault`,this.publicKeyPath=`/api/${m}/registration/public-jwk`}emitError(t){t instanceof e&&void 0!==t.response?"Unauthorized"===t.response.data.name?(this.logout(),this.emit("login-required")):this.emit("error",t.response):this.emit("error",t)}async initEventSourceClient(){if(void 0===this.token)throw new Error("Cannot subscribe to events without login first");const t=this.serverUrl+this.vaultPath+"/events";this.es=new i(t,{headers:{Authorization:"Bearer "+this.token}}),this.es.onmessage=t=>{console.log(t)},this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.emit("connected",e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{this.emit("storage-updated")})),this.es.onerror=t=>{this.emit("error",t)}}close(){this.logout(),this.emit("close")}async login(e,i){const s={username:e,authkey:i};try{const e=await t.post(this.serverUrl+this.vaultPath+"/auth",s);if(200!==e.status)return this.emitError(e),!1;const i=e.data;return this.token=i.token,await this.initEventSourceClient(),this.emit("logged-in"),!0}catch(t){return this.emitError(t),!1}}logout(){this.token=void 0,this.es?.close()}async getRemoteStorageTimestamp(){try{if(void 0===this.token)return this.emit("login-required"),null;const e=await t.get(this.serverUrl+this.vaultPath+"/timestamp",{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});return 200!==e.status?(this.emitError(e),null):e.data.timestamp}catch(t){return this.emitError(t),null}}async updateStorage(e,i=!1){try{if(void 0===this.token)return this.emit("login-required"),!1;if(i){const t=await this.getRemoteStorageTimestamp();e.timestamp=null!==t?t:void 0}const s=await t.post(this.serverUrl+this.vaultPath,e,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});return 201!==s.status?(this.emitError(s),!1):(this.timestamp=s.data.timestamp,!0)}catch(t){this.emitError(t)}return!1}async deleteStorage(){try{if(void 0===this.token)return this.logout(),this.emit("login-required"),!1;const e=await t.delete(this.serverUrl+this.vaultPath,{headers:{Authorization:"Bearer "+this.token}});return 204!==e.status?(this.emitError(e),!1):(this.emit("storage-deleted"),!0)}catch(t){this.emitError(t)}return!1}async getServerPublicKey(){try{const e=await t.get(this.serverUrl+this.publicKeyPath);return 200!==e.status?(this.emitError(e),null):e.data.jwk}catch(t){return this.emitError(t),null}}}class v{_encKey;_authKey;derivationOptions;initialized;constructor(t,e){this.derivationOptions=e,this.initialized=this.init(t)}async init(t){const e=await g(t,this.derivationOptions.master,!0),[i,s]=await Promise.all([g(e,this.derivationOptions.auth),g(e,this.derivationOptions.enc)]);this._authKey=i,this._encKey=s}async getAuthKey(){return await this.initialized,this._authKey.export().toString("base64url")}async getEncKey(){return await this.initialized,this._encKey}}async function g(t,e,i=!1){let s={};void 0!==e.algOptions&&(s={N:16384,r:8,p:1,...e.algOptions},s.maxmem=256*s.N*s.r);const o=new Promise(((o,n)=>{r(t,e.salt,e.derivedKeyLength,s,((t,e)=>{null!==t&&n(t),o(i?e:a(e))}))}));return await o}export{v as KeyManager,p as VaultClient,g as deriveKey};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LWNsaWVudC50cyIsIi4uLy4uL3NyYy90cy9rZXktbWFuYWdlci50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsibG9hZEVudkZpbGUiLCJpbnZhbGlkTXNnIiwidmFybmFtZSIsInZhbHVlcyIsInJldCIsInVuZGVmaW5lZCIsImJvb2xlYW5GYWxzZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuVHJ1ZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuQWxsb3dlZFZhbHVlcyIsImNvbmNhdCIsInBhcnNlUHJvY2Nlc3NFbnZWYXIiLCJ2YXJOYW1lIiwib3B0aW9ucyIsInZhbHVlIiwiYSIsInByb2Nlc3MiLCJlbnYiLCJpc0Jvb2xlYW4iLCJhbGxvd2VkVmFsdWVzIiwiZGVmYXVsdFZhbHVlIiwiaW5jbHVkZXMiLCJSYW5nZUVycm9yIiwiam9pbiIsImFwaVZlcnNpb24iLCJWYXVsdENsaWVudCIsIkV2ZW50RW1pdHRlciIsInRpbWVzdGFtcCIsInRva2VuIiwibmFtZSIsInNlcnZlclVybCIsInZhdWx0UGF0aCIsInB1YmxpY0tleVBhdGgiLCJlcyIsImNvbnN0cnVjdG9yIiwic3VwZXIiLCJ0aGlzIiwicmFuZG9tQnl0ZXMiLCJ0b1N0cmluZyIsImVtaXRFcnJvciIsImVycm9yIiwiQXhpb3NFcnJvciIsInJlc3BvbnNlIiwiZGF0YSIsImxvZ291dCIsImVtaXQiLCJhc3luYyIsIkVycm9yIiwic3NlRW5kcG9pbnQiLCJFdmVudFNvdXJjZSIsImhlYWRlcnMiLCJBdXRob3JpemF0aW9uIiwib25tZXNzYWdlIiwibXNnIiwiY29uc29sZSIsImxvZyIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwiSlNPTiIsInBhcnNlIiwib25lcnJvciIsImNsb3NlIiwidXNlcm5hbWUiLCJhdXRoa2V5IiwicmVxQm9keSIsInJlcyIsImF4aW9zIiwicG9zdCIsInN0YXR1cyIsImJvZHkiLCJpbml0RXZlbnRTb3VyY2VDbGllbnQiLCJnZXQiLCJzdG9yYWdlIiwiZm9yY2UiLCJnZXRSZW1vdGVTdG9yYWdlVGltZXN0YW1wIiwiZGVsZXRlIiwiandrIiwiS2V5TWFuYWdlciIsIl9lbmNLZXkiLCJfYXV0aEtleSIsImRlcml2YXRpb25PcHRpb25zIiwiaW5pdGlhbGl6ZWQiLCJwYXNzd29yZCIsIm9wdHMiLCJpbml0IiwibWFzdGVyS2V5IiwiZGVyaXZlS2V5IiwibWFzdGVyIiwiYXV0aEtleSIsImVuY0tleSIsIlByb21pc2UiLCJhbGwiLCJhdXRoIiwiZW5jIiwiZXhwb3J0IiwicmV0dXJuQnVmZmVyIiwic2NyeXB0T3B0aW9ucyIsImFsZ09wdGlvbnMiLCJOIiwiciIsInAiLCJtYXhtZW0iLCJrZXlQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsInNjcnlwdCIsInNhbHQiLCJkZXJpdmVkS2V5TGVuZ3RoIiwiZXJyIiwia2V5IiwiY3JlYXRlU2VjcmV0S2V5Il0sIm1hcHBpbmdzIjoidU5BRUFBLElBTUEsTUFBTUMsRUFBYSxDQUFDQyxFQUFpQkMsS0FDbkMsSUFBSUMsRUFBTSxxQkFBcUJGLE1BRS9CLFlBRGVHLElBQVhGLElBQXNCQyxHQUFPLHNCQUFzQkQsTUFDaERDLENBQUcsRUFFTkUsRUFBNEIsQ0FBQyxJQUFLLFFBQVMsU0FDM0NDLEVBQTJCLENBQUMsSUFBSyxPQUFRLFNBQ3pDQyxFQUF1QkYsRUFBMEJHLE9BQU9GLEdBUTlDLFNBQUFHLEVBQXFCQyxFQUFpQkMsR0FDcEQsTUFBTUMsT0FuQlFSLEtBRFFTLEVBb0JjQyxRQUFRQyxJQUFJTCxJQW5CckIsR0FBS0csRUFEbEMsSUFBd0JBLEVBc0J0QixNQUFNRyxHQUROTCxFQUFVQSxHQUFXLEtBQ01LLFlBQWEsRUFPeEMsR0FOSUEsSUFDRkwsRUFBVSxJQUNMQSxFQUNITSxjQUFlVixJQUdMLEtB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
