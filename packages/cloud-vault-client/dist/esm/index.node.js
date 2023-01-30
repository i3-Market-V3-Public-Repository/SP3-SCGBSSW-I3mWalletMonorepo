import t from"axios";import e from"eventsource";import{randomBytes as i}from"node:crypto";import{EventEmitter as s}from"node:events";import{config as r}from"dotenv";r();const o=(t,e)=>{let i=`Invalid value for ${t}. `;return void 0!==e&&(i+=`Allowed values are ${e} `),i},a=["0","false","FALSE"],n=["1","true","FALSE"],l=a.concat(n);function u(t,e){const i=void 0===(s=process.env[t])?"":s;var s;const r=(e=e??{})?.isBoolean??!1;if(r&&(e={...e,allowedValues:l}),""===i){if(void 0!==e.defaultValue)return e.defaultValue;if(void 0!==e.allowedValues&&!e.allowedValues.includes(""))throw new RangeError(o(t,e.allowedValues.join(", ")))}if(r&&n.includes(i))return!0;if(r&&a.includes(i))return!1;if(void 0!==e.allowedValues&&!e.allowedValues.includes(i))throw new RangeError(o(t,e.allowedValues.join(", ")));return i}u("NODE_ENV",{defaultValue:"production",allowedValues:["production","development"]});const d="v"+u("npm_package_version",{defaultValue:"0.0.1"})[0];class h extends s{constructor(t,e){super(),this.name=e??i(16).toString("hex"),this.serverUrl=t,this.vaultPath=`/api/v${d}/vault`}async initEventSourceClient(){if(void 0===this.token)throw new Error("Cannot subscribe to events without login first");const t=this.serverUrl+this.vaultPath+"/events";this.es=new e(t,{headers:{Authorization:"Bearer "+this.token}}),this.es.addEventListener("connected",(t=>{const e=JSON.parse(t.data);this.emit("connected",e.timestamp)})),this.es.addEventListener("storage-updated",(t=>{const e=JSON.parse(t.data);e.timestamp!==this.timestamp&&(this.timestamp=e.timestamp,this.emit("storage-updated",this.timestamp))})),this.es.addEventListener("storage-deleted",(t=>{this.emit("storage-updated")})),this.es.onerror=t=>{this.emit("error",t)}}close(){this.logout(),this.emit("close")}async login(e,i){const s={username:e,authkey:i};try{const e=await t.post(this.serverUrl+this.vaultPath+"/auth",s);if(200!==e.status)return!1;const i=e.data;return this.token=i.token,await this.initEventSourceClient(),this.emit("logged-in"),!0}catch(t){return this.emit("error",t),!1}}logout(){this.token=void 0,this.es.close()}async updateStorage(e,i=!1){if(void 0===this.token)return this.emit("login-required"),!1;const s=await t.post(this.serverUrl+this.vaultPath,e,{headers:{Authorization:"Bearer "+this.token,"Content-Type":"application/json"}});if(201!==s.status){return"Unauthorized"===s.data.name?(this.logout(),this.emit("login-required")):this.emit("error",s.data),!1}return this.timestamp=s.data.timestamp,!0}async deleteStorage(){if(void 0===this.token)return this.logout(),this.emit("login-required"),!1;const e=await t.get(this.serverUrl+this.vaultPath,{headers:{Authorization:"Bearer "+this.token}});if(204!==e.status){return"Unauthorized"===e.data.name?(this.logout(),this.emit("login-required")):this.emit("error",e.data),!1}return this.emit("storage-deleted"),!0}}export{h as VaultClient};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmlnL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL3ZhdWx0LWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsibG9hZEVudkZpbGUiLCJpbnZhbGlkTXNnIiwidmFybmFtZSIsInZhbHVlcyIsInJldCIsInVuZGVmaW5lZCIsImJvb2xlYW5GYWxzZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuVHJ1ZUFsbG93ZWRWYWx1ZXMiLCJib29sZWFuQWxsb3dlZFZhbHVlcyIsImNvbmNhdCIsInBhcnNlUHJvY2Nlc3NFbnZWYXIiLCJ2YXJOYW1lIiwib3B0aW9ucyIsInZhbHVlIiwiYSIsInByb2Nlc3MiLCJlbnYiLCJpc0Jvb2xlYW4iLCJhbGxvd2VkVmFsdWVzIiwiZGVmYXVsdFZhbHVlIiwiaW5jbHVkZXMiLCJSYW5nZUVycm9yIiwiam9pbiIsImFwaVZlcnNpb24iLCJWYXVsdENsaWVudCIsIkV2ZW50RW1pdHRlciIsImNvbnN0cnVjdG9yIiwic2VydmVyVXJsIiwibmFtZSIsInN1cGVyIiwidGhpcyIsInJhbmRvbUJ5dGVzIiwidG9TdHJpbmciLCJ2YXVsdFBhdGgiLCJhc3luYyIsInRva2VuIiwiRXJyb3IiLCJzc2VFbmRwb2ludCIsImVzIiwiRXZlbnRTb3VyY2UiLCJoZWFkZXJzIiwiQXV0aG9yaXphdGlvbiIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwibXNnIiwiSlNPTiIsInBhcnNlIiwiZGF0YSIsImVtaXQiLCJ0aW1lc3RhbXAiLCJvbmVycm9yIiwiY2xvc2UiLCJsb2dvdXQiLCJ1c2VybmFtZSIsImF1dGhrZXkiLCJyZXFCb2R5IiwicmVzIiwiYXhpb3MiLCJwb3N0Iiwic3RhdHVzIiwiYm9keSIsImluaXRFdmVudFNvdXJjZUNsaWVudCIsImVycm9yIiwic3RvcmFnZSIsImZv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
