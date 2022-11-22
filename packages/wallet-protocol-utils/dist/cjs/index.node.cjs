"use strict";Object.defineProperty(exports,"__esModule",{value:!0});var t=require("@i3m/wallet-protocol"),e=require("rxjs"),i=require("node:readline/promises"),s=require("crypto"),o=require("os"),r=require("fs/promises"),a=require("path");function n(t){if(t&&t.__esModule)return t;var e=Object.create(null);return t&&Object.keys(t).forEach((function(i){if("default"!==i){var s=Object.getOwnPropertyDescriptor(t,i);Object.defineProperty(e,i,s.get?s:{enumerable:!0,get:function(){return t[i]}})}})),e.default=t,Object.freeze(e)}var c=n(i),l=n(s);const h=async t=>{{const e=await Promise.resolve().then((function(){return d}));return await e.pinConsoleDialog(t?.consoleDialog)}},p=h;class u{constructor(t){this.fetch=async(...t)=>{if(await this.initialized,null==this.session)throw new Error("no session");return await this.session.send(...t)},this.protocol=t.protocol,this.$session=new e.BehaviorSubject(void 0),this.initialized=new Promise(((e,i)=>{this.init(t.storage).then((()=>{e(!0)})).catch((t=>{i(t)}))}))}async init(t,e){if(void 0===t){const t=(await Promise.resolve().then((function(){return f}))).SessionFileStorage;this.storage=new t(e?.fileStorage)}else this.storage=t}get hasSession(){return void 0!==this.session}async createIfNotExists(){if(await this.initialized,void 0!==this.session)return this.session;const t=await this.protocol.run();return await this.setSession(t),t}async removeSession(){await this.initialized,await this.setSession()}async setSession(t){if(await this.initialized,this.session=t,null==t)await this.storage.clear();else{const e=t.toJSON();await this.storage.setSessionData(JSON.stringify(e))}this.$session.next(t)}async loadSession(){let e;await this.initialized;try{const i=await this.storage.getSessionData();null!==i&&(e=await t.Session.fromJSON(this.protocol.transport,i))}catch(t){}await this.setSession(e)}}var d=Object.freeze({__proto__:null,pinConsoleDialog:async t=>{const e=t?.message??"Introduce the PIN:",i=c.createInterface({input:process.stdin,output:process.stdout}),s=await i.question(e);return console.log(s),i.close(),s}});var f=Object.freeze({__proto__:null,SessionFileStorage:class{constructor(t){if(!("undefined"!=typeof process&&null!=process.versions&&null!=process.versions.node))throw new Error("FileStore can only be instantiated from Node.js");this.filepath="string"==typeof t?.filepath&&""!==t.filepath?t.filepath:a.join(o.tmpdir(),"i3m-wallet-session"),this.password=t?.password,this.initialized=new Promise(((t,e)=>{this.init().then((()=>{t(!0)})).catch((t=>{e(t)}))}))}async init(){await r.mkdir(a.dirname(this.filepath),{recursive:!0})}kdf(t,e){return l.scryptSync(t,e,32)}async encryptJson(t){if(void 0===this.password)throw new Error("For the store to be encrypted you must provide a password");const e=JSON.stringify(t),i=l.randomBytes(16),s=l.randomBytes(64),o=this.kdf(this.password,s),r=l.createCipheriv("aes-256-gcm",o,i),a=Buffer.concat([r.update(e,"utf8"),r.final()]),n=r.getAuthTag();return Buffer.concat([s,i,n,a])}async decryptToJson(t){if(void 0===this.password)throw new Error("For the store to be encrypted you must provide a password");const e=Buffer.from(t),i=e.slice(0,64),s=e.slice(64,80),o=e.slice(80,96),r=e.slice(96),a=this.kdf(this.password,i),n=l.createDecipheriv("aes-256-gcm",a,s);n.setAuthTag(o);return JSON.parse(Buffer.concat([n.update(r),n.final()]).toString("utf8"))}async getSessionData(){let t;await this.initialized;const e=await r.readFile(this.filepath);if(t=void 0===this.password?e.toString("utf8"):await this.decryptToJson(e),""===t)throw new Error("invalid storage file or invalid format");return t}async setSessionData(t){await this.initialized,void 0===this.password?await r.writeFile(this.filepath,JSON.stringify(t),{encoding:"utf8"}):await r.writeFile(this.filepath,await this.encryptJson(t))}async clear(){await this.initialized,await r.rm(this.filepath,{force:!0})}}});exports.LocalSessionManager=class extends u{constructor(t,e={}){super({protocol:t,storageOptions:{localStorage:{key:e.localStorageKey}}}),this.protocol=t}},exports.SessionManager=u,exports.openModal=p,exports.pinDialog=h;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9waW4tZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL3Nlc3Npb24tbWFuYWdlci50cyIsIi4uLy4uL3NyYy90cy9waW4tZGlhbG9ncy9waW4tY29uc29sZS1kaWFsb2cudHMiLCIuLi8uLi9zcmMvdHMvc2Vzc2lvbi1zdG9yYWdlcy9zZXNzaW9uLWZpbGUtc3RvcmFnZS50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsicGluRGlhbG9nIiwiYXN5bmMiLCJvcHRzIiwicGluQ29uc29sZURpYWxvZyIsIlByb21pc2UiLCJjb25zb2xlRGlhbG9nIiwib3Blbk1vZGFsIiwiU2Vzc2lvbk1hbmFnZXIiLCJjb25zdHJ1Y3RvciIsIm9wdGlvbnMiLCJ0aGlzIiwiZmV0Y2giLCJhcmdzIiwiaW5pdGlhbGl6ZWQiLCJzZXNzaW9uIiwiRXJyb3IiLCJzZW5kIiwicHJvdG9jb2wiLCIkc2Vzc2lvbiIsIkJlaGF2aW9yU3ViamVjdCIsInVuZGVmaW5lZCIsInJlc29sdmUiLCJyZWplY3QiLCJpbml0Iiwic3RvcmFnZSIsInRoZW4iLCJjYXRjaCIsInJlYXNvbiIsInN0b3JhZ2VPcHRpb25zIiwiU2Vzc2lvbkZpbGVTdG9yYWdlIiwic2Vzc2lvbkZpbGVTdG9yYWdlIiwiZmlsZVN0b3JhZ2UiLCJoYXNTZXNzaW9uIiwicnVuIiwic2V0U2Vzc2lvbiIsImNsZWFyIiwic2Vzc2lvbkpzb24iLCJ0b0pTT04iLCJzZXRTZXNzaW9uRGF0YSIsIkpTT04iLCJzdHJpbmdpZnkiLCJuZXh0IiwiZ2V0U2Vzc2lvbkRhdGEiLCJTZXNzaW9uIiwiZnJvbUpTT04iLCJ0cmFuc3BvcnQiLCJlcnJvciIsInF1ZXJ5IiwibWVzc2FnZSIsInJsIiwicmVhZGxpbmUiLCJjcmVhdGVJbnRlcmZhY2UiLCJpbnB1dCIsInByb2Nlc3MiLCJzdGRpbiIsIm91dHB1dCIsInN0ZG91dCIsInBpbiIsInF1ZXN0aW9uIiwiY29uc29sZSIsImxvZyIsImNsb3NlIiwidmVyc2lvbnMiLCJub2RlIiwiZmlsZXBhdGgiLCJqb2luIiwidG1wZGlyIiwicGFzc3dvcmQiLCJta2RpciIsImRpcm5hbWUiLCJyZWN1cnNpdmUiLCJrZGYiLCJzYWx0IiwiY3J5cHRvIiwic2NyeXB0U3luYyIsImpzb24iLCJwbGFpbnRleHQiLCJpdiIsInJhbmRvbUJ5dGVzIiwia2V5IiwiY2lwaGVyIiwiY3JlYXRlQ2lwaGVyaXYiLCJlbmNyeXB0ZWQiLCJCdWZmZXIiLCJjb25jYXQiLCJ1cGRhdGUiLCJmaW5hbCIsInRhZyIsImdldEF1dGhUYWciLCJjcnlwdG9ncmFtIiwiYnVmIiwiZnJvbSIsInNsaWNlIiwiY2lwaGVydGV4dCIsImRlY2lwaGVyIiwiY3JlYXRlRGVjaXBoZXJpdiIsInNldEF1dGhUYWciLCJwYXJzZSIsInRvU3RyaW5nIiwiaXRlbSIsImZpbGVCdWYiLCJyZWFkRmlsZSIsImRlY3J5cHRUb0pzb24iLCJ3cml0ZUZpbGUiLCJlbmNvZGluZyIsImVuY3J5cHRKc29uIiwicm0iLCJmb3JjZSIsInN1cGVyIiwibG9jYWxTdG9yYWdlIiwibG9jYWxTdG9yYWdlS2V5Il0sIm1hcHBpbmdzIjoic2lCQU9hQSxFQUFZQyxNQUFPQyxJQUl2QixDQUNMLE1BQU1DLFFBQXlCQywrQ0FDL0IsYUFBYUQsRUFBaUJBLGlCQUFpQkQsR0FBTUcsY0FDdEQsR0FTVUMsRUFBWU4sUUNoQlpPLEVBT1hDLFlBQWFDLEdBNEJiQyxLQUFBQyxNQUE0QlYsU0FBVVcsS0FHcEMsU0FGTUYsS0FBS0csWUFFUyxNQUFoQkgsS0FBS0ksUUFDUCxNQUFNLElBQUlDLE1BQU0sY0FHbEIsYUFBYUwsS0FBS0ksUUFBUUUsUUFBUUosRUFBSyxFQWxDdkNGLEtBQUtPLFNBQVdSLEVBQVFRLFNBQ3hCUCxLQUFLUSxTQUFXLElBQUlDLEVBQWVBLHFCQUF5QkMsR0FDNURWLEtBQUtHLFlBQWMsSUFBSVQsU0FBUSxDQUFDaUIsRUFBU0MsS0FDdkNaLEtBQUthLEtBQUtkLEVBQVFlLFNB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
