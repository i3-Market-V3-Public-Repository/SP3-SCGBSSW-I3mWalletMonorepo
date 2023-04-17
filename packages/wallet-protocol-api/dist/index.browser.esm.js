class e extends Error{constructor(e,t,o){super(e),this.code=t,this.body=o}}class t{constructor(e){this.api=e}async list(e){const t=await this.api.executeQuery({path:"/identities",method:"GET"},void 0,e,void 0);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}async select(e){const t=await this.api.executeQuery({path:"/identities/select",method:"GET"},void 0,e,void 0);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}async create(e){const t=await this.api.executeQuery({path:"/identities",method:"POST",headers:{"Content-Type":"application/json"}},void 0,void 0,e);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}async sign(e,t){const o=await this.api.executeQuery({path:"/identities/{did}/sign",method:"POST",headers:{"Content-Type":"application/json"}},e,void 0,t);if(void 0!==o.code)throw new Error(`${o.code}: ${o.message}`);return o}async info(e){const t=await this.api.executeQuery({path:"/identities/{did}/info",method:"GET"},e,void 0,void 0);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}async deployTransaction(e,t){const o=await this.api.executeQuery({path:"/identities/{did}/deploy-tx",method:"POST"},e,void 0,t);if(void 0!==o.code)throw new Error(`${o.code}: ${o.message}`);return o}}class o{constructor(e){this.api=e}async list(e){const t=await this.api.executeQuery({path:"/resources",method:"GET"},void 0,e,void 0);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}async create(e){const t=await this.api.executeQuery({path:"/resources",method:"POST",headers:{"Content-Type":"application/json"}},void 0,void 0,e);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}}class i{constructor(e){this.api=e}async disclose(e){const t=await this.api.executeQuery({path:"/disclosure/{jwt}",method:"GET"},e,void 0,void 0);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}}class s{constructor(e){this.api=e}async deploy(e){const t=await this.api.executeQuery({path:"/transaction/deploy",method:"POST"},void 0,void 0,e);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}}class r{constructor(e){this.api=e}async verify(e){const t=await this.api.executeQuery({path:"/did-jwt/verify",method:"POST",headers:{"Content-Type":"application/json"}},void 0,void 0,e);if(void 0!==t.code)throw new Error(`${t.code}: ${t.message}`);return t}}class n{constructor(e){this.api=e}async get(){const e=await this.api.executeQuery({path:"/providerinfo",method:"GET"},void 0,void 0,void 0);if(void 0!==e.code)throw new Error(`${e.code}: ${e.message}`);return e}}class a{constructor(e){this.session=e,this.identities=new t(this),this.transaction=new s(this),this.resources=new o(this),this.disclosure=new i(this),this.didJwt=new r(this),this.providerinfo=new n(this)}async executeQuery(t,o,i,s){let r,n="";void 0!==i&&(n="?"+Object.keys(i).map((e=>`${encodeURIComponent(e)}=${encodeURIComponent(i[e])}`)).join("&")),void 0!==s&&(r=JSON.stringify(s));let a=t.path+n;if(void 0!==o)for(const[e,t]of Object.entries(o))a=a.replace(`{${e}}`,t);const d=await this.session.send({url:a,init:{headers:t.headers,method:t.method,body:r}}),c=JSON.parse(d.body);if(d.status>=300||d.status<200)throw new e(c.reason??"Unknown reason",d.status,c);return c}}export{a as WalletApi,e as WalletApiError};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5lc20uanMiLCJzb3VyY2VzIjpbIi4uL3NyYy90cy9lcnJvci50cyIsIi4uL3NyYy90cy9tb2RlbHMvaWRlbnRpdGllcy50cyIsIi4uL3NyYy90cy9tb2RlbHMvcmVzb3VyY2VzLnRzIiwiLi4vc3JjL3RzL21vZGVscy9kaXNjbG9zdXJlLnRzIiwiLi4vc3JjL3RzL21vZGVscy90cmFuc2FjdGlvbi50cyIsIi4uL3NyYy90cy9tb2RlbHMvZGlkLWp3dC50cyIsIi4uL3NyYy90cy9tb2RlbHMvcHJvdmlkZXJpbmZvLnRzIiwiLi4vc3JjL3RzL2FwaS50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiV2FsbGV0QXBpRXJyb3IiLCJFcnJvciIsImNvbnN0cnVjdG9yIiwibWVzc2FnZSIsImNvZGUiLCJib2R5Iiwic3VwZXIiLCJ0aGlzIiwiSWRlbnRpdGllc0FwaSIsImFwaSIsImFzeW5jIiwicXVlcnlQYXJhbXMiLCJyZXNwb25zZSIsImV4ZWN1dGVRdWVyeSIsInBhdGgiLCJtZXRob2QiLCJ1bmRlZmluZWQiLCJoZWFkZXJzIiwicGF0aFBhcmFtcyIsIlJlc291cmNlc0FwaSIsIm9wdGlvbnMiLCJEaXNjbG9zdXJlQXBpIiwiVHJhbnNhY3Rpb25BcGkiLCJEaWRKd3RBcGkiLCJQcm92aWRlckluZm9BcGkiLCJXYWxsZXRBcGkiLCJzZXNzaW9uIiwiaWRlbnRpdGllcyIsInRyYW5zYWN0aW9uIiwicmVzb3VyY2VzIiwiZGlzY2xvc3VyZSIsImRpZEp3dCIsInByb3ZpZGVyaW5mbyIsImJvZHlPYmplY3QiLCJxdWVyeVBhcmFtc1N0cmluZyIsIk9iamVjdCIsImtleXMiLCJtYXAiLCJrZXkiLCJlbmNvZGVVUklDb21wb25lbnQiLCJqb2luIiwiSlNPTiIsInN0cmluZ2lmeSIsInVybCIsInZhbHVlIiwiZW50cmllcyIsInJlcGxhY2UiLCJyZXNwIiwic2VuZCIsImluaXQiLCJyZXNwQm9keSIsInBhcnNlIiwic3RhdHVzIiwi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
