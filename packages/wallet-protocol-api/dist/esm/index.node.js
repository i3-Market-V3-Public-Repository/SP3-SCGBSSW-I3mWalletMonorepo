class t{constructor(t){this.api=t}async list(t){return await this.api.executeQuery({path:"/identities",method:"GET"},void 0,t,void 0)}async select(t){return await this.api.executeQuery({path:"/identities/select",method:"GET"},void 0,t,void 0)}async create(t){return await this.api.executeQuery({path:"/identities",method:"POST",headers:{"Content-Type":"application/json"}},void 0,void 0,t)}async sign(t,e){return await this.api.executeQuery({path:"/identities/{did}/sign",method:"POST",headers:{"Content-Type":"application/json"}},t,void 0,e)}async info(t){return await this.api.executeQuery({path:"/identities/{did}/info",method:"GET"},t,void 0,void 0)}async deployTransaction(t,e){return await this.api.executeQuery({path:"/identities/{did}/deploy-tx",method:"POST"},t,void 0,e)}}class e{constructor(t){this.api=t}async list(){return await this.api.executeQuery({path:"/resources",method:"GET"},void 0,void 0,void 0)}async create(t){return await this.api.executeQuery({path:"/resources",method:"POST",headers:{"Content-Type":"application/json"}},void 0,void 0,t)}}class i{constructor(t){this.api=t}async disclose(t){return await this.api.executeQuery({path:"/disclosure/{jwt}",method:"GET"},t,void 0,void 0)}}class s{constructor(t){this.api=t}async deploy(t){return await this.api.executeQuery({path:"/transaction/deploy",method:"POST"},void 0,void 0,t)}}class a{constructor(t){this.api=t}async verify(t){return await this.api.executeQuery({path:"/did-jwt/verify",method:"POST"},void 0,void 0,t)}}class o{constructor(t){this.api=t}async get(){return await this.api.executeQuery({path:"/providerinfo",method:"GET"},void 0,void 0,void 0)}}class n{constructor(n){this.session=n,this.identities=new t(this),this.transaction=new s(this),this.resources=new e(this),this.disclosure=new i(this),this.didJwt=new a(this),this.providerinfo=new o(this)}async executeQuery(t,e,i,s){let a,o="";void 0!==i&&(o="?"+Object.keys(i).map((t=>`${encodeURIComponent(t)}=${encodeURIComponent(i[t])}`)).join("&")),void 0!==s&&(a=JSON.stringify(s));let n=t.path+o;if(void 0!==e)for(const[t,i]of Object.entries(e))n=n.replace(`{${t}}`,i);const r=await this.session.send({url:n,init:{headers:t.headers,method:t.method,body:a}});return JSON.parse(r.body)}}export{n as WalletApi};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL21vZGVscy9pZGVudGl0aWVzLnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy9yZXNvdXJjZXMudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL2Rpc2Nsb3N1cmUudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL3RyYW5zYWN0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy9kaWQtand0LnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy9wcm92aWRlcmluZm8udHMiLCIuLi8uLi9zcmMvdHMvYXBpLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJJZGVudGl0aWVzQXBpIiwiY29uc3RydWN0b3IiLCJhcGkiLCJ0aGlzIiwiYXN5bmMiLCJxdWVyeVBhcmFtcyIsImV4ZWN1dGVRdWVyeSIsInBhdGgiLCJtZXRob2QiLCJ1bmRlZmluZWQiLCJib2R5IiwiaGVhZGVycyIsInBhdGhQYXJhbXMiLCJSZXNvdXJjZXNBcGkiLCJEaXNjbG9zdXJlQXBpIiwiVHJhbnNhY3Rpb25BcGkiLCJEaWRKd3RBcGkiLCJQcm92aWRlckluZm9BcGkiLCJXYWxsZXRBcGkiLCJzZXNzaW9uIiwiaWRlbnRpdGllcyIsInRyYW5zYWN0aW9uIiwicmVzb3VyY2VzIiwiZGlzY2xvc3VyZSIsImRpZEp3dCIsInByb3ZpZGVyaW5mbyIsImJvZHlPYmplY3QiLCJxdWVyeVBhcmFtc1N0cmluZyIsIk9iamVjdCIsImtleXMiLCJtYXAiLCJrZXkiLCJlbmNvZGVVUklDb21wb25lbnQiLCJqb2luIiwiSlNPTiIsInN0cmluZ2lmeSIsInVybCIsInZhbHVlIiwiZW50cmllcyIsInJlcGxhY2UiLCJyZXNwIiwic2VuZCIsImluaXQiLCJwYXJzZSJdLCJtYXBwaW5ncyI6Ik1BSWFBLEVBQ1hDLFlBQXVCQyxHQUFBQyxTQUFBRCxFQUV2QkUsV0FBWUMsR0FDVixhQUFhRixLQUFLRCxJQUFJSSxhQUFhLENBQ2pDQyxLQUFNLGNB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
