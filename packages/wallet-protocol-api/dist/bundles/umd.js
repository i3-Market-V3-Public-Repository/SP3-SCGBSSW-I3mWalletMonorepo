!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((e="undefined"!=typeof globalThis?globalThis:e||self).walletProtocolApi={})}(this,(function(e){"use strict";const t={path:"identities",method:"GET"};e.WalletApi=class{constructor(e){this.session=e}async executeQuery(e,t,o){let n,s="";void 0!==t&&(s="?"+Object.keys(t).map((e=>`${encodeURIComponent(e)}=${encodeURIComponent(t[e])}`)).join("&")),void 0!==o&&(n=JSON.parse(o));const i=e.path+s,d=await this.session.send({url:i,init:{headers:e.headers,method:e.method,body:n}});return JSON.parse(d.body)}async getIdentites(e){return await this.executeQuery(t,e,void 0)}},Object.defineProperty(e,"__esModule",{value:!0})}));