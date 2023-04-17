"use strict";var e=require("@i3m/base-wallet"),r=require("os"),t=require("path"),i=require("@i3m/bok-wallet"),a=require("fs");function o(e){return e&&e.__esModule?e:{default:e}}var l=o(i);exports.serverWalletBuilder=async function(i){let o;if(void 0===i?.filepath){const e=t.join(r.homedir(),".server-wallet");try{a.mkdirSync(e)}catch(e){}o=t.join(e,"store")}else o=i.filepath;if(!0===i?.reset)try{a.rmSync(o)}catch(e){}const s=new e.NullDialog,n=new e.FileStore(o,i?.password),u=new e.ConsoleToast;return await l.default({dialog:s,store:n,toast:u,provider:i?.provider,providersData:i?.providerData})};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uL3NyYy90cy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiYXN5bmMiLCJvcHRpb25zIiwiZmlsZXBhdGgiLCJ1bmRlZmluZWQiLCJmaWxlZGlyIiwiam9pbiIsImhvbWVkaXIiLCJta2RpclN5bmMiLCJlcnJvciIsInJlc2V0Iiwicm1TeW5jIiwiZGlhbG9nIiwiTnVsbERpYWxvZyIsInN0b3JlIiwiRmlsZVN0b3JlIiwicGFzc3dvcmQiLCJ0b2FzdCIsIkNvbnNvbGVUb2FzdCIsIndhbGxldEJ1aWxkZXIiLCJwcm92aWRlciIsInByb3ZpZGVyc0RhdGEiLCJwcm92aWRlckRhdGEiXSwibWFwcGluZ3MiOiJ3TkFxQk9BLGVBQW9DQyxHQUN6QyxJQUFJQyxFQUNKLFFBQTBCQyxJQUF0QkYsR0FBU0MsU0FBd0IsQ0FDbkMsTUFBTUUsRUFBVUMsRUFBSUEsS0FBQ0MsWUFBVyxrQkFDaEMsSUFDRUMsRUFBU0EsVUFBQ0gsRUFDWCxDQUFDLE1BQU9JLEdBQVUsQ0FDbkJOLEVBQVdHLEVBQUlBLEtBQUNELEVBQVMsUUFDMUIsTUFDQ0YsRUFBV0QsRUFBUUMsU0FFckIsSUFBdUIsSUFBbkJELEdBQVNRLE1BQ1gsSUFDRUMsRUFBTUEsT0FBQ1IsRUFDUixDQUFDLE1BQU9NLEdBQVUsQ0FFckIsTUFBTUcsRUFBUyxJQUFJQyxFQUFBQSxXQUNiQyxFQUFRLElBQUlDLEVBQVNBLFVBQWlCWixFQUFVRCxHQUFTYyxVQUN6REMsRUFBUSxJQUFJQyxFQUFBQSxhQUNsQixhQUFjQyxFQUFBQSxRQUFjLENBQzFCUCxTQUNBRSxRQUNBRyxRQUNBRyxTQUFVbEIsR0FBU2tCLFNBQ25CQyxjQUFlbkIsR0FBU29CLGNBRTVCIn0=