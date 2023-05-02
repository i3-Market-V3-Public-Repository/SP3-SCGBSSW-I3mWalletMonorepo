import{Session as e}from"@i3m/wallet-protocol";import{BehaviorSubject as t}from"rxjs";const n=async e=>{{const t=await Promise.resolve().then((function(){return l}));return await t.pinHtmlFormDialog(e?.htmlFormDialog)}},s=n;class o{constructor(e){this.fetch=async(...e)=>{if(await this.initialized,null==this.session)throw new Error("no session");return await this.session.send(...e)},this.protocol=e.protocol,this.$session=new t(void 0),this.initialized=this.init()}async init(e,t){if(void 0===e){const e=(await Promise.resolve().then((function(){return r}))).SessionLocalStorage;this.storage=new e(t?.localStorage)}else this.storage=e}get hasSession(){return void 0!==this.session}async createIfNotExists(){if(await this.initialized,void 0!==this.session)return this.session;const e=await this.protocol.run();return await this.setSession(e),e}async removeSession(){await this.initialized,await this.setSession()}async setSession(e){if(await this.initialized,this.session=e,null==e)await this.storage.clear();else{const t=e.toJSON();await this.storage.setSessionData(t)}this.$session.next(e)}async loadSession(){let t;await this.initialized;try{const n=await this.storage.getSessionData();null!==n&&(t=await e.fromJSON(this.protocol.transport,n))}catch(e){}await this.setSession(t)}}class a extends o{constructor(e,t={}){super({protocol:e,storageOptions:{localStorage:{key:t.localStorageKey}}}),this.protocol=e}}const i={overlayClass:"wallet-protocol-overlay",modalClass:"wallet-modal",titleClass:"wallet-title",messageClass:"wallet-message",inputBoxClass:"wallet-input-box",inputClass:"wallet-input",buttonClass:"wallet-button"};var l=Object.freeze({__proto__:null,pinHtmlFormDialog:async(e=i)=>{const t=Object.assign({},e,i),n=document.createElement("div");document.body.appendChild(n),n.className=t.overlayClass;const s=document.createElement("style");n.appendChild(s),s.innerText=".__WALLET_PROTOCOL_OVERLAY__ {\n    position: absolute;\n    display: flex;\n    height: 100%;\n    width: 100%;\n    top: 0;\n    left: 0;\n    align-items: center;\n    justify-content: center;\n    background-color: #000000AA;\n    font-family: 'sans-serif';\n    color: #202531;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MODAL__ {\n    display: flex;\n    flex-direction: column;\n    align-items: center;\n    justify-content: center;\n    border: 2px solid #1A1E27;\n    border-radius: 5px;\n    padding: 10px 20px;\n    background-image: linear-gradient(to bottom left, white, #D2D6E1);\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_TITLE__ {\n    font-weight: bold;\n    padding: 5px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MESSAGE__ {\n    opacity: 0.5;\n    padding: 5px;\n    font-size: 15px\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT_BOX__ {\n    display: flex;\n    margin: 20px;\n    height: 32px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT__ {\n    border-radius: 3px;\n    border-top-right-radius: 0;\n    border-bottom-right-radius: 0;\n    outline: none;\n    padding: 5px;\n    font-family: monospace;\n    border: 2px solid #1A1E27;\n    border-right: none;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_BUTTON__ {\n    height: 100%;\n    padding: 5px;\n    border-radius: 3px;\n    border: 2px solid #1A1E27;\n    border-top-left-radius: 0;\n    border-bottom-left-radius: 0;\n    cursor: pointer;\n}\n".replace(/__WALLET_PROTOCOL_OVERLAY__/g,t.overlayClass).replace(/__WALLET_MODAL__/g,t.modalClass).replace(/__WALLET_TITLE__/g,t.titleClass).replace(/__WALLET_MESSAGE__/g,t.messageClass).replace(/__WALLET_INPUT_BOX__/g,t.inputBoxClass).replace(/__WALLET_INPUT__/g,t.inputClass).replace(/__WALLET_BUTTON__/g,t.buttonClass);const o=document.createElement("div");n.appendChild(o),o.className=t.modalClass;const a=document.createElement("span");o.appendChild(a),a.className=t.titleClass,a.innerText="Connecting to your wallet...";const l=document.createElement("span");o.appendChild(l),l.className=t.messageClass,l.innerText="Set up your wallet on pairing mode and put the PIN here";const r=document.createElement("div");o.appendChild(r),r.className=t.inputBoxClass;const c=document.createElement("input");r.appendChild(c),c.className=t.inputClass,c.autofocus=!0,c.setAttribute("placeholder","pin...");const _=document.createElement("button");return r.appendChild(_),_.className=t.buttonClass,_.innerText="Synchronize",await new Promise(((e,t)=>{const s=t=>{document.body.removeChild(n),e(t??"")};c.addEventListener("keypress",(e=>{"Enter"===e.key&&s(c.value)})),_.addEventListener("click",(()=>s(c.value))),n.addEventListener("click",(e=>{e.target===n&&s()}))}))}});var r=Object.freeze({__proto__:null,SessionLocalStorage:class{constructor(e){this.key="string"==typeof e?.key&&""!==e.key?e.key:"wallet-session"}async getSessionData(){const e=localStorage.getItem(this.key);if(null==e)throw new Error("no session data stored");return JSON.parse(e)}async setSessionData(e){localStorage.setItem(this.key,JSON.stringify(e))}async clear(){localStorage.removeItem(this.key)}}});export{a as LocalSessionManager,o as SessionManager,s as openModal,n as pinDialog};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5lc20uanMiLCJzb3VyY2VzIjpbIi4uL3NyYy90cy9waW4tZGlhbG9nLnRzIiwiLi4vc3JjL3RzL3Nlc3Npb24tbWFuYWdlci50cyIsIi4uL3NyYy90cy9waW4tZGlhbG9ncy9waW4taHRtbGZvcm0tZGlhbG9nLnRzIiwiLi4vc3JjL3RzL3Nlc3Npb24tc3RvcmFnZXMvc2Vzc2lvbi1sb2NhbHN0b3JhZ2UudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbInBpbkRpYWxvZyIsImFzeW5jIiwib3B0cyIsInBpbkh0bWxGb3JtRGlhbG9nIiwiUHJvbWlzZSIsImh0bWxGb3JtRGlhbG9nIiwib3Blbk1vZGFsIiwiU2Vzc2lvbk1hbmFnZXIiLCJjb25zdHJ1Y3RvciIsIm9wdGlvbnMiLCJ0aGlzIiwiZmV0Y2giLCJhcmdzIiwiaW5pdGlhbGl6ZWQiLCJzZXNzaW9uIiwiRXJyb3IiLCJzZW5kIiwicHJvdG9jb2wiLCIkc2Vzc2lvbiIsIkJlaGF2aW9yU3ViamVjdCIsInVuZGVmaW5lZCIsImluaXQiLCJzdG9yYWdlIiwic3RvcmFnZU9wdGlvbnMiLCJTZXNzaW9uTG9jYWxTdG9yYWdlIiwicmVzb2x2ZSIsInRoZW4iLCJzZXNzaW9uTG9jYWxzdG9yYWdlIiwibG9jYWxTdG9yYWdlIiwiaGFzU2Vzc2lvbiIsInJ1biIsInNldFNlc3Npb24iLCJjbGVhciIsInNlc3Npb25Kc29uIiwidG9KU09OIiwic2V0U2Vzc2lvbkRhdGEiLCJuZXh0IiwiZ2V0U2Vzc2lvbkRhdGEiLCJTZXNzaW9uIiwiZnJvbUpTT04iLCJ0cmFuc3BvcnQiLCJlcnJvciIsIkxvY2FsU2Vzc2lvbk1hbmFnZXIiLCJzdXBlciIsImtleSIsImxvY2FsU3RvcmFnZUtleSIsImRlZmF1bHRIdG1sT3B0aW9ucyIsIm92ZXJsYXlDbGFzcyIsIm1vZGFsQ2xhc3MiLCJ0aXRsZUNsYXNzIiwibWVzc2FnZUNsYXNzIiwiaW5wdXRCb3hDbGFzcyIsImlucHV0Q2xhc3MiLCJidXR0b25DbGFzcyIsIk9iamVjdCIsImFzc2lnbiIsIm92ZXJsYXkiLCJkb2N1bWVudCIsImNyZWF0ZUVsZW1lbnQiLCJib2R5IiwiYXBwZW5kQ2hpbGQiLCJjbGFzc05hbWUiLCJzdHlsZSIsImlubmVyVGV4dCIsInJlcGxhY2UiLCJtb2RhbCIsInRpdGxlIiwibWVzc2FnZSIsImlucHV0Qm94IiwicGluSW5wdXQiLCJhdXRvZm9jdXMiLCJzZXRBdHRyaWJ1dGUiLCJwYWlyQnV0dG9uIiwicmVqZWN0IiwiY2xvc2UiLCJ2YWx1ZSIsInJlbW92ZUNoaWxkIiwiYWRkRXZlbnRMaXN0ZW5lciIsImV2IiwidGFyZ2V0IiwiaXRlbSIsImdldEl0ZW0iLCJKU09OIiwicGFyc2UiLCJqc29uIiwic2V0SXRlbSIsInN0cmluZ2lmeSIsInJlbW92ZUl0ZW0iXSwibWFwcGluZ3MiOiI0RkFPYUEsRUFBWUMsTUFBT0MsSUFDZCxDQUNkLE1BQU1DLFFBQTBCQywrQ0FDaEMsYUFBYUQsRUFBa0JBLGtCQUFrQkQsR0FBTUcsZUFJeEQsR0FTVUMsRUFBWU4sUUNoQlpPLEVBT1hDLFlBQWFDLEdBd0JiQyxLQUFBQyxNQUE0QlYsU0FBVVcsS0FHcEMsU0FGTUYsS0FBS0csWUFFUyxNQUFoQkgsS0FBS0ksUUFDUCxNQUFNLElBQUlDLE1BQU0sY0FHbEIsYUFBYUwsS0FBS0ksUUFBUUUsUUFBUUosRUFBSyxFQTlCdkNGLEtBQUtPLFNBQVdSLEVBQVFRLFNBQ3hCUCxLQUFLUSxTQUFXLElBQUlDLE9BQXdDQyxHQUM1RFYsS0FBS0csWUFBY0gsS0FBS1csTUFDekIsQ0FFT3BCLFdBQVlxQixFQUEwQkMsR0FDNUMsUUFBZ0JILElBQVpFLEVBQ2MsQ0FDZCxNQUFNRSxTQUE2QnBCLFFBQWlEcUIsVUFBQUMsTUFBQSxXQUFBLE9BQUFDLENBQUEsS0FBRUgsb0JBQ3RGZCxLQUFLWSxRQUFVLElBQUlFLEVBQW9CRCxHQUFnQkssYUFJeEQsTUFFRGxCLEtBQUtZLFFBQVVBLENBRWxCLENBRUdPLGlCQUNGLFlBQXdCVCxJQUFqQlYsS0FBS0ksT0FDYixDQVlEYiwwQkFHRSxTQUZNUyxLQUFLRyxpQkFFVU8sSUFBakJWLEtBQUtJLFFBQ1AsT0FBT0osS0FBS0ksUUFFZCxNQUFNQSxRQUFnQkosS0FBS08sU0FBU2EsTUFHcEMsYUFGTXBCLEtBQUtxQixXQUFXakIsR0FFZkEsQ0FDUixDQUVEYiw0QkFDUVMsS0FBS0csa0JBRUxILEtBQUtxQixZQUNaLENBRUQ5QixpQkFBa0JhLEdBSWhCLFNBSE1KLEtBQUtHLFlBRVhILEtBQUtJLFFBQVVBLEVBQ1hBLGNBQ0lKLEtBQUtZLFFBQVFVLFlBQ2QsQ0FDTCxNQUFNQyxFQUFjbkIsRUFBUW9CLGVBQ3RCeEIsS0FBS1ksUUFBUWEsZUFBZUYsRUFDbkMsQ0FDRHZCLEtBQUtRLFNBQVNrQixLQUFLdEIsRUFDcEIsQ0FFRGIsb0JBR0UsSUFBSWEsUUFGRUosS0FBS0csWUFHWCxJQUNFLE1BQU1vQixRQUFvQnZCLEtBQUtZLFFBQVFlLGlCQUNuQixPQUFoQkosSUFDRm5CLFFBQWdCd0IsRUFBUUMsU0FBUzdCLEtBQUtPLFNBQVN1QixVQUFXUCxHQUU3RCxDQUFDLE1BQU9RLEdBQVMsT0FFWi9CLEtBQUtxQixXQUFXakIsRUFDdkIsRUFRRyxNQUFPNEIsVUFBNkRuQyxFQUN4RUMsWUFBdUJTLEVBQTZCUixFQUEwQyxJQUM1RmtDLE1BQU0sQ0FBRTFCLFdBQVVNLGVBQWdCLENBQUVLLGFBQWMsQ0FBRWdCLElBQUtuQyxFQUFRb0Msb0JBRDVDbkMsS0FBUU8sU0FBUkEsQ0FFdEIsRUNqR0gsTUFBTTZCLEVBQXlELENBQzdEQyxhQUFjLDBCQUNkQyxXQUFZLGVBQ1pDLFdBQVksZUFDWkMsYUFBYyxpQkFDZEMsY0FBZSxtQkFDZkMsV0FBWSxlQUNaQyxZQUFhLHVFQVFrQnBELE1BQU9DLEVBQWlDNEMsS0FDdkUsTUFBTXJDLEVBQThDNkMsT0FBT0MsT0FBTyxDQUFBLEVBQUlyRCxFQUFNNEMsR0FFdEVVLEVBQVVDLFNBQVNDLGNBQWMsT0FDdkNELFNBQVNFLEtBQUtDLFlBQVlKLEdBQzFCQSxFQUFRSyxVQUFZcEQsRUFBUXNDLGFBRTVCLE1BQU1lLEVBQVFMLFNBQVNDLGNBQWMsU0FDckNGLEVBQVFJLFlBQVlFLEdBQ3BCQSxFQUFNQyxtN0NBQ0hDLFFBQVEsK0JBQWdDdkQsRUFBUXNDLGNBQ2hEaUIsUUFBUSxvQkFBcUJ2RCxFQUFRdUMsWUFDckNnQixRQUFRLG9CQUFxQnZELEVBQVF3QyxZQUNyQ2UsUUFBUSxzQkFBdUJ2RCxFQUFReUMsY0FDdkNjLFFBQVEsd0JBQXlCdkQsRUFBUTBDLGVBQ3pDYSxRQUFRLG9CQUFxQnZELEVBQVEyQyxZQUNyQ1ksUUFBUSxxQkFBc0J2RCxFQUFRNEMsYUFFekMsTUFBTVksRUFBUVIsU0FBU0MsY0FBYyxPQUNyQ0YsRUFBUUksWUFBWUssR0FDcEJBLEVBQU1KLFVBQVlwRCxFQUFRdUMsV0FFMUIsTUFBTWtCLEVBQVFULFNBQVNDLGNBQWMsUUFDckNPLEVBQU1MLFlBQVlNLEdBQ2xCQSxFQUFNTCxVQUFZcEQsRUFBUXdDLFdBQzFCaUIsRUFBTUgsVUFBWSwrQkFFbEIsTUFBTUksRUFBVVYsU0FBU0MsY0FBYyxRQUN2Q08sRUFBTUwsWUFBWU8sR0FDbEJBLEVBQVFOLFVBQVlwRCxFQUFReUMsYUFDNUJpQixFQUFRSixVQUFZLDBEQUVwQixNQUFNSyxFQUFXWCxTQUFTQyxjQUFjLE9BQ3hDTyxFQUFNTCxZQUFZUSxHQUNsQkEsRUFBU1AsVUFBWXBELEVBQVEwQyxjQUU3QixNQUFNa0IsRUFBV1osU0FBU0MsY0FBYyxTQUN4Q1UsRUFBU1IsWUFBWVMsR0FDckJBLEVBQVNSLFVBQVlwRCxFQUFRMkMsV0FDN0JpQixFQUFTQyxXQUFZLEVBQ3JCRCxFQUFTRSxhQUFhLGNBQWUsVUFFckMsTUFBTUMsRUFBYWYsU0FBU0MsY0FBYyxVQUsxQyxPQUpBVSxFQUFTUixZQUFZWSxHQUNyQkEsRUFBV1gsVUFBWXBELEVBQVE0QyxZQUMvQm1CLEVBQVdULFVBQVksb0JBRVYsSUFBSTNELFNBQVEsQ0FBQ3FCLEVBQVNnRCxLQUNqQyxNQUFNQyxFQUFTQyxJQUNibEIsU0FBU0UsS0FBS2lCLFlBQVlwQixHQUMxQi9CLEVBQVFrRCxHQUFTLEdBQUcsRUFFdEJOLEVBQVNRLGlCQUFpQixZQUFhQyxJQUN0QixVQUFYQSxFQUFHbEMsS0FDTDhCLEVBQU1MLEVBQVNNLE1BQ2hCLElBRUhILEVBQVdLLGlCQUFpQixTQUFTLElBQU1ILEVBQU1MLEVBQVNNLFNBQzFEbkIsRUFBUXFCLGlCQUFpQixTQUFVQyxJQUM3QkEsRUFBR0MsU0FBV3ZCLEdBQ2hCa0IsR0FDRCxHQUNELEdBQ0Ysa0VDL0VGbEUsWUFBYUMsR0FDWEMsS0FBS2tDLElBQStCLGlCQUFqQm5DLEdBQVNtQyxLQUFvQyxLQUFoQm5DLEVBQVFtQyxJQUFjbkMsRUFBUW1DLElBQU0sZ0JBQ3JGLENBRUQzQyx1QkFDRSxNQUFNK0UsRUFBT3BELGFBQWFxRCxRQUFRdkUsS0FBS2tDLEtBQ3ZDLEdBQVksTUFBUm9DLEVBQ0YsTUFBTSxJQUFJakUsTUFBTSwwQkFFbEIsT0FBT21FLEtBQUtDLE1BQU1ILEVBQ25CLENBRUQvRSxxQkFBc0JtRixHQUNwQnhELGFBQWF5RCxRQUFRM0UsS0FBS2tDLElBQUtzQyxLQUFLSSxVQUFVRixHQUMvQyxDQUVEbkYsY0FDRTJCLGFBQWEyRCxXQUFXN0UsS0FBS2tDLElBQzlCIn0=
