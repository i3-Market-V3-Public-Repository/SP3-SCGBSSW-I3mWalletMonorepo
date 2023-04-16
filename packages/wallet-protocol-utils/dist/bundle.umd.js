!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?e(exports):"function"==typeof define&&define.amd?define(["exports"],e):e((t="undefined"!=typeof globalThis?globalThis:t||self).walletProtocolUtils={})}(this,(function(t){"use strict";const e=async t=>{{const e=await Promise.resolve().then((function(){return nt}));return await e.pinHtmlFormDialog(t?.htmlFormDialog)}},r=e;const n={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function o(...t){const e=t.reduce(((t,e)=>t+e.length),0);if(0===t.length)throw new RangeError("Cannot concat no arrays");const r=new Uint8Array(e);let n=0;for(const e of t)r.set(e,n),n+=e.length;return r}function i(t,e){for(let r=0;r<t.length;r++)t[r]^=e[r]}function s(t){return null!=t&&"object"==typeof t&&!Array.isArray(t)}function a(t){return s(t)||Array.isArray(t)?Array.isArray(t)?t.map((t=>Array.isArray(t)||s(t)?a(t):t)):Object.keys(t).sort().map((e=>[e,a(t[e])])):t}function c(t){return JSON.stringify(a(t))}function l(t,e="SHA-256"){const r=["SHA-1","SHA-256","SHA-384","SHA-512"];if(!r.includes(e))throw RangeError(`Valid hash algorithm values are any of ${JSON.stringify(r)}`);return async function(t,e){const r=(new TextEncoder).encode(c(t)).buffer;let n="";{const t=await crypto.subtle.digest(e,r),o="0123456789abcdef";new Uint8Array(t).forEach((t=>{n+=o[t>>4]+o[15&t]}))}return n}(t,e)}Object.freeze({__proto__:null,COMMITMENT_LENGTH:256,DEFAULT_RANDOM_LENGTH:36,DEFAULT_TIMEOUT:3e4,INITIAL_PORT:29170,NONCE_LENGTH:128,PORT_LENGTH:12,PORT_SPACE:4096}),Object.freeze({__proto__:null,RPC_URL_PATH:".well-known/wallet-protocol"});class u{async randomFill(t,e,r){throw new Error("not implemented")}async randomFillBits(t,e,r){const n=Math.ceil(r/8),o=new Uint8Array(n);await this.randomFill(o,0,n),m.insertBits(o,t,0,e,r)}}class p{constructor(t,e){this.algorithm=t,this.key=e}async encrypt(t){throw new Error("not implemented")}async decrypt(t){throw new Error("not implemented")}}const h=new class extends u{async randomFill(t,e,r){const n=new Uint8Array(r);crypto.getRandomValues(n);for(let o=0;o<r;o++)t[e+o]=n[o]}},f={"aes-256-gcm":{name:"AES-GCM",tagLength:128}};class d extends p{async encrypt(t){const e=new Uint8Array(12);await h.randomFill(e,0,e.length);const r=f[this.algorithm],n=await crypto.subtle.importKey("raw",this.key,r,!1,["encrypt"]),o=await crypto.subtle.encrypt({...r,iv:e},n,t),i=[];return i.push(e),i.push(new Uint8Array(o)),m.join(...i)}async decrypt(t){const e=[];"aes-256-gcm"===this.algorithm&&(e[0]=12),e[1]=t.length-e[0];const[r,n]=m.split(t,...e),o=f[this.algorithm],i=await crypto.subtle.importKey("raw",this.key,o,!1,["decrypt"]),s=await crypto.subtle.decrypt({...o,iv:r},i,n);return new Uint8Array(s)}}const y=t=>{const e=t.match(/.{1,2}/g);if(null===e)throw new Error(`not a hex: ${t}`);return new Uint8Array(e.map((t=>parseInt(t,16))))},_=t=>t.reduce(((t,e)=>t+e.toString(16).padStart(2,"0")),""),b=t=>function(t,e=!1,r=!0){let n="";return n=(t=>{const e=[];for(let r=0;r<t.length;r+=32768)e.push(String.fromCharCode.apply(null,t.subarray(r,r+32768)));return btoa(e.join(""))})("string"==typeof t?(new TextEncoder).encode(t):new Uint8Array(t)),e&&(n=function(t){return t.replace(/\+/g,"-").replace(/\//g,"_")}(n)),r||(n=n.replace(/=/g,"")),n}(t,!0,!1),w=t=>function(t,e=!1){{let r=!1;if(/^[0-9a-zA-Z_-]+={0,2}$/.test(t))r=!0;else if(!/^[0-9a-zA-Z+/]*={0,2}$/.test(t))throw new Error("Not a valid base64 input");r&&(t=t.replace(/-/g,"+").replace(/_/g,"/").replace(/=/g,""));const n=new Uint8Array(atob(t).split("").map((t=>t.charCodeAt(0))));return e?(new TextDecoder).decode(n):n}}(t,!1),m={join:(...t)=>{const e=t.reduce(((t,e)=>t+e.length),0),r=new Uint8Array(e);let n=0;for(const e of t)r.set(e,n),n+=e.length;return r},split:(t,...e)=>{const r=[];let n=0;for(const o of e)r.push(t.slice(n,n+o)),n+=o;return r},insertBytes:(t,e,r,n,o)=>{for(let i=0;i<o;i++)e[i+n]=t[i+r]},insertBits:(t,e,r,n,o)=>{let i=Math.floor(r/8),s=r%8,a=Math.floor(n/8),c=n%8,l=t[i]??0;const u=c-s;for(let r=0;r<o;r++){let r;r=u>=0?(l&128>>s)<<u:l&128>>s;const n=e[a]&~(128>>c)|r;e[a]=n,s++,c++,s>=8&&(i++,s=0,l=t[i]??0),c>=8&&(a++,c=0)}},extractBits:(t,e,r)=>{const n=Math.ceil(r/8),o=new Uint8Array(n);return m.insertBits(t,o,e,0,r),o}},v=async(t,e,r)=>{const s=new Uint8Array(16),a=new Uint8Array(96),c=y(t),l=y(e);m.insertBytes(r,a,0,0,32),m.insertBytes(c,a,0,32,32),m.insertBytes(l,a,0,64,32);const u=await function(t,e,r,s,a="SHA-256"){return new Promise(((c,l)=>{a in n||l(new RangeError(`Valid hash algorithm values are any of ${Object.keys(n).toString()}`)),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)||l(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof e?e=(new TextEncoder).encode(e):e instanceof ArrayBuffer?e=new Uint8Array(e):ArrayBuffer.isView(e)?e=new Uint8Array(e.buffer,e.byteOffset,e.byteLength):l(RangeError("S should be string, ArrayBuffer, TypedArray, DataView")),crypto.subtle.importKey("raw",t,"PBKDF2",!1,["deriveBits"]).then((u=>{const p={name:"PBKDF2",hash:a,salt:e,iterations:r};crypto.subtle.deriveBits(p,u,8*s).then((t=>c(t)),(u=>{(async function(t,e,r,s,a){if(!(a in n))throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(n).toString()}`);if(!Number.isInteger(r)||r<=0)throw new RangeError("c must be a positive integer");const c=n[a].outputLength;if(!Number.isInteger(s)||s<=0||s>=(2**32-1)*c)throw new RangeError("dkLen must be a positive integer < (2 ** 32 - 1) * hLen");const l=Math.ceil(s/c),u=s-(l-1)*c,p=new Array(l);0===t.byteLength&&(t=new Uint8Array(n[a].blockSize));const h=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:{name:a}},!0,["sign"]),f=async function(t,e){const r=await crypto.subtle.sign("HMAC",t,e);return new Uint8Array(r)};for(let t=0;t<l;t++)p[t]=await d(h,e,r,t+1);async function d(t,e,r,n){const s=await f(t,o(e,function(t){const e=new ArrayBuffer(4);return new DataView(e).setUint32(0,t,!1),new Uint8Array(e)}(n)));let a=s;for(let e=1;e<r;e++)a=await f(t,a),i(s,a);return s}return p[l-1]=p[l-1].slice(0,u),o(...p).buffer})(t,e,r,s,a).then((t=>c(t)),(t=>l(t)))}))}),(t=>l(t)))}))}(a,s,1,32);return new Uint8Array(u)};class g{constructor(t,e,r,n,o,i,s,a){this.port=t,this.from=e,this.to=r,this.na=n,this.nb=o,this.secret=i,this.cipher=new d("aes-256-gcm",s),this.decipher=new d("aes-256-gcm",a)}async encrypt(t){return await this.cipher.encrypt(t)}async decrypt(t){return await this.decipher.decrypt(t)}toJSON(){return{from:this.from,to:this.to,port:this.port,na:b(this.na),nb:b(this.nb),secret:b(this.secret)}}async fromHash(){return await l(this.from)}async toHash(){return await l(this.to)}static async fromSecret(t,e,r,n,o,i){const s=await l(e),a=await l(r),c=await v(s,a,i),u=await v(a,s,i);return new g(t,e,r,n,o,i,c,u)}static async fromJSON(t){const e=w(t.na),r=w(t.nb),n=w(t.secret);return await this.fromSecret(t.port,t.from,t.to,e,r,n)}}class A{constructor(t,e,r){this.transport=t,this.masterKey=e,this.code=r}async send(t){return await this.transport.send(this.masterKey,this.code,t)}toJSON(){return{masterKey:this.masterKey.toJSON(),code:_(this.code)}}static async fromJSON(t,e){const r=await g.fromJSON(e.masterKey),n=y(e.code);let o;if("object"==typeof t)o=t;else{if(!(t instanceof Function))throw new Error("First param must be transport or constructor of transport");o=new t}return new A(o,r,n)}}var E=function(t,e){return E=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(t,e){t.__proto__=e}||function(t,e){for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&(t[r]=e[r])},E(t,e)};function S(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Class extends value "+String(e)+" is not a constructor or null");function r(){this.constructor=t}E(t,e),t.prototype=null===e?Object.create(e):(r.prototype=e.prototype,new r)}function O(t){var e="function"==typeof Symbol&&Symbol.iterator,r=e&&t[e],n=0;if(r)return r.call(t);if(t&&"number"==typeof t.length)return{next:function(){return t&&n>=t.length&&(t=void 0),{value:t&&t[n++],done:!t}}};throw new TypeError(e?"Object is not iterable.":"Symbol.iterator is not defined.")}function L(t,e){var r="function"==typeof Symbol&&t[Symbol.iterator];if(!r)return t;var n,o,i=r.call(t),s=[];try{for(;(void 0===e||e-- >0)&&!(n=i.next()).done;)s.push(n.value)}catch(t){o={error:t}}finally{try{n&&!n.done&&(r=i.return)&&r.call(i)}finally{if(o)throw o.error}}return s}function T(t,e,r){if(r||2===arguments.length)for(var n,o=0,i=e.length;o<i;o++)!n&&o in e||(n||(n=Array.prototype.slice.call(e,0,o)),n[o]=e[o]);return t.concat(n||Array.prototype.slice.call(e))}function x(t){return"function"==typeof t}function C(t){var e=t((function(t){Error.call(t),t.stack=(new Error).stack}));return e.prototype=Object.create(Error.prototype),e.prototype.constructor=e,e}var P=C((function(t){return function(e){t(this),this.message=e?e.length+" errors occurred during unsubscription:\n"+e.map((function(t,e){return e+1+") "+t.toString()})).join("\n  "):"",this.name="UnsubscriptionError",this.errors=e}}));function N(t,e){if(t){var r=t.indexOf(e);0<=r&&t.splice(r,1)}}var U=function(){function t(t){this.initialTeardown=t,this.closed=!1,this._parentage=null,this._finalizers=null}var e;return t.prototype.unsubscribe=function(){var t,e,r,n,o;if(!this.closed){this.closed=!0;var i=this._parentage;if(i)if(this._parentage=null,Array.isArray(i))try{for(var s=O(i),a=s.next();!a.done;a=s.next()){a.value.remove(this)}}catch(e){t={error:e}}finally{try{a&&!a.done&&(e=s.return)&&e.call(s)}finally{if(t)throw t.error}}else i.remove(this);var c=this.initialTeardown;if(x(c))try{c()}catch(t){o=t instanceof P?t.errors:[t]}var l=this._finalizers;if(l){this._finalizers=null;try{for(var u=O(l),p=u.next();!p.done;p=u.next()){var h=p.value;try{j(h)}catch(t){o=null!=o?o:[],t instanceof P?o=T(T([],L(o)),L(t.errors)):o.push(t)}}}catch(t){r={error:t}}finally{try{p&&!p.done&&(n=u.return)&&n.call(u)}finally{if(r)throw r.error}}}if(o)throw new P(o)}},t.prototype.add=function(e){var r;if(e&&e!==this)if(this.closed)j(e);else{if(e instanceof t){if(e.closed||e._hasParent(this))return;e._addParent(this)}(this._finalizers=null!==(r=this._finalizers)&&void 0!==r?r:[]).push(e)}},t.prototype._hasParent=function(t){var e=this._parentage;return e===t||Array.isArray(e)&&e.includes(t)},t.prototype._addParent=function(t){var e=this._parentage;this._parentage=Array.isArray(e)?(e.push(t),e):e?[e,t]:t},t.prototype._removeParent=function(t){var e=this._parentage;e===t?this._parentage=null:Array.isArray(e)&&N(e,t)},t.prototype.remove=function(e){var r=this._finalizers;r&&N(r,e),e instanceof t&&e._removeParent(this)},t.EMPTY=((e=new t).closed=!0,e),t}(),R=U.EMPTY;function k(t){return t instanceof U||t&&"closed"in t&&x(t.remove)&&x(t.add)&&x(t.unsubscribe)}function j(t){x(t)?t():t.unsubscribe()}var z={onUnhandledError:null,onStoppedNotification:null,Promise:void 0,useDeprecatedSynchronousErrorHandling:!1,useDeprecatedNextContext:!1},B={setTimeout:function(t,e){for(var r=[],n=2;n<arguments.length;n++)r[n-2]=arguments[n];var o=B.delegate;return(null==o?void 0:o.setTimeout)?o.setTimeout.apply(o,T([t,e],L(r))):setTimeout.apply(void 0,T([t,e],L(r)))},clearTimeout:function(t){var e=B.delegate;return((null==e?void 0:e.clearTimeout)||clearTimeout)(t)},delegate:void 0};function I(){}function D(t){t()}var H=function(t){function e(e){var r=t.call(this)||this;return r.isStopped=!1,e?(r.destination=e,k(e)&&e.add(r)):r.destination=K,r}return S(e,t),e.create=function(t,e,r){return new F(t,e,r)},e.prototype.next=function(t){this.isStopped||this._next(t)},e.prototype.error=function(t){this.isStopped||(this.isStopped=!0,this._error(t))},e.prototype.complete=function(){this.isStopped||(this.isStopped=!0,this._complete())},e.prototype.unsubscribe=function(){this.closed||(this.isStopped=!0,t.prototype.unsubscribe.call(this),this.destination=null)},e.prototype._next=function(t){this.destination.next(t)},e.prototype._error=function(t){try{this.destination.error(t)}finally{this.unsubscribe()}},e.prototype._complete=function(){try{this.destination.complete()}finally{this.unsubscribe()}},e}(U),M=Function.prototype.bind;function W(t,e){return M.call(t,e)}var V=function(){function t(t){this.partialObserver=t}return t.prototype.next=function(t){var e=this.partialObserver;if(e.next)try{e.next(t)}catch(t){J(t)}},t.prototype.error=function(t){var e=this.partialObserver;if(e.error)try{e.error(t)}catch(t){J(t)}else J(t)},t.prototype.complete=function(){var t=this.partialObserver;if(t.complete)try{t.complete()}catch(t){J(t)}},t}(),F=function(t){function e(e,r,n){var o,i,s=t.call(this)||this;x(e)||!e?o={next:null!=e?e:void 0,error:null!=r?r:void 0,complete:null!=n?n:void 0}:s&&z.useDeprecatedNextContext?((i=Object.create(e)).unsubscribe=function(){return s.unsubscribe()},o={next:e.next&&W(e.next,i),error:e.error&&W(e.error,i),complete:e.complete&&W(e.complete,i)}):o=e;return s.destination=new V(o),s}return S(e,t),e}(H);function J(t){var e;e=t,B.setTimeout((function(){throw e}))}var K={closed:!0,next:I,error:function(t){throw t},complete:I},Y="function"==typeof Symbol&&Symbol.observable||"@@observable";function $(t){return t}var G=function(){function t(t){t&&(this._subscribe=t)}return t.prototype.lift=function(e){var r=new t;return r.source=this,r.operator=e,r},t.prototype.subscribe=function(t,e,r){var n,o=this,i=(n=t)&&n instanceof H||function(t){return t&&x(t.next)&&x(t.error)&&x(t.complete)}(n)&&k(n)?t:new F(t,e,r);return D((function(){var t=o,e=t.operator,r=t.source;i.add(e?e.call(i,r):r?o._subscribe(i):o._trySubscribe(i))})),i},t.prototype._trySubscribe=function(t){try{return this._subscribe(t)}catch(e){t.error(e)}},t.prototype.forEach=function(t,e){var r=this;return new(e=X(e))((function(e,n){var o=new F({next:function(e){try{t(e)}catch(t){n(t),o.unsubscribe()}},error:n,complete:e});r.subscribe(o)}))},t.prototype._subscribe=function(t){var e;return null===(e=this.source)||void 0===e?void 0:e.subscribe(t)},t.prototype[Y]=function(){return this},t.prototype.pipe=function(){for(var t,e=[],r=0;r<arguments.length;r++)e[r]=arguments[r];return(0===(t=e).length?$:1===t.length?t[0]:function(e){return t.reduce((function(t,e){return e(t)}),e)})(this)},t.prototype.toPromise=function(t){var e=this;return new(t=X(t))((function(t,r){var n;e.subscribe((function(t){return n=t}),(function(t){return r(t)}),(function(){return t(n)}))}))},t.create=function(e){return new t(e)},t}();function X(t){var e;return null!==(e=null!=t?t:z.Promise)&&void 0!==e?e:Promise}var Z=C((function(t){return function(){t(this),this.name="ObjectUnsubscribedError",this.message="object unsubscribed"}})),q=function(t){function e(){var e=t.call(this)||this;return e.closed=!1,e.currentObservers=null,e.observers=[],e.isStopped=!1,e.hasError=!1,e.thrownError=null,e}return S(e,t),e.prototype.lift=function(t){var e=new Q(this,this);return e.operator=t,e},e.prototype._throwIfClosed=function(){if(this.closed)throw new Z},e.prototype.next=function(t){var e=this;D((function(){var r,n;if(e._throwIfClosed(),!e.isStopped){e.currentObservers||(e.currentObservers=Array.from(e.observers));try{for(var o=O(e.currentObservers),i=o.next();!i.done;i=o.next()){i.value.next(t)}}catch(t){r={error:t}}finally{try{i&&!i.done&&(n=o.return)&&n.call(o)}finally{if(r)throw r.error}}}}))},e.prototype.error=function(t){var e=this;D((function(){if(e._throwIfClosed(),!e.isStopped){e.hasError=e.isStopped=!0,e.thrownError=t;for(var r=e.observers;r.length;)r.shift().error(t)}}))},e.prototype.complete=function(){var t=this;D((function(){if(t._throwIfClosed(),!t.isStopped){t.isStopped=!0;for(var e=t.observers;e.length;)e.shift().complete()}}))},e.prototype.unsubscribe=function(){this.isStopped=this.closed=!0,this.observers=this.currentObservers=null},Object.defineProperty(e.prototype,"observed",{get:function(){var t;return(null===(t=this.observers)||void 0===t?void 0:t.length)>0},enumerable:!1,configurable:!0}),e.prototype._trySubscribe=function(e){return this._throwIfClosed(),t.prototype._trySubscribe.call(this,e)},e.prototype._subscribe=function(t){return this._throwIfClosed(),this._checkFinalizedStatuses(t),this._innerSubscribe(t)},e.prototype._innerSubscribe=function(t){var e=this,r=this,n=r.hasError,o=r.isStopped,i=r.observers;return n||o?R:(this.currentObservers=null,i.push(t),new U((function(){e.currentObservers=null,N(i,t)})))},e.prototype._checkFinalizedStatuses=function(t){var e=this,r=e.hasError,n=e.thrownError,o=e.isStopped;r?t.error(n):o&&t.complete()},e.prototype.asObservable=function(){var t=new G;return t.source=this,t},e.create=function(t,e){return new Q(t,e)},e}(G),Q=function(t){function e(e,r){var n=t.call(this)||this;return n.destination=e,n.source=r,n}return S(e,t),e.prototype.next=function(t){var e,r;null===(r=null===(e=this.destination)||void 0===e?void 0:e.next)||void 0===r||r.call(e,t)},e.prototype.error=function(t){var e,r;null===(r=null===(e=this.destination)||void 0===e?void 0:e.error)||void 0===r||r.call(e,t)},e.prototype.complete=function(){var t,e;null===(e=null===(t=this.destination)||void 0===t?void 0:t.complete)||void 0===e||e.call(t)},e.prototype._subscribe=function(t){var e,r;return null!==(r=null===(e=this.source)||void 0===e?void 0:e.subscribe(t))&&void 0!==r?r:R},e}(q),tt=function(t){function e(e){var r=t.call(this)||this;return r._value=e,r}return S(e,t),Object.defineProperty(e.prototype,"value",{get:function(){return this.getValue()},enumerable:!1,configurable:!0}),e.prototype._subscribe=function(e){var r=t.prototype._subscribe.call(this,e);return!r.closed&&e.next(this._value),r},e.prototype.getValue=function(){var t=this,e=t.hasError,r=t.thrownError,n=t._value;if(e)throw r;return this._throwIfClosed(),n},e.prototype.next=function(e){t.prototype.next.call(this,this._value=e)},e}(q);class et{constructor(t){this.fetch=async(...t)=>{if(await this.initialized,null==this.session)throw new Error("no session");return await this.session.send(...t)},this.protocol=t.protocol,this.$session=new tt(void 0),this.initialized=this.init()}async init(t,e){if(void 0===t){const t=(await Promise.resolve().then((function(){return ot}))).SessionLocalStorage;this.storage=new t(e?.localStorage)}else this.storage=t}get hasSession(){return void 0!==this.session}async createIfNotExists(){if(await this.initialized,void 0!==this.session)return this.session;const t=await this.protocol.run();return await this.setSession(t),t}async removeSession(){await this.initialized,await this.setSession()}async setSession(t){if(await this.initialized,this.session=t,null==t)await this.storage.clear();else{const e=t.toJSON();await this.storage.setSessionData(e)}this.$session.next(t)}async loadSession(){let t;await this.initialized;try{const e=await this.storage.getSessionData();null!==e&&(t=await A.fromJSON(this.protocol.transport,e))}catch(t){}await this.setSession(t)}}const rt={overlayClass:"wallet-protocol-overlay",modalClass:"wallet-modal",titleClass:"wallet-title",messageClass:"wallet-message",inputBoxClass:"wallet-input-box",inputClass:"wallet-input",buttonClass:"wallet-button"};var nt=Object.freeze({__proto__:null,pinHtmlFormDialog:async(t=rt)=>{const e=Object.assign({},t,rt),r=document.createElement("div");document.body.appendChild(r),r.className=e.overlayClass;const n=document.createElement("style");r.appendChild(n),n.innerText=".__WALLET_PROTOCOL_OVERLAY__ {\n    position: absolute;\n    display: flex;\n    height: 100%;\n    width: 100%;\n    top: 0;\n    left: 0;\n    align-items: center;\n    justify-content: center;\n    background-color: #000000AA;\n    font-family: 'sans-serif';\n    color: #202531;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MODAL__ {\n    display: flex;\n    flex-direction: column;\n    align-items: center;\n    justify-content: center;\n    border: 2px solid #1A1E27;\n    border-radius: 5px;\n    padding: 10px 20px;\n    background-image: linear-gradient(to bottom left, white, #D2D6E1);\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_TITLE__ {\n    font-weight: bold;\n    padding: 5px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MESSAGE__ {\n    opacity: 0.5;\n    padding: 5px;\n    font-size: 15px\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT_BOX__ {\n    display: flex;\n    margin: 20px;\n    height: 32px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT__ {\n    border-radius: 3px;\n    border-top-right-radius: 0;\n    border-bottom-right-radius: 0;\n    outline: none;\n    padding: 5px;\n    border: 2px solid #1A1E27;\n    border-right: none;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_BUTTON__ {\n    height: 100%;\n    padding: 5px;\n    border-radius: 3px;\n    border: 2px solid #1A1E27;\n    border-top-left-radius: 0;\n    border-bottom-left-radius: 0;\n    cursor: pointer;\n}\n".replace(/__WALLET_PROTOCOL_OVERLAY__/g,e.overlayClass).replace(/__WALLET_MODAL__/g,e.modalClass).replace(/__WALLET_TITLE__/g,e.titleClass).replace(/__WALLET_MESSAGE__/g,e.messageClass).replace(/__WALLET_INPUT_BOX__/g,e.inputBoxClass).replace(/__WALLET_INPUT__/g,e.inputClass).replace(/__WALLET_BUTTON__/g,e.buttonClass);const o=document.createElement("div");r.appendChild(o),o.className=e.modalClass;const i=document.createElement("span");o.appendChild(i),i.className=e.titleClass,i.innerText="Connecting to your wallet...";const s=document.createElement("span");o.appendChild(s),s.className=e.messageClass,s.innerText="Set up your wallet on pairing mode and put the PIN here";const a=document.createElement("div");o.appendChild(a),a.className=e.inputBoxClass;const c=document.createElement("input");a.appendChild(c),c.className=e.inputClass,c.setAttribute("placeholder","pin...");const l=document.createElement("button");return a.appendChild(l),l.className=e.buttonClass,l.innerText="Syncronize",await new Promise(((t,e)=>{const n=e=>{document.body.removeChild(r),t(e??"")};l.addEventListener("click",(()=>n(c.value))),r.addEventListener("click",(t=>{t.target===r&&n()}))}))}});var ot=Object.freeze({__proto__:null,SessionLocalStorage:class{constructor(t){this.key="string"==typeof t?.key&&""!==t.key?t.key:"wallet-session"}async getSessionData(){const t=localStorage.getItem(this.key);if(null==t)throw new Error("no session data stored");return JSON.parse(t)}async setSessionData(t){localStorage.setItem(this.key,JSON.stringify(t))}async clear(){localStorage.removeItem(this.key)}}});t.LocalSessionManager=class extends et{constructor(t,e={}){super({protocol:t,storageOptions:{localStorage:{key:e.localStorageKey}}}),this.protocol=t}},t.SessionManager=et,t.openModal=r,t.pinDialog=e}));
