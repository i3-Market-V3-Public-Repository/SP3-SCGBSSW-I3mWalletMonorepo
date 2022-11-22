!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?e(exports):"function"==typeof define&&define.amd?define(["exports"],e):e((t="undefined"!=typeof globalThis?globalThis:t||self).walletProtocolUtils={})}(this,(function(t){"use strict";const e=async t=>{{const e=await Promise.resolve().then((function(){return Ut}));return await e.pinHtmlFormDialog(t?.htmlFormDialog)}},n=e;function r(t,e=!1,n=!0){let r="";r=(t=>{const e=[];for(let n=0;n<t.length;n+=32768)e.push(String.fromCharCode.apply(null,t.subarray(n,n+32768)));return btoa(e.join(""))})("string"==typeof t?(new TextEncoder).encode(t):new Uint8Array(t));return e&&(r=function(t){return t.replace(/\+/g,"-").replace(/\//g,"_")}(r)),n||(r=r.replace(/=/g,"")),r}function i(t,e=!1){{let n=!1;if(/^[0-9a-zA-Z_-]+={0,2}$/.test(t))n=!0;else if(!/^[0-9a-zA-Z+/]*={0,2}$/.test(t))throw new Error("Not a valid base64 input");n&&(t=t.replace(/-/g,"+").replace(/_/g,"/").replace(/=/g,""));const r=new Uint8Array(atob(t).split("").map((t=>t.charCodeAt(0))));return e?(new TextDecoder).decode(r):r}}const o={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function s(t,e,n,r,i="SHA-256"){return new Promise(((s,u)=>{i in o||u(new RangeError(`Valid hash algorithm values are any of ${Object.keys(o).toString()}`)),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)||u(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof e?e=(new TextEncoder).encode(e):e instanceof ArrayBuffer?e=new Uint8Array(e):ArrayBuffer.isView(e)?e=new Uint8Array(e.buffer,e.byteOffset,e.byteLength):u(RangeError("S should be string, ArrayBuffer, TypedArray, DataView")),crypto.subtle.importKey("raw",t,"PBKDF2",!1,["deriveBits"]).then((l=>{const h={name:"PBKDF2",hash:i,salt:e,iterations:n};crypto.subtle.deriveBits(h,l,8*r).then((t=>s(t)),(l=>{(async function(t,e,n,r,i){if(!(i in o))throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(o).toString()}`);if(!Number.isInteger(n)||n<=0)throw new RangeError("c must be a positive integer");const s=o[i].outputLength;if(!Number.isInteger(r)||r<=0||r>=(2**32-1)*s)throw new RangeError("dkLen must be a positive integer < (2 ** 32 - 1) * hLen");const u=Math.ceil(r/s),l=r-(u-1)*s,h=new Array(u);0===t.byteLength&&(t=new Uint8Array(o[i].blockSize));const f=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:{name:i}},!0,["sign"]),p=async function(t,e){const n=await crypto.subtle.sign("HMAC",t,e);return new Uint8Array(n)};for(let t=0;t<u;t++)h[t]=await d(f,e,n,t+1);async function d(t,e,n,r){function i(t){const e=new ArrayBuffer(4);return new DataView(e).setUint32(0,t,!1),new Uint8Array(e)}const o=await p(t,a(e,i(r)));let s=o;for(let e=1;e<n;e++)s=await p(t,s),c(o,s);return o}return h[u-1]=h[u-1].slice(0,l),a(...h).buffer})(t,e,n,r,i).then((t=>s(t)),(t=>u(t)))}))}),(t=>u(t)))}))}function a(...t){const e=t.reduce(((t,e)=>t+e.length),0);if(0===t.length)throw new RangeError("Cannot concat no arrays");const n=new Uint8Array(e);let r=0;for(const e of t)n.set(e,r),r+=e.length;return n}function c(t,e){for(let n=0;n<t.length;n++)t[n]^=e[n]}function u(t){return null!=t&&"object"==typeof t&&!Array.isArray(t)}function l(t){return u(t)||Array.isArray(t)?Array.isArray(t)?t.map((t=>Array.isArray(t)||u(t)?l(t):t)):Object.keys(t).sort().map((e=>[e,l(t[e])])):t}function h(t){return JSON.stringify(l(t))}function f(t,e="SHA-256"){const n=["SHA-1","SHA-256","SHA-384","SHA-512"];if(!n.includes(e))throw RangeError(`Valid hash algorithm values are any of ${JSON.stringify(n)}`);return async function(t,e){const n=(new TextEncoder).encode(h(t)).buffer;let r="";{const t=await crypto.subtle.digest(e,n),i="0123456789abcdef";new Uint8Array(t).forEach((t=>{r+=i[t>>4]+i[15&t]}))}return r}(t,e)}class p{async randomFill(t,e,n){throw new Error("not implemented")}async randomFillBits(t,e,n){const r=Math.ceil(n/8),i=new Uint8Array(r);await this.randomFill(i,0,r),A.insertBits(i,t,0,e,n)}}class d{constructor(t,e){this.algorithm=t,this.key=e}async encrypt(t){throw new Error("not implemented")}async decrypt(t){throw new Error("not implemented")}}const y=new class extends p{async randomFill(t,e,n){const r=new Uint8Array(n);crypto.getRandomValues(r);for(let i=0;i<n;i++)t[e+i]=r[i]}},v={"aes-256-gcm":{name:"AES-GCM",tagLength:128}};class _ extends d{async encrypt(t){const e=new Uint8Array(12);await y.randomFill(e,0,e.length);const n=v[this.algorithm],r=await crypto.subtle.importKey("raw",this.key,n,!1,["encrypt"]),i=await crypto.subtle.encrypt({...n,iv:e},r,t),o=[];return o.push(e),o.push(new Uint8Array(i)),A.join(...o)}async decrypt(t){const e=[];if("aes-256-gcm"===this.algorithm)e[0]=12;e[1]=t.length-e[0];const[n,r]=A.split(t,...e),i=v[this.algorithm],o=await crypto.subtle.importKey("raw",this.key,i,!1,["decrypt"]),s=await crypto.subtle.decrypt({...i,iv:n},o,r);return new Uint8Array(s)}}const b=t=>{const e=t.match(/.{1,2}/g);if(null===e)throw new Error(`not a hex: ${t}`);return new Uint8Array(e.map((t=>parseInt(t,16))))},m=t=>t.reduce(((t,e)=>t+e.toString(16).padStart(2,"0")),""),w=t=>r(t,!0,!1),g=t=>i(t,!1),A={join:(...t)=>{const e=t.reduce(((t,e)=>t+e.length),0),n=new Uint8Array(e);let r=0;for(const e of t)n.set(e,r),r+=e.length;return n},split:(t,...e)=>{const n=[];let r=0;for(const i of e)n.push(t.slice(r,r+i)),r+=i;return n},insertBytes:(t,e,n,r,i)=>{for(let o=0;o<i;o++)e[o+r]=t[o+n]},insertBits:(t,e,n,r,i)=>{let o=Math.floor(n/8),s=n%8,a=Math.floor(r/8),c=r%8,u=t[o]??0;const l=c-s;for(let n=0;n<i;n++){let n;n=l>=0?(u&128>>s)<<l:u&128>>s;const r=e[a]&~(128>>c)|n;e[a]=r,s++,c++,s>=8&&(o++,s=0,u=t[o]??0),c>=8&&(a++,c=0)}},extractBits:(t,e,n)=>{const r=Math.ceil(n/8),i=new Uint8Array(r);return A.insertBits(t,i,e,0,n),i}},S=async(t,e,n)=>{const r=new Uint8Array(16),i=new Uint8Array(96),o=b(t),a=b(e);A.insertBytes(n,i,0,0,32),A.insertBytes(o,i,0,32,32),A.insertBytes(a,i,0,64,32);const c=await s(i,r,1,32);return new Uint8Array(c)};class x{constructor(t,e,n,r,i,o,s,a){this.port=t,this.from=e,this.to=n,this.na=r,this.nb=i,this.secret=o,this.cipher=new _("aes-256-gcm",s),this.decipher=new _("aes-256-gcm",a)}async encrypt(t){return await this.cipher.encrypt(t)}async decrypt(t){return await this.decipher.decrypt(t)}toJSON(){return{from:this.from,to:this.to,port:this.port,na:w(this.na),nb:w(this.nb),secret:w(this.secret)}}async fromHash(){return await f(this.from)}async toHash(){return await f(this.to)}static async fromSecret(t,e,n,r,i,o){const s=await f(e),a=await f(n),c=await S(s,a,o),u=await S(a,s,o);return new x(t,e,n,r,i,o,c,u)}static async fromJSON(t){const e=g(t.na),n=g(t.nb),r=g(t.secret);return await this.fromSecret(t.port,t.from,t.to,e,n,r)}}class E{constructor(t,e,n){this.transport=t,this.masterKey=e,this.code=n}async send(t){return await this.transport.send(this.masterKey,this.code,t)}toJSON(){return{masterKey:this.masterKey.toJSON(),code:m(this.code)}}static async fromJSON(t,e){const n=await x.fromJSON(e.masterKey),r=b(e.code);let i;if("object"==typeof t)i=t;else{if(!(t instanceof Function))throw new Error("First param must be transport or constructor of transport");i=new t}return new E(i,n,r)}}var O=function(t,e){return O=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(t,e){t.__proto__=e}||function(t,e){for(var n in e)Object.prototype.hasOwnProperty.call(e,n)&&(t[n]=e[n])},O(t,e)};function L(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Class extends value "+String(e)+" is not a constructor or null");function n(){this.constructor=t}O(t,e),t.prototype=null===e?Object.create(e):(n.prototype=e.prototype,new n)}function T(t){var e="function"==typeof Symbol&&Symbol.iterator,n=e&&t[e],r=0;if(n)return n.call(t);if(t&&"number"==typeof t.length)return{next:function(){return t&&r>=t.length&&(t=void 0),{value:t&&t[r++],done:!t}}};throw new TypeError(e?"Object is not iterable.":"Symbol.iterator is not defined.")}function C(t,e){var n="function"==typeof Symbol&&t[Symbol.iterator];if(!n)return t;var r,i,o=n.call(t),s=[];try{for(;(void 0===e||e-- >0)&&!(r=o.next()).done;)s.push(r.value)}catch(t){i={error:t}}finally{try{r&&!r.done&&(n=o.return)&&n.call(o)}finally{if(i)throw i.error}}return s}function I(t,e,n){if(n||2===arguments.length)for(var r,i=0,o=e.length;i<o;i++)!r&&i in e||(r||(r=Array.prototype.slice.call(e,0,i)),r[i]=e[i]);return t.concat(r||Array.prototype.slice.call(e))}function P(t){return"function"==typeof t}function k(t){var e=t((function(t){Error.call(t),t.stack=(new Error).stack}));return e.prototype=Object.create(Error.prototype),e.prototype.constructor=e,e}var N=k((function(t){return function(e){t(this),this.message=e?e.length+" errors occurred during unsubscription:\n"+e.map((function(t,e){return e+1+") "+t.toString()})).join("\n  "):"",this.name="UnsubscriptionError",this.errors=e}}));function F(t,e){if(t){var n=t.indexOf(e);0<=n&&t.splice(n,1)}}var j=function(){function t(t){this.initialTeardown=t,this.closed=!1,this._parentage=null,this._finalizers=null}var e;return t.prototype.unsubscribe=function(){var t,e,n,r,i;if(!this.closed){this.closed=!0;var o=this._parentage;if(o)if(this._parentage=null,Array.isArray(o))try{for(var s=T(o),a=s.next();!a.done;a=s.next()){a.value.remove(this)}}catch(e){t={error:e}}finally{try{a&&!a.done&&(e=s.return)&&e.call(s)}finally{if(t)throw t.error}}else o.remove(this);var c=this.initialTeardown;if(P(c))try{c()}catch(t){i=t instanceof N?t.errors:[t]}var u=this._finalizers;if(u){this._finalizers=null;try{for(var l=T(u),h=l.next();!h.done;h=l.next()){var f=h.value;try{B(f)}catch(t){i=null!=i?i:[],t instanceof N?i=I(I([],C(i)),C(t.errors)):i.push(t)}}}catch(t){n={error:t}}finally{try{h&&!h.done&&(r=l.return)&&r.call(l)}finally{if(n)throw n.error}}}if(i)throw new N(i)}},t.prototype.add=function(e){var n;if(e&&e!==this)if(this.closed)B(e);else{if(e instanceof t){if(e.closed||e._hasParent(this))return;e._addParent(this)}(this._finalizers=null!==(n=this._finalizers)&&void 0!==n?n:[]).push(e)}},t.prototype._hasParent=function(t){var e=this._parentage;return e===t||Array.isArray(e)&&e.includes(t)},t.prototype._addParent=function(t){var e=this._parentage;this._parentage=Array.isArray(e)?(e.push(t),e):e?[e,t]:t},t.prototype._removeParent=function(t){var e=this._parentage;e===t?this._parentage=null:Array.isArray(e)&&F(e,t)},t.prototype.remove=function(e){var n=this._finalizers;n&&F(n,e),e instanceof t&&e._removeParent(this)},t.EMPTY=((e=new t).closed=!0,e),t}(),U=j.EMPTY;function z(t){return t instanceof j||t&&"closed"in t&&P(t.remove)&&P(t.add)&&P(t.unsubscribe)}function B(t){P(t)?t():t.unsubscribe()}var R={onUnhandledError:null,onStoppedNotification:null,Promise:void 0,useDeprecatedSynchronousErrorHandling:!1,useDeprecatedNextContext:!1},W=function(t,e){for(var n=[],r=2;r<arguments.length;r++)n[r-2]=arguments[r];return setTimeout.apply(void 0,I([t,e],C(n)))};function M(){}function V(t){t()}var D=function(t){function e(e){var n=t.call(this)||this;return n.isStopped=!1,e?(n.destination=e,z(e)&&e.add(n)):n.destination=$,n}return L(e,t),e.create=function(t,e,n){return new K(t,e,n)},e.prototype.next=function(t){this.isStopped||this._next(t)},e.prototype.error=function(t){this.isStopped||(this.isStopped=!0,this._error(t))},e.prototype.complete=function(){this.isStopped||(this.isStopped=!0,this._complete())},e.prototype.unsubscribe=function(){this.closed||(this.isStopped=!0,t.prototype.unsubscribe.call(this),this.destination=null)},e.prototype._next=function(t){this.destination.next(t)},e.prototype._error=function(t){try{this.destination.error(t)}finally{this.unsubscribe()}},e.prototype._complete=function(){try{this.destination.complete()}finally{this.unsubscribe()}},e}(j),q=Function.prototype.bind;function H(t,e){return q.call(t,e)}var J=function(){function t(t){this.partialObserver=t}return t.prototype.next=function(t){var e=this.partialObserver;if(e.next)try{e.next(t)}catch(t){Y(t)}},t.prototype.error=function(t){var e=this.partialObserver;if(e.error)try{e.error(t)}catch(t){Y(t)}else Y(t)},t.prototype.complete=function(){var t=this.partialObserver;if(t.complete)try{t.complete()}catch(t){Y(t)}},t}(),K=function(t){function e(e,n,r){var i,o,s=t.call(this)||this;P(e)||!e?i={next:null!=e?e:void 0,error:null!=n?n:void 0,complete:null!=r?r:void 0}:s&&R.useDeprecatedNextContext?((o=Object.create(e)).unsubscribe=function(){return s.unsubscribe()},i={next:e.next&&H(e.next,o),error:e.error&&H(e.error,o),complete:e.complete&&H(e.complete,o)}):i=e;return s.destination=new J(i),s}return L(e,t),e}(D);function Y(t){var e;e=t,W((function(){throw e}))}var $={closed:!0,next:M,error:function(t){throw t},complete:M},G="function"==typeof Symbol&&Symbol.observable||"@@observable";function X(t){return t}function Z(t){return 0===t.length?X:1===t.length?t[0]:function(e){return t.reduce((function(t,e){return e(t)}),e)}}var Q=function(){function t(t){t&&(this._subscribe=t)}return t.prototype.lift=function(e){var n=new t;return n.source=this,n.operator=e,n},t.prototype.subscribe=function(t,e,n){var r,i=this,o=(r=t)&&r instanceof D||function(t){return t&&P(t.next)&&P(t.error)&&P(t.complete)}(r)&&z(r)?t:new K(t,e,n);return V((function(){var t=i,e=t.operator,n=t.source;o.add(e?e.call(o,n):n?i._subscribe(o):i._trySubscribe(o))})),o},t.prototype._trySubscribe=function(t){try{return this._subscribe(t)}catch(e){t.error(e)}},t.prototype.forEach=function(t,e){var n=this;return new(e=tt(e))((function(e,r){var i=new K({next:function(e){try{t(e)}catch(t){r(t),i.unsubscribe()}},error:r,complete:e});n.subscribe(i)}))},t.prototype._subscribe=function(t){var e;return null===(e=this.source)||void 0===e?void 0:e.subscribe(t)},t.prototype[G]=function(){return this},t.prototype.pipe=function(){for(var t=[],e=0;e<arguments.length;e++)t[e]=arguments[e];return Z(t)(this)},t.prototype.toPromise=function(t){var e=this;return new(t=tt(t))((function(t,n){var r;e.subscribe((function(t){return r=t}),(function(t){return n(t)}),(function(){return t(r)}))}))},t.create=function(e){return new t(e)},t}();function tt(t){var e;return null!==(e=null!=t?t:R.Promise)&&void 0!==e?e:Promise}function et(t){return P(null==t?void 0:t.lift)}function nt(t,e,n,r,i){return new rt(t,e,n,r,i)}var rt=function(t){function e(e,n,r,i,o,s){var a=t.call(this,e)||this;return a.onFinalize=o,a.shouldUnsubscribe=s,a._next=n?function(t){try{n(t)}catch(t){e.error(t)}}:t.prototype._next,a._error=i?function(t){try{i(t)}catch(t){e.error(t)}finally{this.unsubscribe()}}:t.prototype._error,a._complete=r?function(){try{r()}catch(t){e.error(t)}finally{this.unsubscribe()}}:t.prototype._complete,a}return L(e,t),e.prototype.unsubscribe=function(){var e;if(!this.shouldUnsubscribe||this.shouldUnsubscribe()){var n=this.closed;t.prototype.unsubscribe.call(this),!n&&(null===(e=this.onFinalize)||void 0===e||e.call(this))}},e}(D);function it(){return t=function(t,e){var n=null;t._refCount++;var r=nt(e,void 0,void 0,void 0,(function(){if(!t||t._refCount<=0||0<--t._refCount)n=null;else{var r=t._connection,i=n;n=null,!r||i&&r!==i||r.unsubscribe(),e.unsubscribe()}}));t.subscribe(r),r.closed||(n=t.connect())},function(e){if(et(e))return e.lift((function(e){try{return t(e,this)}catch(t){this.error(t)}}));throw new TypeError("Unable to lift unknown Observable type")};var t}!function(t){function e(e,n){var r=t.call(this)||this;return r.source=e,r.subjectFactory=n,r._subject=null,r._refCount=0,r._connection=null,et(e)&&(r.lift=e.lift),r}L(e,t),e.prototype._subscribe=function(t){return this.getSubject().subscribe(t)},e.prototype.getSubject=function(){var t=this._subject;return t&&!t.isStopped||(this._subject=this.subjectFactory()),this._subject},e.prototype._teardown=function(){this._refCount=0;var t=this._connection;this._subject=this._connection=null,null==t||t.unsubscribe()},e.prototype.connect=function(){var t=this,e=this._connection;if(!e){e=this._connection=new j;var n=this.getSubject();e.add(this.source.subscribe(nt(n,void 0,(function(){t._teardown(),n.complete()}),(function(e){t._teardown(),n.error(e)}),(function(){return t._teardown()})))),e.closed&&(this._connection=null,e=j.EMPTY)}return e},e.prototype.refCount=function(){return it()(this)}}(Q);var ot,st={now:function(){return(st.delegate||performance).now()},delegate:void 0},at={schedule:function(t){var e=requestAnimationFrame,n=cancelAnimationFrame,r=e((function(e){n=void 0,t(e)}));return new j((function(){return null==n?void 0:n(r)}))},requestAnimationFrame:function(){for(var t=[],e=0;e<arguments.length;e++)t[e]=arguments[e];var n=at.delegate;return((null==n?void 0:n.requestAnimationFrame)||requestAnimationFrame).apply(void 0,I([],C(t)))},cancelAnimationFrame:function(){for(var t=[],e=0;e<arguments.length;e++)t[e]=arguments[e];return cancelAnimationFrame.apply(void 0,I([],C(t)))},delegate:void 0};new Q((function(t){var e=ot||st,n=e.now(),r=0,i=function(){t.closed||(r=at.requestAnimationFrame((function(o){r=0;var s=e.now();t.next({timestamp:ot?s:o,elapsed:s-n}),i()})))};return i(),function(){r&&at.cancelAnimationFrame(r)}}));var ct=k((function(t){return function(){t(this),this.name="ObjectUnsubscribedError",this.message="object unsubscribed"}})),ut=function(t){function e(){var e=t.call(this)||this;return e.closed=!1,e.currentObservers=null,e.observers=[],e.isStopped=!1,e.hasError=!1,e.thrownError=null,e}return L(e,t),e.prototype.lift=function(t){var e=new lt(this,this);return e.operator=t,e},e.prototype._throwIfClosed=function(){if(this.closed)throw new ct},e.prototype.next=function(t){var e=this;V((function(){var n,r;if(e._throwIfClosed(),!e.isStopped){e.currentObservers||(e.currentObservers=Array.from(e.observers));try{for(var i=T(e.currentObservers),o=i.next();!o.done;o=i.next()){o.value.next(t)}}catch(t){n={error:t}}finally{try{o&&!o.done&&(r=i.return)&&r.call(i)}finally{if(n)throw n.error}}}}))},e.prototype.error=function(t){var e=this;V((function(){if(e._throwIfClosed(),!e.isStopped){e.hasError=e.isStopped=!0,e.thrownError=t;for(var n=e.observers;n.length;)n.shift().error(t)}}))},e.prototype.complete=function(){var t=this;V((function(){if(t._throwIfClosed(),!t.isStopped){t.isStopped=!0;for(var e=t.observers;e.length;)e.shift().complete()}}))},e.prototype.unsubscribe=function(){this.isStopped=this.closed=!0,this.observers=this.currentObservers=null},Object.defineProperty(e.prototype,"observed",{get:function(){var t;return(null===(t=this.observers)||void 0===t?void 0:t.length)>0},enumerable:!1,configurable:!0}),e.prototype._trySubscribe=function(e){return this._throwIfClosed(),t.prototype._trySubscribe.call(this,e)},e.prototype._subscribe=function(t){return this._throwIfClosed(),this._checkFinalizedStatuses(t),this._innerSubscribe(t)},e.prototype._innerSubscribe=function(t){var e=this,n=this,r=n.hasError,i=n.isStopped,o=n.observers;return r||i?U:(this.currentObservers=null,o.push(t),new j((function(){e.currentObservers=null,F(o,t)})))},e.prototype._checkFinalizedStatuses=function(t){var e=this,n=e.hasError,r=e.thrownError,i=e.isStopped;n?t.error(r):i&&t.complete()},e.prototype.asObservable=function(){var t=new Q;return t.source=this,t},e.create=function(t,e){return new lt(t,e)},e}(Q),lt=function(t){function e(e,n){var r=t.call(this)||this;return r.destination=e,r.source=n,r}return L(e,t),e.prototype.next=function(t){var e,n;null===(n=null===(e=this.destination)||void 0===e?void 0:e.next)||void 0===n||n.call(e,t)},e.prototype.error=function(t){var e,n;null===(n=null===(e=this.destination)||void 0===e?void 0:e.error)||void 0===n||n.call(e,t)},e.prototype.complete=function(){var t,e;null===(e=null===(t=this.destination)||void 0===t?void 0:t.complete)||void 0===e||e.call(t)},e.prototype._subscribe=function(t){var e,n;return null!==(n=null===(e=this.source)||void 0===e?void 0:e.subscribe(t))&&void 0!==n?n:U},e}(ut),ht=function(t){function e(e){var n=t.call(this)||this;return n._value=e,n}return L(e,t),Object.defineProperty(e.prototype,"value",{get:function(){return this.getValue()},enumerable:!1,configurable:!0}),e.prototype._subscribe=function(e){var n=t.prototype._subscribe.call(this,e);return!n.closed&&e.next(this._value),n},e.prototype.getValue=function(){var t=this,e=t.hasError,n=t.thrownError,r=t._value;if(e)throw n;return this._throwIfClosed(),r},e.prototype.next=function(e){t.prototype.next.call(this,this._value=e)},e}(ut),ft={now:function(){return(ft.delegate||Date).now()},delegate:void 0};!function(t){function e(e,n,r){void 0===e&&(e=1/0),void 0===n&&(n=1/0),void 0===r&&(r=ft);var i=t.call(this)||this;return i._bufferSize=e,i._windowTime=n,i._timestampProvider=r,i._buffer=[],i._infiniteTimeWindow=!0,i._infiniteTimeWindow=n===1/0,i._bufferSize=Math.max(1,e),i._windowTime=Math.max(1,n),i}L(e,t),e.prototype.next=function(e){var n=this,r=n.isStopped,i=n._buffer,o=n._infiniteTimeWindow,s=n._timestampProvider,a=n._windowTime;r||(i.push(e),!o&&i.push(s.now()+a)),this._trimBuffer(),t.prototype.next.call(this,e)},e.prototype._subscribe=function(t){this._throwIfClosed(),this._trimBuffer();for(var e=this._innerSubscribe(t),n=this._infiniteTimeWindow,r=this._buffer.slice(),i=0;i<r.length&&!t.closed;i+=n?1:2)t.next(r[i]);return this._checkFinalizedStatuses(t),e},e.prototype._trimBuffer=function(){var t=this,e=t._bufferSize,n=t._timestampProvider,r=t._buffer,i=t._infiniteTimeWindow,o=(i?1:2)*e;if(e<1/0&&o<r.length&&r.splice(0,r.length-o),!i){for(var s=n.now(),a=0,c=1;c<r.length&&r[c]<=s;c+=2)a=c;a&&r.splice(0,a+1)}}}(ut),function(t){function e(){var e=null!==t&&t.apply(this,arguments)||this;return e._value=null,e._hasValue=!1,e._isComplete=!1,e}L(e,t),e.prototype._checkFinalizedStatuses=function(t){var e=this,n=e.hasError,r=e._hasValue,i=e._value,o=e.thrownError,s=e.isStopped,a=e._isComplete;n?t.error(o):(s||a)&&(r&&t.next(i),t.complete())},e.prototype.next=function(t){this.isStopped||(this._value=t,this._hasValue=!0)},e.prototype.complete=function(){var e=this,n=e._hasValue,r=e._value;e._isComplete||(this._isComplete=!0,n&&t.prototype.next.call(this,r),t.prototype.complete.call(this))}}(ut);var pt,dt=function(t){function e(e,n){return t.call(this)||this}return L(e,t),e.prototype.schedule=function(t,e){return this},e}(j),yt=function(t,e){for(var n=[],r=2;r<arguments.length;r++)n[r-2]=arguments[r];return setInterval.apply(void 0,I([t,e],C(n)))},vt=function(t){return clearInterval(t)},_t=function(t){function e(e,n){var r=t.call(this,e,n)||this;return r.scheduler=e,r.work=n,r.pending=!1,r}return L(e,t),e.prototype.schedule=function(t,e){var n;if(void 0===e&&(e=0),this.closed)return this;this.state=t;var r=this.id,i=this.scheduler;return null!=r&&(this.id=this.recycleAsyncId(i,r,e)),this.pending=!0,this.delay=e,this.id=null!==(n=this.id)&&void 0!==n?n:this.requestAsyncId(i,this.id,e),this},e.prototype.requestAsyncId=function(t,e,n){return void 0===n&&(n=0),yt(t.flush.bind(t,this),n)},e.prototype.recycleAsyncId=function(t,e,n){if(void 0===n&&(n=0),null!=n&&this.delay===n&&!1===this.pending)return e;null!=e&&vt(e)},e.prototype.execute=function(t,e){if(this.closed)return new Error("executing a cancelled action");this.pending=!1;var n=this._execute(t,e);if(n)return n;!1===this.pending&&null!=this.id&&(this.id=this.recycleAsyncId(this.scheduler,this.id,null))},e.prototype._execute=function(t,e){var n,r=!1;try{this.work(t)}catch(t){r=!0,n=t||new Error("Scheduled action threw falsy error")}if(r)return this.unsubscribe(),n},e.prototype.unsubscribe=function(){if(!this.closed){var e=this.id,n=this.scheduler,r=n.actions;this.work=this.state=this.scheduler=null,this.pending=!1,F(r,this),null!=e&&(this.id=this.recycleAsyncId(n,e,null)),this.delay=null,t.prototype.unsubscribe.call(this)}},e}(dt),bt=1,mt={};function wt(t){return t in mt&&(delete mt[t],!0)}var gt=function(t){var e=bt++;return mt[e]=!0,pt||(pt=Promise.resolve()),pt.then((function(){return wt(e)&&t()})),e},At=function(t){wt(t)},St={setImmediate:function(){for(var t=[],e=0;e<arguments.length;e++)t[e]=arguments[e];var n=St.delegate;return((null==n?void 0:n.setImmediate)||gt).apply(void 0,I([],C(t)))},clearImmediate:function(t){return At(t)},delegate:void 0},xt=function(t){function e(e,n){var r=t.call(this,e,n)||this;return r.scheduler=e,r.work=n,r}return L(e,t),e.prototype.requestAsyncId=function(e,n,r){return void 0===r&&(r=0),null!==r&&r>0?t.prototype.requestAsyncId.call(this,e,n,r):(e.actions.push(this),e._scheduled||(e._scheduled=St.setImmediate(e.flush.bind(e,void 0))))},e.prototype.recycleAsyncId=function(e,n,r){var i;if(void 0===r&&(r=0),null!=r?r>0:this.delay>0)return t.prototype.recycleAsyncId.call(this,e,n,r);var o=e.actions;null!=n&&(null===(i=o[o.length-1])||void 0===i?void 0:i.id)!==n&&(St.clearImmediate(n),e._scheduled=void 0)},e}(_t),Et=function(){function t(e,n){void 0===n&&(n=t.now),this.schedulerActionCtor=e,this.now=n}return t.prototype.schedule=function(t,e,n){return void 0===e&&(e=0),new this.schedulerActionCtor(this,t).schedule(n,e)},t.now=ft.now,t}(),Ot=function(t){function e(e,n){void 0===n&&(n=Et.now);var r=t.call(this,e,n)||this;return r.actions=[],r._active=!1,r}return L(e,t),e.prototype.flush=function(t){var e=this.actions;if(this._active)e.push(t);else{var n;this._active=!0;do{if(n=t.execute(t.state,t.delay))break}while(t=e.shift());if(this._active=!1,n){for(;t=e.shift();)t.unsubscribe();throw n}}},e}(Et),Lt=function(t){function e(){return null!==t&&t.apply(this,arguments)||this}return L(e,t),e.prototype.flush=function(t){this._active=!0;var e=this._scheduled;this._scheduled=void 0;var n,r=this.actions;t=t||r.shift();do{if(n=t.execute(t.state,t.delay))break}while((t=r[0])&&t.id===e&&r.shift());if(this._active=!1,n){for(;(t=r[0])&&t.id===e&&r.shift();)t.unsubscribe();throw n}},e}(Ot);new Lt(xt),new Ot(_t);var Tt=function(t){function e(e,n){var r=t.call(this,e,n)||this;return r.scheduler=e,r.work=n,r}return L(e,t),e.prototype.schedule=function(e,n){return void 0===n&&(n=0),n>0?t.prototype.schedule.call(this,e,n):(this.delay=n,this.state=e,this.scheduler.flush(this),this)},e.prototype.execute=function(e,n){return n>0||this.closed?t.prototype.execute.call(this,e,n):this._execute(e,n)},e.prototype.requestAsyncId=function(e,n,r){return void 0===r&&(r=0),null!=r&&r>0||null==r&&this.delay>0?t.prototype.requestAsyncId.call(this,e,n,r):(e.flush(this),0)},e}(_t),Ct=function(t){function e(){return null!==t&&t.apply(this,arguments)||this}return L(e,t),e}(Ot);new Ct(Tt);var It=function(t){function e(e,n){var r=t.call(this,e,n)||this;return r.scheduler=e,r.work=n,r}return L(e,t),e.prototype.requestAsyncId=function(e,n,r){return void 0===r&&(r=0),null!==r&&r>0?t.prototype.requestAsyncId.call(this,e,n,r):(e.actions.push(this),e._scheduled||(e._scheduled=at.requestAnimationFrame((function(){return e.flush(void 0)}))))},e.prototype.recycleAsyncId=function(e,n,r){var i;if(void 0===r&&(r=0),null!=r?r>0:this.delay>0)return t.prototype.recycleAsyncId.call(this,e,n,r);var o=e.actions;null!=n&&(null===(i=o[o.length-1])||void 0===i?void 0:i.id)!==n&&(at.cancelAnimationFrame(n),e._scheduled=void 0)},e}(_t),Pt=function(t){function e(){return null!==t&&t.apply(this,arguments)||this}return L(e,t),e.prototype.flush=function(t){this._active=!0;var e=this._scheduled;this._scheduled=void 0;var n,r=this.actions;t=t||r.shift();do{if(n=t.execute(t.state,t.delay))break}while((t=r[0])&&t.id===e&&r.shift());if(this._active=!1,n){for(;(t=r[0])&&t.id===e&&r.shift();)t.unsubscribe();throw n}},e}(Ot);new Pt(It),function(t){function e(e,n){void 0===e&&(e=Nt),void 0===n&&(n=1/0);var r=t.call(this,e,(function(){return r.frame}))||this;return r.maxFrames=n,r.frame=0,r.index=-1,r}L(e,t),e.prototype.flush=function(){for(var t,e,n=this.actions,r=this.maxFrames;(e=n[0])&&e.delay<=r&&(n.shift(),this.frame=e.delay,!(t=e.execute(e.state,e.delay))););if(t){for(;e=n.shift();)e.unsubscribe();throw t}},e.frameTimeFactor=10}(Ot);var kt,Nt=function(t){function e(e,n,r){void 0===r&&(r=e.index+=1);var i=t.call(this,e,n)||this;return i.scheduler=e,i.work=n,i.index=r,i.active=!0,i.index=e.index=r,i}return L(e,t),e.prototype.schedule=function(n,r){if(void 0===r&&(r=0),Number.isFinite(r)){if(!this.id)return t.prototype.schedule.call(this,n,r);this.active=!1;var i=new e(this.scheduler,this.work);return this.add(i),i.schedule(n,r)}return j.EMPTY},e.prototype.requestAsyncId=function(t,n,r){void 0===r&&(r=0),this.delay=t.frame+r;var i=t.actions;return i.push(this),i.sort(e.sortActions),1},e.prototype.recycleAsyncId=function(t,e,n){},e.prototype._execute=function(e,n){if(!0===this.active)return t.prototype._execute.call(this,e,n)},e.sortActions=function(t,e){return t.delay===e.delay?t.index===e.index?0:t.index>e.index?1:-1:t.delay>e.delay?1:-1},e}(_t);new Q((function(t){return t.complete()})),function(t){t.NEXT="N",t.ERROR="E",t.COMPLETE="C"}(kt||(kt={})),k((function(t){return function(){t(this),this.name="EmptyError",this.message="no elements in sequence"}})),k((function(t){return function(){t(this),this.name="ArgumentOutOfRangeError",this.message="argument out of range"}})),k((function(t){return function(e){t(this),this.name="NotFoundError",this.message=e}})),k((function(t){return function(e){t(this),this.name="SequenceError",this.message=e}})),k((function(t){return function(e){void 0===e&&(e=null),t(this),this.message="Timeout has occurred",this.name="TimeoutError",this.info=e}})),new Q(M);class Ft{constructor(t){this.fetch=async(...t)=>{if(await this.initialized,null==this.session)throw new Error("no session");return await this.session.send(...t)},this.protocol=t.protocol,this.$session=new ht(void 0),this.initialized=new Promise(((e,n)=>{this.init(t.storage).then((()=>{e(!0)})).catch((t=>{n(t)}))}))}async init(t,e){if(void 0===t){const t=(await Promise.resolve().then((function(){return zt}))).SessionLocalStorage;this.storage=new t(e?.localStorage)}else this.storage=t}get hasSession(){return void 0!==this.session}async createIfNotExists(){if(await this.initialized,void 0!==this.session)return this.session;const t=await this.protocol.run();return await this.setSession(t),t}async removeSession(){await this.initialized,await this.setSession()}async setSession(t){if(await this.initialized,this.session=t,null==t)await this.storage.clear();else{const e=t.toJSON();await this.storage.setSessionData(JSON.stringify(e))}this.$session.next(t)}async loadSession(){let t;await this.initialized;try{const e=await this.storage.getSessionData();null!==e&&(t=await E.fromJSON(this.protocol.transport,e))}catch(t){}await this.setSession(t)}}const jt={overlayClass:"wallet-protocol-overlay",modalClass:"wallet-modal",titleClass:"wallet-title",messageClass:"wallet-message",inputBoxClass:"wallet-input-box",inputClass:"wallet-input",buttonClass:"wallet-button"};var Ut=Object.freeze({__proto__:null,pinHtmlFormDialog:async(t=jt)=>{const e=Object.assign({},t,jt),n=document.createElement("div");document.body.appendChild(n),n.className=e.overlayClass;const r=document.createElement("style");n.appendChild(r),r.innerText=".__WALLET_PROTOCOL_OVERLAY__ {\n    position: absolute;\n    display: flex;\n    height: 100%;\n    width: 100%;\n    top: 0;\n    left: 0;\n    align-items: center;\n    justify-content: center;\n    background-color: #000000AA;\n    font-family: 'sans-serif';\n    color: #202531;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MODAL__ {\n    display: flex;\n    flex-direction: column;\n    align-items: center;\n    justify-content: center;\n    border: 2px solid #1A1E27;\n    border-radius: 5px;\n    padding: 10px 20px;\n    background-image: linear-gradient(to bottom left, white, #D2D6E1);\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_TITLE__ {\n    font-weight: bold;\n    padding: 5px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MESSAGE__ {\n    opacity: 0.5;\n    padding: 5px;\n    font-size: 15px\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT_BOX__ {\n    display: flex;\n    margin: 20px;\n    height: 32px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT__ {\n    border-radius: 3px;\n    border-top-right-radius: 0;\n    border-bottom-right-radius: 0;\n    outline: none;\n    padding: 5px;\n    border: 2px solid #1A1E27;\n    border-right: none;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_BUTTON__ {\n    height: 100%;\n    padding: 5px;\n    border-radius: 3px;\n    border: 2px solid #1A1E27;\n    border-top-left-radius: 0;\n    border-bottom-left-radius: 0;\n    cursor: pointer;\n}\n".replace(/__WALLET_PROTOCOL_OVERLAY__/g,e.overlayClass).replace(/__WALLET_MODAL__/g,e.modalClass).replace(/__WALLET_TITLE__/g,e.titleClass).replace(/__WALLET_MESSAGE__/g,e.messageClass).replace(/__WALLET_INPUT_BOX__/g,e.inputBoxClass).replace(/__WALLET_INPUT__/g,e.inputClass).replace(/__WALLET_BUTTON__/g,e.buttonClass);const i=document.createElement("div");n.appendChild(i),i.className=e.modalClass;const o=document.createElement("span");i.appendChild(o),o.className=e.titleClass,o.innerText="Connecting to your wallet...";const s=document.createElement("span");i.appendChild(s),s.className=e.messageClass,s.innerText="Set up your wallet on pairing mode and put the PIN here";const a=document.createElement("div");i.appendChild(a),a.className=e.inputBoxClass;const c=document.createElement("input");a.appendChild(c),c.className=e.inputClass,c.setAttribute("placeholder","pin...");const u=document.createElement("button");return a.appendChild(u),u.className=e.buttonClass,u.innerText="Syncronize",await new Promise(((t,e)=>{const r=e=>{document.body.removeChild(n),t(e??"")};u.addEventListener("click",(()=>r(c.value))),n.addEventListener("click",(t=>{t.target===n&&r()}))}))}});var zt=Object.freeze({__proto__:null,SessionLocalStorage:class{constructor(t){this.key="string"==typeof t?.key&&""!==t.key?t.key:"wallet-session"}async getSessionData(){const t=localStorage.getItem(this.key);if(null==t)throw new Error("no session data stored");return JSON.parse(t)}async setSessionData(t){localStorage.setItem(this.key,JSON.stringify(t))}async clear(){localStorage.removeItem(this.key)}}});t.LocalSessionManager=class extends Ft{constructor(t,e={}){super({protocol:t,storageOptions:{localStorage:{key:e.localStorageKey}}}),this.protocol=t}},t.SessionManager=Ft,t.openModal=n,t.pinDialog=e,Object.defineProperty(t,"__esModule",{value:!0})}));
