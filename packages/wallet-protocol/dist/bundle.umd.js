!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?e(exports):"function"==typeof define&&define.amd?define(["exports"],e):e((t="undefined"!=typeof globalThis?globalThis:t||self).walletProtocol={})}(this,(function(t){"use strict";class e{async send(t,e,r){throw new Error("this transport cannot send messages")}finish(t){t.emit("finished")}}var r={...Object.freeze({__proto__:null,COMMITMENT_LENGTH:256,DEFAULT_RANDOM_LENGTH:36,DEFAULT_TIMEOUT:3e4,INITIAL_PORT:29170,NONCE_LENGTH:128,PORT_LENGTH:12,PORT_SPACE:4096}),...Object.freeze({__proto__:null,RPC_URL_PATH:".well-known/wallet-protocol"})};class n{async generateKeys(){throw new Error("not implemented")}async getPublicKey(){throw new Error("not implemented")}async deriveBits(t){throw new Error("not implemented")}}class s{async randomFill(t,e,r){throw new Error("not implemented")}async randomFillBits(t,e,r){const n=Math.ceil(r/8),s=new Uint8Array(n);await this.randomFill(s,0,n),p.insertBits(s,t,0,e,r)}}class i{constructor(t,e){this.algorithm=t,this.key=e}async encrypt(t){throw new Error("not implemented")}async decrypt(t){throw new Error("not implemented")}}class a{async digest(t,e){throw new Error("not implemented")}}const o=new class extends s{async randomFill(t,e,r){const n=new Uint8Array(r);crypto.getRandomValues(n);for(let s=0;s<r;s++)t[e+s]=n[s]}},c={"aes-256-gcm":{name:"AES-GCM",tagLength:128}};class h extends i{async encrypt(t){const e=new Uint8Array(12);await o.randomFill(e,0,e.length);const r=c[this.algorithm],n=await crypto.subtle.importKey("raw",this.key,r,!1,["encrypt"]),s=await crypto.subtle.encrypt({...r,iv:e},n,t),i=[];return i.push(e),i.push(new Uint8Array(s)),p.join(...i)}async decrypt(t){const e=[];if("aes-256-gcm"===this.algorithm)e[0]=12;e[1]=t.length-e[0];const[r,n]=p.split(t,...e),s=c[this.algorithm],i=await crypto.subtle.importKey("raw",this.key,s,!1,["decrypt"]),a=await crypto.subtle.decrypt({...s,iv:r},i,n);return new Uint8Array(a)}}class u extends n{async generateKeys(){this.keys=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},!0,["deriveKey","deriveBits"])}async getPublicKey(){if(void 0===this.keys||void 0===this.keys.publicKey)throw new Error("keys must be initialized fist");const t=await crypto.subtle.exportKey("raw",this.keys.publicKey);return d.u8Arr2Hex(new Uint8Array(t))}async deriveBits(t){if(void 0===this.keys||void 0===this.keys.privateKey)throw new Error("keys must be generated first");const e=d.hex2U8Arr(t),r=await crypto.subtle.importKey("raw",e,{name:"ECDH",namedCurve:"P-256"},!0,[]),n=await crypto.subtle.deriveBits({name:"ECDH",public:r},this.keys.privateKey,256);return new Uint8Array(n)}}const l={sha256:"SHA-256"};const y=new class extends a{async digest(t,e){const r=l[t],n=await crypto.subtle.digest(r,e);return new Uint8Array(n)}};const d={utf2U8Arr:t=>(new TextEncoder).encode(t),u8Arr2Utf:t=>(new TextDecoder).decode(t),num2U8Arr:(t,e)=>{if(void 0===e)for(e=1;2**(8*e)<t;)e++;const r=new Uint8Array(e);let n=t;for(let t=e-1;t>=0;t--){const e=n>>8,s=n-(e<<8);r[t]=s,n=e}return r},u8Arr2Num:t=>{let e=0;for(let r=0;r<t.length;r++)e+=t[r]<<t.length-1-r;return e},hex2U8Arr:t=>{const e=t.match(/.{1,2}/g);if(null===e)throw new Error(`not a hex: ${t}`);return new Uint8Array(e.map((t=>parseInt(t,16))))},u8Arr2Hex:t=>t.reduce(((t,e)=>t+e.toString(16).padStart(2,"0")),""),u8Arr2Base64:t=>function(t,e=!1,r=!0){let n="";return n=(t=>{const e=[];for(let r=0;r<t.length;r+=32768)e.push(String.fromCharCode.apply(null,t.subarray(r,r+32768)));return btoa(e.join(""))})("string"==typeof t?(new TextEncoder).encode(t):new Uint8Array(t)),e&&(n=function(t){return t.replace(/\+/g,"-").replace(/\//g,"_")}(n)),r||(n=n.replace(/=/g,"")),n}(t,!0,!1),base642U8Arr:t=>function(t,e=!1){{let r=!1;if(/^[0-9a-zA-Z_-]+={0,2}$/.test(t))r=!0;else if(!/^[0-9a-zA-Z+/]*={0,2}$/.test(t))throw new Error("Not a valid base64 input");r&&(t=t.replace(/-/g,"+").replace(/_/g,"/").replace(/=/g,""));const n=new Uint8Array(atob(t).split("").map((t=>t.charCodeAt(0))));return e?(new TextDecoder).decode(n):n}}(t,!1)},p={join:(...t)=>{const e=t.reduce(((t,e)=>t+e.length),0),r=new Uint8Array(e);let n=0;for(const e of t)r.set(e,n),n+=e.length;return r},split:(t,...e)=>{const r=[];let n=0;for(const s of e)r.push(t.slice(n,n+s)),n+=s;return r},insertBytes:(t,e,r,n,s)=>{for(let i=0;i<s;i++)e[i+n]=t[i+r]},insertBits:(t,e,r,n,s)=>{let i=Math.floor(r/8),a=r%8,o=Math.floor(n/8),c=n%8,h=t[i]??0;const u=c-a;for(let r=0;r<s;r++){let r;r=u>=0?(h&128>>a)<<u:h&128>>a;const n=e[o]&~(128>>c)|r;e[o]=n,a++,c++,a>=8&&(i++,a=0,h=t[i]??0),c>=8&&(o++,c=0)}},extractBits:(t,e,r)=>{const n=Math.ceil(r/8),s=new Uint8Array(n);return p.insertBits(t,s,e,0,r),s}};class w{constructor(t){this.maxLength=t,this._values=new Array(t),this._first=0,this._length=0}get length(){return this._length}push(t){this._values[this.lastIndex]=t,this.length>=this.maxLength?this._first=(this._first+1)%this.maxLength:this._length++}pop(){if(this.length>0){const t=this._values[this._first];return this._first=(this._first+1)%this.maxLength,this._length--,t}}get lastIndex(){return(this._first+this._length)%this.maxLength}get last(){return this._values[this.lastIndex]}}class f{constructor(t=1){this.queueLength=t,this.queue=new w(t)}get promise(){return this.createPromise()}async createPromise(){const t=this.queue.pop();return void 0!==t?t:await new Promise(((t,e)=>{if(void 0!==this.rejectPending||void 0!==this.resolvePending)return e(new O("wallet protocol: cannot create two promises of one subject")),void this.unbindPromise();this.resolvePending=e=>{t(e)},this.rejectPending=t=>e(t)}))}next(t){null!=this.resolvePending?(this.resolvePending(t),this.unbindPromise()):this.queue.push(t)}err(t){null!=this.rejectPending&&(this.rejectPending(t),this.unbindPromise())}finish(){void 0!==this.rejectPending&&(this.rejectPending(new O("wallet protocol: the subject has a pending promise")),this.unbindPromise())}unbindPromise(){this.resolvePending=void 0,this.rejectPending=void 0}}const g={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function A(t,e,r,n,s="SHA-256"){return new Promise(((i,a)=>{s in g||a(new RangeError(`Valid hash algorithm values are any of ${Object.keys(g).toString()}`)),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)||a(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof e?e=(new TextEncoder).encode(e):e instanceof ArrayBuffer?e=new Uint8Array(e):ArrayBuffer.isView(e)?e=new Uint8Array(e.buffer,e.byteOffset,e.byteLength):a(RangeError("S should be string, ArrayBuffer, TypedArray, DataView")),crypto.subtle.importKey("raw",t,"PBKDF2",!1,["deriveBits"]).then((o=>{const c={name:"PBKDF2",hash:s,salt:e,iterations:r};crypto.subtle.deriveBits(c,o,8*n).then((t=>i(t)),(o=>{(async function(t,e,r,n,s){if(!(s in g))throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(g).toString()}`);if(!Number.isInteger(r)||r<=0)throw new RangeError("c must be a positive integer");const i=g[s].outputLength;if(!Number.isInteger(n)||n<=0||n>=(2**32-1)*i)throw new RangeError("dkLen must be a positive integer < (2 ** 32 - 1) * hLen");const a=Math.ceil(n/i),o=n-(a-1)*i,c=new Array(a);0===t.byteLength&&(t=new Uint8Array(g[s].blockSize));const h=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:{name:s}},!0,["sign"]),u=async function(t,e){const r=await crypto.subtle.sign("HMAC",t,e);return new Uint8Array(r)};for(let t=0;t<a;t++)c[t]=await l(h,e,r,t+1);async function l(t,e,r,n){const s=await u(t,m(e,function(t){const e=new ArrayBuffer(4);return new DataView(e).setUint32(0,t,!1),new Uint8Array(e)}(n)));let i=s;for(let e=1;e<r;e++)i=await u(t,i),b(s,i);return s}return c[a-1]=c[a-1].slice(0,o),m(...c).buffer})(t,e,r,n,s).then((t=>i(t)),(t=>a(t)))}))}),(t=>a(t)))}))}function m(...t){const e=t.reduce(((t,e)=>t+e.length),0);if(0===t.length)throw new RangeError("Cannot concat no arrays");const r=new Uint8Array(e);let n=0;for(const e of t)r.set(e,n),n+=e.length;return r}function b(t,e){for(let r=0;r<t.length;r++)t[r]^=e[r]}function x(t){return null!=t&&"object"==typeof t&&!Array.isArray(t)}function E(t){return x(t)||Array.isArray(t)?Array.isArray(t)?t.map((t=>Array.isArray(t)||x(t)?E(t):t)):Object.keys(t).sort().map((e=>[e,E(t[e])])):t}function v(t){return JSON.stringify(E(t))}function S(t,e="SHA-256"){const r=["SHA-1","SHA-256","SHA-384","SHA-512"];if(!r.includes(e))throw RangeError(`Valid hash algorithm values are any of ${JSON.stringify(r)}`);return async function(t,e){const r=(new TextEncoder).encode(v(t)).buffer;let n="";{const t=await crypto.subtle.digest(e,r),s="0123456789abcdef";new Uint8Array(t).forEach((t=>{n+=s[t>>4]+s[15&t]}))}return n}(t,e)}class U{constructor(){this.events={}}on(t,e){return void 0===this.events[t]&&(this.events[t]=[]),this.events[t].push(e),this}emit(t,...e){const r=this.events[t];return void 0!==r&&(r.forEach((t=>t(...e))),!0)}}const P=async(t,e,r)=>{const n=new Uint8Array(16),s=new Uint8Array(96),i=d.hex2U8Arr(t),a=d.hex2U8Arr(e);p.insertBytes(r,s,0,0,32),p.insertBytes(i,s,0,32,32),p.insertBytes(a,s,0,64,32);const o=await A(s,n,1,32);return new Uint8Array(o)};class T{constructor(t,e,r,n,s,i,a,o){this.port=t,this.from=e,this.to=r,this.na=n,this.nb=s,this.secret=i,this.cipher=new h("aes-256-gcm",a),this.decipher=new h("aes-256-gcm",o)}async encrypt(t){return await this.cipher.encrypt(t)}async decrypt(t){return await this.decipher.decrypt(t)}toJSON(){return{from:this.from,to:this.to,port:this.port,na:d.u8Arr2Base64(this.na),nb:d.u8Arr2Base64(this.nb),secret:d.u8Arr2Base64(this.secret)}}async fromHash(){return await S(this.from)}async toHash(){return await S(this.to)}static async fromSecret(t,e,r,n,s,i){const a=await S(e),o=await S(r),c=await P(a,o,i),h=await P(o,a,i);return new T(t,e,r,n,s,i,c,h)}static async fromJSON(t){const e=d.base642U8Arr(t.na),r=d.base642U8Arr(t.nb),n=d.base642U8Arr(t.secret);return await this.fromSecret(t.port,t.from,t.to,e,r,n)}}class _{constructor(t,e,r){this.transport=t,this.masterKey=e,this.code=r}async send(t){return await this.transport.send(this.masterKey,this.code,t)}toJSON(){return{masterKey:this.masterKey.toJSON(),code:d.u8Arr2Hex(this.code)}}static async fromJSON(t,e){const r=await T.fromJSON(e.masterKey),n=d.hex2U8Arr(e.code);let s;if("object"==typeof t)s=t;else{if(!(t instanceof Function))throw new Error("First param must be transport or constructor of transport");s=new t}return new _(s,r,n)}}class N{constructor(t,e){this.buffer=t,this.l=e}toString(){return d.u8Arr2Base64(this.buffer)}extractPort(){const t=Math.ceil(r.PORT_LENGTH/8),e=this.l%8,n=new Uint8Array(t);p.insertBits(this.buffer,n,this.l,e,r.PORT_LENGTH);const s=d.u8Arr2Num(n);return r.INITIAL_PORT+s}extractRb(){return p.extractBits(this.buffer,0,this.l)}static async generate(t,e){const n=Math.ceil((e+r.PORT_LENGTH)/8),s=new Uint8Array(n);await o.randomFillBits(s,0,e);const i=t-r.INITIAL_PORT;if(i<0||i>r.PORT_SPACE)throw new Error(`the port ${t} is out of the port space`);const a=d.num2U8Arr(i,2);return p.insertBits(a,s,16-r.PORT_LENGTH,e,r.PORT_LENGTH),new N(s,e)}static fromString(t,e){return new N(d.base642U8Arr(t),e)}}const B={async generate(t){console.warn("Using the default code verifier. Note that it is not secure for production.");const e=await t.toJSON();return d.utf2U8Arr(JSON.stringify(e))},async getMasterKey(t){const e=d.u8Arr2Utf(t);return await T.fromJSON(JSON.parse(e))}};class O extends Error{}class L extends O{}class R extends e{constructor(t={}){super(),this.opts={host:t.host??"::1",id:t.id??{name:"Initiator"},l:t.l??r.DEFAULT_RANDOM_LENGTH,getConnectionString:t.getConnectionString??(async()=>{throw new Error("getConnectionString must be provided")})}}async prepare(t,e){const r=await this.opts.getConnectionString();if(""===r)throw new L("empty connection string");try{this.connString=N.fromString(r,this.opts.l)}catch(t){throw new L("invalid pin format")}const n=Math.ceil(this.opts.l/8),s=new Uint8Array(n);return await o.randomFillBits(s,0,this.opts.l),{id:this.opts.id,publicKey:e,rx:s}}async publicKeyExchange(t,e){if(void 0===this.connString)throw new L("missing connection string");const r=await this.sendRequest({method:"publicKeyExchange",sender:this.opts.id,publicKey:e.publicKey,ra:d.u8Arr2Base64(e.rx)}),n={id:r.sender,publicKey:r.publicKey,rx:this.connString.extractRb()};return{a:e,b:n,port:this.connString.extractPort(),sent:e,received:n}}async authentication(t,e){const r=await this.sendRequest({method:"commitment",cx:d.u8Arr2Base64(e.cx)}),n=await this.sendRequest({method:"nonce",nx:d.u8Arr2Base64(e.nx)}),s={cx:d.base642U8Arr(r.cx),nx:d.base642U8Arr(n.nx),r:e.r};return{a:e,b:{cx:d.base642U8Arr(r.cx),nx:d.base642U8Arr(n.nx),r:e.r},sent:e,received:s}}async verification(t,e){const r=await this.sendRequest({method:"verification"}),n=d.base642U8Arr(r.ciphertext);return await e.decrypt(n)}finish(t){super.finish(t),this.connString=void 0}}class K extends e{constructor(t={}){super(),this.opts={port:t.port??r.INITIAL_PORT,timeout:t.timeout??r.DEFAULT_TIMEOUT,id:t.id??{name:"Responder"},l:t.l??r.DEFAULT_RANDOM_LENGTH,codeGenerator:t.codeGenerator??B},this.rpcSubject=new f}async pairing(t,e,r){this.stopPairing(),this.connString=await N.generate(e,this.opts.l),this.lastPairing=setTimeout((()=>{this.stopPairing(),this.finish(t)}),r)}stopPairing(){null!=this.lastPairing&&(clearTimeout(this.lastPairing),this.lastPairing=void 0)}get isPairing(){return void 0!==this.connString}get port(){return this.opts.port}get timeout(){return this.opts.timeout}async prepare(t,e){if(await this.pairing(t,this.port,this.timeout),null===this.connString||void 0===this.connString)throw new Error("could not generate connection string");return t.emit("connString",this.connString),{id:this.opts.id,publicKey:e,rx:this.connString.extractRb()}}async waitRequest(t){for(;;){const e=await this.rpcSubject.promise;if(e.req.method===t)return e}}async publicKeyExchange(t,e){if(void 0===this.connString)throw new Error("protocol not properly initialized");const{req:r,res:n}=await this.waitRequest("publicKeyExchange");await n.send({method:"publicKeyExchange",sender:e.id,publicKey:e.publicKey});const s={id:r.sender,publicKey:r.publicKey,rx:d.base642U8Arr(r.ra??"")};return{a:s,b:e,port:this.connString.extractPort(),sent:e,received:s}}async authentication(t,e){const r=await this.waitRequest("commitment");await r.res.send({method:"commitment",cx:d.u8Arr2Base64(e.cx)});const n=r.req,s=await this.waitRequest("nonce");await s.res.send({method:"nonce",nx:d.u8Arr2Base64(e.nx)});const i=s.req,a={cx:d.base642U8Arr(n.cx),nx:d.base642U8Arr(i.nx),r:e.r};return{a:a,b:e,sent:e,received:a}}async verification(t,e){const r=await this.waitRequest("verification"),n=await this.opts.codeGenerator.generate(e),s=await e.encrypt(n);return await r.res.send({method:"verificationChallenge",ciphertext:d.u8Arr2Base64(s)}),n}finish(t){super.finish(t),this.stopPairing(),this.rpcSubject.finish(),this.connString=void 0}}class H{}class C extends H{constructor(t){super(),this.res=t}async send(t){this.res.write(JSON.stringify(t)),this.res.end()}}t.BaseTransport=e,t.ConnectionString=N,t.HttpInitiatorTransport=class extends R{async baseSend(t,e){{const s=`http://${n=this.opts.host,/(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi.test(n)?`[${this.opts.host}]`:this.opts.host}:${t}/${r.RPC_URL_PATH}`,i=await fetch(s,e),a=await i.text();return{status:i.status,body:a}}var n}async sendRequest(t){if(void 0===this.connString)throw new Error("cannot connect to the rpc yet: port missing");const e=this.connString.extractPort(),r=await this.baseSend(e,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(t)});return JSON.parse(r.body)}async send(t,e,r){const n=d.utf2U8Arr(JSON.stringify(r)),s=await t.encrypt(n),i=await this.baseSend(t.port,{method:"POST",headers:{Authorization:d.u8Arr2Utf(e)},body:d.u8Arr2Base64(s)});if(i.status<=300&&i.status>=200){const e=d.base642U8Arr(i.body),r=await t.decrypt(e);i.body=d.u8Arr2Utf(r)}return i}},t.HttpResponderTransport=class extends K{constructor(t){super(t),this.listeners=[],this.rpcUrl=t?.rpcUrl??`/${r.RPC_URL_PATH}`}async readRequestBody(t){const e=[];for await(const r of t)e.push(r);return Buffer.concat(e).toString()}async dispatchProtocolMessage(t,e){if(!this.isPairing)throw new Error("not in pairing mode");const r=await this.readRequestBody(t),n=JSON.parse(r);this.rpcSubject.next({req:n,res:new C(e)})}async dispatchEncryptedMessage(t,e,r){const n=d.utf2U8Arr(r),s=await this.opts.codeGenerator.getMasterKey(n),i=await this.readRequestBody(t),a=d.base642U8Arr(i),o=await s.decrypt(a),c=d.u8Arr2Utf(o),h=JSON.parse(c);let u={};const l=h.init??{};void 0!==l.body&&""!==l.body&&(u=JSON.parse(l.body));const y=Object.entries(l.headers??{}).reduce(((t,[e,r])=>(t[e.toLocaleLowerCase()]=r,t)),t.headers),p=new Proxy(t,{get(t,e){switch(e){case"url":return h.url;case"method":return l.method;case"headers":return y;case"_body":case"walletProtocol":return!0;case"body":return u;default:return t[e]}}});e.end=new Proxy(e.end,{apply:(t,r,n)=>{const i=void 0===r.statusCode?500:r.statusCode;if(i>=200&&i<300){const i=n[0],a=async()=>{let a;if("string"==typeof i)a=d.utf2U8Arr(i);else{if(!(i instanceof Buffer))throw new Error("cannot manage this chunk...");a=i}const o=await s.encrypt(a),c=d.u8Arr2Base64(o);e.setHeader("Content-Length",c.length),t.call(r,c,...n.slice(1))};a().catch((t=>{console.error(t)}))}else t.call(r,...n)}}),await this.callListeners(p,e)}async dispatchRequest(t,e){if(t.url===this.rpcUrl){if("POST"!==t.method)throw new Error("method must be POST");return void 0!==t.headers.authorization?await this.dispatchEncryptedMessage(t,e,t.headers.authorization):await this.dispatchProtocolMessage(t,e)}await this.callListeners(t,e)}async callListeners(t,e){for(const r of this.listeners)r(t,e)}use(t){this.listeners.push(t)}},t.InvalidPinError=L,t.MasterKey=T,t.Queue=w,t.Session=_,t.Subject=f,t.WalletProtocol=class extends U{constructor(t){super(),this.transport=t}async computeR(t,e){return t.map(((t,r)=>t^e[r]))}async computeNx(){const t=Math.ceil(r.NONCE_LENGTH/8),e=new Uint8Array(t);return await o.randomFillBits(e,0,r.NONCE_LENGTH),e}async computeCx(t,e,n){const s=Math.ceil(r.NONCE_LENGTH/8),i=Math.ceil(r.DEFAULT_RANDOM_LENGTH/8),a=d.hex2U8Arr(t.a.publicKey),o=d.hex2U8Arr(t.b.publicKey),c=new Uint8Array(64+s+i);p.insertBytes(a,c,1,0,32),p.insertBytes(o,c,1,32,32),p.insertBits(e,c,0,512,r.NONCE_LENGTH),p.insertBits(n,c,0,512+r.NONCE_LENGTH,r.DEFAULT_RANDOM_LENGTH);return await y.digest("sha256",c)}async validateAuthData(t,e){const{cx:r,nx:n}=e.received,{cx:s,nx:i,r:a}=e.sent;if(!(r.length===s.length&&n.length===i.length))throw new L("invalid received auth data length");if(r.every(((t,e)=>t===s[e])))throw new L("received and sent Cx are the same");if(!(await this.computeCx(t,n,a)).every(((t,e)=>t===r[e])))throw new L("received a wrong Cx")}async computeMasterKey(t,e,n){const s=Math.ceil(r.NONCE_LENGTH/8),i=await t.deriveBits(e.received.publicKey),a=new Uint8Array(16),o=new Uint8Array(32+2*s+6+64),c=new Uint8Array([109,97,115,116,101,114]),h=await S(e.a,"SHA-256"),u=d.hex2U8Arr(h),l=await S(e.b,"SHA-256"),y=d.hex2U8Arr(l);p.insertBytes(i,o,0,0,32),p.insertBytes(n.a.nx,o,0,32,s),p.insertBytes(n.a.nx,o,0,32+s,s),p.insertBytes(c,o,0,32+2*s,6),p.insertBytes(u,o,0,32+2*s+6,32),p.insertBytes(y,o,0,32+2*s+6+32,32);const w=await A(o,a,1,32);return await T.fromSecret(e.port,e.sent.id,e.received.id,n.a.nx,n.b.nx,new Uint8Array(w))}async run(){const t=(async()=>{const t=new u;await t.generateKeys();const e=await t.getPublicKey(),r=await this.transport.prepare(this,e);let n;try{n=await this.transport.publicKeyExchange(this,r)}catch(t){if(t instanceof TypeError)throw new L(t.message);throw t}const s=await this.computeR(n.a.rx,n.b.rx),i=await this.computeNx(),a={r:s,nx:i,cx:await this.computeCx(n,i,s)},o=await this.transport.authentication(this,a);await this.validateAuthData(n,o);const c=await this.computeMasterKey(t,n,o),h=await this.transport.verification(this,c),l=new _(this.transport,c,h);return this.emit("masterKey",c),l})();return this._running=t,t.finally((()=>{this.transport.finish(this),this._running=void 0})),await t}get isRunning(){return void 0!==this._running}async finish(){this.transport.finish(this),void 0!==this._running&&await this._running.catch((()=>{}))}on(t,e){return super.on(t,e)}emit(t,...e){return super.emit(t,...e)}},t.WalletProtocolError=O,t.constants=r,t.defaultCodeGenerator=B}));
