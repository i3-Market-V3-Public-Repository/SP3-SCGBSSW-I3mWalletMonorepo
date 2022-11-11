var walletProtocol=function(t){"use strict";class e{async send(t,e,r){throw new Error("this transport cannot send messages")}finish(t){t.emit("finished")}}var r={...Object.freeze({__proto__:null,PORT_LENGTH:12,DEFAULT_RANDOM_LENGTH:36,DEFAULT_TIMEOUT:3e4,PORT_SPACE:4096,INITIAL_PORT:29170,NONCE_LENGTH:128,COMMITMENT_LENGTH:256}),...Object.freeze({__proto__:null,RPC_URL_PATH:".well-known/wallet-protocol"})};class n{async generateKeys(){throw new Error("not implemented")}async getPublicKey(){throw new Error("not implemented")}async deriveBits(t){throw new Error("not implemented")}}class s{constructor(t,e){this.algorithm=t,this.key=e}async encrypt(t){throw new Error("not implemented")}async decrypt(t){throw new Error("not implemented")}}const i=void 0,a=void 0;function o(t,e=!1,r=!0){let n="";n=(t=>{const e=[];for(let r=0;r<t.length;r+=32768)e.push(String.fromCharCode.apply(null,t.subarray(r,r+32768)));return btoa(e.join(""))})("string"==typeof t?(new TextEncoder).encode(t):new Uint8Array(t));return e&&(n=function(t){return t.replace(/\+/g,"-").replace(/\//g,"_")}(n)),r||(n=n.replace(/=/g,"")),n}function c(t,e=!1){{let r=!1;if(/^[0-9a-zA-Z_-]+={0,2}$/.test(t))r=!0;else if(!/^[0-9a-zA-Z+/]*={0,2}$/.test(t))throw new Error("Not a valid base64 input");r&&(t=t.replace(/-/g,"+").replace(/_/g,"/").replace(/=/g,""));const n=new Uint8Array(atob(t).split("").map((t=>t.charCodeAt(0))));return e?(new TextDecoder).decode(n):n}}const h=t=>(new TextEncoder).encode(t),u=t=>(new TextDecoder).decode(t),l=(t,e)=>{if(void 0===e)for(e=1;2**(8*e)<t;)e++;const r=new Uint8Array(e);let n=t;for(let t=e-1;t>=0;t--){const e=n>>8,s=n-(e<<8);r[t]=s,n=e}return r},y=t=>{let e=0;for(let r=0;r<t.length;r++)e+=t[r]<<t.length-1-r;return e},p=t=>{const e=t.match(/.{1,2}/g);if(null===e)throw new Error(`not a hex: ${t}`);return new Uint8Array(e.map((t=>parseInt(t,16))))},d=t=>t.reduce(((t,e)=>t+e.toString(16).padStart(2,"0")),""),w=t=>o(t,!0,!1),f=t=>c(t,!1),g={join:(...t)=>{const e=t.reduce(((t,e)=>t+e.length),0),r=new Uint8Array(e);let n=0;for(const e of t)r.set(e,n),n+=e.length;return r},split:(t,...e)=>{const r=[];let n=0;for(const s of e)r.push(t.slice(n,n+s)),n+=s;return r},insertBytes:(t,e,r,n,s)=>{for(let i=0;i<s;i++)e[i+n]=t[i+r]},insertBits:(t,e,r,n,s)=>{let i=Math.floor(r/8),a=r%8,o=Math.floor(n/8),c=n%8,h=t[i]??0;const u=c-a;for(let r=0;r<s;r++){let r;r=u>=0?(h&128>>a)<<u:h&128>>a;const n=e[o]&~(128>>c)|r;e[o]=n,a++,c++,a>=8&&(i++,a=0,h=t[i]??0),c>=8&&(o++,c=0)}},extractBits:(t,e,r)=>{const n=Math.ceil(r/8),s=new Uint8Array(n);return g.insertBits(t,s,e,0,r),s}};class m{get promise(){return this.createPromise()}async createPromise(){return await new Promise(((t,e)=>{this.resolve=t,this.reject=e}))}next(t){null!=this.resolve&&this.resolve(t)}err(t){null!=this.reject&&this.reject(t)}}const b={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function A(t,e,r,n,s="SHA-256"){return new Promise(((i,a)=>{s in b||a(new RangeError(`Valid hash algorithm values are any of ${Object.keys(b).toString()}`)),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)||a(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof e?e=(new TextEncoder).encode(e):e instanceof ArrayBuffer?e=new Uint8Array(e):ArrayBuffer.isView(e)?e=new Uint8Array(e.buffer,e.byteOffset,e.byteLength):a(RangeError("S should be string, ArrayBuffer, TypedArray, DataView")),crypto.subtle.importKey("raw",t,"PBKDF2",!1,["deriveBits"]).then((o=>{const c={name:"PBKDF2",hash:s,salt:e,iterations:r};crypto.subtle.deriveBits(c,o,8*n).then((t=>i(t)),(o=>{(async function(t,e,r,n,s){if(!(s in b))throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(b).toString()}`);if(!Number.isInteger(r)||r<=0)throw new RangeError("c must be a positive integer");const i=b[s].outputLength;if(!Number.isInteger(n)||n<=0||n>=(2**32-1)*i)throw new RangeError("dkLen must be a positive integer < (2 ** 32 - 1) * hLen");const a=Math.ceil(n/i),o=n-(a-1)*i,c=new Array(a);0===t.byteLength&&(t=new Uint8Array(b[s].blockSize));const h=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:{name:s}},!0,["sign"]),u=async function(t,e){const r=await crypto.subtle.sign("HMAC",t,e);return new Uint8Array(r)};for(let t=0;t<a;t++)c[t]=await l(h,e,r,t+1);async function l(t,e,r,n){function s(t){const e=new ArrayBuffer(4);return new DataView(e).setUint32(0,t,!1),new Uint8Array(e)}const i=await u(t,S(e,s(n)));let a=i;for(let e=1;e<r;e++)a=await u(t,a),E(i,a);return i}return c[a-1]=c[a-1].slice(0,o),S(...c).buffer})(t,e,r,n,s).then((t=>i(t)),(t=>a(t)))}))}),(t=>a(t)))}))}function S(...t){const e=t.reduce(((t,e)=>t+e.length),0);if(0===t.length)throw new RangeError("Cannot concat no arrays");const r=new Uint8Array(e);let n=0;for(const e of t)r.set(e,n),n+=e.length;return r}function E(t,e){for(let r=0;r<t.length;r++)t[r]^=e[r]}function x(t){return null!=t&&"object"==typeof t&&!Array.isArray(t)}function T(t){return x(t)||Array.isArray(t)?Array.isArray(t)?t.map((t=>Array.isArray(t)||x(t)?T(t):t)):Object.keys(t).sort().map((e=>[e,T(t[e])])):t}function N(t){return JSON.stringify(T(t))}function v(t,e="SHA-256"){const r=["SHA-1","SHA-256","SHA-384","SHA-512"];if(!r.includes(e))throw RangeError(`Valid hash algorithm values are any of ${JSON.stringify(r)}`);return async function(t,e){const r=(new TextEncoder).encode(N(t)).buffer;let n="";{const t=await crypto.subtle.digest(e,r),s="0123456789abcdef";new Uint8Array(t).forEach((t=>{n+=s[t>>4]+s[15&t]}))}return n}(t,e)}class O{constructor(){this.events={}}on(t,e){return void 0===this.events[t]&&(this.events[t]=[]),this.events[t].push(e),this}emit(t,...e){const r=this.events[t];return void 0!==r&&(r.forEach((t=>t(...e))),!0)}}const P=async(t,e,r)=>{const n=new Uint8Array(16),s=new Uint8Array(96),i=p(t),a=p(e);g.insertBytes(r,s,0,0,32),g.insertBytes(i,s,0,32,32),g.insertBytes(a,s,0,64,32);const o=await A(s,n,1,32);return new Uint8Array(o)};class R{constructor(t,e,r,n,i,a,o,c){this.port=t,this.from=e,this.to=r,this.na=n,this.nb=i,this.secret=a,this.cipher=new s("aes-256-gcm",o),this.decipher=new s("aes-256-gcm",c)}async encrypt(t){return await this.cipher.encrypt(t)}async decrypt(t){return await this.decipher.decrypt(t)}toJSON(){return{from:this.from,to:this.to,port:this.port,na:w(this.na),nb:w(this.nb),secret:w(this.secret)}}async fromHash(){return await v(this.from)}async toHash(){return await v(this.to)}static async fromSecret(t,e,r,n,s,i){const a=await v(e),o=await v(r),c=await P(a,o,i),h=await P(o,a,i);return new R(t,e,r,n,s,i,c,h)}static async fromJSON(t){const e=f(t.na),r=f(t.nb),n=f(t.secret);return await this.fromSecret(t.port,t.from,t.to,e,r,n)}}class _{constructor(t,e,r){this.transport=t,this.masterKey=e,this.code=r}async send(t){return await this.transport.send(this.masterKey,this.code,t)}toJSON(){return{masterKey:this.masterKey.toJSON(),code:d(this.code)}}static async fromJSON(t,e){const r=await R.fromJSON(e.masterKey),n=p(e.code);let s;if("object"==typeof t)s=t;else{if(!(t instanceof Function))throw new Error("First param must be transport or constructor of transport");s=new t}return new _(s,r,n)}}class L{constructor(t,e){this.buffer=t,this.l=e}toString(){return w(this.buffer)}extractPort(){const t=Math.ceil(r.PORT_LENGTH/8),e=this.l%8,n=new Uint8Array(t);g.insertBits(this.buffer,n,this.l,e,r.PORT_LENGTH);const s=y(n);return r.INITIAL_PORT+s}extractRb(){return g.extractBits(this.buffer,0,this.l)}static async generate(t,e){const n=Math.ceil((e+r.PORT_LENGTH)/8),s=new Uint8Array(n);await i.randomFillBits(s,0,e);const a=t-r.INITIAL_PORT;if(a<0||a>r.PORT_SPACE)throw new Error(`the port ${t} is out of the port space`);const o=l(a,2);return g.insertBits(o,s,16-r.PORT_LENGTH,e,r.PORT_LENGTH),new L(s,e)}static fromString(t,e){return new L(f(t),e)}}const U={async generate(t){console.warn("Using the default code verifier. Note that it is not secure for production.");const e=await t.toJSON();return h(JSON.stringify(e))},async getMasterKey(t){const e=u(t);return await R.fromJSON(JSON.parse(e))}};class B extends e{constructor(t={}){super(),this.opts={host:t.host??"localhost",id:t.id??{name:"Initiator"},l:t.l??r.DEFAULT_RANDOM_LENGTH,getConnectionString:t.getConnectionString??(async()=>{throw new Error("getConnectionString must be provided")})}}async prepare(t,e){const r=await this.opts.getConnectionString();if(""===r)throw new Error("empty connection string");this.connString=L.fromString(r,this.opts.l);const n=Math.ceil(this.opts.l/8),s=new Uint8Array(n);return await i.randomFillBits(s,0,this.opts.l),{id:this.opts.id,publicKey:e,rx:s}}async publicKeyExchange(t,e){if(void 0===this.connString)throw new Error("missing connection string");const r=await this.sendRequest({method:"publicKeyExchange",sender:this.opts.id,publicKey:e.publicKey,ra:w(e.rx)}),n={id:r.sender,publicKey:r.publicKey,rx:this.connString.extractRb()};return{a:e,b:n,port:this.connString.extractPort(),sent:e,received:n}}async authentication(t,e){const r=await this.sendRequest({method:"commitment",cx:w(e.cx)}),n=await this.sendRequest({method:"nonce",nx:w(e.nx)}),s={cx:f(r.cx),nx:f(n.nx),r:e.r};return{a:e,b:{cx:f(r.cx),nx:f(n.nx),r:e.r},sent:e,received:s}}async verification(t,e){const r=await this.sendRequest({method:"verification"}),n=f(r.ciphertext);return await e.decrypt(n)}finish(t){super.finish(t),this.connString=void 0}}class H extends e{constructor(t={}){super(),this.opts={port:t.port??r.INITIAL_PORT,timeout:t.timeout??r.DEFAULT_TIMEOUT,id:t.id??{name:"Responder"},l:t.l??r.DEFAULT_RANDOM_LENGTH,codeGenerator:t.codeGenerator??U},this.rpcSubject=new m}async pairing(t,e,r){this.stopPairing(),this.connString=await L.generate(e,this.opts.l),this.lastPairing=setTimeout((()=>{this.stopPairing(),this.finish(t)}),r)}stopPairing(){null!=this.lastPairing&&(clearTimeout(this.lastPairing),this.lastPairing=void 0)}get isPairing(){return void 0!==this.connString}get port(){return this.opts.port}get timeout(){return this.opts.timeout}async prepare(t,e){if(await this.pairing(t,this.port,this.timeout),null===this.connString||void 0===this.connString)throw new Error("could not generate connection string");return t.emit("connString",this.connString),{id:this.opts.id,publicKey:e,rx:this.connString.extractRb()}}async waitRequest(t){for(;;){const e=await this.rpcSubject.promise;if(e.req.method===t)return e}}async publicKeyExchange(t,e){if(void 0===this.connString)throw new Error("protocol not properly initialized");const{req:r,res:n}=await this.waitRequest("publicKeyExchange");await n.send({method:"publicKeyExchange",sender:e.id,publicKey:e.publicKey});const s={id:r.sender,publicKey:r.publicKey,rx:f(r.ra??"")};return{a:s,b:e,port:this.connString.extractPort(),sent:e,received:s}}async authentication(t,e){const r=await this.waitRequest("commitment");await r.res.send({method:"commitment",cx:w(e.cx)});const n=r.req,s=await this.waitRequest("nonce");await s.res.send({method:"nonce",nx:w(e.nx)});const i=s.req,a={cx:f(n.cx),nx:f(i.nx),r:e.r};return{a:a,b:e,sent:e,received:a}}async verification(t,e){const r=await this.waitRequest("verification"),n=await this.opts.codeGenerator.generate(e),s=await e.encrypt(n);return await r.res.send({method:"verificationChallenge",ciphertext:w(s)}),n}finish(t){super.finish(t),this.stopPairing(),this.rpcSubject.err("Finished"),this.connString=void 0}}class K{}class C extends K{constructor(t){super(),this.res=t}async send(t){this.res.write(JSON.stringify(t)),this.res.end()}}return t.BaseTransport=e,t.ConnectionString=L,t.HttpInitiatorTransport=class extends B{buildRpcUrl(t){return`http://${this.opts.host}:${t}/${r.RPC_URL_PATH}`}async baseSend(t,e){{const r=this.buildRpcUrl(t),n=await fetch(r,e),s=await n.text();return{status:n.status,body:s}}}async sendRequest(t){if(void 0===this.connString)throw new Error("cannot connect to the rpc yet: port missing");const e=this.connString.extractPort(),r=await this.baseSend(e,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(t)});return JSON.parse(r.body)}async send(t,e,r){const n=h(JSON.stringify(r)),s=await t.encrypt(n),i=await this.baseSend(t.port,{method:"POST",headers:{Authorization:u(e)},body:w(s)});if(i.status<=300&&i.status>=200){const e=f(i.body),r=await t.decrypt(e);i.body=u(r)}return i}},t.HttpResponderTransport=class extends H{constructor(t){super(t),this.listeners=[],this.rpcUrl=t?.rpcUrl??`/${r.RPC_URL_PATH}`}async readRequestBody(t){const e=[];for await(const r of t)e.push(r);return Buffer.concat(e).toString()}async dispatchProtocolMessage(t,e){if(!this.isPairing)throw new Error("not in pairing mode");const r=await this.readRequestBody(t),n=JSON.parse(r);this.rpcSubject.next({req:n,res:new C(e)})}async dispatchEncryptedMessage(t,e,r){const n=h(r),s=await this.opts.codeGenerator.getMasterKey(n),i=await this.readRequestBody(t),a=f(i),o=await s.decrypt(a),c=u(o),l=JSON.parse(c);let y={};const p=l.init??{};void 0!==p.body&&""!==p.body&&(y=JSON.parse(p.body));const d=Object.entries(p.headers??{}).reduce(((t,[e,r])=>(t[e.toLocaleLowerCase()]=r,t)),t.headers),g=new Proxy(t,{get(t,e){switch(e){case"url":return l.url;case"method":return p.method;case"headers":return d;case"_body":case"walletProtocol":return!0;case"body":return y;default:return t[e]}}});e.end=new Proxy(e.end,{apply:(t,r,n)=>{const i=void 0===r.statusCode?500:r.statusCode;if(i>=200&&i<300){const i=n[0],a=async()=>{let a;if("string"==typeof i)a=h(i);else{if(!(i instanceof Buffer))throw new Error("cannot manage this chunk...");a=i}const o=await s.encrypt(a),c=w(o);e.setHeader("Content-Length",c.length),t.call(r,c,...n.slice(1))};a().catch((t=>{console.error(t)}))}else t.call(r,...n)}}),await this.callListeners(g,e)}async dispatchRequest(t,e){if(t.url===this.rpcUrl){if("POST"!==t.method)throw new Error("method must be POST");return void 0!==t.headers.authorization?await this.dispatchEncryptedMessage(t,e,t.headers.authorization):await this.dispatchProtocolMessage(t,e)}await this.callListeners(t,e)}async callListeners(t,e){for(const r of this.listeners)r(t,e)}use(t){this.listeners.push(t)}},t.MasterKey=R,t.Session=_,t.WalletProtocol=class extends O{constructor(t){super(),this.transport=t}async computeR(t,e){return t.map(((t,r)=>t^e[r]))}async computeNx(){const t=Math.ceil(r.NONCE_LENGTH/8),e=new Uint8Array(t);return await i.randomFillBits(e,0,r.NONCE_LENGTH),e}async computeCx(t,e,n){const s=Math.ceil(r.NONCE_LENGTH/8),i=Math.ceil(r.DEFAULT_RANDOM_LENGTH/8),o=p(t.a.publicKey),c=p(t.b.publicKey),h=new Uint8Array(64+s+i);g.insertBytes(o,h,1,0,32),g.insertBytes(c,h,1,32,32),g.insertBits(e,h,0,512,r.NONCE_LENGTH),g.insertBits(n,h,0,512+r.NONCE_LENGTH,r.DEFAULT_RANDOM_LENGTH);return await a.digest("sha256",h)}async validateAuthData(t,e){const{cx:r,nx:n}=e.received,{cx:s,nx:i,r:a}=e.sent;if(!(r.length===s.length&&n.length===i.length))throw new Error("invalid received auth data length");if(r.every(((t,e)=>t===s[e])))throw new Error("received and sent Cx are the same");if(!(await this.computeCx(t,n,a)).every(((t,e)=>t===r[e])))throw new Error("received a wrong Cx")}async computeMasterKey(t,e,n){const s=Math.ceil(r.NONCE_LENGTH/8),i=await t.deriveBits(e.received.publicKey),a=new Uint8Array(16),o=new Uint8Array(32+2*s+6+64),c=new Uint8Array([109,97,115,116,101,114]),h=await v(e.a,"SHA-256"),u=p(h),l=await v(e.b,"SHA-256"),y=p(l);g.insertBytes(i,o,0,0,32),g.insertBytes(n.a.nx,o,0,32,s),g.insertBytes(n.a.nx,o,0,32+s,s),g.insertBytes(c,o,0,32+2*s,6),g.insertBytes(u,o,0,32+2*s+6,32),g.insertBytes(y,o,0,32+2*s+6+32,32);const d=await A(o,a,1,32);return await R.fromSecret(e.port,e.sent.id,e.received.id,n.a.nx,n.b.nx,new Uint8Array(d))}async run(){return await(async()=>{const t=new n;await t.generateKeys();const e=await t.getPublicKey(),r=await this.transport.prepare(this,e),s=await this.transport.publicKeyExchange(this,r),i=await this.computeR(s.a.rx,s.b.rx),a=await this.computeNx(),o={r:i,nx:a,cx:await this.computeCx(s,a,i)},c=await this.transport.authentication(this,o);await this.validateAuthData(s,c);const h=await this.computeMasterKey(t,s,c),u=await this.transport.verification(this,h),l=new _(this.transport,h,u);return this.emit("masterKey",h),l})().finally((()=>{this.transport.finish(this)}))}on(t,e){return super.on(t,e)}emit(t,...e){return super.emit(t,...e)}},t.constants=r,t.defaultCodeGenerator=U,Object.defineProperty(t,"__esModule",{value:!0}),t}({});
