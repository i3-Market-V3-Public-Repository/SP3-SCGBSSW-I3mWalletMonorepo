var e=function(){if("undefined"!=typeof globalThis)return globalThis;if("undefined"!=typeof self)return self;if("undefined"!=typeof window)return window;throw new Error("unable to locate global object")}(),t=e.crypto;class r extends Error{constructor(e){super(e),this.code=r.code,this.name=this.constructor.name,Error.captureStackTrace&&Error.captureStackTrace(this,this.constructor)}}r.code="ERR_JOSE_GENERIC";class a extends r{constructor(){super(...arguments),this.code=a.code}}a.code="ERR_JOSE_ALG_NOT_ALLOWED";class n extends r{constructor(){super(...arguments),this.code=n.code}}n.code="ERR_JOSE_NOT_SUPPORTED";class i extends r{constructor(){super(...arguments),this.code=i.code,this.message="decryption operation failed"}}i.code="ERR_JWE_DECRYPTION_FAILED";class o extends r{constructor(){super(...arguments),this.code=o.code}}o.code="ERR_JWE_INVALID";class s extends r{constructor(){super(...arguments),this.code=s.code}}s.code="ERR_JWS_INVALID";class c extends r{constructor(){super(...arguments),this.code=c.code}}c.code="ERR_JWK_INVALID";class d extends r{constructor(){super(...arguments),this.code=d.code,this.message="signature verification failed"}}d.code="ERR_JWS_SIGNATURE_VERIFICATION_FAILED";const p=t.getRandomValues.bind(t),h=new TextEncoder,y=new TextDecoder;function u(...e){const t=e.reduce(((e,{length:t})=>e+t),0),r=new Uint8Array(t);let a=0;return e.forEach((e=>{r.set(e,a),a+=e.length})),r}function l(e,t){return u(h.encode(e),new Uint8Array([0]),t)}function w(e,t,r){if(t<0||t>=4294967296)throw new RangeError(`value must be >= 0 and <= 4294967295. Received ${t}`);e.set([t>>>24,t>>>16,t>>>8,255&t],r)}function m(e){const t=Math.floor(e/4294967296),r=e%4294967296,a=new Uint8Array(8);return w(a,t,0),w(a,r,4),a}function f(e){const t=new Uint8Array(4);return w(t,e),t}function g(e){return u(f(e.length),e)}const A=t=>{let r=t;"string"==typeof r&&(r=h.encode(r));const a=[];for(let e=0;e<r.length;e+=32768)a.push(String.fromCharCode.apply(null,r.subarray(e,e+32768)));return e.btoa(a.join("")).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")},E=t=>{let r=t;r instanceof Uint8Array&&(r=y.decode(r)),r=r.replace(/-/g,"+").replace(/_/g,"/").replace(/\s/g,"");try{return new Uint8Array(e.atob(r).split("").map((e=>e.charCodeAt(0))))}catch(e){throw new TypeError("The input to be decoded is not correctly encoded.")}};async function S(e){return e instanceof Uint8Array?{kty:"oct",k:A(e)}:(async e=>{if(!e.extractable)throw new TypeError("non-extractable key cannot be extracted as a JWK");const{ext:r,key_ops:a,alg:n,use:i,...o}=await t.subtle.exportKey("jwk",e);return o})(e)}const b=new Map([["A128CBC-HS256",128],["A128GCM",96],["A128GCMKW",96],["A192CBC-HS384",128],["A192GCM",96],["A192GCMKW",96],["A256CBC-HS512",128],["A256GCM",96],["A256GCMKW",96]]),H=e=>t=>{const r=b.get(t);if(!r)throw new n(`Unsupported JWE Algorithm: ${t}`);return e(new Uint8Array(r>>3))},v=(e,t)=>{if(t.length<<3!==b.get(e))throw new o("Invalid Initialization Vector length")},C=(e,t)=>{let r;switch(e){case"A128CBC-HS256":case"A192CBC-HS384":case"A256CBC-HS512":if(r=parseInt(e.substr(-3),10),!(t instanceof Uint8Array))throw new TypeError(`${e} content encryption requires Uint8Array as key input`);break;case"A128GCM":case"A192GCM":case"A256GCM":r=parseInt(e.substr(1,3),10);break;default:throw new n(`Content Encryption Algorithm ${e} is unsupported either by JOSE or your javascript runtime`)}if(t instanceof Uint8Array){if(t.length<<3!==r)throw new o("Invalid Content Encryption Key length")}else{if(void 0===t.algorithm)throw new TypeError("Invalid Content Encryption Key type");{const{length:e}=t.algorithm;if(e!==r)throw new o("Invalid Content Encryption Key length")}}};const K=async(e,r,a,n,i)=>(C(e,a),v(e,n),"CBC"===e.substr(4,3)?async function(e,r,a,n,i){const o=parseInt(e.substr(1,3),10),s=await t.subtle.importKey("raw",a.subarray(o>>3),"AES-CBC",!1,["encrypt"]),c=await t.subtle.importKey("raw",a.subarray(0,o>>3),{hash:{name:"SHA-"+(o<<1)},name:"HMAC"},!1,["sign"]),d=new Uint8Array(await t.subtle.encrypt({iv:n,name:"AES-CBC"},s,r)),p=u(i,n,d,m(i.length<<3));return{ciphertext:d,tag:new Uint8Array((await t.subtle.sign("HMAC",c,p)).slice(0,o>>3))}}(e,r,a,n,i):async function(e,r,a,n){const i=r instanceof Uint8Array?await t.subtle.importKey("raw",r,"AES-GCM",!1,["encrypt"]):r,o=new Uint8Array(await t.subtle.encrypt({additionalData:n,iv:a,name:"AES-GCM",tagLength:128},i,e)),s=o.slice(-16);return{ciphertext:o.slice(0,-16),tag:s}}(r,a,n,i)),P=async()=>{throw new n('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `inflateRaw` decrypt option to provide Inflate Raw implementation, e.g. using the "pako" module.')},_=async()=>{throw new n('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime.')},k=new Map([["A128CBC-HS256",256],["A128GCM",128],["A192CBC-HS384",384],["A192GCM",192],["A256CBC-HS512",512],["A256GCM",256]]),W=e=>t=>{const r=k.get(t);if(!r)throw new n(`Unsupported JWE Algorithm: ${t}`);return e(new Uint8Array(r>>3))},U=[{hash:{name:"SHA-256"},name:"HMAC"},!0,["sign"]];function J(e,t){if(e.algorithm.length!==parseInt(t.substr(1,3),10))throw new TypeError(`invalid key size for alg: ${t}`)}const R=async(e,r,a)=>{let n;n=r instanceof Uint8Array?await t.subtle.importKey("raw",r,"AES-KW",!0,["wrapKey"]):r,J(n,e);const i=await t.subtle.importKey("raw",a,...U);return new Uint8Array(await t.subtle.wrapKey("raw",i,n,"AES-KW"))},M=async(e,r,a)=>{let n;n=r instanceof Uint8Array?await t.subtle.importKey("raw",r,"AES-KW",!0,["unwrapKey"]):r,J(n,e);const i=await t.subtle.unwrapKey("raw",a,n,"AES-KW",...U);return new Uint8Array(await t.subtle.exportKey("raw",i))},x=async(e,r)=>{const a=`SHA-${e.substr(-3)}`;return new Uint8Array(await t.subtle.digest(a,r))},T=async function(e,t,r,a){const n=Math.ceil((r>>3)/32);let i;for(let r=1;r<=n;r++){const n=new Uint8Array(4+t.length+a.length);n.set(f(r)),n.set(t,4),n.set(a,4+t.length),i=i?u(i,await e(n)):await e(n)}return i=i.slice(0,r>>3),i}.bind(void 0,x.bind(void 0,"sha256")),D=async(e,r,a,n,i=new Uint8Array(0),o=new Uint8Array(0))=>{const s=u(g(h.encode(a)),g(i),g(o),f(n));if(!r.usages.includes("deriveBits"))throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"');const c=new Uint8Array(await t.subtle.deriveBits({name:"ECDH",public:e},r,Math.ceil(parseInt(r.algorithm.namedCurve.substr(-3),10)/8)<<3));return T(c,n,s)},O=["P-256","P-384","P-521"],B=e=>O.includes(e.algorithm.namedCurve);function I(e){if(!(e instanceof Uint8Array)||e.length<8)throw new o("PBES2 Salt Input must be 8 or more octets")}const G=async(e,r,a,n=Math.floor(2049*Math.random())+2048,i=p(new Uint8Array(16)))=>{I(i);const o=l(e,i),s=parseInt(e.substr(13,3),10),c={hash:{name:`SHA-${e.substr(8,3)}`},iterations:n,name:"PBKDF2",salt:o},d={length:s,name:"AES-KW"};let h,y;if(h=r instanceof Uint8Array?await t.subtle.importKey("raw",r,"PBKDF2",!1,["deriveBits"]):r,h.usages.includes("deriveBits"))y=new Uint8Array(await t.subtle.deriveBits(c,h,s));else{if(!h.usages.includes("deriveKey"))throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');y=await t.subtle.deriveKey(c,h,d,!1,["wrapKey"])}return{encryptedKey:await R(e.substr(-6),y,a),p2c:n,p2s:A(i)}},$=async(e,r,a,n,i)=>{I(i);const o=l(e,i),s=parseInt(e.substr(13,3),10),c={hash:{name:`SHA-${e.substr(8,3)}`},iterations:n,name:"PBKDF2",salt:o},d={length:s,name:"AES-KW"};let p,h;if(p=r instanceof Uint8Array?await t.subtle.importKey("raw",r,"PBKDF2",!1,["deriveBits"]):r,p.usages.includes("deriveBits"))h=new Uint8Array(await t.subtle.deriveBits(c,p,s));else{if(!p.usages.includes("deriveKey"))throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');h=await t.subtle.deriveKey(c,p,d,!1,["unwrapKey"])}return M(e.substr(-6),h,a)};function j(e){switch(e){case"RSA-OAEP":case"RSA-OAEP-256":case"RSA-OAEP-384":case"RSA-OAEP-512":return"RSA-OAEP";default:throw new n(`alg ${e} is unsupported either by JOSE or your javascript runtime`)}}var z=(e,t)=>{if(e.startsWith("HS")){const r=parseInt(e.substr(-3),10),{length:a}=t.algorithm;if("number"!=typeof a||a<r)throw new TypeError(`${e} requires symmetric keys to be ${r} bits or larger`)}if(e.startsWith("RS")||e.startsWith("PS")){const{modulusLength:r}=t.algorithm;if("number"!=typeof r||r<2048)throw new TypeError(`${e} requires key modulusLength to be 2048 bits or larger`)}};async function N(e,r,a,n,o,s){const c=parseInt(e.substr(1,3),10),d=await t.subtle.importKey("raw",r.subarray(c>>3),"AES-CBC",!1,["decrypt"]),p=await t.subtle.importKey("raw",r.subarray(0,c>>3),{hash:{name:"SHA-"+(c<<1)},name:"HMAC"},!1,["sign"]);let h;try{h=new Uint8Array(await t.subtle.decrypt({iv:n,name:"AES-CBC"},d,a))}catch(e){}const y=u(s,n,a,m(s.length<<3)),l=new Uint8Array((await t.subtle.sign("HMAC",p,y)).slice(0,c>>3));let w;try{w=((e,t)=>{if(!(e instanceof Uint8Array))throw new TypeError("First argument must be a buffer");if(!(t instanceof Uint8Array))throw new TypeError("Second argument must be a buffer");if(e.length!==t.length)throw new TypeError("Input buffers must have the same length");const r=e.length;let a=0,n=-1;for(;++n<r;)a|=e[n]^t[n];return 0===a})(o,l)}catch(e){}if(!h||!w)throw new i;return h}const F=async(e,r,a,n,o,s)=>(C(e,r),v(e,n),"CBC"===e.substr(4,3)?N(e,r,a,n,o,s):async function(e,r,a,n,o){const s=e instanceof Uint8Array?await t.subtle.importKey("raw",e,"AES-GCM",!1,["decrypt"]):e;try{return new Uint8Array(await t.subtle.decrypt({additionalData:o,iv:a,name:"AES-GCM",tagLength:128},s,u(r,n)))}catch(e){throw new i}}(r,a,n,o,s)),L=H(p),V=W(p);async function q(e,r,a,i,o={}){let s,c,d;switch(e){case"dir":d=a;break;case"ECDH-ES":case"ECDH-ES+A128KW":case"ECDH-ES+A192KW":case"ECDH-ES+A256KW":{if(!B(a))throw new n("ECDH-ES with the provided key is not allowed or not supported by your javascript runtime");const{apu:p,apv:h}=o;let{epk:y}=o;y||(y=await(async e=>(await t.subtle.generateKey({name:"ECDH",namedCurve:e.algorithm.namedCurve},!0,["deriveBits"])).privateKey)(a));const u=await async function(e){const{crv:r,kty:a,x:n,y:i}=await t.subtle.exportKey("jwk",e);return{crv:r,kty:a,x:n,y:i}}(y),l=await D(a,y,"ECDH-ES"===e?r:e,parseInt(e.substr(-5,3),10)||k.get(r),p,h);if(c={epk:u},p&&(c.apu=A(p)),h&&(c.apv=A(h)),"ECDH-ES"===e){d=l;break}d=i||V(r);const w=e.substr(-6);s=await R(w,l,d);break}case"RSA1_5":case"RSA-OAEP":case"RSA-OAEP-256":case"RSA-OAEP-384":case"RSA-OAEP-512":d=i||V(r),s=await(async(e,r,a)=>{if(z(e,r),r.usages.includes("encrypt"))return new Uint8Array(await t.subtle.encrypt(j(e),r,a));if(r.usages.includes("wrapKey")){const n=await t.subtle.importKey("raw",a,...U);return new Uint8Array(await t.subtle.wrapKey("raw",n,r,j(e)))}throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation')})(e,a,d);break;case"PBES2-HS256+A128KW":case"PBES2-HS384+A192KW":case"PBES2-HS512+A256KW":{d=i||V(r);const{p2c:t,p2s:n}=o;({encryptedKey:s,...c}=await G(e,a,d,t,n));break}case"A128KW":case"A192KW":case"A256KW":d=i||V(r),s=await R(e,a,d);break;case"A128GCMKW":case"A192GCMKW":case"A256GCMKW":{d=i||V(r);const{iv:t}=o;({encryptedKey:s,...c}=await(async(e,t,r,a)=>{const n=e.substr(0,7);a||(a=L(n));const{ciphertext:i,tag:o}=await K(n,r,t,a,new Uint8Array(0));return{encryptedKey:i,iv:A(a),tag:A(o)}})(e,a,d,t));break}default:throw new n('unsupported or invalid "alg" (JWE Algorithm) header value')}return{cek:d,encryptedKey:s,parameters:c}}const Y=(...e)=>{const t=e.filter(Boolean);if(0===t.length||1===t.length)return!0;let r;for(const e of t){const t=Object.keys(e);if(r&&0!==r.size)for(const e of t){if(r.has(e))return!1;r.add(e)}else r=new Set(t)}return!0};function X(e,t,r,a,i){if(void 0!==i.crit&&void 0===a.crit)throw new e('"crit" (Critical) Header Parameter MUST be integrity protected');if(!a||void 0===a.crit)return new Set;if(!Array.isArray(a.crit)||0===a.crit.length||a.crit.some((e=>"string"!=typeof e||0===e.length)))throw new e('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');let o;o=void 0!==r?new Map([...Object.entries(r),...t.entries()]):t;for(const t of a.crit){if(!o.has(t))throw new n(`Extension Header Parameter "${t}" is not recognized`);if(void 0===i[t])throw new e(`Extension Header Parameter "${t}" is missing`);if(o.get(t)&&void 0===a[t])throw new e(`Extension Header Parameter "${t}" MUST be integrity protected`)}return new Set(a.crit)}const Q=H(p),Z=X.bind(void 0,o,new Map);class ee{constructor(e){this._plaintext=e}setKeyManagementParameters(e){if(this._keyManagementParameters)throw new TypeError("setKeyManagementParameters can only be called once");return this._keyManagementParameters=e,this}setProtectedHeader(e){if(this._protectedHeader)throw new TypeError("setProtectedHeader can only be called once");return this._protectedHeader=e,this}setSharedUnprotectedHeader(e){if(this._sharedUnprotectedHeader)throw new TypeError("setSharedUnprotectedHeader can only be called once");return this._sharedUnprotectedHeader=e,this}setUnprotectedHeader(e){if(this._unprotectedHeader)throw new TypeError("setUnprotectedHeader can only be called once");return this._unprotectedHeader=e,this}setAdditionalAuthenticatedData(e){return this._aad=e,this}setContentEncryptionKey(e){if(this._cek)throw new TypeError("setContentEncryptionKey can only be called once");return this._cek=e,this}setInitializationVector(e){if(this._iv)throw new TypeError("setInitializationVector can only be called once");return this._iv=e,this}async encrypt(e,t){if(!this._protectedHeader&&!this._unprotectedHeader&&!this._sharedUnprotectedHeader)throw new o("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");if(!Y(this._protectedHeader,this._unprotectedHeader,this._sharedUnprotectedHeader))throw new o("JWE Shared Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");const r={...this._protectedHeader,...this._unprotectedHeader,...this._sharedUnprotectedHeader};if(Z(null==t?void 0:t.crit,this._protectedHeader,r),void 0!==r.zip){if(!this._protectedHeader||!this._protectedHeader.zip)throw new o('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');if("DEF"!==r.zip)throw new n('unsupported JWE "zip" (Compression Algorithm) Header Parameter value')}const{alg:a,enc:i}=r;if("string"!=typeof a||!a)throw new o('JWE "alg" (Algorithm) Header Parameter missing or invalid');if("string"!=typeof i||!i)throw new o('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');let s,c,d,p,l,w,m;if("dir"===a){if(this._cek)throw new TypeError("setContentEncryptionKey cannot be called when using Direct Encryption")}else if("ECDH-ES"===a&&this._cek)throw new TypeError("setContentEncryptionKey cannot be called when using Direct Key Agreement");{let t;({cek:c,encryptedKey:s,parameters:t}=await q(a,i,e,this._cek,this._keyManagementParameters)),t&&(this._protectedHeader?this._protectedHeader={...this._protectedHeader,...t}:this.setProtectedHeader(t))}if(this._iv||(this._iv=Q(i)),p=this._protectedHeader?h.encode(A(JSON.stringify(this._protectedHeader))):h.encode(""),this._aad?(l=A(this._aad),d=u(p,h.encode("."),h.encode(l))):d=p,"DEF"===r.zip){const e=await((null==t?void 0:t.deflateRaw)||_)(this._plaintext);({ciphertext:w,tag:m}=await K(i,e,c,this._iv,d))}else({ciphertext:w,tag:m}=await K(i,this._plaintext,c,this._iv,d));const f={ciphertext:A(w),iv:A(this._iv),tag:A(m)};return s&&(f.encrypted_key=A(s)),l&&(f.aad=l),this._protectedHeader&&(f.protected=y.decode(p)),this._sharedUnprotectedHeader&&(f.unprotected=this._sharedUnprotectedHeader),this._unprotectedHeader&&(f.header=this._unprotectedHeader),f}}class te{constructor(e){this._flattened=new ee(e)}setContentEncryptionKey(e){return this._flattened.setContentEncryptionKey(e),this}setInitializationVector(e){return this._flattened.setInitializationVector(e),this}setProtectedHeader(e){return this._flattened.setProtectedHeader(e),this}setKeyManagementParameters(e){return this._flattened.setKeyManagementParameters(e),this}async encrypt(e,t){const r=await this._flattened.encrypt(e,t);return[r.protected,r.encrypted_key,r.iv,r.ciphertext,r.tag].join(".")}}function re(e){return!!e&&e.constructor===Object}const ae=(e,t)=>{if("string"!=typeof e||!e)throw new c(`${t} missing or invalid`)};const ne=async e=>{var r,a;const{algorithm:i,keyUsages:o}=function(e){let t,r;switch(e.kty){case"oct":switch(e.alg){case"HS256":case"HS384":case"HS512":t={name:"HMAC",hash:{name:`SHA-${e.alg.substr(-3)}`}},r=["sign","verify"];break;case"A128CBC-HS256":case"A192CBC-HS384":case"A256CBC-HS512":throw new n(`${e.alg} keys cannot be imported as CryptoKey instances`);case"A128GCM":case"A192GCM":case"A256GCM":case"A128GCMKW":case"A192GCMKW":case"A256GCMKW":t={name:"AES-GCM"},r=["encrypt","decrypt"];break;case"A128KW":case"A192KW":case"A256KW":t={name:"AES-KW"},r=["wrapKey","unwrapKey"];break;case"PBES2-HS256+A128KW":case"PBES2-HS384+A192KW":case"PBES2-HS512+A256KW":t={name:"PBKDF2"},r=["deriveBits"];break;default:throw new n('unsupported or invalid JWK "alg" (Algorithm) Parameter value')}break;case"RSA":switch(e.alg){case"PS256":case"PS384":case"PS512":t={name:"RSA-PSS",hash:{name:`SHA-${e.alg.substr(-3)}`}},r=e.d?["sign"]:["verify"];break;case"RS256":case"RS384":case"RS512":t={name:"RSASSA-PKCS1-v1_5",hash:{name:`SHA-${e.alg.substr(-3)}`}},r=e.d?["sign"]:["verify"];break;case"RSA-OAEP":case"RSA-OAEP-256":case"RSA-OAEP-384":case"RSA-OAEP-512":t={name:"RSA-OAEP",hash:{name:`SHA-${parseInt(e.alg.substr(-3),10)||1}`}},r=e.d?["decrypt","unwrapKey"]:["encrypt","wrapKey"];break;default:throw new n('unsupported or invalid JWK "alg" (Algorithm) Parameter value')}break;case"EC":switch(e.alg){case"ES256":case"ES384":case"ES512":t={name:"ECDSA",namedCurve:e.crv},r=e.d?["sign"]:["verify"];break;case"ECDH-ES":case"ECDH-ES+A128KW":case"ECDH-ES+A192KW":case"ECDH-ES+A256KW":t={name:"ECDH",namedCurve:e.crv},r=e.d?["deriveBits"]:[];break;default:throw new n('unsupported or invalid JWK "alg" (Algorithm) Parameter value')}break;default:throw new n('unsupported or invalid JWK "kty" (Key Type) Parameter value')}return{algorithm:t,keyUsages:r}}(e);let s="jwk",c={...e};return delete c.alg,"PBKDF2"===i.name&&(s="raw",c=E(e.k)),t.subtle.importKey(s,c,i,null!==(r=e.ext)&&void 0!==r&&r,null!==(a=e.key_ops)&&void 0!==a?a:o)};async function ie(e,t,r){if(!re(e))throw new TypeError("JWK must be an object");if(t||(t=e.alg),"string"!=typeof t||!t)throw new TypeError('"alg" argument is required when "jwk.alg" is not present');switch(e.kty){case"oct":if("string"!=typeof e.k||!e.k)throw new TypeError('missing "k" (Key Value) Parameter value');return null!=r||(r=!0!==e.ext),r?ne({...e,alg:t,ext:!1}):E(e.k);case"RSA":if(void 0!==e.oth)throw new n('RSA JWK "oth" (Other Primes Info) Parameter value is unsupported');case"EC":case"OKP":return ne({...e,alg:t});default:throw new n('unsupported "kty" (Key Type) Parameter value')}}function oe(e){switch(e){case"HS256":return{hash:{name:"SHA-256"},name:"HMAC"};case"HS384":return{hash:{name:"SHA-384"},name:"HMAC"};case"HS512":return{hash:{name:"SHA-512"},name:"HMAC"};case"PS256":return{hash:{name:"SHA-256"},name:"RSA-PSS",saltLength:32};case"PS384":return{hash:{name:"SHA-384"},name:"RSA-PSS",saltLength:48};case"PS512":return{hash:{name:"SHA-512"},name:"RSA-PSS",saltLength:64};case"RS256":return{hash:{name:"SHA-256"},name:"RSASSA-PKCS1-v1_5"};case"RS384":return{hash:{name:"SHA-384"},name:"RSASSA-PKCS1-v1_5"};case"RS512":return{hash:{name:"SHA-512"},name:"RSASSA-PKCS1-v1_5"};case"ES256":return{hash:{name:"SHA-256"},name:"ECDSA",namedCurve:"P-256"};case"ES384":return{hash:{name:"SHA-384"},name:"ECDSA",namedCurve:"P-384"};case"ES512":return{hash:{name:"SHA-512"},name:"ECDSA",namedCurve:"P-521"};default:throw new n(`alg ${e} is unsupported either by JOSE or your javascript runtime`)}}const se=(e,t)=>{if(e.startsWith("HS")||"dir"===e||e.startsWith("PBES2")||e.match(/^A\d{3}(?:GCM)KW$/)){if(t instanceof Uint8Array||"secret"===t.type)return;throw new TypeError('CryptoKey or KeyObject instances for symmetric algorithms must be of type "secret"')}if(t instanceof Uint8Array)throw new TypeError("CryptoKey or KeyObject instances must be used for asymmetric algorithms");if("secret"===t.type)throw new TypeError('CryptoKey or KeyObject instances for asymmetric algorithms must not be of type "secret"')},ce=X.bind(void 0,s,new Map([["b64",!0]]));class de{constructor(e){this._payload=e}setProtectedHeader(e){if(this._protectedHeader)throw new TypeError("setProtectedHeader can only be called once");return this._protectedHeader=e,this}setUnprotectedHeader(e){if(this._unprotectedHeader)throw new TypeError("setUnprotectedHeader can only be called once");return this._unprotectedHeader=e,this}async sign(e,r){if(!this._protectedHeader&&!this._unprotectedHeader)throw new s("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");if(!Y(this._protectedHeader,this._unprotectedHeader))throw new s("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");const a={...this._protectedHeader,...this._unprotectedHeader};let n=!0;if(ce(null==r?void 0:r.crit,this._protectedHeader,a).has("b64")&&(n=this._protectedHeader.b64,"boolean"!=typeof n))throw new s('The "b64" (base64url-encode payload) Header Parameter must be a boolean');const{alg:i}=a;if("string"!=typeof i||!i)throw new s('JWS "alg" (Algorithm) Header Parameter missing or invalid');se(i,e);let o,c=this._payload;n&&(c=h.encode(A(c))),o=this._protectedHeader?h.encode(A(JSON.stringify(this._protectedHeader))):h.encode("");const d=u(o,h.encode("."),c),p=await(async(e,r,a)=>{let n;if(r instanceof Uint8Array){if(!e.startsWith("HS"))throw new TypeError("symmetric keys are only applicable for HMAC-based algorithms");n=await t.subtle.importKey("raw",r,{hash:{name:`SHA-${e.substr(-3)}`},name:"HMAC"},!1,["sign"])}else n=r;z(e,n);const i=await t.subtle.sign(oe(e),n,a);return new Uint8Array(i)})(i,e,d),l={signature:A(p)};return n&&(l.payload=y.decode(c)),this._unprotectedHeader&&(l.header=this._unprotectedHeader),this._protectedHeader&&(l.protected=y.decode(o)),l}}class pe{constructor(e){this._flattened=new de(e)}setProtectedHeader(e){return this._flattened.setProtectedHeader(e),this}async sign(e,t){const r=await this._flattened.sign(e,t);if(void 0===r.payload)throw new TypeError("use the flattened module for creating JWS with b64: false");return`${r.protected}.${r.payload}.${r.signature}`}}const he=async function(e,t="SHA-256"){const r=["SHA-1","SHA-256","SHA-384","SHA-512"];if(!r.includes(t))throw new RangeError(`Valid hash algorith values are any of ${JSON.stringify(r)}`);const a=new TextEncoder,n="string"==typeof e?a.encode(e).buffer:e;let i="";{const e=await crypto.subtle.digest(t,n),r="0123456789abcdef";new Uint8Array(e).forEach((e=>{i+=r[e>>4]+r[15&e]}))}return i};function ye(e){if(!e)throw new o("JWE Encrypted Key missing")}function ue(e,t,r){if(void 0===e[t])throw new o(`JOSE Header ${r} (${t}) missing`)}async function le(e,r,a,i){switch(e){case"dir":if(void 0!==a)throw new o("Encountered unexpected JWE Encrypted Key");return r;case"ECDH-ES":if(void 0!==a)throw new o("Encountered unexpected JWE Encrypted Key");case"ECDH-ES+A128KW":case"ECDH-ES+A192KW":case"ECDH-ES+A256KW":{if(ue(i,"epk","Ephemeral Public Key"),!B(r))throw new n("ECDH-ES with the provided key is not allowed or not supported by your javascript runtime");const o=await(s=i.epk,t.subtle.importKey("jwk",s,{name:"ECDH",namedCurve:s.crv},!0,[]));let c,d;void 0!==i.apu&&(c=E(i.apu)),void 0!==i.apv&&(d=E(i.apv));const p=await D(o,r,"ECDH-ES"===e?i.enc:e,parseInt(e.substr(-5,3),10)||k.get(i.enc),c,d);if("ECDH-ES"===e)return p;ye(a);const h=e.substr(-6);return M(h,p,a)}case"RSA1_5":case"RSA-OAEP":case"RSA-OAEP-256":case"RSA-OAEP-384":case"RSA-OAEP-512":return ye(a),(async(e,r,a)=>{if(z(e,r),r.usages.includes("decrypt"))return new Uint8Array(await t.subtle.decrypt(j(e),r,a));if(r.usages.includes("unwrapKey")){const n=await t.subtle.unwrapKey("raw",a,r,j(e),...U);return new Uint8Array(await t.subtle.exportKey("raw",n))}throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation')})(e,r,a);case"PBES2-HS256+A128KW":case"PBES2-HS384+A192KW":case"PBES2-HS512+A256KW":{ye(a),ue(i,"p2c","PBES2 Count"),ue(i,"p2s","PBES2 Salt");const{p2c:t}=i,n=E(i.p2s);return $(e,r,a,t,n)}case"A128KW":case"A192KW":case"A256KW":return ye(a),M(e,r,a);case"A128GCMKW":case"A192GCMKW":case"A256GCMKW":ye(a),ue(i,"iv","Initialization Vector"),ue(i,"tag","Authentication Tag");return(async(e,t,r,a,n)=>{const i=e.substr(0,7);return F(i,t,r,a,n,new Uint8Array(0))})(e,r,a,E(i.iv),E(i.tag));default:throw new n('unsupported or invalid "alg" (JWE Algorithm) header value')}var s}const we=(e,t)=>{if(void 0!==t&&(!Array.isArray(t)||t.some((e=>"string"!=typeof e))))throw new TypeError(`"${e}" option must be an array of strings`);if(t)return new Set(t)},me=W(p),fe=X.bind(void 0,o,new Map),ge=we.bind(void 0,"keyManagementAlgorithms"),Ae=we.bind(void 0,"contentEncryptionAlgorithms");async function Ee(e,t,r){var i;if(!re(e))throw new o("Flattened JWE must be an object");if(void 0===e.protected&&void 0===e.header&&void 0===e.unprotected)throw new o("JOSE Header missing");if("string"!=typeof e.iv)throw new o("JWE Initialization Vector missing or incorrect type");if("string"!=typeof e.ciphertext)throw new o("JWE Ciphertext missing or incorrect type");if("string"!=typeof e.tag)throw new o("JWE Authentication Tag missing or incorrect type");if(void 0!==e.protected&&"string"!=typeof e.protected)throw new o("JWE Protected Header incorrect type");if(void 0!==e.encrypted_key&&"string"!=typeof e.encrypted_key)throw new o("JWE Encrypted Key incorrect type");if(void 0!==e.aad&&"string"!=typeof e.aad)throw new o("JWE AAD incorrect type");if(void 0!==e.header&&!re(e.header))throw new o("JWE Shared Unprotected Header incorrect type");if(void 0!==e.unprotected&&!re(e.unprotected))throw new o("JWE Per-Recipient Unprotected Header incorrect type");let s;if(e.protected){const t=E(e.protected);s=JSON.parse(y.decode(t))}if(!Y(s,e.header,e.unprotected))throw new o("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");const c={...s,...e.header,...e.unprotected};if(fe(null==r?void 0:r.crit,s,c),void 0!==c.zip){if(!s||!s.zip)throw new o('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');if("DEF"!==c.zip)throw new n('unsupported JWE "zip" (Compression Algorithm) Header Parameter value')}const{alg:d,enc:p}=c;if("string"!=typeof d||!d)throw new o("missing JWE Algorithm (alg) in JWE Header");if("string"!=typeof p||!p)throw new o("missing JWE Encryption Algorithm (enc) in JWE Header");const l=r&&ge(r.keyManagementAlgorithms),w=r&&Ae(r.contentEncryptionAlgorithms);if(l&&!l.has(d))throw new a('"alg" (Algorithm) Header Parameter not allowed');if(w&&!w.has(p))throw new a('"enc" (Encryption Algorithm) Header Parameter not allowed');let m,f;void 0!==e.encrypted_key&&(m=E(e.encrypted_key)),"function"==typeof t&&(t=await t(s,e));try{f=await le(d,t,m,c)}catch(e){if(e instanceof TypeError)throw e;f=me(p)}const g=E(e.iv),A=E(e.tag),S=h.encode(null!==(i=e.protected)&&void 0!==i?i:"");let b;b=void 0!==e.aad?u(S,h.encode("."),h.encode(e.aad)):S;let H=await F(p,f,E(e.ciphertext),g,A,b);"DEF"===c.zip&&(H=await((null==r?void 0:r.inflateRaw)||P)(H));const v={plaintext:H};return void 0!==e.protected&&(v.protectedHeader=s),void 0!==e.aad&&(v.additionalAuthenticatedData=E(e.aad)),void 0!==e.unprotected&&(v.sharedUnprotectedHeader=e.unprotected),void 0!==e.header&&(v.unprotectedHeader=e.header),v}async function Se(e,t,r){if(e instanceof Uint8Array&&(e=y.decode(e)),"string"!=typeof e)throw new o("Compact JWE must be a string or Uint8Array");const{0:a,1:n,2:i,3:s,4:c,length:d}=e.split(".");if(5!==d)throw new o("Invalid Compact JWE");const p=await Ee({ciphertext:s||void 0,iv:i||void 0,protected:a||void 0,tag:c||void 0,encrypted_key:n||void 0},t,r);return{plaintext:p.plaintext,protectedHeader:p.protectedHeader}}const be=X.bind(void 0,s,new Map([["b64",!0]])),He=we.bind(void 0,"algorithms");async function ve(e,r,n){var i;if(!re(e))throw new s("Flattened JWS must be an object");if(void 0===e.protected&&void 0===e.header)throw new s('Flattened JWS must have either of the "protected" or "header" members');if(void 0!==e.protected&&"string"!=typeof e.protected)throw new s("JWS Protected Header incorrect type");if(void 0===e.payload)throw new s("JWS Payload missing");if("string"!=typeof e.signature)throw new s("JWS Signature missing or incorrect type");if(void 0!==e.header&&!re(e.header))throw new s("JWS Unprotected Header incorrect type");let o={};if(e.protected){const t=E(e.protected);o=JSON.parse(y.decode(t))}if(!Y(o,e.header))throw new s("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");const c={...o,...e.header};let p=!0;if(be(null==n?void 0:n.crit,o,c).has("b64")&&(p=o.b64,"boolean"!=typeof p))throw new s('The "b64" (base64url-encode payload) Header Parameter must be a boolean');const{alg:l}=c;if("string"!=typeof l||!l)throw new s('JWS "alg" (Algorithm) Header Parameter missing or invalid');const w=n&&He(n.algorithms);if(w&&!w.has(l))throw new a('"alg" (Algorithm) Header Parameter not allowed');if(p){if("string"!=typeof e.payload)throw new s("JWS Payload must be a string")}else if("string"!=typeof e.payload&&!(e.payload instanceof Uint8Array))throw new s("JWS Payload must be a string or an Uint8Array instance");"function"==typeof r&&(r=await r(o,e)),se(l,r);const m=u(h.encode(null!==(i=e.protected)&&void 0!==i?i:""),h.encode("."),"string"==typeof e.payload?h.encode(e.payload):e.payload),f=E(e.signature);if(!await(async(e,r,a,n)=>{let i;if(r instanceof Uint8Array){if(!e.startsWith("HS"))throw new TypeError("symmetric keys are only applicable for HMAC-based algorithms");i=await t.subtle.importKey("raw",r,{hash:{name:`SHA-${e.substr(-3)}`},name:"HMAC"},!1,["verify"])}else i=r;z(e,i);const o=oe(e);try{return await t.subtle.verify(o,i,a,n)}catch(e){return!1}})(l,r,f,m))throw new d;let g;g=p?E(e.payload):"string"==typeof e.payload?h.encode(e.payload):e.payload;const A={payload:g};return void 0!==e.protected&&(A.protectedHeader=o),void 0!==e.header&&(A.unprotectedHeader=e.header),A}async function Ce(e,t,r){if(e instanceof Uint8Array&&(e=y.decode(e)),"string"!=typeof e)throw new s("Compact JWS must be a string or Uint8Array");const{0:a,1:n,2:i,length:o}=e.split(".");if(3!==o)throw new s("Invalid Compact JWS");const c=await ve({payload:n||void 0,protected:a||void 0,signature:i||void 0},t,r);return{payload:c.payload,protectedHeader:c.protectedHeader}}const Ke=async(e,t,r)=>{const a=await Pe(e,t);if(await he(r)!==a.exchange.poo_dgst)throw new Error("the hashed proof of origin received does not correspond to the poo_dgst parameter in the proof of origin");if(Date.now()-a.iat>5e3)throw new Error("timestamp error");return!0},Pe=async(e,t)=>{const{payload:r}=await Ce(t,e).catch((e=>{throw new Error(`PoR: ${String(e)}`)}));return JSON.parse((new TextDecoder).decode(r).toString())},_e=async(e,t,r)=>{const a=await ke(e,t),n=await he(r);if(a.exchange.cipherblock_dgst!==n)throw new Error("the cipherblock_dgst parameter in the proof of origin does not correspond to hash of the cipherblock received by the provider");if(Date.now()-a.iat>5e3)throw new Error("timestamp error");return!0},ke=async(e,t)=>{const{payload:r}=await Ce(t,e).catch((e=>{throw new Error("PoO "+String(e))}));return JSON.parse((new TextDecoder).decode(r).toString())},We=async(e,t,r,a,n)=>{await Ce(r,e).catch((e=>{throw new Error("PoP "+String(e))}));const i=await ke(t,n),o=await he(JSON.stringify(a));if(i.exchange.key_commitment===o)return!0;throw new Error("hashed key not correspond to poO key_commitment parameter")},Ue=async(e,t)=>{const r=new TextDecoder,a=await ie(t,"A256GCM"),{plaintext:n}=await Se(e,a);return r.decode(n)},Je=async(e,t,r,a)=>{const n=await Ue(t,r);if(await he(n)===a.exchange.block_commitment)return!0;throw new Error("hashed CipherBlock not correspond to block_commitment parameter included in the proof of origin")},Re="ES256",Me=async(e,t,r,a,n,i,o)=>{const s="string"==typeof t?(new TextEncoder).encode(t):new Uint8Array(t),c=await ie(o),d=await new te(s).setProtectedHeader({alg:"dir",enc:"A256GCM"}).encrypt(c),p=await he(d),h=await he(s),y=await he(JSON.stringify(o)),u={iss:r,sub:a,iat:Date.now(),exchange:{id:n,orig:r,dest:a,block_id:i,block_desc:"description",hash_alg:"sha256",cipherblock_dgst:p,block_commitment:h,key_commitment:y}};return{cipherblock:d,poO:await Te(e,u)}},xe=async()=>{let e;e=await window.crypto.subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt","decrypt"]);const t=await S(e),r=await async function(e,t="sha256"){if(!re(e))throw new TypeError("JWK must be an object");let r;switch(e.kty){case"EC":ae(e.crv,'"crv" (Curve) Parameter'),ae(e.x,'"x" (X Coordinate) Parameter'),ae(e.y,'"y" (Y Coordinate) Parameter'),r={crv:e.crv,kty:e.kty,x:e.x,y:e.y};break;case"OKP":ae(e.crv,'"crv" (Subtype of Key Pair) Parameter'),ae(e.x,'"x" (Public Key) Parameter'),r={crv:e.crv,kty:e.kty,x:e.x};break;case"RSA":ae(e.e,'"e" (Exponent) Parameter'),ae(e.n,'"n" (Modulus) Parameter'),r={e:e.e,kty:e.kty,n:e.n};break;case"oct":ae(e.k,'"k" (Key Value) Parameter'),r={k:e.k,kty:e.kty};break;default:throw new n('"kty" (Key Type) Parameter missing or unsupported')}const a=h.encode(JSON.stringify(r));return A(await x(t,a))}(t);return t.kid=r,t.alg="A256GCM",t},Te=async(e,t)=>{const r=(new TextEncoder).encode(JSON.stringify(t));return await new pe(r).setProtectedHeader({alg:"ES256"}).sign(e)},De=async(e,t,r,a,n)=>{const i=await he(t),o={iss:r,sub:a,iat:Date.now(),exchange:{poo_dgst:i,hash_alg:"sha256",exchangeId:n}};return await Te(e,o)},Oe=async(e,t,r,a)=>{const n=await ke(e,t);return{privateStorage:{availability:"privateStorage",permissions:{view:[n.exchange.orig,n.exchange.dest]},type:"dict",id:n.exchange.id,content:{[n.exchange.block_id]:{poO:t,poR:r}}},blockchain:{availability:"blockchain",type:"jwk",content:{[a.kid]:a}}}};export{Re as SIGNING_ALG,Oe as createBlockchainProof,xe as createJwk,Me as createPoO,De as createPoR,ke as decodePoo,Pe as decodePor,Ue as decryptCipherblock,he as sha,Te as signProof,Je as validateCipherblock,_e as validatePoO,We as validatePoP,Ke as validatePoR};
