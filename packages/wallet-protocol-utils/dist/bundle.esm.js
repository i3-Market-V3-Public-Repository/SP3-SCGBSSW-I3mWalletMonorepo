const pinDialog = async (opts) => {
    {
        const pinHtmlFormDialog = await Promise.resolve().then(function () { return pinHtmlformDialog; });
        return await pinHtmlFormDialog.pinHtmlFormDialog(opts?.htmlFormDialog);
    }
};
const openModal = pinDialog;

function e$2(e,r=!1,t=!0){let n="";n=(e=>{const r=[];for(let t=0;t<e.length;t+=32768)r.push(String.fromCharCode.apply(null,e.subarray(t,t+32768)));return btoa(r.join(""))})("string"==typeof e?(new TextEncoder).encode(e):new Uint8Array(e));return r&&(n=function(e){return e.replace(/\+/g,"-").replace(/\//g,"_")}(n)),t||(n=n.replace(/=/g,"")),n}function r$2(e,r=!1){{let t=!1;if(/^[0-9a-zA-Z_-]+={0,2}$/.test(e))t=!0;else if(!/^[0-9a-zA-Z+/]*={0,2}$/.test(e))throw new Error("Not a valid base64 input");t&&(e=e.replace(/-/g,"+").replace(/_/g,"/").replace(/=/g,""));const n=new Uint8Array(atob(e).split("").map((e=>e.charCodeAt(0))));return r?(new TextDecoder).decode(n):n}}

const e$1={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function t$1(t,a,o,i,s="SHA-256"){return new Promise(((u,c)=>{s in e$1||c(new RangeError(`Valid hash algorithm values are any of ${Object.keys(e$1).toString()}`)),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)||c(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof a?a=(new TextEncoder).encode(a):a instanceof ArrayBuffer?a=new Uint8Array(a):ArrayBuffer.isView(a)?a=new Uint8Array(a.buffer,a.byteOffset,a.byteLength):c(RangeError("S should be string, ArrayBuffer, TypedArray, DataView")),crypto.subtle.importKey("raw",t,"PBKDF2",!1,["deriveBits"]).then((f=>{const y={name:"PBKDF2",hash:s,salt:a,iterations:o};crypto.subtle.deriveBits(y,f,8*i).then((e=>u(e)),(f=>{(async function(t,a,o,i,s){if(!(s in e$1))throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(e$1).toString()}`);if(!Number.isInteger(o)||o<=0)throw new RangeError("c must be a positive integer");const u=e$1[s].outputLength;if(!Number.isInteger(i)||i<=0||i>=(2**32-1)*u)throw new RangeError("dkLen must be a positive integer < (2 ** 32 - 1) * hLen");const c=Math.ceil(i/u),f=i-(c-1)*u,y=new Array(c);0===t.byteLength&&(t=new Uint8Array(e$1[s].blockSize));const w=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:{name:s}},!0,["sign"]),g=async function(e,t){const r=await crypto.subtle.sign("HMAC",e,t);return new Uint8Array(r)};for(let e=0;e<c;e++)y[e]=await h(w,a,o,e+1);async function h(e,t,a,o){function i(e){const t=new ArrayBuffer(4);return new DataView(t).setUint32(0,e,!1),new Uint8Array(t)}const s=await g(e,r$1(t,i(o)));let u=s;for(let t=1;t<a;t++)u=await g(e,u),n$1(s,u);return s}return y[c-1]=y[c-1].slice(0,f),r$1(...y).buffer})(t,a,o,i,s).then((e=>u(e)),(e=>c(e)));}));}),(e=>c(e)));}))}function r$1(...e){const t=e.reduce(((e,t)=>e+t.length),0);if(0===e.length)throw new RangeError("Cannot concat no arrays");const r=new Uint8Array(t);let n=0;for(const t of e)r.set(t,n),n+=t.length;return r}function n$1(e,t){for(let r=0;r<e.length;r++)e[r]^=t[r];}

function r(r){return null!=r&&"object"==typeof r&&!Array.isArray(r)}function n(t){return r(t)||Array.isArray(t)?Array.isArray(t)?t.map((t=>Array.isArray(t)||r(t)?n(t):t)):Object.keys(t).sort().map((r=>[r,n(t[r])])):t}function t(r){return JSON.stringify(n(r))}function e(r,n="SHA-256"){const e=["SHA-1","SHA-256","SHA-384","SHA-512"];if(!e.includes(n))throw RangeError(`Valid hash algorithm values are any of ${JSON.stringify(e)}`);return async function(r,n){const e=(new TextEncoder).encode(t(r)).buffer;let a="";{const r=await crypto.subtle.digest(n,e),t="0123456789abcdef";new Uint8Array(r).forEach((r=>{a+=t[r>>4]+t[15&r];}));}return a}(r,n)}

({...Object.freeze({__proto__:null,COMMITMENT_LENGTH:256,DEFAULT_RANDOM_LENGTH:36,DEFAULT_TIMEOUT:3e4,INITIAL_PORT:29170,NONCE_LENGTH:128,PORT_LENGTH:12,PORT_SPACE:4096}),...Object.freeze({__proto__:null,RPC_URL_PATH:".well-known/wallet-protocol"})});class a{async randomFill(t,e,r){throw new Error("not implemented")}async randomFillBits(t,e,r){const s=Math.ceil(r/8),n=new Uint8Array(s);await this.randomFill(n,0,s),f.insertBits(n,t,0,e,r);}}class o{constructor(t,e){this.algorithm=t,this.key=e;}async encrypt(t){throw new Error("not implemented")}async decrypt(t){throw new Error("not implemented")}}const h=new class extends a{async randomFill(t,e,r){const s=new Uint8Array(r);crypto.getRandomValues(s);for(let n=0;n<r;n++)t[e+n]=s[n];}},u={"aes-256-gcm":{name:"AES-GCM",tagLength:128}};class d extends o{async encrypt(t){const e=new Uint8Array(12);await h.randomFill(e,0,e.length);const r=u[this.algorithm],s=await crypto.subtle.importKey("raw",this.key,r,!1,["encrypt"]),n=await crypto.subtle.encrypt({...r,iv:e},s,t),i=[];return i.push(e),i.push(new Uint8Array(n)),f.join(...i)}async decrypt(t){const e=[];if("aes-256-gcm"===this.algorithm)e[0]=12;e[1]=t.length-e[0];const[r,s]=f.split(t,...e),n=u[this.algorithm],i=await crypto.subtle.importKey("raw",this.key,n,!1,["decrypt"]),a=await crypto.subtle.decrypt({...n,iv:r},i,s);return new Uint8Array(a)}}const w={utf2U8Arr:t=>(new TextEncoder).encode(t),u8Arr2Utf:t=>(new TextDecoder).decode(t),num2U8Arr:(t,e)=>{if(void 0===e)for(e=1;2**(8*e)<t;)e++;const r=new Uint8Array(e);let s=t;for(let t=e-1;t>=0;t--){const e=s>>8,n=s-(e<<8);r[t]=n,s=e;}return r},u8Arr2Num:t=>{let e=0;for(let r=0;r<t.length;r++)e+=t[r]<<t.length-1-r;return e},hex2U8Arr:t=>{const e=t.match(/.{1,2}/g);if(null===e)throw new Error(`not a hex: ${t}`);return new Uint8Array(e.map((t=>parseInt(t,16))))},u8Arr2Hex:t=>t.reduce(((t,e)=>t+e.toString(16).padStart(2,"0")),""),u8Arr2Base64:e=>e$2(e,!0,!1),base642U8Arr:e=>r$2(e,!1)},f={join:(...t)=>{const e=t.reduce(((t,e)=>t+e.length),0),r=new Uint8Array(e);let s=0;for(const e of t)r.set(e,s),s+=e.length;return r},split:(t,...e)=>{const r=[];let s=0;for(const n of e)r.push(t.slice(s,s+n)),s+=n;return r},insertBytes:(t,e,r,s,n)=>{for(let i=0;i<n;i++)e[i+s]=t[i+r];},insertBits:(t,e,r,s,n)=>{let i=Math.floor(r/8),a=r%8,o=Math.floor(s/8),c=s%8,h=t[i]??0;const u=c-a;for(let r=0;r<n;r++){let r;r=u>=0?(h&128>>a)<<u:h&128>>a;const s=e[o]&~(128>>c)|r;e[o]=s,a++,c++,a>=8&&(i++,a=0,h=t[i]??0),c>=8&&(o++,c=0);}},extractBits:(t,e,r)=>{const s=Math.ceil(r/8),n=new Uint8Array(s);return f.insertBits(t,n,e,0,r),n}};const A=async(t,r,s)=>{const n=new Uint8Array(16),i=new Uint8Array(96),a=w.hex2U8Arr(t),o=w.hex2U8Arr(r);f.insertBytes(s,i,0,0,32),f.insertBytes(a,i,0,32,32),f.insertBytes(o,i,0,64,32);const c=await t$1(i,n,1,32);return new Uint8Array(c)};class b{constructor(t,e,r,s,n,i,a,o){this.port=t,this.from=e,this.to=r,this.na=s,this.nb=n,this.secret=i,this.cipher=new d("aes-256-gcm",a),this.decipher=new d("aes-256-gcm",o);}async encrypt(t){return await this.cipher.encrypt(t)}async decrypt(t){return await this.decipher.decrypt(t)}toJSON(){return {from:this.from,to:this.to,port:this.port,na:w.u8Arr2Base64(this.na),nb:w.u8Arr2Base64(this.nb),secret:w.u8Arr2Base64(this.secret)}}async fromHash(){return await e(this.from)}async toHash(){return await e(this.to)}static async fromSecret(t,e$1,s,n,i,a){const o=await e(e$1),c=await e(s),h=await A(o,c,a),u=await A(c,o,a);return new b(t,e$1,s,n,i,a,h,u)}static async fromJSON(t){const e=w.base642U8Arr(t.na),r=w.base642U8Arr(t.nb),s=w.base642U8Arr(t.secret);return await this.fromSecret(t.port,t.from,t.to,e,r,s)}}class x{constructor(t,e,r){this.transport=t,this.masterKey=e,this.code=r;}async send(t){return await this.transport.send(this.masterKey,this.code,t)}toJSON(){return {masterKey:this.masterKey.toJSON(),code:w.u8Arr2Hex(this.code)}}static async fromJSON(t,e){const r=await b.fromJSON(e.masterKey),s=w.hex2U8Arr(e.code);let n;if("object"==typeof t)n=t;else {if(!(t instanceof Function))throw new Error("First param must be transport or constructor of transport");n=new t;}return new x(n,r,s)}}

/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    if (typeof b !== "function" && b !== null)
        throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spreadArray(to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
}

function isFunction(value) {
    return typeof value === 'function';
}

function createErrorClass(createImpl) {
    var _super = function (instance) {
        Error.call(instance);
        instance.stack = new Error().stack;
    };
    var ctorFunc = createImpl(_super);
    ctorFunc.prototype = Object.create(Error.prototype);
    ctorFunc.prototype.constructor = ctorFunc;
    return ctorFunc;
}

var UnsubscriptionError = createErrorClass(function (_super) {
    return function UnsubscriptionErrorImpl(errors) {
        _super(this);
        this.message = errors
            ? errors.length + " errors occurred during unsubscription:\n" + errors.map(function (err, i) { return i + 1 + ") " + err.toString(); }).join('\n  ')
            : '';
        this.name = 'UnsubscriptionError';
        this.errors = errors;
    };
});

function arrRemove(arr, item) {
    if (arr) {
        var index = arr.indexOf(item);
        0 <= index && arr.splice(index, 1);
    }
}

var Subscription = (function () {
    function Subscription(initialTeardown) {
        this.initialTeardown = initialTeardown;
        this.closed = false;
        this._parentage = null;
        this._finalizers = null;
    }
    Subscription.prototype.unsubscribe = function () {
        var e_1, _a, e_2, _b;
        var errors;
        if (!this.closed) {
            this.closed = true;
            var _parentage = this._parentage;
            if (_parentage) {
                this._parentage = null;
                if (Array.isArray(_parentage)) {
                    try {
                        for (var _parentage_1 = __values(_parentage), _parentage_1_1 = _parentage_1.next(); !_parentage_1_1.done; _parentage_1_1 = _parentage_1.next()) {
                            var parent_1 = _parentage_1_1.value;
                            parent_1.remove(this);
                        }
                    }
                    catch (e_1_1) { e_1 = { error: e_1_1 }; }
                    finally {
                        try {
                            if (_parentage_1_1 && !_parentage_1_1.done && (_a = _parentage_1.return)) _a.call(_parentage_1);
                        }
                        finally { if (e_1) throw e_1.error; }
                    }
                }
                else {
                    _parentage.remove(this);
                }
            }
            var initialFinalizer = this.initialTeardown;
            if (isFunction(initialFinalizer)) {
                try {
                    initialFinalizer();
                }
                catch (e) {
                    errors = e instanceof UnsubscriptionError ? e.errors : [e];
                }
            }
            var _finalizers = this._finalizers;
            if (_finalizers) {
                this._finalizers = null;
                try {
                    for (var _finalizers_1 = __values(_finalizers), _finalizers_1_1 = _finalizers_1.next(); !_finalizers_1_1.done; _finalizers_1_1 = _finalizers_1.next()) {
                        var finalizer = _finalizers_1_1.value;
                        try {
                            execFinalizer(finalizer);
                        }
                        catch (err) {
                            errors = errors !== null && errors !== void 0 ? errors : [];
                            if (err instanceof UnsubscriptionError) {
                                errors = __spreadArray(__spreadArray([], __read(errors)), __read(err.errors));
                            }
                            else {
                                errors.push(err);
                            }
                        }
                    }
                }
                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                finally {
                    try {
                        if (_finalizers_1_1 && !_finalizers_1_1.done && (_b = _finalizers_1.return)) _b.call(_finalizers_1);
                    }
                    finally { if (e_2) throw e_2.error; }
                }
            }
            if (errors) {
                throw new UnsubscriptionError(errors);
            }
        }
    };
    Subscription.prototype.add = function (teardown) {
        var _a;
        if (teardown && teardown !== this) {
            if (this.closed) {
                execFinalizer(teardown);
            }
            else {
                if (teardown instanceof Subscription) {
                    if (teardown.closed || teardown._hasParent(this)) {
                        return;
                    }
                    teardown._addParent(this);
                }
                (this._finalizers = (_a = this._finalizers) !== null && _a !== void 0 ? _a : []).push(teardown);
            }
        }
    };
    Subscription.prototype._hasParent = function (parent) {
        var _parentage = this._parentage;
        return _parentage === parent || (Array.isArray(_parentage) && _parentage.includes(parent));
    };
    Subscription.prototype._addParent = function (parent) {
        var _parentage = this._parentage;
        this._parentage = Array.isArray(_parentage) ? (_parentage.push(parent), _parentage) : _parentage ? [_parentage, parent] : parent;
    };
    Subscription.prototype._removeParent = function (parent) {
        var _parentage = this._parentage;
        if (_parentage === parent) {
            this._parentage = null;
        }
        else if (Array.isArray(_parentage)) {
            arrRemove(_parentage, parent);
        }
    };
    Subscription.prototype.remove = function (teardown) {
        var _finalizers = this._finalizers;
        _finalizers && arrRemove(_finalizers, teardown);
        if (teardown instanceof Subscription) {
            teardown._removeParent(this);
        }
    };
    Subscription.EMPTY = (function () {
        var empty = new Subscription();
        empty.closed = true;
        return empty;
    })();
    return Subscription;
}());
var EMPTY_SUBSCRIPTION = Subscription.EMPTY;
function isSubscription(value) {
    return (value instanceof Subscription ||
        (value && 'closed' in value && isFunction(value.remove) && isFunction(value.add) && isFunction(value.unsubscribe)));
}
function execFinalizer(finalizer) {
    if (isFunction(finalizer)) {
        finalizer();
    }
    else {
        finalizer.unsubscribe();
    }
}

var config = {
    onUnhandledError: null,
    onStoppedNotification: null,
    Promise: undefined,
    useDeprecatedSynchronousErrorHandling: false,
    useDeprecatedNextContext: false,
};

var timeoutProvider = {
    setTimeout: function (handler, timeout) {
        var args = [];
        for (var _i = 2; _i < arguments.length; _i++) {
            args[_i - 2] = arguments[_i];
        }
        var delegate = timeoutProvider.delegate;
        if (delegate === null || delegate === void 0 ? void 0 : delegate.setTimeout) {
            return delegate.setTimeout.apply(delegate, __spreadArray([handler, timeout], __read(args)));
        }
        return setTimeout.apply(void 0, __spreadArray([handler, timeout], __read(args)));
    },
    clearTimeout: function (handle) {
        var delegate = timeoutProvider.delegate;
        return ((delegate === null || delegate === void 0 ? void 0 : delegate.clearTimeout) || clearTimeout)(handle);
    },
    delegate: undefined,
};

function reportUnhandledError(err) {
    timeoutProvider.setTimeout(function () {
        {
            throw err;
        }
    });
}

function noop() { }

function errorContext(cb) {
    {
        cb();
    }
}

var Subscriber = (function (_super) {
    __extends(Subscriber, _super);
    function Subscriber(destination) {
        var _this = _super.call(this) || this;
        _this.isStopped = false;
        if (destination) {
            _this.destination = destination;
            if (isSubscription(destination)) {
                destination.add(_this);
            }
        }
        else {
            _this.destination = EMPTY_OBSERVER;
        }
        return _this;
    }
    Subscriber.create = function (next, error, complete) {
        return new SafeSubscriber(next, error, complete);
    };
    Subscriber.prototype.next = function (value) {
        if (this.isStopped) ;
        else {
            this._next(value);
        }
    };
    Subscriber.prototype.error = function (err) {
        if (this.isStopped) ;
        else {
            this.isStopped = true;
            this._error(err);
        }
    };
    Subscriber.prototype.complete = function () {
        if (this.isStopped) ;
        else {
            this.isStopped = true;
            this._complete();
        }
    };
    Subscriber.prototype.unsubscribe = function () {
        if (!this.closed) {
            this.isStopped = true;
            _super.prototype.unsubscribe.call(this);
            this.destination = null;
        }
    };
    Subscriber.prototype._next = function (value) {
        this.destination.next(value);
    };
    Subscriber.prototype._error = function (err) {
        try {
            this.destination.error(err);
        }
        finally {
            this.unsubscribe();
        }
    };
    Subscriber.prototype._complete = function () {
        try {
            this.destination.complete();
        }
        finally {
            this.unsubscribe();
        }
    };
    return Subscriber;
}(Subscription));
var _bind = Function.prototype.bind;
function bind(fn, thisArg) {
    return _bind.call(fn, thisArg);
}
var ConsumerObserver = (function () {
    function ConsumerObserver(partialObserver) {
        this.partialObserver = partialObserver;
    }
    ConsumerObserver.prototype.next = function (value) {
        var partialObserver = this.partialObserver;
        if (partialObserver.next) {
            try {
                partialObserver.next(value);
            }
            catch (error) {
                handleUnhandledError(error);
            }
        }
    };
    ConsumerObserver.prototype.error = function (err) {
        var partialObserver = this.partialObserver;
        if (partialObserver.error) {
            try {
                partialObserver.error(err);
            }
            catch (error) {
                handleUnhandledError(error);
            }
        }
        else {
            handleUnhandledError(err);
        }
    };
    ConsumerObserver.prototype.complete = function () {
        var partialObserver = this.partialObserver;
        if (partialObserver.complete) {
            try {
                partialObserver.complete();
            }
            catch (error) {
                handleUnhandledError(error);
            }
        }
    };
    return ConsumerObserver;
}());
var SafeSubscriber = (function (_super) {
    __extends(SafeSubscriber, _super);
    function SafeSubscriber(observerOrNext, error, complete) {
        var _this = _super.call(this) || this;
        var partialObserver;
        if (isFunction(observerOrNext) || !observerOrNext) {
            partialObserver = {
                next: (observerOrNext !== null && observerOrNext !== void 0 ? observerOrNext : undefined),
                error: error !== null && error !== void 0 ? error : undefined,
                complete: complete !== null && complete !== void 0 ? complete : undefined,
            };
        }
        else {
            var context_1;
            if (_this && config.useDeprecatedNextContext) {
                context_1 = Object.create(observerOrNext);
                context_1.unsubscribe = function () { return _this.unsubscribe(); };
                partialObserver = {
                    next: observerOrNext.next && bind(observerOrNext.next, context_1),
                    error: observerOrNext.error && bind(observerOrNext.error, context_1),
                    complete: observerOrNext.complete && bind(observerOrNext.complete, context_1),
                };
            }
            else {
                partialObserver = observerOrNext;
            }
        }
        _this.destination = new ConsumerObserver(partialObserver);
        return _this;
    }
    return SafeSubscriber;
}(Subscriber));
function handleUnhandledError(error) {
    {
        reportUnhandledError(error);
    }
}
function defaultErrorHandler(err) {
    throw err;
}
var EMPTY_OBSERVER = {
    closed: true,
    next: noop,
    error: defaultErrorHandler,
    complete: noop,
};

var observable = (function () { return (typeof Symbol === 'function' && Symbol.observable) || '@@observable'; })();

function identity(x) {
    return x;
}

function pipeFromArray(fns) {
    if (fns.length === 0) {
        return identity;
    }
    if (fns.length === 1) {
        return fns[0];
    }
    return function piped(input) {
        return fns.reduce(function (prev, fn) { return fn(prev); }, input);
    };
}

var Observable = (function () {
    function Observable(subscribe) {
        if (subscribe) {
            this._subscribe = subscribe;
        }
    }
    Observable.prototype.lift = function (operator) {
        var observable = new Observable();
        observable.source = this;
        observable.operator = operator;
        return observable;
    };
    Observable.prototype.subscribe = function (observerOrNext, error, complete) {
        var _this = this;
        var subscriber = isSubscriber(observerOrNext) ? observerOrNext : new SafeSubscriber(observerOrNext, error, complete);
        errorContext(function () {
            var _a = _this, operator = _a.operator, source = _a.source;
            subscriber.add(operator
                ?
                    operator.call(subscriber, source)
                : source
                    ?
                        _this._subscribe(subscriber)
                    :
                        _this._trySubscribe(subscriber));
        });
        return subscriber;
    };
    Observable.prototype._trySubscribe = function (sink) {
        try {
            return this._subscribe(sink);
        }
        catch (err) {
            sink.error(err);
        }
    };
    Observable.prototype.forEach = function (next, promiseCtor) {
        var _this = this;
        promiseCtor = getPromiseCtor(promiseCtor);
        return new promiseCtor(function (resolve, reject) {
            var subscriber = new SafeSubscriber({
                next: function (value) {
                    try {
                        next(value);
                    }
                    catch (err) {
                        reject(err);
                        subscriber.unsubscribe();
                    }
                },
                error: reject,
                complete: resolve,
            });
            _this.subscribe(subscriber);
        });
    };
    Observable.prototype._subscribe = function (subscriber) {
        var _a;
        return (_a = this.source) === null || _a === void 0 ? void 0 : _a.subscribe(subscriber);
    };
    Observable.prototype[observable] = function () {
        return this;
    };
    Observable.prototype.pipe = function () {
        var operations = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            operations[_i] = arguments[_i];
        }
        return pipeFromArray(operations)(this);
    };
    Observable.prototype.toPromise = function (promiseCtor) {
        var _this = this;
        promiseCtor = getPromiseCtor(promiseCtor);
        return new promiseCtor(function (resolve, reject) {
            var value;
            _this.subscribe(function (x) { return (value = x); }, function (err) { return reject(err); }, function () { return resolve(value); });
        });
    };
    Observable.create = function (subscribe) {
        return new Observable(subscribe);
    };
    return Observable;
}());
function getPromiseCtor(promiseCtor) {
    var _a;
    return (_a = promiseCtor !== null && promiseCtor !== void 0 ? promiseCtor : config.Promise) !== null && _a !== void 0 ? _a : Promise;
}
function isObserver(value) {
    return value && isFunction(value.next) && isFunction(value.error) && isFunction(value.complete);
}
function isSubscriber(value) {
    return (value && value instanceof Subscriber) || (isObserver(value) && isSubscription(value));
}

var ObjectUnsubscribedError = createErrorClass(function (_super) {
    return function ObjectUnsubscribedErrorImpl() {
        _super(this);
        this.name = 'ObjectUnsubscribedError';
        this.message = 'object unsubscribed';
    };
});

var Subject = (function (_super) {
    __extends(Subject, _super);
    function Subject() {
        var _this = _super.call(this) || this;
        _this.closed = false;
        _this.currentObservers = null;
        _this.observers = [];
        _this.isStopped = false;
        _this.hasError = false;
        _this.thrownError = null;
        return _this;
    }
    Subject.prototype.lift = function (operator) {
        var subject = new AnonymousSubject(this, this);
        subject.operator = operator;
        return subject;
    };
    Subject.prototype._throwIfClosed = function () {
        if (this.closed) {
            throw new ObjectUnsubscribedError();
        }
    };
    Subject.prototype.next = function (value) {
        var _this = this;
        errorContext(function () {
            var e_1, _a;
            _this._throwIfClosed();
            if (!_this.isStopped) {
                if (!_this.currentObservers) {
                    _this.currentObservers = Array.from(_this.observers);
                }
                try {
                    for (var _b = __values(_this.currentObservers), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var observer = _c.value;
                        observer.next(value);
                    }
                }
                catch (e_1_1) { e_1 = { error: e_1_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
            }
        });
    };
    Subject.prototype.error = function (err) {
        var _this = this;
        errorContext(function () {
            _this._throwIfClosed();
            if (!_this.isStopped) {
                _this.hasError = _this.isStopped = true;
                _this.thrownError = err;
                var observers = _this.observers;
                while (observers.length) {
                    observers.shift().error(err);
                }
            }
        });
    };
    Subject.prototype.complete = function () {
        var _this = this;
        errorContext(function () {
            _this._throwIfClosed();
            if (!_this.isStopped) {
                _this.isStopped = true;
                var observers = _this.observers;
                while (observers.length) {
                    observers.shift().complete();
                }
            }
        });
    };
    Subject.prototype.unsubscribe = function () {
        this.isStopped = this.closed = true;
        this.observers = this.currentObservers = null;
    };
    Object.defineProperty(Subject.prototype, "observed", {
        get: function () {
            var _a;
            return ((_a = this.observers) === null || _a === void 0 ? void 0 : _a.length) > 0;
        },
        enumerable: false,
        configurable: true
    });
    Subject.prototype._trySubscribe = function (subscriber) {
        this._throwIfClosed();
        return _super.prototype._trySubscribe.call(this, subscriber);
    };
    Subject.prototype._subscribe = function (subscriber) {
        this._throwIfClosed();
        this._checkFinalizedStatuses(subscriber);
        return this._innerSubscribe(subscriber);
    };
    Subject.prototype._innerSubscribe = function (subscriber) {
        var _this = this;
        var _a = this, hasError = _a.hasError, isStopped = _a.isStopped, observers = _a.observers;
        if (hasError || isStopped) {
            return EMPTY_SUBSCRIPTION;
        }
        this.currentObservers = null;
        observers.push(subscriber);
        return new Subscription(function () {
            _this.currentObservers = null;
            arrRemove(observers, subscriber);
        });
    };
    Subject.prototype._checkFinalizedStatuses = function (subscriber) {
        var _a = this, hasError = _a.hasError, thrownError = _a.thrownError, isStopped = _a.isStopped;
        if (hasError) {
            subscriber.error(thrownError);
        }
        else if (isStopped) {
            subscriber.complete();
        }
    };
    Subject.prototype.asObservable = function () {
        var observable = new Observable();
        observable.source = this;
        return observable;
    };
    Subject.create = function (destination, source) {
        return new AnonymousSubject(destination, source);
    };
    return Subject;
}(Observable));
var AnonymousSubject = (function (_super) {
    __extends(AnonymousSubject, _super);
    function AnonymousSubject(destination, source) {
        var _this = _super.call(this) || this;
        _this.destination = destination;
        _this.source = source;
        return _this;
    }
    AnonymousSubject.prototype.next = function (value) {
        var _a, _b;
        (_b = (_a = this.destination) === null || _a === void 0 ? void 0 : _a.next) === null || _b === void 0 ? void 0 : _b.call(_a, value);
    };
    AnonymousSubject.prototype.error = function (err) {
        var _a, _b;
        (_b = (_a = this.destination) === null || _a === void 0 ? void 0 : _a.error) === null || _b === void 0 ? void 0 : _b.call(_a, err);
    };
    AnonymousSubject.prototype.complete = function () {
        var _a, _b;
        (_b = (_a = this.destination) === null || _a === void 0 ? void 0 : _a.complete) === null || _b === void 0 ? void 0 : _b.call(_a);
    };
    AnonymousSubject.prototype._subscribe = function (subscriber) {
        var _a, _b;
        return (_b = (_a = this.source) === null || _a === void 0 ? void 0 : _a.subscribe(subscriber)) !== null && _b !== void 0 ? _b : EMPTY_SUBSCRIPTION;
    };
    return AnonymousSubject;
}(Subject));

var BehaviorSubject = (function (_super) {
    __extends(BehaviorSubject, _super);
    function BehaviorSubject(_value) {
        var _this = _super.call(this) || this;
        _this._value = _value;
        return _this;
    }
    Object.defineProperty(BehaviorSubject.prototype, "value", {
        get: function () {
            return this.getValue();
        },
        enumerable: false,
        configurable: true
    });
    BehaviorSubject.prototype._subscribe = function (subscriber) {
        var subscription = _super.prototype._subscribe.call(this, subscriber);
        !subscription.closed && subscriber.next(this._value);
        return subscription;
    };
    BehaviorSubject.prototype.getValue = function () {
        var _a = this, hasError = _a.hasError, thrownError = _a.thrownError, _value = _a._value;
        if (hasError) {
            throw thrownError;
        }
        this._throwIfClosed();
        return _value;
    };
    BehaviorSubject.prototype.next = function (value) {
        _super.prototype.next.call(this, (this._value = value));
    };
    return BehaviorSubject;
}(Subject));

class SessionManager {
    constructor(options) {
        this.fetch = async (...args) => {
            await this.initialized;
            if (this.session == null) {
                throw new Error('no session');
            }
            return await this.session.send(...args);
        };
        this.protocol = options.protocol;
        this.$session = new BehaviorSubject(undefined);
        this.initialized = this.init();
    }
    async init(storage, storageOptions) {
        if (storage === undefined) {
            {
                const SessionLocalStorage = (await Promise.resolve().then(function () { return sessionLocalstorage; })).SessionLocalStorage;
                this.storage = new SessionLocalStorage(storageOptions?.localStorage);
            }
        }
        else {
            this.storage = storage;
        }
    }
    get hasSession() {
        return this.session !== undefined;
    }
    async createIfNotExists() {
        await this.initialized;
        if (this.session !== undefined) {
            return this.session;
        }
        const session = await this.protocol.run();
        await this.setSession(session);
        return session;
    }
    async removeSession() {
        await this.initialized;
        await this.setSession();
    }
    async setSession(session) {
        await this.initialized;
        this.session = session;
        if (session === undefined || session === null) {
            await this.storage.clear();
        }
        else {
            const sessionJson = session.toJSON();
            await this.storage.setSessionData(sessionJson);
        }
        this.$session.next(session);
    }
    async loadSession() {
        await this.initialized;
        let session;
        try {
            const sessionJson = await this.storage.getSessionData();
            if (sessionJson !== null) {
                session = await x.fromJSON(this.protocol.transport, sessionJson);
            }
        }
        catch (error) { }
        await this.setSession(session);
    }
}
class LocalSessionManager extends SessionManager {
    constructor(protocol, options = {}) {
        super({ protocol, storageOptions: { localStorage: { key: options.localStorageKey } } });
        this.protocol = protocol;
    }
}

var styleCss = ".__WALLET_PROTOCOL_OVERLAY__ {\n    position: absolute;\n    display: flex;\n    height: 100%;\n    width: 100%;\n    top: 0;\n    left: 0;\n    align-items: center;\n    justify-content: center;\n    background-color: #000000AA;\n    font-family: 'sans-serif';\n    color: #202531;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MODAL__ {\n    display: flex;\n    flex-direction: column;\n    align-items: center;\n    justify-content: center;\n    border: 2px solid #1A1E27;\n    border-radius: 5px;\n    padding: 10px 20px;\n    background-image: linear-gradient(to bottom left, white, #D2D6E1);\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_TITLE__ {\n    font-weight: bold;\n    padding: 5px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MESSAGE__ {\n    opacity: 0.5;\n    padding: 5px;\n    font-size: 15px\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT_BOX__ {\n    display: flex;\n    margin: 20px;\n    height: 32px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT__ {\n    border-radius: 3px;\n    border-top-right-radius: 0;\n    border-bottom-right-radius: 0;\n    outline: none;\n    padding: 5px;\n    border: 2px solid #1A1E27;\n    border-right: none;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_BUTTON__ {\n    height: 100%;\n    padding: 5px;\n    border-radius: 3px;\n    border: 2px solid #1A1E27;\n    border-top-left-radius: 0;\n    border-bottom-left-radius: 0;\n    cursor: pointer;\n}\n";

const defaultHtmlOptions = {
    overlayClass: 'wallet-protocol-overlay',
    modalClass: 'wallet-modal',
    titleClass: 'wallet-title',
    messageClass: 'wallet-message',
    inputBoxClass: 'wallet-input-box',
    inputClass: 'wallet-input',
    buttonClass: 'wallet-button'
};
const pinHtmlFormDialog = async (opts = defaultHtmlOptions) => {
    const options = Object.assign({}, opts, defaultHtmlOptions);
    const overlay = document.createElement('div');
    document.body.appendChild(overlay);
    overlay.className = options.overlayClass;
    const style = document.createElement('style');
    overlay.appendChild(style);
    style.innerText = styleCss
        .replace(/__WALLET_PROTOCOL_OVERLAY__/g, options.overlayClass)
        .replace(/__WALLET_MODAL__/g, options.modalClass)
        .replace(/__WALLET_TITLE__/g, options.titleClass)
        .replace(/__WALLET_MESSAGE__/g, options.messageClass)
        .replace(/__WALLET_INPUT_BOX__/g, options.inputBoxClass)
        .replace(/__WALLET_INPUT__/g, options.inputClass)
        .replace(/__WALLET_BUTTON__/g, options.buttonClass);
    const modal = document.createElement('div');
    overlay.appendChild(modal);
    modal.className = options.modalClass;
    const title = document.createElement('span');
    modal.appendChild(title);
    title.className = options.titleClass;
    title.innerText = 'Connecting to your wallet...';
    const message = document.createElement('span');
    modal.appendChild(message);
    message.className = options.messageClass;
    message.innerText = 'Set up your wallet on pairing mode and put the PIN here';
    const inputBox = document.createElement('div');
    modal.appendChild(inputBox);
    inputBox.className = options.inputBoxClass;
    const pinInput = document.createElement('input');
    inputBox.appendChild(pinInput);
    pinInput.className = options.inputClass;
    pinInput.autofocus = true;
    pinInput.setAttribute('placeholder', 'pin...');
    const pairButton = document.createElement('button');
    inputBox.appendChild(pairButton);
    pairButton.className = options.buttonClass;
    pairButton.innerText = 'Syncronize';
    return await new Promise((resolve, reject) => {
        const close = (value) => {
            document.body.removeChild(overlay);
            resolve(value ?? '');
        };
        pinInput.addEventListener('keypress', (ev) => {
            if (ev.key === 'Enter') {
                close(pinInput.value);
            }
        });
        pairButton.addEventListener('click', () => close(pinInput.value));
        overlay.addEventListener('click', (ev) => {
            if (ev.target === overlay) {
                close();
            }
        });
    });
};

var pinHtmlformDialog = /*#__PURE__*/Object.freeze({
    __proto__: null,
    pinHtmlFormDialog: pinHtmlFormDialog
});

class SessionLocalStorage {
    constructor(options) {
        this.key = (typeof options?.key === 'string' && options.key !== '') ? options.key : 'wallet-session';
    }
    async getSessionData() {
        const item = localStorage.getItem(this.key);
        if (item == null) {
            throw new Error('no session data stored');
        }
        return JSON.parse(item);
    }
    async setSessionData(json) {
        localStorage.setItem(this.key, JSON.stringify(json));
    }
    async clear() {
        localStorage.removeItem(this.key);
    }
}

var sessionLocalstorage = /*#__PURE__*/Object.freeze({
    __proto__: null,
    SessionLocalStorage: SessionLocalStorage
});

export { LocalSessionManager, SessionManager, openModal, pinDialog };
