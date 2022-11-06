'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var crypto = require('crypto');
var base64 = require('@juanelas/base64');
var pbkdf2Hmac = require('pbkdf2-hmac');
var objectSha = require('object-sha');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

function _interopNamespace(e) {
    if (e && e.__esModule) return e;
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () { return e[k]; }
                });
            }
        });
    }
    n["default"] = e;
    return Object.freeze(n);
}

var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var base64__namespace = /*#__PURE__*/_interopNamespace(base64);
var pbkdf2Hmac__default = /*#__PURE__*/_interopDefaultLegacy(pbkdf2Hmac);
var objectSha__namespace = /*#__PURE__*/_interopNamespace(objectSha);

class BaseTransport {
    async send(masterKey, code, req) {
        throw new Error('this transport cannot send messages');
    }
    finish(protocol) {
        protocol.emit('finished');
    }
}

const PORT_LENGTH = 12;
const DEFAULT_RANDOM_LENGTH = 36; // In bits
const DEFAULT_TIMEOUT = 30000; // in milliseconds
const PORT_SPACE = 2 ** PORT_LENGTH;
const INITIAL_PORT = 29170;
const NONCE_LENGTH = 128; // In bits
const COMMITMENT_LENGTH = 256; // In bits

var protocolConstants = /*#__PURE__*/Object.freeze({
    __proto__: null,
    PORT_LENGTH: PORT_LENGTH,
    DEFAULT_RANDOM_LENGTH: DEFAULT_RANDOM_LENGTH,
    DEFAULT_TIMEOUT: DEFAULT_TIMEOUT,
    PORT_SPACE: PORT_SPACE,
    INITIAL_PORT: INITIAL_PORT,
    NONCE_LENGTH: NONCE_LENGTH,
    COMMITMENT_LENGTH: COMMITMENT_LENGTH
});

const RPC_URL_PATH = '.well-known/wallet-protocol';

var httpConstants = /*#__PURE__*/Object.freeze({
    __proto__: null,
    RPC_URL_PATH: RPC_URL_PATH
});

var constants = {
    ...protocolConstants,
    ...httpConstants
};

class BaseECDH {
    async generateKeys() {
        throw new Error('not implemented');
    }
    async getPublicKey() {
        throw new Error('not implemented');
    }
    async deriveBits(publicKeyHex) {
        throw new Error('not implemented');
    }
}
class BaseRandom {
    async randomFill(buffer, start, size) {
        throw new Error('not implemented');
    }
    async randomFillBits(buffer, start, size) {
        const byteLen = Math.ceil(size / 8);
        const randomBytes = new Uint8Array(byteLen);
        await this.randomFill(randomBytes, 0, byteLen);
        bufferUtils.insertBits(randomBytes, buffer, 0, start, size);
    }
}
class BaseCipher {
    constructor(algorithm, key) {
        this.algorithm = algorithm;
        this.key = key;
    }
    async encrypt(payload) {
        throw new Error('not implemented');
    }
    async decrypt(ciphertext) {
        throw new Error('not implemented');
    }
}
class BaseDigest {
    async digest(algorithm, input) {
        throw new Error('not implemented');
    }
}

class NodeRandom extends BaseRandom {
    async randomFill(buffer, start, size) {
        return await new Promise(resolve => {
            crypto__default["default"].randomFill(buffer, start, size, () => {
                resolve();
            });
        });
    }
}
const random = new NodeRandom();

class Cipher extends BaseCipher {
    async encrypt(payload) {
        const iv = new Uint8Array(12);
        await random.randomFill(iv, 0, iv.length);
        const cryptoKey = crypto__default["default"].createSecretKey(this.key);
        const cipher = crypto__default["default"].createCipheriv(this.algorithm, cryptoKey, iv);
        const buffers = [];
        buffers.push(iv);
        buffers.push(cipher.update(payload));
        buffers.push(cipher.final());
        buffers.push(cipher.getAuthTag());
        return bufferUtils.join(...buffers);
    }
    async decrypt(cryptosecuence) {
        const sizes = [];
        switch (this.algorithm) {
            case 'aes-256-gcm':
                sizes[0] = 12; // IV Size
                sizes[2] = 16; // AuthTag size
                break;
        }
        sizes[1] = cryptosecuence.length - sizes[0] - (sizes[2] ?? 0);
        const [iv, ciphertext, authTag] = bufferUtils.split(cryptosecuence, ...sizes);
        const cryptoKey = crypto__default["default"].createSecretKey(this.key);
        const decipher = crypto__default["default"].createDecipheriv(this.algorithm, cryptoKey, iv);
        if (authTag !== undefined) {
            decipher.setAuthTag(authTag);
        }
        const buffers = [];
        buffers.push(decipher.update(ciphertext));
        buffers.push(decipher.final());
        return bufferUtils.join(...buffers);
    }
}

class ECDH extends BaseECDH {
    constructor() {
        super();
        this.ecdh = crypto__default["default"].createECDH('prime256v1');
    }
    async generateKeys() {
        // FIXME: PSEUDO RANDOM! DANGER!! OR NOT???
        this.ecdh.generateKeys();
    }
    async getPublicKey() {
        return this.ecdh.getPublicKey('hex');
    }
    async deriveBits(publicKeyHex) {
        const key = this.ecdh.computeSecret(publicKeyHex, 'hex');
        return new Uint8Array(key);
    }
}

class NodeDigest extends BaseDigest {
    async digest(algorithm, input) {
        const hash = crypto__default["default"].createHash(algorithm);
        const buffer = hash.update(input).digest();
        return new Uint8Array(buffer.buffer);
    }
}
const digest = new NodeDigest();

const format = {
    utf2U8Arr: (text) => {
        return new TextEncoder().encode(text);
    },
    u8Arr2Utf: (arr) => {
        return new TextDecoder().decode(arr);
    },
    num2U8Arr: (num, len) => {
        if (len === undefined) {
            len = 1;
            while (2 ** (len * 8) < num) {
                len++;
            }
        }
        const arr = new Uint8Array(len);
        let rest = num;
        for (let i = len - 1; i >= 0; i--) {
            const nextRest = rest >> 8;
            const num = rest - (nextRest << 8);
            arr[i] = num;
            rest = nextRest;
        }
        return arr;
    },
    u8Arr2Num: (buffer) => {
        let num = 0;
        for (let i = 0; i < buffer.length; i++) {
            num += buffer[i] << ((buffer.length - 1) - i);
        }
        return num;
    },
    hex2U8Arr: (hex) => {
        const match = hex.match(/.{1,2}/g);
        if (match === null) {
            throw new Error(`not a hex: ${hex}`);
        }
        return new Uint8Array(match.map(byte => parseInt(byte, 16)));
    },
    u8Arr2Hex: (arr) => {
        return arr.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
    },
    u8Arr2Base64: (arr) => {
        return base64__namespace.encode(arr, true, false);
    },
    base642U8Arr: (b64) => {
        return base64__namespace.decode(b64, false);
    }
};

const bufferUtils = {
    join: (...list) => {
        const size = list.reduce((a, b) => a + b.length, 0);
        const buffer = new Uint8Array(size);
        let accLen = 0;
        for (const el of list) {
            buffer.set(el, accLen);
            accLen += el.length;
        }
        return buffer;
    },
    split: (buffer, ...sizes) => {
        const list = [];
        let start = 0;
        for (const size of sizes) {
            list.push(buffer.slice(start, start + size));
            start += size;
        }
        return list;
    },
    insertBytes: (src, dst, fromStart, toStart, size) => {
        for (let i = 0; i < size; i++) {
            dst[i + toStart] = src[i + fromStart];
        }
    },
    insertBits: (src, dst, fromStart, toStart, size) => {
        let fromByteIndex = Math.floor(fromStart / 8);
        let fromBitIndex = fromStart % 8;
        let toByteIndex = Math.floor(toStart / 8);
        let toBitIndex = toStart % 8;
        let currFromByte = src[fromByteIndex] ?? 0;
        const deltaOffset = toBitIndex - fromBitIndex;
        for (let i = 0; i < size; i++) {
            let currBit;
            if (deltaOffset >= 0) {
                currBit = ((currFromByte & (128 >> fromBitIndex)) << deltaOffset);
            }
            else {
                currBit = ((currFromByte & (128 >> fromBitIndex)));
            }
            const bitSet = ((dst[toByteIndex] & ~(128 >> toBitIndex)) | currBit);
            dst[toByteIndex] = bitSet;
            // Move pointers
            fromBitIndex++;
            toBitIndex++;
            if (fromBitIndex >= 8) {
                fromByteIndex++;
                fromBitIndex = 0;
                currFromByte = src[fromByteIndex] ?? 0;
            }
            if (toBitIndex >= 8) {
                toByteIndex++;
                toBitIndex = 0;
            }
        }
    },
    extractBits: (buf, start, size) => {
        const byteSize = Math.ceil(size / 8);
        const dst = new Uint8Array(byteSize);
        bufferUtils.insertBits(buf, dst, start, 0, size);
        return dst;
    }
};

class Subject {
    get promise() {
        return this.createPromise();
    }
    async createPromise() {
        return await new Promise((resolve, reject) => {
            this.resolve = resolve;
            this.reject = reject;
        });
    }
    next(value) {
        if (this.resolve != null) {
            this.resolve(value);
        }
    }
    err(reason) {
        if (this.reject != null) {
            this.reject(reason);
        }
    }
}

class EventEmitter {
    constructor() {
        this.events = {};
    }
    on(event, cb) {
        if (this.events[event] === undefined) {
            this.events[event] = [];
        }
        this.events[event].push(cb);
        return this;
    }
    emit(event, ...data) {
        const eventCbs = this.events[event];
        if (eventCbs !== undefined) {
            eventCbs.forEach(eventCb => eventCb(...data));
            return true;
        }
        return false;
    }
}

const deriveKey = async (from, to, secret) => {
    // Prepare data
    const salt = new Uint8Array(16);
    const pbkdf2Input = new Uint8Array(32 * 3);
    const fromBuffer = format.hex2U8Arr(from);
    const toBuffer = format.hex2U8Arr(to);
    // Prepare input
    bufferUtils.insertBytes(secret, pbkdf2Input, 0, 0, 32);
    bufferUtils.insertBytes(fromBuffer, pbkdf2Input, 0, 32, 32);
    bufferUtils.insertBytes(toBuffer, pbkdf2Input, 0, 32 * 2, 32);
    const derivatedSecret = await pbkdf2Hmac__default["default"](pbkdf2Input, salt, 1, 32);
    return new Uint8Array(derivatedSecret);
};
class MasterKey {
    constructor(port, from, to, na, nb, secret, encryptKey, decryptKey) {
        this.port = port;
        this.from = from;
        this.to = to;
        this.na = na;
        this.nb = nb;
        this.secret = secret;
        this.cipher = new Cipher('aes-256-gcm', encryptKey);
        this.decipher = new Cipher('aes-256-gcm', decryptKey);
    }
    async encrypt(message) {
        return await this.cipher.encrypt(message);
    }
    async decrypt(ciphertext) {
        return await this.decipher.decrypt(ciphertext);
    }
    toJSON() {
        return {
            from: this.from,
            to: this.to,
            port: this.port,
            na: format.u8Arr2Base64(this.na),
            nb: format.u8Arr2Base64(this.nb),
            secret: format.u8Arr2Base64(this.secret)
        };
    }
    async fromHash() {
        return await objectSha__namespace.digest(this.from);
    }
    async toHash() {
        return await objectSha__namespace.digest(this.to);
    }
    static async fromSecret(port, from, to, na, nb, secret) {
        const fromHash = await objectSha__namespace.digest(from);
        const toHash = await objectSha__namespace.digest(to);
        const encryptKey = await deriveKey(fromHash, toHash, secret);
        const decryptKey = await deriveKey(toHash, fromHash, secret);
        return new MasterKey(port, from, to, na, nb, secret, encryptKey, decryptKey);
    }
    static async fromJSON(data) {
        const na = format.base642U8Arr(data.na);
        const nb = format.base642U8Arr(data.nb);
        const secret = format.base642U8Arr(data.secret);
        return await this.fromSecret(data.port, data.from, data.to, na, nb, secret);
    }
}

class Session {
    constructor(transport, masterKey, code) {
        this.transport = transport;
        this.masterKey = masterKey;
        this.code = code;
    }
    async send(request) {
        return await this.transport.send(this.masterKey, this.code, request);
    }
    toJSON() {
        return {
            masterKey: this.masterKey.toJSON(),
            code: format.u8Arr2Hex(this.code)
        };
    }
    static async fromJSON(TransportOrConstructor, json) {
        const masterKey = await MasterKey.fromJSON(json.masterKey);
        const code = format.hex2U8Arr(json.code);
        let transport;
        if (typeof TransportOrConstructor === 'object') {
            transport = TransportOrConstructor;
        }
        else if (TransportOrConstructor instanceof Function) {
            transport = new TransportOrConstructor();
        }
        else {
            throw new Error('First param must be transport or constructor of transport');
        }
        return new Session(transport, masterKey, code);
    }
}

class WalletProtocol extends EventEmitter {
    constructor(transport) {
        super();
        this.transport = transport;
    }
    async computeR(ra, rb) {
        return ra.map((val, i) => val ^ rb[i]);
    }
    async computeNx() {
        const nLen = Math.ceil(constants.NONCE_LENGTH / 8);
        const nx = new Uint8Array(nLen);
        await random.randomFillBits(nx, 0, constants.NONCE_LENGTH);
        return nx;
    }
    async computeCx(pkeData, nx, r) {
        const nLen = Math.ceil(constants.NONCE_LENGTH / 8);
        const rLen = Math.ceil(constants.DEFAULT_RANDOM_LENGTH / 8);
        const pka = format.hex2U8Arr(pkeData.a.publicKey);
        const pkb = format.hex2U8Arr(pkeData.b.publicKey);
        const inputLen = 2 * 32 + nLen + rLen;
        const input = new Uint8Array(inputLen);
        // Build input data
        // TODO: change format?
        bufferUtils.insertBytes(pka, input, 1, 0, 32);
        bufferUtils.insertBytes(pkb, input, 1, 32, 32);
        bufferUtils.insertBits(nx, input, 0, 2 * 32 * 8, constants.NONCE_LENGTH);
        bufferUtils.insertBits(r, input, 0, 2 * 32 * 8 + constants.NONCE_LENGTH, constants.DEFAULT_RANDOM_LENGTH);
        // Compute hash
        const hash = await digest.digest('sha256', input);
        return hash;
    }
    async validateAuthData(fullPkeData, fullAuthData) {
        const { cx: receivedCx, nx: receivedNx } = fullAuthData.received;
        const { cx: sentCx, nx: sentNx, r } = fullAuthData.sent;
        // Check valid lengths
        const validLengths = receivedCx.length === sentCx.length &&
            receivedNx.length === sentNx.length;
        if (!validLengths) {
            throw new Error('invalid received auth data length');
        }
        // Check different Cx
        const equalCx = receivedCx.every((byte, i) => byte === sentCx[i]);
        if (equalCx) {
            throw new Error('received and sent Cx are the same');
        }
        // Check valid Cx
        const expectedCx = await this.computeCx(fullPkeData, receivedNx, r);
        const validCx = expectedCx.every((byte, i) => byte === receivedCx[i]);
        if (!validCx) {
            throw new Error('received a wrong Cx');
        }
    }
    async computeMasterKey(ecdh, fullPkeData, fullAuthData) {
        const nLen = Math.ceil(constants.NONCE_LENGTH / 8);
        // Prepare data
        const sharedSecret = await ecdh.deriveBits(fullPkeData.received.publicKey);
        const salt = new Uint8Array(16);
        const secretWithContext = new Uint8Array(32 + 2 * nLen + 6 + 32 * 2);
        const masterContext = new Uint8Array([109, 97, 115, 116, 101, 114]); // 'master' in UTF-8
        const aHash = await objectSha__namespace.digest(fullPkeData.a, 'SHA-256');
        const aHashBuffer = format.hex2U8Arr(aHash);
        const bHash = await objectSha__namespace.digest(fullPkeData.b, 'SHA-256');
        const bHashBuffer = format.hex2U8Arr(bHash);
        // Prepare input
        bufferUtils.insertBytes(sharedSecret, secretWithContext, 0, 0, 32);
        bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32, nLen);
        bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32 + nLen, nLen);
        bufferUtils.insertBytes(masterContext, secretWithContext, 0, 32 + 2 * nLen, 6);
        bufferUtils.insertBytes(aHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6, 32);
        bufferUtils.insertBytes(bHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6 + 32, 32);
        // Compute master key
        const secret = await pbkdf2Hmac__default["default"](secretWithContext, salt, 1, 32);
        const masterKey = await MasterKey.fromSecret(fullPkeData.port, fullPkeData.sent.id, fullPkeData.received.id, fullAuthData.a.nx, fullAuthData.b.nx, new Uint8Array(secret));
        return masterKey;
    }
    async run() {
        const _run = async () => {
            // Initial protocol preparation
            const ecdh = new ECDH();
            await ecdh.generateKeys();
            const publicKey = await ecdh.getPublicKey();
            // Prepare public key exchange
            const pkeData = await this.transport.prepare(this, publicKey);
            // Perform public key exchange
            const fullPkeData = await this.transport.publicKeyExchange(this, pkeData);
            // Prepare authenticate
            const r = await this.computeR(fullPkeData.a.rx, fullPkeData.b.rx);
            const nx = await this.computeNx();
            const cx = await this.computeCx(fullPkeData, nx, r);
            const authData = { r, nx, cx };
            // Perform authenticate
            const fullAuthData = await this.transport.authentication(this, authData);
            // Verify authentication
            await this.validateAuthData(fullPkeData, fullAuthData);
            // Generate master key
            const masterKey = await this.computeMasterKey(ecdh, fullPkeData, fullAuthData);
            const code = await this.transport.verification(this, masterKey);
            //
            const session = new Session(this.transport, masterKey, code);
            this.emit('masterKey', masterKey);
            return session;
        };
        return await _run().finally(() => {
            this.transport.finish(this);
        });
    }
    on(event, listener) {
        return super.on(event, listener);
    }
    emit(event, ...args) {
        return super.emit(event, ...args);
    }
}

class ConnectionString {
    constructor(buffer, l) {
        this.buffer = buffer;
        this.l = l;
    }
    toString() {
        return format.u8Arr2Base64(this.buffer);
    }
    extractPort() {
        const portBytesLen = Math.ceil(constants.PORT_LENGTH / 8);
        const portBytesOffset = this.l % 8;
        const portBytes = new Uint8Array(portBytesLen);
        bufferUtils.insertBits(this.buffer, portBytes, this.l, portBytesOffset, constants.PORT_LENGTH);
        const dport = format.u8Arr2Num(portBytes);
        return constants.INITIAL_PORT + dport;
    }
    extractRb() {
        return bufferUtils.extractBits(this.buffer, 0, this.l);
    }
    static async generate(port, l) {
        const connBytesLen = Math.ceil((l + constants.PORT_LENGTH) / 8);
        const buf = new Uint8Array(connBytesLen);
        await random.randomFillBits(buf, 0, l);
        const dport = port - constants.INITIAL_PORT;
        if (dport < 0 || dport > constants.PORT_SPACE) {
            throw new Error(`the port ${port} is out of the port space`);
        }
        const portBytes = format.num2U8Arr(dport, 2);
        bufferUtils.insertBits(portBytes, buf, 2 * 8 - constants.PORT_LENGTH, l, constants.PORT_LENGTH);
        return new ConnectionString(buf, l);
    }
    static fromString(connString, l) {
        return new ConnectionString(format.base642U8Arr(connString), l);
    }
}

const defaultCodeGenerator = {
    async generate(masterKey) {
        console.warn('Using the default code verifier. Note that it is not secure for production.');
        const keyCode = await masterKey.toJSON();
        return format.utf2U8Arr(JSON.stringify(keyCode));
    },
    async getMasterKey(code) {
        const keyCode = format.u8Arr2Utf(code);
        return await MasterKey.fromJSON(JSON.parse(keyCode));
    }
};

class InitiatorTransport extends BaseTransport {
    constructor(opts = {}) {
        super();
        this.opts = {
            host: opts.host ?? 'localhost',
            id: opts.id ?? { name: 'Initiator' },
            l: opts.l ?? constants.DEFAULT_RANDOM_LENGTH,
            getConnectionString: opts.getConnectionString ?? (async () => {
                throw new Error('getConnectionString must be provided');
            })
        };
    }
    async prepare(protocol, publicKey) {
        const connString = await this.opts.getConnectionString();
        if (connString === '') {
            throw new Error('empty connection string');
        }
        this.connString = ConnectionString.fromString(connString, this.opts.l);
        const lLen = Math.ceil(this.opts.l / 8);
        const ra = new Uint8Array(lLen);
        await random.randomFillBits(ra, 0, this.opts.l);
        return {
            id: this.opts.id,
            publicKey,
            rx: ra
        };
    }
    async publicKeyExchange(protocol, pkeData) {
        if (this.connString === undefined) {
            throw new Error('missing connection string');
        }
        const response = await this.sendRequest({
            method: 'publicKeyExchange',
            sender: this.opts.id,
            publicKey: pkeData.publicKey,
            ra: format.u8Arr2Base64(pkeData.rx)
        });
        const received = {
            id: response.sender,
            publicKey: response.publicKey,
            rx: this.connString.extractRb()
        };
        return {
            a: pkeData,
            b: received,
            port: this.connString.extractPort(),
            sent: pkeData,
            received
        };
    }
    async authentication(protocol, authData) {
        const commitmentReq = await this.sendRequest({
            method: 'commitment',
            cx: format.u8Arr2Base64(authData.cx)
        });
        const nonceReq = await this.sendRequest({
            method: 'nonce',
            nx: format.u8Arr2Base64(authData.nx)
        });
        const received = {
            cx: format.base642U8Arr(commitmentReq.cx),
            nx: format.base642U8Arr(nonceReq.nx),
            r: authData.r
        };
        return {
            a: authData,
            b: {
                cx: format.base642U8Arr(commitmentReq.cx),
                nx: format.base642U8Arr(nonceReq.nx),
                r: authData.r
            },
            sent: authData,
            received
        };
    }
    async verification(protocol, masterKey) {
        const verifChallenge = await this.sendRequest({
            method: 'verification'
        });
        const inCiphertext = format.base642U8Arr(verifChallenge.ciphertext);
        const code = await masterKey.decrypt(inCiphertext);
        return code;
    }
    finish(protocol) {
        super.finish(protocol);
        this.connString = undefined;
    }
}

class HttpInitiatorTransport extends InitiatorTransport {
    buildRpcUrl(port) {
        return `http://${this.opts.host}:${port}/${constants.RPC_URL_PATH}`;
    }
    async baseSend(port, httpReq) {
        {
            const http = require('http');
            const resp = await new Promise(resolve => {
                const postData = httpReq.body;
                const req = http.request({
                    path: `/${constants.RPC_URL_PATH}`,
                    port,
                    method: httpReq.method ?? 'POST',
                    headers: {
                        ...httpReq.headers,
                        'Content-Length': Buffer.byteLength(postData)
                    }
                }, (res) => {
                    let data = '';
                    res.on('data', (chunk) => {
                        data += chunk;
                    });
                    res.on('end', () => {
                        resolve({
                            status: res.statusCode ?? 200,
                            body: data
                        });
                    });
                });
                req.write(postData);
                req.end();
            });
            return resp;
        }
    }
    async sendRequest(request) {
        if (this.connString === undefined) {
            throw new Error('cannot connect to the rpc yet: port missing');
        }
        const port = this.connString.extractPort();
        const resp = await this.baseSend(port, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        });
        return JSON.parse(resp.body);
    }
    async send(masterKey, code, req) {
        const message = format.utf2U8Arr(JSON.stringify(req));
        const ciphertext = await masterKey.encrypt(message);
        const resp = await this.baseSend(masterKey.port, {
            method: 'POST',
            headers: {
                Authorization: format.u8Arr2Utf(code)
            },
            body: format.u8Arr2Base64(ciphertext)
        });
        // Decrypt body
        if (resp.status <= 300 && resp.status >= 200) {
            const bodyCiphertext = format.base642U8Arr(resp.body);
            const jsonBuffer = await masterKey.decrypt(bodyCiphertext);
            resp.body = format.u8Arr2Utf(jsonBuffer);
        }
        return resp;
    }
}

class ResponderTransport extends BaseTransport {
    constructor(opts = {}) {
        super();
        this.opts = {
            port: opts.port ?? constants.INITIAL_PORT,
            timeout: opts.timeout ?? constants.DEFAULT_TIMEOUT,
            id: opts.id ?? { name: 'Responder' },
            l: opts.l ?? constants.DEFAULT_RANDOM_LENGTH,
            codeGenerator: opts.codeGenerator ?? defaultCodeGenerator
        };
        this.rpcSubject = new Subject();
    }
    async pairing(protocol, port, timeout) {
        this.stopPairing();
        this.connString = await ConnectionString.generate(port, this.opts.l);
        this.lastPairing = setTimeout(() => {
            this.stopPairing();
            this.finish(protocol);
        }, timeout);
    }
    stopPairing() {
        if (this.lastPairing != null) {
            clearTimeout(this.lastPairing);
            this.lastPairing = undefined;
        }
    }
    get isPairing() {
        return this.connString !== undefined;
    }
    get port() {
        return this.opts.port;
    }
    get timeout() {
        return this.opts.timeout;
    }
    async prepare(protocol, publicKey) {
        await this.pairing(protocol, this.port, this.timeout);
        if (this.connString === null || this.connString === undefined) {
            throw new Error('could not generate connection string');
        }
        protocol.emit('connString', this.connString);
        return {
            id: this.opts.id,
            publicKey,
            rx: this.connString.extractRb()
        };
    }
    async waitRequest(method) {
        while (true) {
            const rpcRequest = await this.rpcSubject.promise;
            if (rpcRequest.req.method !== method) {
                continue;
            }
            return rpcRequest;
        }
    }
    async publicKeyExchange(protocol, pkeData) {
        if (this.connString === undefined) {
            throw new Error('protocol not properly initialized');
        }
        const { req, res } = await this.waitRequest('publicKeyExchange');
        await res.send({
            method: 'publicKeyExchange',
            sender: pkeData.id,
            publicKey: pkeData.publicKey
        });
        const received = {
            id: req.sender,
            publicKey: req.publicKey,
            rx: format.base642U8Arr(req.ra ?? '')
        };
        return {
            a: received,
            b: pkeData,
            port: this.connString.extractPort(),
            sent: pkeData,
            received
        };
    }
    async authentication(protocol, authData) {
        const cxData = await this.waitRequest('commitment');
        await cxData.res.send({
            method: 'commitment',
            cx: format.u8Arr2Base64(authData.cx)
        });
        const commitmentReq = cxData.req;
        const nxData = await this.waitRequest('nonce');
        await nxData.res.send({
            method: 'nonce',
            nx: format.u8Arr2Base64(authData.nx)
        });
        const nonceReq = nxData.req;
        const received = {
            cx: format.base642U8Arr(commitmentReq.cx),
            nx: format.base642U8Arr(nonceReq.nx),
            r: authData.r
        };
        return {
            a: received,
            b: authData,
            sent: authData,
            received
        };
    }
    async verification(protocol, masterKey) {
        const verifData = await this.waitRequest('verification');
        const code = await this.opts.codeGenerator.generate(masterKey);
        const ciphertext = await masterKey.encrypt(code);
        await verifData.res.send({
            method: 'verificationChallenge',
            ciphertext: format.u8Arr2Base64(ciphertext)
        });
        return code;
    }
    finish(protocol) {
        super.finish(protocol);
        this.stopPairing();
        // TODO: When has error??
        this.rpcSubject.err('Finished');
        this.connString = undefined;
    }
}

class Response {
}

class HttpResponse extends Response {
    constructor(res) {
        super();
        this.res = res;
    }
    async send(request) {
        this.res.write(JSON.stringify(request));
        this.res.end();
    }
}

class HttpResponderTransport extends ResponderTransport {
    constructor(opts) {
        super(opts);
        this.listeners = [];
        this.rpcUrl = opts?.rpcUrl ?? `/${constants.RPC_URL_PATH}`;
    }
    async readRequestBody(req) {
        const buffers = [];
        for await (const chunk of req) {
            buffers.push(chunk);
        }
        return Buffer.concat(buffers).toString();
    }
    async dispatchProtocolMessage(req, res) {
        if (!this.isPairing) {
            throw new Error('not in pairing mode');
        }
        const data = await this.readRequestBody(req);
        const reqBody = JSON.parse(data);
        this.rpcSubject.next({ req: reqBody, res: new HttpResponse(res) });
    }
    async dispatchEncryptedMessage(req, res, authentication) {
        const code = format.utf2U8Arr(authentication);
        const masterKey = await this.opts.codeGenerator.getMasterKey(code);
        const ciphertextBase64 = await this.readRequestBody(req);
        const ciphertext = format.base642U8Arr(ciphertextBase64);
        const message = await masterKey.decrypt(ciphertext);
        const messageJson = format.u8Arr2Utf(message);
        const body = JSON.parse(messageJson);
        let innerBody = {};
        const init = body.init ?? {};
        if (init.body !== undefined && init.body !== '') {
            innerBody = JSON.parse(init.body);
        }
        const headers = Object
            .entries(init.headers ?? {})
            .reduce((h, [key, value]) => {
            h[key.toLocaleLowerCase()] = value;
            return h;
        }, req.headers);
        const reqProxy = new Proxy(req, {
            get(target, p) {
                switch (p) {
                    case 'url':
                        return body.url;
                    case 'method':
                        return init.method;
                    case 'headers':
                        return headers;
                    case '_body':
                        return true;
                    case 'body':
                        return innerBody;
                    case 'walletProtocol':
                        return true;
                    default:
                        return target[p];
                }
            }
        });
        // TODO: Implement this in a better way??
        res.end = new Proxy(res.end, {
            apply: (target, thisArg, argsArray) => {
                const statusCode = thisArg.statusCode === undefined ? 500 : thisArg.statusCode;
                if (statusCode >= 200 && statusCode < 300) {
                    const chunk = argsArray[0];
                    const send = async () => {
                        let buffer;
                        if (typeof chunk === 'string') {
                            buffer = format.utf2U8Arr(chunk);
                        }
                        else if (chunk instanceof Buffer) {
                            buffer = chunk;
                        }
                        else {
                            throw new Error('cannot manage this chunk...');
                        }
                        const ciphertext = await masterKey.encrypt(buffer);
                        const ciphertextBase64 = format.u8Arr2Base64(ciphertext);
                        res.setHeader('Content-Length', ciphertextBase64.length);
                        target.call(thisArg, ciphertextBase64, ...argsArray.slice(1));
                    };
                    send().catch(err => { console.error(err); });
                }
                else {
                    target.call(thisArg, ...argsArray);
                }
            }
        });
        await this.callListeners(reqProxy, res);
    }
    async dispatchRequest(req, res) {
        if (req.url === this.rpcUrl) {
            if (req.method !== 'POST') {
                throw new Error('method must be POST');
            }
            if (req.headers.authorization !== undefined) {
                return await this.dispatchEncryptedMessage(req, res, req.headers.authorization);
            }
            else {
                return await this.dispatchProtocolMessage(req, res);
            }
        }
        else {
            await this.callListeners(req, res);
        }
    }
    async callListeners(req, res) {
        for (const listener of this.listeners) {
            listener(req, res);
        }
    }
    use(listener) {
        this.listeners.push(listener);
    }
}

exports.BaseTransport = BaseTransport;
exports.ConnectionString = ConnectionString;
exports.HttpInitiatorTransport = HttpInitiatorTransport;
exports.HttpResponderTransport = HttpResponderTransport;
exports.MasterKey = MasterKey;
exports.Session = Session;
exports.WalletProtocol = WalletProtocol;
exports.constants = constants;
exports.defaultCodeGenerator = defaultCodeGenerator;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy90cmFuc3BvcnQvdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9wcm90b2NvbC50cyIsIi4uLy4uL3NyYy90cy9jb25zdGFudHMvaHR0cC50cyIsIi4uLy4uL3NyYy90cy9jb25zdGFudHMvaW5kZXgudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL3R5cGVzLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9ub2RlanMvcmFuZG9tLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9ub2RlanMvY2lwaGVyLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9ub2RlanMvZWNkaC50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vbm9kZWpzL2RpZ2VzdC50cyIsIi4uLy4uL3NyYy90cy91dGlsL2Zvcm1hdC50cyIsIi4uLy4uL3NyYy90cy91dGlsL2J1ZmZlci50cyIsIi4uLy4uL3NyYy90cy9zdWJqZWN0LnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2V2ZW50LWVtaXR0ZXIudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvbWFzdGVyLWtleS50cyIsIi4uLy4uL3NyYy90cy9wcm90b2NvbC9zZXNzaW9uLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL3Byb3RvY29sLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2Nvbm5lY3Rpb24tc3RyaW5nLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2NvZGUtZ2VuZXJhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9pbml0aWF0b3ItdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtaW5pdGlhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9yZXNwb25kZXItdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9yZXNwb25zZS50cyIsIi4uLy4uL3NyYy90cy90cmFuc3BvcnQvaHR0cC9odHRwLXJlc3BvbnNlLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtcmVzcG9uZGVyLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJjcnlwdG8iLCJiYXNlNjQiLCJwYmtkZjJIbWFjIiwib2JqZWN0U2hhIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O01BY3NCLGFBQWEsQ0FBQTtBQU9qQyxJQUFBLE1BQU0sSUFBSSxDQUFFLFNBQW9CLEVBQUUsSUFBZ0IsRUFBRSxHQUFRLEVBQUE7QUFDMUQsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHFDQUFxQyxDQUFDLENBQUE7S0FDdkQ7QUFFRCxJQUFBLE1BQU0sQ0FBRSxRQUF3QixFQUFBO0FBQzlCLFFBQUEsUUFBUSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtLQUMxQjtBQUNGOztBQzNCTSxNQUFNLFdBQVcsR0FBRyxFQUFFLENBQUE7QUFDdEIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUE7QUFDaEMsTUFBTSxlQUFlLEdBQUcsS0FBSyxDQUFBO0FBQzdCLE1BQU0sVUFBVSxHQUFHLENBQUMsSUFBSSxXQUFXLENBQUE7QUFDbkMsTUFBTSxZQUFZLEdBQUcsS0FBSyxDQUFBO0FBRTFCLE1BQU0sWUFBWSxHQUFHLEdBQUcsQ0FBQTtBQUN4QixNQUFNLGlCQUFpQixHQUFHLEdBQUcsQ0FBQTs7Ozs7Ozs7Ozs7OztBQ1A3QixNQUFNLFlBQVksR0FBRyw2QkFBNkI7Ozs7Ozs7QUNFekQsZ0JBQWU7QUFDYixJQUFBLEdBQUcsaUJBQWlCO0FBQ3BCLElBQUEsR0FBRyxhQUFhO0NBQ2pCOztNQ0pZLFFBQVEsQ0FBQTtBQUNuQixJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0FBRUQsSUFBQSxNQUFNLFlBQVksR0FBQTtBQUNoQixRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztJQUVELE1BQU0sVUFBVSxDQUFFLFlBQW9CLEVBQUE7QUFDcEMsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7QUFDRixDQUFBO01BRVksVUFBVSxDQUFBO0FBQ3JCLElBQUEsTUFBTSxVQUFVLENBQUUsTUFBa0IsRUFBRSxLQUFhLEVBQUUsSUFBWSxFQUFBO0FBQy9ELFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0FBRUQsSUFBQSxNQUFNLGNBQWMsQ0FBRSxNQUFrQixFQUFFLEtBQWEsRUFBRSxJQUFZLEVBQUE7UUFDbkUsTUFBTSxPQUFPLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDbkMsUUFBQSxNQUFNLFdBQVcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUMzQyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsV0FBVyxFQUFFLENBQUMsRUFBRSxPQUFPLENBQUMsQ0FBQTtBQUM5QyxRQUFBLFdBQVcsQ0FBQyxVQUFVLENBQUMsV0FBVyxFQUFFLE1BQU0sRUFBRSxDQUFDLEVBQUUsS0FBSyxFQUFFLElBQUksQ0FBQyxDQUFBO0tBQzVEO0FBQ0YsQ0FBQTtNQUdZLFVBQVUsQ0FBQTtJQUNyQixXQUNrQixDQUFBLFNBQTJCLEVBQzNCLEdBQWUsRUFBQTtRQURmLElBQVMsQ0FBQSxTQUFBLEdBQVQsU0FBUyxDQUFrQjtRQUMzQixJQUFHLENBQUEsR0FBQSxHQUFILEdBQUcsQ0FBWTtLQUM1QjtJQUVMLE1BQU0sT0FBTyxDQUFFLE9BQW1CLEVBQUE7QUFDaEMsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7SUFFRCxNQUFNLE9BQU8sQ0FBRSxVQUFzQixFQUFBO0FBQ25DLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0FBQ0YsQ0FBQTtNQUlZLFVBQVUsQ0FBQTtBQUNyQixJQUFBLE1BQU0sTUFBTSxDQUFFLFNBQXlCLEVBQUUsS0FBaUIsRUFBQTtBQUN4RCxRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztBQUNGOztBQ2hERCxNQUFNLFVBQVcsU0FBUSxVQUFVLENBQUE7QUFDakMsSUFBQSxNQUFNLFVBQVUsQ0FBRSxNQUFrQixFQUFFLEtBQWEsRUFBRSxJQUFZLEVBQUE7QUFDL0QsUUFBQSxPQUFPLE1BQU0sSUFBSSxPQUFPLENBQU8sT0FBTyxJQUFHO1lBQ3ZDQSwwQkFBTSxDQUFDLFVBQVUsQ0FBQyxNQUFNLEVBQUUsS0FBSyxFQUFFLElBQUksRUFBRSxNQUFLO0FBQzFDLGdCQUFBLE9BQU8sRUFBRSxDQUFBO0FBQ1gsYUFBQyxDQUFDLENBQUE7QUFDSixTQUFDLENBQUMsQ0FBQTtLQUNIO0FBQ0YsQ0FBQTtBQUNNLE1BQU0sTUFBTSxHQUFlLElBQUksVUFBVSxFQUFFOztBQ1A1QyxNQUFPLE1BQU8sU0FBUSxVQUFVLENBQUE7SUFDcEMsTUFBTSxPQUFPLENBQUUsT0FBbUIsRUFBQTtBQUNoQyxRQUFBLE1BQU0sRUFBRSxHQUFHLElBQUksVUFBVSxDQUFDLEVBQUUsQ0FBQyxDQUFBO0FBQzdCLFFBQUEsTUFBTSxNQUFNLENBQUMsVUFBVSxDQUFDLEVBQUUsRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQ3pDLE1BQU0sU0FBUyxHQUFHQSwwQkFBTSxDQUFDLGVBQWUsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDbEQsUUFBQSxNQUFNLE1BQU0sR0FBR0EsMEJBQU0sQ0FBQyxjQUFjLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxTQUFTLEVBQUUsRUFBRSxDQUFDLENBQUE7UUFFbkUsTUFBTSxPQUFPLEdBQWlCLEVBQUUsQ0FBQTtBQUNoQyxRQUFBLE9BQU8sQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUE7UUFDaEIsT0FBTyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUE7UUFDcEMsT0FBTyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxFQUFFLENBQUMsQ0FBQTtRQUM1QixPQUFPLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsQ0FBQyxDQUFBO0FBRWpDLFFBQUEsT0FBTyxXQUFXLENBQUMsSUFBSSxDQUFDLEdBQUcsT0FBTyxDQUFDLENBQUE7S0FDcEM7SUFFRCxNQUFNLE9BQU8sQ0FBRSxjQUEwQixFQUFBO1FBQ3ZDLE1BQU0sS0FBSyxHQUFhLEVBQUUsQ0FBQTtRQUMxQixRQUFRLElBQUksQ0FBQyxTQUFTO0FBQ3BCLFlBQUEsS0FBSyxhQUFhO0FBQ2hCLGdCQUFBLEtBQUssQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUE7QUFDYixnQkFBQSxLQUFLLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFBO2dCQUNiLE1BQUs7QUFDUixTQUFBO1FBQ0QsS0FBSyxDQUFDLENBQUMsQ0FBQyxHQUFHLGNBQWMsQ0FBQyxNQUFNLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxJQUFJLEtBQUssQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQTtBQUM3RCxRQUFBLE1BQU0sQ0FBQyxFQUFFLEVBQUUsVUFBVSxFQUFFLE9BQU8sQ0FBQyxHQUFHLFdBQVcsQ0FBQyxLQUFLLENBQUMsY0FBYyxFQUFFLEdBQUcsS0FBSyxDQUFDLENBQUE7UUFFN0UsTUFBTSxTQUFTLEdBQUdBLDBCQUFNLENBQUMsZUFBZSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUNsRCxRQUFBLE1BQU0sUUFBUSxHQUFHQSwwQkFBTSxDQUFDLGdCQUFnQixDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUUsU0FBUyxFQUFFLEVBQUUsQ0FBQyxDQUFBO1FBQ3ZFLElBQUksT0FBTyxLQUFLLFNBQVMsRUFBRTtBQUN6QixZQUFBLFFBQVEsQ0FBQyxVQUFVLENBQUMsT0FBTyxDQUFDLENBQUE7QUFDN0IsU0FBQTtRQUVELE1BQU0sT0FBTyxHQUFpQixFQUFFLENBQUE7UUFDaEMsT0FBTyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUE7UUFDekMsT0FBTyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsS0FBSyxFQUFFLENBQUMsQ0FBQTtBQUM5QixRQUFBLE9BQU8sV0FBVyxDQUFDLElBQUksQ0FBQyxHQUFHLE9BQU8sQ0FBQyxDQUFBO0tBQ3BDO0FBQ0Y7O0FDeENLLE1BQU8sSUFBSyxTQUFRLFFBQVEsQ0FBQTtBQUVoQyxJQUFBLFdBQUEsR0FBQTtBQUNFLFFBQUEsS0FBSyxFQUFFLENBQUE7UUFDUCxJQUFJLENBQUMsSUFBSSxHQUFHQSwwQkFBTSxDQUFDLFVBQVUsQ0FBQyxZQUFZLENBQUMsQ0FBQTtLQUM1QztBQUVELElBQUEsTUFBTSxZQUFZLEdBQUE7O0FBRWhCLFFBQUEsSUFBSSxDQUFDLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTtLQUN6QjtBQUVELElBQUEsTUFBTSxZQUFZLEdBQUE7UUFDaEIsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQTtLQUNyQztJQUVELE1BQU0sVUFBVSxDQUFFLFlBQW9CLEVBQUE7QUFDcEMsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxZQUFZLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDeEQsUUFBQSxPQUFPLElBQUksVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFBO0tBQzNCO0FBQ0Y7O0FDcEJELE1BQU0sVUFBVyxTQUFRLFVBQVUsQ0FBQTtBQUNqQyxJQUFBLE1BQU0sTUFBTSxDQUFFLFNBQXlCLEVBQUUsS0FBaUIsRUFBQTtRQUN4RCxNQUFNLElBQUksR0FBR0EsMEJBQU0sQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDLENBQUE7UUFDekMsTUFBTSxNQUFNLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQTtBQUUxQyxRQUFBLE9BQU8sSUFBSSxVQUFVLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0tBQ3JDO0FBQ0YsQ0FBQTtBQUNNLE1BQU0sTUFBTSxHQUFHLElBQUksVUFBVSxFQUFFOztBQ1QvQixNQUFNLE1BQU0sR0FBRztBQUNwQixJQUFBLFNBQVMsRUFBRSxDQUFDLElBQVksS0FBZ0I7UUFDdEMsT0FBTyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtLQUN0QztBQUVELElBQUEsU0FBUyxFQUFFLENBQUMsR0FBZSxLQUFZO1FBQ3JDLE9BQU8sSUFBSSxXQUFXLEVBQUUsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7S0FDckM7QUFFRCxJQUFBLFNBQVMsRUFBRSxDQUFDLEdBQVcsRUFBRSxHQUFZLEtBQWdCO1FBQ25ELElBQUksR0FBRyxLQUFLLFNBQVMsRUFBRTtZQUNyQixHQUFHLEdBQUcsQ0FBQyxDQUFBO1lBQ1AsT0FBTyxDQUFDLEtBQUssR0FBRyxHQUFHLENBQUMsQ0FBQyxHQUFHLEdBQUcsRUFBRTtBQUMzQixnQkFBQSxHQUFHLEVBQUUsQ0FBQTtBQUNOLGFBQUE7QUFDRixTQUFBO0FBQ0QsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUUvQixJQUFJLElBQUksR0FBRyxHQUFHLENBQUE7QUFDZCxRQUFBLEtBQUssSUFBSSxDQUFDLEdBQUcsR0FBRyxHQUFHLENBQUMsRUFBRSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFO0FBQ2pDLFlBQUEsTUFBTSxRQUFRLEdBQUcsSUFBSSxJQUFJLENBQUMsQ0FBQTtZQUMxQixNQUFNLEdBQUcsR0FBRyxJQUFJLElBQUksUUFBUSxJQUFJLENBQUMsQ0FBQyxDQUFBO0FBQ2xDLFlBQUEsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLEdBQUcsQ0FBQTtZQUVaLElBQUksR0FBRyxRQUFRLENBQUE7QUFDaEIsU0FBQTtBQUVELFFBQUEsT0FBTyxHQUFHLENBQUE7S0FDWDtBQUVELElBQUEsU0FBUyxFQUFFLENBQUMsTUFBa0IsS0FBWTtRQUN4QyxJQUFJLEdBQUcsR0FBRyxDQUFDLENBQUE7QUFDWCxRQUFBLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxNQUFNLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFO0FBQ3RDLFlBQUEsR0FBRyxJQUFJLE1BQU0sQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFBO0FBQzlDLFNBQUE7QUFFRCxRQUFBLE9BQU8sR0FBRyxDQUFBO0tBQ1g7QUFFRCxJQUFBLFNBQVMsRUFBRSxDQUFDLEdBQVcsS0FBZ0I7UUFDckMsTUFBTSxLQUFLLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUNsQyxJQUFJLEtBQUssS0FBSyxJQUFJLEVBQUU7QUFDbEIsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGNBQWMsR0FBRyxDQUFBLENBQUUsQ0FBQyxDQUFBO0FBQ3JDLFNBQUE7QUFFRCxRQUFBLE9BQU8sSUFBSSxVQUFVLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxJQUFJLElBQUksUUFBUSxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUE7S0FDN0Q7QUFFRCxJQUFBLFNBQVMsRUFBRSxDQUFDLEdBQWUsS0FBWTtBQUNyQyxRQUFBLE9BQU8sR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxJQUFJLEtBQUssR0FBRyxHQUFHLElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtLQUMvRTtBQUVELElBQUEsWUFBWSxFQUFFLENBQUMsR0FBZSxLQUFZO1FBQ3hDLE9BQU9DLGlCQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7S0FDdkM7QUFFRCxJQUFBLFlBQVksRUFBRSxDQUFDLEdBQVcsS0FBZ0I7UUFDeEMsT0FBT0EsaUJBQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBZSxDQUFBO0tBQy9DO0NBQ0Y7O0FDN0RNLE1BQU0sV0FBVyxHQUFHO0FBQ3pCLElBQUEsSUFBSSxFQUFFLENBQUMsR0FBRyxJQUFrQixLQUFnQjtRQUMxQyxNQUFNLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUMsQ0FBQTtBQUNuRCxRQUFBLE1BQU0sTUFBTSxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFBO1FBQ25DLElBQUksTUFBTSxHQUFHLENBQUMsQ0FBQTtBQUNkLFFBQUEsS0FBSyxNQUFNLEVBQUUsSUFBSSxJQUFJLEVBQUU7QUFDckIsWUFBQSxNQUFNLENBQUMsR0FBRyxDQUFDLEVBQUUsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUN0QixZQUFBLE1BQU0sSUFBSSxFQUFFLENBQUMsTUFBTSxDQUFBO0FBQ3BCLFNBQUE7QUFFRCxRQUFBLE9BQU8sTUFBTSxDQUFBO0tBQ2Q7QUFFRCxJQUFBLEtBQUssRUFBRSxDQUFDLE1BQWtCLEVBQUUsR0FBRyxLQUFlLEtBQWtCO1FBQzlELE1BQU0sSUFBSSxHQUFpQixFQUFFLENBQUE7UUFDN0IsSUFBSSxLQUFLLEdBQUcsQ0FBQyxDQUFBO0FBQ2IsUUFBQSxLQUFLLE1BQU0sSUFBSSxJQUFJLEtBQUssRUFBRTtBQUN4QixZQUFBLElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxLQUFLLEVBQUUsS0FBSyxHQUFHLElBQUksQ0FBQyxDQUFDLENBQUE7WUFDNUMsS0FBSyxJQUFJLElBQUksQ0FBQTtBQUNkLFNBQUE7QUFFRCxRQUFBLE9BQU8sSUFBSSxDQUFBO0tBQ1o7QUFFRCxJQUFBLFdBQVcsRUFBRSxDQUFDLEdBQWUsRUFBRSxHQUFlLEVBQUUsU0FBaUIsRUFBRSxPQUFlLEVBQUUsSUFBWSxLQUFJO1FBQ2xHLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxJQUFJLEVBQUUsQ0FBQyxFQUFFLEVBQUU7QUFDN0IsWUFBQSxHQUFHLENBQUMsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxHQUFHLEdBQUcsQ0FBQyxDQUFDLEdBQUcsU0FBUyxDQUFDLENBQUE7QUFDdEMsU0FBQTtLQUNGO0FBRUQsSUFBQSxVQUFVLEVBQUUsQ0FBQyxHQUFlLEVBQUUsR0FBZSxFQUFFLFNBQWlCLEVBQUUsT0FBZSxFQUFFLElBQVksS0FBSTtRQUNqRyxJQUFJLGFBQWEsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLFNBQVMsR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUM3QyxRQUFBLElBQUksWUFBWSxHQUFHLFNBQVMsR0FBRyxDQUFDLENBQUE7UUFDaEMsSUFBSSxXQUFXLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDekMsUUFBQSxJQUFJLFVBQVUsR0FBRyxPQUFPLEdBQUcsQ0FBQyxDQUFBO1FBQzVCLElBQUksWUFBWSxHQUFHLEdBQUcsQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLENBQUE7QUFDMUMsUUFBQSxNQUFNLFdBQVcsR0FBRyxVQUFVLEdBQUcsWUFBWSxDQUFBO1FBRTdDLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxJQUFJLEVBQUUsQ0FBQyxFQUFFLEVBQUU7QUFDN0IsWUFBQSxJQUFJLE9BQWUsQ0FBQTtZQUNuQixJQUFJLFdBQVcsSUFBSSxDQUFDLEVBQUU7QUFDcEIsZ0JBQUEsT0FBTyxJQUFJLENBQUMsWUFBWSxJQUFJLEdBQUcsSUFBSSxZQUFZLENBQUMsS0FBSyxXQUFXLENBQUMsQ0FBQTtBQUNsRSxhQUFBO0FBQU0saUJBQUE7QUFDTCxnQkFBQSxPQUFPLEtBQUssWUFBWSxJQUFJLEdBQUcsSUFBSSxZQUFZLENBQUMsRUFBRSxDQUFBO0FBQ25ELGFBQUE7QUFFRCxZQUFBLE1BQU0sTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFDLFdBQVcsQ0FBQyxHQUFHLEVBQUUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxJQUFJLE9BQU8sQ0FBQyxDQUFBO0FBQ3BFLFlBQUEsR0FBRyxDQUFDLFdBQVcsQ0FBQyxHQUFHLE1BQU0sQ0FBQTs7QUFHekIsWUFBQSxZQUFZLEVBQUUsQ0FBQTtBQUNkLFlBQUEsVUFBVSxFQUFFLENBQUE7WUFDWixJQUFJLFlBQVksSUFBSSxDQUFDLEVBQUU7QUFDckIsZ0JBQUEsYUFBYSxFQUFFLENBQUE7Z0JBQ2YsWUFBWSxHQUFHLENBQUMsQ0FBQTtBQUNoQixnQkFBQSxZQUFZLEdBQUcsR0FBRyxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUN2QyxhQUFBO1lBQ0QsSUFBSSxVQUFVLElBQUksQ0FBQyxFQUFFO0FBQ25CLGdCQUFBLFdBQVcsRUFBRSxDQUFBO2dCQUNiLFVBQVUsR0FBRyxDQUFDLENBQUE7QUFDZixhQUFBO0FBQ0YsU0FBQTtLQUNGO0lBRUQsV0FBVyxFQUFFLENBQUMsR0FBZSxFQUFFLEtBQWEsRUFBRSxJQUFZLEtBQWdCO1FBQ3hFLE1BQU0sUUFBUSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxHQUFHLENBQUMsQ0FBQyxDQUFBO0FBQ3BDLFFBQUEsTUFBTSxHQUFHLEdBQUcsSUFBSSxVQUFVLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDcEMsUUFBQSxXQUFXLENBQUMsVUFBVSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsS0FBSyxFQUFFLENBQUMsRUFBRSxJQUFJLENBQUMsQ0FBQTtBQUVoRCxRQUFBLE9BQU8sR0FBRyxDQUFBO0tBQ1g7Q0FDRjs7TUN0RVksT0FBTyxDQUFBO0FBSWxCLElBQUEsSUFBSSxPQUFPLEdBQUE7QUFDVCxRQUFBLE9BQU8sSUFBSSxDQUFDLGFBQWEsRUFBRSxDQUFBO0tBQzVCO0FBRVMsSUFBQSxNQUFNLGFBQWEsR0FBQTtRQUMzQixPQUFPLE1BQU0sSUFBSSxPQUFPLENBQUksQ0FBQyxPQUFPLEVBQUUsTUFBTSxLQUFJO0FBQzlDLFlBQUEsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUE7QUFDdEIsWUFBQSxJQUFJLENBQUMsTUFBTSxHQUFHLE1BQU0sQ0FBQTtBQUN0QixTQUFDLENBQUMsQ0FBQTtLQUNIO0FBRUQsSUFBQSxJQUFJLENBQUUsS0FBUSxFQUFBO0FBQ1osUUFBQSxJQUFJLElBQUksQ0FBQyxPQUFPLElBQUksSUFBSSxFQUFFO0FBQ3hCLFlBQUEsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtBQUNwQixTQUFBO0tBQ0Y7QUFFRCxJQUFBLEdBQUcsQ0FBRSxNQUFXLEVBQUE7QUFDZCxRQUFBLElBQUksSUFBSSxDQUFDLE1BQU0sSUFBSSxJQUFJLEVBQUU7QUFDdkIsWUFBQSxJQUFJLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQ3BCLFNBQUE7S0FDRjtBQUNGOztNQzFCWSxZQUFZLENBQUE7QUFHdkIsSUFBQSxXQUFBLEdBQUE7QUFDRSxRQUFBLElBQUksQ0FBQyxNQUFNLEdBQUcsRUFBRSxDQUFBO0tBQ2pCO0lBRUQsRUFBRSxDQUFFLEtBQWEsRUFBRSxFQUFZLEVBQUE7UUFDN0IsSUFBSSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxLQUFLLFNBQVMsRUFBRTtBQUNwQyxZQUFBLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEdBQUcsRUFBRSxDQUFBO0FBQ3hCLFNBQUE7UUFFRCxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQTtBQUMzQixRQUFBLE9BQU8sSUFBSSxDQUFBO0tBQ1o7QUFFRCxJQUFBLElBQUksQ0FBRSxLQUFhLEVBQUUsR0FBRyxJQUFTLEVBQUE7UUFDL0IsTUFBTSxRQUFRLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQyxJQUFJLFFBQVEsS0FBSyxTQUFTLEVBQUU7QUFDMUIsWUFBQSxRQUFRLENBQUMsT0FBTyxDQUFDLE9BQU8sSUFBSSxPQUFPLENBQUMsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFBO0FBQzdDLFlBQUEsT0FBTyxJQUFJLENBQUE7QUFDWixTQUFBO0FBQ0QsUUFBQSxPQUFPLEtBQUssQ0FBQTtLQUNiO0FBQ0Y7O0FDcEJELE1BQU0sU0FBUyxHQUFHLE9BQ2hCLElBQVksRUFBRSxFQUFVLEVBQUUsTUFBa0IsS0FDckI7O0FBRXZCLElBQUEsTUFBTSxJQUFJLEdBQUcsSUFBSSxVQUFVLENBQUMsRUFBRSxDQUFDLENBQUE7SUFDL0IsTUFBTSxXQUFXLEdBQUcsSUFBSSxVQUFVLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFBO0lBQzFDLE1BQU0sVUFBVSxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUE7SUFDekMsTUFBTSxRQUFRLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxFQUFFLENBQUMsQ0FBQTs7QUFHckMsSUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLE1BQU0sRUFBRSxXQUFXLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUN0RCxJQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsVUFBVSxFQUFFLFdBQVcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBQzNELElBQUEsV0FBVyxDQUFDLFdBQVcsQ0FBQyxRQUFRLEVBQUUsV0FBVyxFQUFFLENBQUMsRUFBRSxFQUFFLEdBQUcsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBRTdELElBQUEsTUFBTSxlQUFlLEdBQUcsTUFBTUMsOEJBQVUsQ0FBQyxXQUFXLEVBQUUsSUFBSSxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUNsRSxJQUFBLE9BQU8sSUFBSSxVQUFVLENBQUMsZUFBZSxDQUFDLENBQUE7QUFDeEMsQ0FBQyxDQUFBO01BRVksU0FBUyxDQUFBO0FBSXBCLElBQUEsV0FBQSxDQUNrQixJQUFZLEVBQ1osSUFBYyxFQUNkLEVBQVksRUFDWixFQUFjLEVBQ2QsRUFBYyxFQUNwQixNQUFrQixFQUM1QixVQUFzQixFQUN0QixVQUFzQixFQUFBO1FBUE4sSUFBSSxDQUFBLElBQUEsR0FBSixJQUFJLENBQVE7UUFDWixJQUFJLENBQUEsSUFBQSxHQUFKLElBQUksQ0FBVTtRQUNkLElBQUUsQ0FBQSxFQUFBLEdBQUYsRUFBRSxDQUFVO1FBQ1osSUFBRSxDQUFBLEVBQUEsR0FBRixFQUFFLENBQVk7UUFDZCxJQUFFLENBQUEsRUFBQSxHQUFGLEVBQUUsQ0FBWTtRQUNwQixJQUFNLENBQUEsTUFBQSxHQUFOLE1BQU0sQ0FBWTtRQUk1QixJQUFJLENBQUMsTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxVQUFVLENBQUMsQ0FBQTtRQUNuRCxJQUFJLENBQUMsUUFBUSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxVQUFVLENBQUMsQ0FBQTtLQUN0RDtJQUVELE1BQU0sT0FBTyxDQUFFLE9BQW1CLEVBQUE7UUFDaEMsT0FBTyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0tBQzFDO0lBRUQsTUFBTSxPQUFPLENBQUUsVUFBc0IsRUFBQTtRQUNuQyxPQUFPLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7S0FDL0M7SUFFRCxNQUFNLEdBQUE7UUFDSixPQUFPO1lBQ0wsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJO1lBQ2YsRUFBRSxFQUFFLElBQUksQ0FBQyxFQUFFO1lBQ1gsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJO1lBQ2YsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQztZQUNoQyxFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDO1lBQ2hDLE1BQU0sRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUM7U0FDekMsQ0FBQTtLQUNGO0FBRUQsSUFBQSxNQUFNLFFBQVEsR0FBQTtRQUNaLE9BQU8sTUFBTUMsb0JBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFBO0tBQ3pDO0FBRUQsSUFBQSxNQUFNLE1BQU0sR0FBQTtRQUNWLE9BQU8sTUFBTUEsb0JBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxDQUFBO0tBQ3ZDO0FBRUQsSUFBQSxhQUFhLFVBQVUsQ0FBRSxJQUFZLEVBQUUsSUFBYyxFQUFFLEVBQVksRUFBRSxFQUFjLEVBQUUsRUFBYyxFQUFFLE1BQWtCLEVBQUE7UUFDckgsTUFBTSxRQUFRLEdBQUcsTUFBTUEsb0JBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDN0MsTUFBTSxNQUFNLEdBQUcsTUFBTUEsb0JBQVMsQ0FBQyxNQUFNLENBQUMsRUFBRSxDQUFDLENBQUE7UUFFekMsTUFBTSxVQUFVLEdBQUcsTUFBTSxTQUFTLENBQUMsUUFBUSxFQUFFLE1BQU0sRUFBRSxNQUFNLENBQUMsQ0FBQTtRQUM1RCxNQUFNLFVBQVUsR0FBRyxNQUFNLFNBQVMsQ0FBQyxNQUFNLEVBQUUsUUFBUSxFQUFFLE1BQU0sQ0FBQyxDQUFBO0FBRTVELFFBQUEsT0FBTyxJQUFJLFNBQVMsQ0FBQyxJQUFJLEVBQUUsSUFBSSxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLE1BQU0sRUFBRSxVQUFVLEVBQUUsVUFBVSxDQUFDLENBQUE7S0FDN0U7QUFFRCxJQUFBLGFBQWEsUUFBUSxDQUFFLElBQVMsRUFBQTtRQUM5QixNQUFNLEVBQUUsR0FBRyxNQUFNLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQTtRQUN2QyxNQUFNLEVBQUUsR0FBRyxNQUFNLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQTtRQUN2QyxNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUUvQyxPQUFPLE1BQU0sSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLE1BQU0sQ0FBQyxDQUFBO0tBQzVFO0FBQ0Y7O01DbEZZLE9BQU8sQ0FBQTtBQUNsQixJQUFBLFdBQUEsQ0FBdUIsU0FBWSxFQUFZLFNBQW9CLEVBQVksSUFBZ0IsRUFBQTtRQUF4RSxJQUFTLENBQUEsU0FBQSxHQUFULFNBQVMsQ0FBRztRQUFZLElBQVMsQ0FBQSxTQUFBLEdBQVQsU0FBUyxDQUFXO1FBQVksSUFBSSxDQUFBLElBQUEsR0FBSixJQUFJLENBQVk7S0FBSTtJQUVuRyxNQUFNLElBQUksQ0FBRSxPQUE0QixFQUFBO0FBQ3RDLFFBQUEsT0FBTyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDLElBQUksRUFBRSxPQUFPLENBQUMsQ0FBQTtLQUNyRTtJQUVELE1BQU0sR0FBQTtRQUNKLE9BQU87QUFDTCxZQUFBLFNBQVMsRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sRUFBRTtZQUNsQyxJQUFJLEVBQUUsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDO1NBQ2xDLENBQUE7S0FDRjtBQUlELElBQUEsYUFBYSxRQUFRLENBQXVCLHNCQUF5QyxFQUFFLElBQVMsRUFBQTtRQUM5RixNQUFNLFNBQVMsR0FBRyxNQUFNLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFBO1FBQzFELE1BQU0sSUFBSSxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFBO0FBQ3hDLFFBQUEsSUFBSSxTQUFZLENBQUE7QUFDaEIsUUFBQSxJQUFJLE9BQU8sc0JBQXNCLEtBQUssUUFBUSxFQUFFO1lBQzlDLFNBQVMsR0FBRyxzQkFBc0IsQ0FBQTtBQUNuQyxTQUFBO2FBQU0sSUFBSSxzQkFBc0IsWUFBWSxRQUFRLEVBQUU7QUFDckQsWUFBQSxTQUFTLEdBQUcsSUFBSSxzQkFBc0IsRUFBRSxDQUFBO0FBQ3pDLFNBQUE7QUFBTSxhQUFBO0FBQ0wsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7QUFDN0UsU0FBQTtRQUVELE9BQU8sSUFBSSxPQUFPLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQTtLQUMvQztBQUNGOztBQ2ZLLE1BQU8sY0FBZ0QsU0FBUSxZQUFZLENBQUE7QUFDL0UsSUFBQSxXQUFBLENBQW9CLFNBQVksRUFBQTtBQUM5QixRQUFBLEtBQUssRUFBRSxDQUFBO1FBRFcsSUFBUyxDQUFBLFNBQUEsR0FBVCxTQUFTLENBQUc7S0FFL0I7QUFFRCxJQUFBLE1BQU0sUUFBUSxDQUFFLEVBQWMsRUFBRSxFQUFjLEVBQUE7QUFDNUMsUUFBQSxPQUFPLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxLQUFLLEdBQUcsR0FBRyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtLQUN2QztBQUVELElBQUEsTUFBTSxTQUFTLEdBQUE7QUFDYixRQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFlBQVksR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUNsRCxRQUFBLE1BQU0sRUFBRSxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFBO0FBRS9CLFFBQUEsTUFBTSxNQUFNLENBQUMsY0FBYyxDQUFDLEVBQUUsRUFBRSxDQUFDLEVBQUUsU0FBUyxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBQzFELFFBQUEsT0FBTyxFQUFFLENBQUE7S0FDVjtBQUVELElBQUEsTUFBTSxTQUFTLENBQUUsT0FBd0IsRUFBRSxFQUFjLEVBQUUsQ0FBYSxFQUFBO0FBQ3RFLFFBQUEsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsWUFBWSxHQUFHLENBQUMsQ0FBQyxDQUFBO0FBQ2xELFFBQUEsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMscUJBQXFCLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDM0QsUUFBQSxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLENBQUE7QUFDakQsUUFBQSxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLENBQUE7UUFFakQsTUFBTSxRQUFRLEdBQUcsQ0FBQyxHQUFHLEVBQUUsR0FBRyxJQUFJLEdBQUcsSUFBSSxDQUFBO0FBQ3JDLFFBQUEsTUFBTSxLQUFLLEdBQUcsSUFBSSxVQUFVLENBQUMsUUFBUSxDQUFDLENBQUE7OztBQUl0QyxRQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsR0FBRyxFQUFFLEtBQUssRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBQzdDLFFBQUEsV0FBVyxDQUFDLFdBQVcsQ0FBQyxHQUFHLEVBQUUsS0FBSyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsRUFBRSxDQUFDLENBQUE7QUFDOUMsUUFBQSxXQUFXLENBQUMsVUFBVSxDQUFDLEVBQUUsRUFBRSxLQUFLLEVBQUUsQ0FBQyxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxZQUFZLENBQUMsQ0FBQTtRQUN4RSxXQUFXLENBQUMsVUFBVSxDQUFDLENBQUMsRUFBRSxLQUFLLEVBQUUsQ0FBQyxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxZQUFZLEVBQUUsU0FBUyxDQUFDLHFCQUFxQixDQUFDLENBQUE7O1FBR3pHLE1BQU0sSUFBSSxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxRQUFRLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0FBRUQsSUFBQSxNQUFNLGdCQUFnQixDQUFFLFdBQTRCLEVBQUUsWUFBOEIsRUFBQTtBQUNsRixRQUFBLE1BQU0sRUFBRSxFQUFFLEVBQUUsVUFBVSxFQUFFLEVBQUUsRUFBRSxVQUFVLEVBQUUsR0FBRyxZQUFZLENBQUMsUUFBUSxDQUFBO0FBQ2hFLFFBQUEsTUFBTSxFQUFFLEVBQUUsRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLE1BQU0sRUFBRSxDQUFDLEVBQUUsR0FBRyxZQUFZLENBQUMsSUFBSSxDQUFBOztRQUd2RCxNQUFNLFlBQVksR0FBRyxVQUFVLENBQUMsTUFBTSxLQUFLLE1BQU0sQ0FBQyxNQUFNO0FBQ3RELFlBQUEsVUFBVSxDQUFDLE1BQU0sS0FBSyxNQUFNLENBQUMsTUFBTSxDQUFBO1FBQ3JDLElBQUksQ0FBQyxZQUFZLEVBQUU7QUFDakIsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLG1DQUFtQyxDQUFDLENBQUE7QUFDckQsU0FBQTs7UUFHRCxNQUFNLE9BQU8sR0FBRyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsSUFBSSxFQUFFLENBQUMsS0FBSyxJQUFJLEtBQUssTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDakUsUUFBQSxJQUFJLE9BQU8sRUFBRTtBQUNYLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxtQ0FBbUMsQ0FBQyxDQUFBO0FBQ3JELFNBQUE7O0FBR0QsUUFBQSxNQUFNLFVBQVUsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsV0FBVyxFQUFFLFVBQVUsRUFBRSxDQUFDLENBQUMsQ0FBQTtRQUNuRSxNQUFNLE9BQU8sR0FBRyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsSUFBSSxFQUFFLENBQUMsS0FBSyxJQUFJLEtBQUssVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7UUFDckUsSUFBSSxDQUFDLE9BQU8sRUFBRTtBQUNaLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxxQkFBcUIsQ0FBQyxDQUFBO0FBQ3ZDLFNBQUE7S0FDRjtBQUVELElBQUEsTUFBTSxnQkFBZ0IsQ0FBRSxJQUFVLEVBQUUsV0FBNEIsRUFBRSxZQUE4QixFQUFBO0FBQzlGLFFBQUEsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsWUFBWSxHQUFHLENBQUMsQ0FBQyxDQUFBOztBQUdsRCxRQUFBLE1BQU0sWUFBWSxHQUFHLE1BQU0sSUFBSSxDQUFDLFVBQVUsQ0FBQyxXQUFXLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxDQUFBO0FBQzFFLFFBQUEsTUFBTSxJQUFJLEdBQUcsSUFBSSxVQUFVLENBQUMsRUFBRSxDQUFDLENBQUE7QUFDL0IsUUFBQSxNQUFNLGlCQUFpQixHQUFHLElBQUksVUFBVSxDQUFDLEVBQUUsR0FBRyxDQUFDLEdBQUcsSUFBSSxHQUFHLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFDLENBQUE7UUFDcEUsTUFBTSxhQUFhLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDbkUsUUFBQSxNQUFNLEtBQUssR0FBRyxNQUFNQSxvQkFBUyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFBO1FBQzlELE1BQU0sV0FBVyxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUE7QUFDM0MsUUFBQSxNQUFNLEtBQUssR0FBRyxNQUFNQSxvQkFBUyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFBO1FBQzlELE1BQU0sV0FBVyxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUE7O0FBRzNDLFFBQUEsV0FBVyxDQUFDLFdBQVcsQ0FBQyxZQUFZLEVBQUUsaUJBQWlCLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUNsRSxRQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsaUJBQWlCLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxJQUFJLENBQUMsQ0FBQTtBQUMxRSxRQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsaUJBQWlCLEVBQUUsQ0FBQyxFQUFFLEVBQUUsR0FBRyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUE7QUFDakYsUUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLGFBQWEsRUFBRSxpQkFBaUIsRUFBRSxDQUFDLEVBQUUsRUFBRSxHQUFHLENBQUMsR0FBRyxJQUFJLEVBQUUsQ0FBQyxDQUFDLENBQUE7QUFDOUUsUUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLFdBQVcsRUFBRSxpQkFBaUIsRUFBRSxDQUFDLEVBQUUsRUFBRSxHQUFHLENBQUMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFBO1FBQ2pGLFdBQVcsQ0FBQyxXQUFXLENBQUMsV0FBVyxFQUFFLGlCQUFpQixFQUFFLENBQUMsRUFBRSxFQUFFLEdBQUcsQ0FBQyxHQUFHLElBQUksR0FBRyxDQUFDLEdBQUcsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFBOztBQUd0RixRQUFBLE1BQU0sTUFBTSxHQUFHLE1BQU1ELDhCQUFVLENBQUMsaUJBQWlCLEVBQUUsSUFBSSxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUMvRCxRQUFBLE1BQU0sU0FBUyxHQUFHLE1BQU0sU0FBUyxDQUFDLFVBQVUsQ0FDMUMsV0FBVyxDQUFDLElBQUksRUFDaEIsV0FBVyxDQUFDLElBQUksQ0FBQyxFQUFFLEVBQ25CLFdBQVcsQ0FBQyxRQUFRLENBQUMsRUFBRSxFQUN2QixZQUFZLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFDakIsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQ2pCLElBQUksVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUN2QixDQUFBO0FBQ0QsUUFBQSxPQUFPLFNBQVMsQ0FBQTtLQUNqQjtBQUVELElBQUEsTUFBTSxHQUFHLEdBQUE7QUFDUCxRQUFBLE1BQU0sSUFBSSxHQUFHLFlBQWdDOztBQUUzQyxZQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksSUFBSSxFQUFFLENBQUE7QUFDdkIsWUFBQSxNQUFNLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTtBQUN6QixZQUFBLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLFlBQVksRUFBRSxDQUFBOztBQUczQyxZQUFBLE1BQU0sT0FBTyxHQUFHLE1BQU0sSUFBSSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLFNBQVMsQ0FBQyxDQUFBOztBQUc3RCxZQUFBLE1BQU0sV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLEVBQUUsT0FBTyxDQUFDLENBQUE7O0FBR3pFLFlBQUEsTUFBTSxDQUFDLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLFdBQVcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUE7QUFDakUsWUFBQSxNQUFNLEVBQUUsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLEVBQUUsQ0FBQTtBQUNqQyxZQUFBLE1BQU0sRUFBRSxHQUFHLE1BQU0sSUFBSSxDQUFDLFNBQVMsQ0FBQyxXQUFXLEVBQUUsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFBO1lBQ25ELE1BQU0sUUFBUSxHQUFhLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsQ0FBQTs7QUFHeEMsWUFBQSxNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsY0FBYyxDQUFDLElBQUksRUFBRSxRQUFRLENBQUMsQ0FBQTs7WUFHeEUsTUFBTSxJQUFJLENBQUMsZ0JBQWdCLENBQUMsV0FBVyxFQUFFLFlBQVksQ0FBQyxDQUFBOztBQUd0RCxZQUFBLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLGdCQUFnQixDQUFDLElBQUksRUFBRSxXQUFXLEVBQUUsWUFBWSxDQUFDLENBQUE7QUFDOUUsWUFBQSxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsWUFBWSxDQUFDLElBQUksRUFBRSxTQUFTLENBQUMsQ0FBQTs7QUFHL0QsWUFBQSxNQUFNLE9BQU8sR0FBRyxJQUFJLE9BQU8sQ0FBQyxJQUFJLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQTtBQUM1RCxZQUFBLElBQUksQ0FBQyxJQUFJLENBQUMsV0FBVyxFQUFFLFNBQVMsQ0FBQyxDQUFBO0FBRWpDLFlBQUEsT0FBTyxPQUFPLENBQUE7QUFDaEIsU0FBQyxDQUFBO0FBRUQsUUFBQSxPQUFPLE1BQU0sSUFBSSxFQUFFLENBQUMsT0FBTyxDQUFDLE1BQUs7QUFDL0IsWUFBQSxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUM3QixTQUFDLENBQUMsQ0FBQTtLQUNIO0lBS0QsRUFBRSxDQUFFLEtBQWEsRUFBRSxRQUFrQyxFQUFBO1FBQ25ELE9BQU8sS0FBSyxDQUFDLEVBQUUsQ0FBQyxLQUFLLEVBQUUsUUFBUSxDQUFDLENBQUE7S0FDakM7QUFLRCxJQUFBLElBQUksQ0FBRSxLQUFhLEVBQUUsR0FBRyxJQUFXLEVBQUE7UUFDakMsT0FBTyxLQUFLLENBQUMsSUFBSSxDQUFDLEtBQUssRUFBRSxHQUFHLElBQUksQ0FBQyxDQUFBO0tBQ2xDO0FBQ0Y7O01DdktZLGdCQUFnQixDQUFBO0lBQzNCLFdBQXVCLENBQUEsTUFBa0IsRUFBWSxDQUFTLEVBQUE7UUFBdkMsSUFBTSxDQUFBLE1BQUEsR0FBTixNQUFNLENBQVk7UUFBWSxJQUFDLENBQUEsQ0FBQSxHQUFELENBQUMsQ0FBUTtLQUFLO0lBRW5FLFFBQVEsR0FBQTtRQUNOLE9BQU8sTUFBTSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUE7S0FDeEM7SUFFRCxXQUFXLEdBQUE7QUFDVCxRQUFBLE1BQU0sWUFBWSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFdBQVcsR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUN6RCxRQUFBLE1BQU0sZUFBZSxHQUFHLElBQUksQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQ2xDLFFBQUEsTUFBTSxTQUFTLEdBQUcsSUFBSSxVQUFVLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDOUMsUUFBQSxXQUFXLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxNQUFNLEVBQUUsU0FBUyxFQUFFLElBQUksQ0FBQyxDQUFDLEVBQUUsZUFBZSxFQUFFLFNBQVMsQ0FBQyxXQUFXLENBQUMsQ0FBQTtRQUM5RixNQUFNLEtBQUssR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0FBQ3pDLFFBQUEsT0FBTyxTQUFTLENBQUMsWUFBWSxHQUFHLEtBQUssQ0FBQTtLQUN0QztJQUVELFNBQVMsR0FBQTtBQUNQLFFBQUEsT0FBTyxXQUFXLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQTtLQUN2RDtBQUVELElBQUEsYUFBYSxRQUFRLENBQUUsSUFBWSxFQUFFLENBQVMsRUFBQTtBQUM1QyxRQUFBLE1BQU0sWUFBWSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEdBQUcsU0FBUyxDQUFDLFdBQVcsSUFBSSxDQUFDLENBQUMsQ0FBQTtBQUUvRCxRQUFBLE1BQU0sR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLFlBQVksQ0FBQyxDQUFBO1FBQ3hDLE1BQU0sTUFBTSxDQUFDLGNBQWMsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO0FBRXRDLFFBQUEsTUFBTSxLQUFLLEdBQUcsSUFBSSxHQUFHLFNBQVMsQ0FBQyxZQUFZLENBQUE7UUFDM0MsSUFBSSxLQUFLLEdBQUcsQ0FBQyxJQUFJLEtBQUssR0FBRyxTQUFTLENBQUMsVUFBVSxFQUFFO0FBQzdDLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxZQUFZLElBQUksQ0FBQSx5QkFBQSxDQUEyQixDQUFDLENBQUE7QUFDN0QsU0FBQTtRQUVELE1BQU0sU0FBUyxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLENBQUMsQ0FBQyxDQUFBO1FBQzVDLFdBQVcsQ0FBQyxVQUFVLENBQUMsU0FBUyxFQUFFLEdBQUcsRUFBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUUvRixRQUFBLE9BQU8sSUFBSSxnQkFBZ0IsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxDQUFDLENBQUE7S0FDcEM7QUFFRCxJQUFBLE9BQU8sVUFBVSxDQUFFLFVBQWtCLEVBQUUsQ0FBUyxFQUFBO0FBQzlDLFFBQUEsT0FBTyxJQUFJLGdCQUFnQixDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsVUFBVSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7S0FDaEU7QUFDRjs7QUNsQ1ksTUFBQSxvQkFBb0IsR0FBa0I7SUFDakQsTUFBTSxRQUFRLENBQUUsU0FBUyxFQUFBO0FBQ3ZCLFFBQUEsT0FBTyxDQUFDLElBQUksQ0FBQyw2RUFBNkUsQ0FBQyxDQUFBO0FBQzNGLFFBQUEsTUFBTSxPQUFPLEdBQUcsTUFBTSxTQUFTLENBQUMsTUFBTSxFQUFFLENBQUE7UUFDeEMsT0FBTyxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQTtLQUNqRDtJQUNELE1BQU0sWUFBWSxDQUFFLElBQUksRUFBQTtRQUN0QixNQUFNLE9BQU8sR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFBO0FBQ3RDLFFBQUEsT0FBTyxNQUFNLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFBO0tBQ3JEOzs7QUNNRyxNQUFnQixrQkFBNkIsU0FBUSxhQUF1QixDQUFBO0FBTWhGLElBQUEsV0FBQSxDQUFhLE9BQWtDLEVBQUUsRUFBQTtBQUMvQyxRQUFBLEtBQUssRUFBRSxDQUFBO1FBQ1AsSUFBSSxDQUFDLElBQUksR0FBRztBQUNWLFlBQUEsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJLElBQUksV0FBVztZQUM5QixFQUFFLEVBQUUsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUU7QUFDcEMsWUFBQSxDQUFDLEVBQUUsSUFBSSxDQUFDLENBQUMsSUFBSSxTQUFTLENBQUMscUJBQXFCO1lBQzVDLG1CQUFtQixFQUFFLElBQUksQ0FBQyxtQkFBbUIsS0FBSyxZQUE0QjtBQUM1RSxnQkFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHNDQUFzQyxDQUFDLENBQUE7QUFDekQsYUFBQyxDQUFDO1NBQ0gsQ0FBQTtLQUNGO0FBSUQsSUFBQSxNQUFNLE9BQU8sQ0FBRSxRQUF3QixFQUFFLFNBQWlCLEVBQUE7UUFDeEQsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLG1CQUFtQixFQUFFLENBQUE7UUFDeEQsSUFBSSxVQUFVLEtBQUssRUFBRSxFQUFFO0FBQ3JCLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyx5QkFBeUIsQ0FBQyxDQUFBO0FBQzNDLFNBQUE7QUFDRCxRQUFBLElBQUksQ0FBQyxVQUFVLEdBQUcsZ0JBQWdCLENBQUMsVUFBVSxDQUFDLFVBQVUsRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBRXRFLFFBQUEsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUN2QyxRQUFBLE1BQU0sRUFBRSxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFBO0FBQy9CLFFBQUEsTUFBTSxNQUFNLENBQUMsY0FBYyxDQUFDLEVBQUUsRUFBRSxDQUFDLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUUvQyxPQUFPO0FBQ0wsWUFBQSxFQUFFLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxFQUFFO1lBQ2hCLFNBQVM7QUFDVCxZQUFBLEVBQUUsRUFBRSxFQUFFO1NBQ1AsQ0FBQTtLQUNGO0FBRUQsSUFBQSxNQUFNLGlCQUFpQixDQUFFLFFBQXdCLEVBQUUsT0FBZ0IsRUFBQTtBQUNqRSxRQUFBLElBQUksSUFBSSxDQUFDLFVBQVUsS0FBSyxTQUFTLEVBQUU7QUFDakMsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLDJCQUEyQixDQUFDLENBQUE7QUFDN0MsU0FBQTtBQUVELFFBQUEsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUEyQjtBQUNoRSxZQUFBLE1BQU0sRUFBRSxtQkFBbUI7QUFDM0IsWUFBQSxNQUFNLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxFQUFFO1lBQ3BCLFNBQVMsRUFBRSxPQUFPLENBQUMsU0FBUztZQUM1QixFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxPQUFPLENBQUMsRUFBRSxDQUFDO0FBQ3BDLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxNQUFNLFFBQVEsR0FBWTtZQUN4QixFQUFFLEVBQUUsUUFBUSxDQUFDLE1BQU07WUFDbkIsU0FBUyxFQUFFLFFBQVEsQ0FBQyxTQUFTO0FBQzdCLFlBQUEsRUFBRSxFQUFFLElBQUksQ0FBQyxVQUFVLENBQUMsU0FBUyxFQUFFO1NBQ2hDLENBQUE7UUFFRCxPQUFPO0FBQ0wsWUFBQSxDQUFDLEVBQUUsT0FBTztBQUNWLFlBQUEsQ0FBQyxFQUFFLFFBQVE7QUFFWCxZQUFBLElBQUksRUFBRSxJQUFJLENBQUMsVUFBVSxDQUFDLFdBQVcsRUFBRTtBQUNuQyxZQUFBLElBQUksRUFBRSxPQUFPO1lBQ2IsUUFBUTtTQUNULENBQUE7S0FDRjtBQUVELElBQUEsTUFBTSxjQUFjLENBQUUsUUFBd0IsRUFBRSxRQUFrQixFQUFBO0FBQ2hFLFFBQUEsTUFBTSxhQUFhLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFvQjtBQUM5RCxZQUFBLE1BQU0sRUFBRSxZQUFZO1lBQ3BCLEVBQUUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUM7QUFDckMsU0FBQSxDQUFDLENBQUE7QUFFRixRQUFBLE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBcUI7QUFDMUQsWUFBQSxNQUFNLEVBQUUsT0FBTztZQUNmLEVBQUUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUM7QUFDckMsU0FBQSxDQUFDLENBQUE7QUFDRixRQUFBLE1BQU0sUUFBUSxHQUFhO1lBQ3pCLEVBQUUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLGFBQWEsQ0FBQyxFQUFFLENBQUM7WUFDekMsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQztZQUNwQyxDQUFDLEVBQUUsUUFBUSxDQUFDLENBQUM7U0FDZCxDQUFBO1FBRUQsT0FBTztBQUNMLFlBQUEsQ0FBQyxFQUFFLFFBQVE7QUFDWCxZQUFBLENBQUMsRUFBRTtnQkFDRCxFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxhQUFhLENBQUMsRUFBRSxDQUFDO2dCQUN6QyxFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDO2dCQUNwQyxDQUFDLEVBQUUsUUFBUSxDQUFDLENBQUM7QUFDZCxhQUFBO0FBRUQsWUFBQSxJQUFJLEVBQUUsUUFBUTtZQUNkLFFBQVE7U0FDVCxDQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0sWUFBWSxDQUFFLFFBQXdCLEVBQUUsU0FBb0IsRUFBQTtBQUNoRSxRQUFBLE1BQU0sY0FBYyxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBK0I7QUFDMUUsWUFBQSxNQUFNLEVBQUUsY0FBYztBQUN2QixTQUFBLENBQUMsQ0FBQTtRQUVGLE1BQU0sWUFBWSxHQUFHLE1BQU0sQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLFVBQVUsQ0FBQyxDQUFBO1FBQ25FLE1BQU0sSUFBSSxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQUNsRCxRQUFBLE9BQU8sSUFBSSxDQUFBO0tBQ1o7QUFFRCxJQUFBLE1BQU0sQ0FBRSxRQUF3QixFQUFBO0FBQzlCLFFBQUEsS0FBSyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUN0QixRQUFBLElBQUksQ0FBQyxVQUFVLEdBQUcsU0FBUyxDQUFBO0tBQzVCO0FBQ0Y7O0FDbkhLLE1BQU8sc0JBQXVCLFNBQVEsa0JBQTZDLENBQUE7QUFDdkYsSUFBQSxXQUFXLENBQUUsSUFBWSxFQUFBO0FBQ3ZCLFFBQUEsT0FBTyxDQUFVLE9BQUEsRUFBQSxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBSSxDQUFBLEVBQUEsSUFBSSxDQUFJLENBQUEsRUFBQSxTQUFTLENBQUMsWUFBWSxFQUFFLENBQUE7S0FDcEU7QUFFRCxJQUFBLE1BQU0sUUFBUSxDQUFFLElBQVksRUFBRSxPQUFvQixFQUFBO0FBQ2hELFFBU087QUFDTCxZQUFBLE1BQU0sSUFBSSxHQUFhLE9BQUEsQ0FBYSxNQUFNLENBQUMsQ0FBQTtZQUMzQyxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksT0FBTyxDQUFlLE9BQU8sSUFBRztBQUNyRCxnQkFBQSxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsSUFBYyxDQUFBO0FBQ3ZDLGdCQUFBLE1BQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxPQUFPLENBQUM7QUFDdkIsb0JBQUEsSUFBSSxFQUFFLENBQUEsQ0FBQSxFQUFJLFNBQVMsQ0FBQyxZQUFZLENBQUUsQ0FBQTtvQkFDbEMsSUFBSTtBQUNKLG9CQUFBLE1BQU0sRUFBRSxPQUFPLENBQUMsTUFBTSxJQUFJLE1BQU07QUFDaEMsb0JBQUEsT0FBTyxFQUFFO3dCQUNQLEdBQUcsT0FBTyxDQUFDLE9BQWM7QUFDekIsd0JBQUEsZ0JBQWdCLEVBQUUsTUFBTSxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUM7QUFDOUMscUJBQUE7aUJBQ0YsRUFBRSxDQUFDLEdBQUcsS0FBSTtvQkFDVCxJQUFJLElBQUksR0FBRyxFQUFFLENBQUE7b0JBQ2IsR0FBRyxDQUFDLEVBQUUsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxLQUFhLEtBQUk7d0JBQy9CLElBQUksSUFBSSxLQUFLLENBQUE7QUFDZixxQkFBQyxDQUFDLENBQUE7QUFDRixvQkFBQSxHQUFHLENBQUMsRUFBRSxDQUFDLEtBQUssRUFBRSxNQUFLO0FBQ2pCLHdCQUFBLE9BQU8sQ0FBQztBQUNOLDRCQUFBLE1BQU0sRUFBRSxHQUFHLENBQUMsVUFBVSxJQUFJLEdBQUc7QUFDN0IsNEJBQUEsSUFBSSxFQUFFLElBQUk7QUFDWCx5QkFBQSxDQUFDLENBQUE7QUFDSixxQkFBQyxDQUFDLENBQUE7QUFDSixpQkFBQyxDQUFDLENBQUE7QUFFRixnQkFBQSxHQUFHLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxDQUFBO2dCQUNuQixHQUFHLENBQUMsR0FBRyxFQUFFLENBQUE7QUFDWCxhQUFDLENBQUMsQ0FBQTtBQUVGLFlBQUEsT0FBTyxJQUFJLENBQUE7QUFDWixTQUFBO0tBQ0Y7SUFFRCxNQUFNLFdBQVcsQ0FBcUIsT0FBZ0IsRUFBQTtBQUNwRCxRQUFBLElBQUksSUFBSSxDQUFDLFVBQVUsS0FBSyxTQUFTLEVBQUU7QUFDakMsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLDZDQUE2QyxDQUFDLENBQUE7QUFDL0QsU0FBQTtRQUVELE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxVQUFVLENBQUMsV0FBVyxFQUFFLENBQUE7UUFFMUMsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksRUFBRTtBQUNyQyxZQUFBLE1BQU0sRUFBRSxNQUFNO0FBQ2QsWUFBQSxPQUFPLEVBQUU7QUFDUCxnQkFBQSxjQUFjLEVBQUUsa0JBQWtCO0FBQ25DLGFBQUE7QUFDRCxZQUFBLElBQUksRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQztBQUM5QixTQUFBLENBQUMsQ0FBQTtRQUVGLE9BQU8sSUFBSSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUE7S0FDN0I7QUFFRCxJQUFBLE1BQU0sSUFBSSxDQUFFLFNBQW9CLEVBQUUsSUFBZ0IsRUFBRSxHQUFnQixFQUFBO0FBQ2xFLFFBQUEsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUE7UUFDckQsTUFBTSxVQUFVLEdBQUcsTUFBTSxTQUFTLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFBO1FBRW5ELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsSUFBSSxFQUFFO0FBQy9DLFlBQUEsTUFBTSxFQUFFLE1BQU07QUFDZCxZQUFBLE9BQU8sRUFBRTtBQUNQLGdCQUFBLGFBQWEsRUFBRSxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQztBQUN0QyxhQUFBO0FBQ0QsWUFBQSxJQUFJLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUM7QUFDdEMsU0FBQSxDQUFDLENBQUE7O1FBR0YsSUFBSSxJQUFJLENBQUMsTUFBTSxJQUFJLEdBQUcsSUFBSSxJQUFJLENBQUMsTUFBTSxJQUFJLEdBQUcsRUFBRTtZQUM1QyxNQUFNLGNBQWMsR0FBRyxNQUFNLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtZQUNyRCxNQUFNLFVBQVUsR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLENBQUE7WUFDMUQsSUFBSSxDQUFDLElBQUksR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQ3pDLFNBQUE7QUFFRCxRQUFBLE9BQU8sSUFBSSxDQUFBO0tBQ1o7QUFDRjs7QUN4RUssTUFBZ0Isa0JBQTZCLFNBQVEsYUFBdUIsQ0FBQTtBQVNoRixJQUFBLFdBQUEsQ0FBYSxPQUFrQyxFQUFFLEVBQUE7QUFDL0MsUUFBQSxLQUFLLEVBQUUsQ0FBQTtRQUNQLElBQUksQ0FBQyxJQUFJLEdBQUc7QUFDVixZQUFBLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSSxJQUFJLFNBQVMsQ0FBQyxZQUFZO0FBQ3pDLFlBQUEsT0FBTyxFQUFFLElBQUksQ0FBQyxPQUFPLElBQUksU0FBUyxDQUFDLGVBQWU7WUFDbEQsRUFBRSxFQUFFLElBQUksQ0FBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFO0FBQ3BDLFlBQUEsQ0FBQyxFQUFFLElBQUksQ0FBQyxDQUFDLElBQUksU0FBUyxDQUFDLHFCQUFxQjtBQUM1QyxZQUFBLGFBQWEsRUFBRSxJQUFJLENBQUMsYUFBYSxJQUFJLG9CQUFvQjtTQUMxRCxDQUFBO0FBQ0QsUUFBQSxJQUFJLENBQUMsVUFBVSxHQUFHLElBQUksT0FBTyxFQUFFLENBQUE7S0FDaEM7QUFFRCxJQUFBLE1BQU0sT0FBTyxDQUFFLFFBQXdCLEVBQUUsSUFBWSxFQUFFLE9BQWUsRUFBQTtRQUNwRSxJQUFJLENBQUMsV0FBVyxFQUFFLENBQUE7QUFFbEIsUUFBQSxJQUFJLENBQUMsVUFBVSxHQUFHLE1BQU0sZ0JBQWdCLENBQUMsUUFBUSxDQUFDLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQ3BFLFFBQUEsSUFBSSxDQUFDLFdBQVcsR0FBRyxVQUFVLENBQUMsTUFBSztZQUNqQyxJQUFJLENBQUMsV0FBVyxFQUFFLENBQUE7QUFDbEIsWUFBQSxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFBO1NBQ3RCLEVBQUUsT0FBTyxDQUFDLENBQUE7S0FDWjtJQUVELFdBQVcsR0FBQTtBQUNULFFBQUEsSUFBSSxJQUFJLENBQUMsV0FBVyxJQUFJLElBQUksRUFBRTtBQUM1QixZQUFBLFlBQVksQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQUE7QUFDOUIsWUFBQSxJQUFJLENBQUMsV0FBVyxHQUFHLFNBQVMsQ0FBQTtBQUM3QixTQUFBO0tBQ0Y7QUFFRCxJQUFBLElBQUksU0FBUyxHQUFBO0FBQ1gsUUFBQSxPQUFPLElBQUksQ0FBQyxVQUFVLEtBQUssU0FBUyxDQUFBO0tBQ3JDO0FBRUQsSUFBQSxJQUFJLElBQUksR0FBQTtBQUNOLFFBQUEsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQTtLQUN0QjtBQUVELElBQUEsSUFBSSxPQUFPLEdBQUE7QUFDVCxRQUFBLE9BQU8sSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7S0FDekI7QUFFRCxJQUFBLE1BQU0sT0FBTyxDQUFFLFFBQXdCLEVBQUUsU0FBaUIsRUFBQTtBQUN4RCxRQUFBLE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsSUFBSSxDQUFDLElBQUksRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUE7UUFDckQsSUFBSSxJQUFJLENBQUMsVUFBVSxLQUFLLElBQUksSUFBSSxJQUFJLENBQUMsVUFBVSxLQUFLLFNBQVMsRUFBRTtBQUM3RCxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsc0NBQXNDLENBQUMsQ0FBQTtBQUN4RCxTQUFBO1FBRUQsUUFBUSxDQUFDLElBQUksQ0FBQyxZQUFZLEVBQUUsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFBO1FBRTVDLE9BQU87QUFDTCxZQUFBLEVBQUUsRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLEVBQUU7WUFDaEIsU0FBUztBQUNULFlBQUEsRUFBRSxFQUFFLElBQUksQ0FBQyxVQUFVLENBQUMsU0FBUyxFQUFFO1NBQ2hDLENBQUE7S0FDRjtJQUVELE1BQU0sV0FBVyxDQUFtRSxNQUFTLEVBQUE7QUFDM0YsUUFBQSxPQUFPLElBQUksRUFBRTtZQUNYLE1BQU0sVUFBVSxHQUFHLE1BQU0sSUFBSSxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUE7QUFDaEQsWUFBQSxJQUFJLFVBQVUsQ0FBQyxHQUFHLENBQUMsTUFBTSxLQUFLLE1BQU0sRUFBRTtnQkFDcEMsU0FBUTtBQUNULGFBQUE7QUFFRCxZQUFBLE9BQU8sVUFBNEIsQ0FBQTtBQUNwQyxTQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0saUJBQWlCLENBQUUsUUFBd0IsRUFBRSxPQUFnQixFQUFBO0FBQ2pFLFFBQUEsSUFBSSxJQUFJLENBQUMsVUFBVSxLQUFLLFNBQVMsRUFBRTtBQUNqQyxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsbUNBQW1DLENBQUMsQ0FBQTtBQUNyRCxTQUFBO0FBRUQsUUFBQSxNQUFNLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFBO1FBQ2hFLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQztBQUNiLFlBQUEsTUFBTSxFQUFFLG1CQUFtQjtZQUMzQixNQUFNLEVBQUUsT0FBTyxDQUFDLEVBQUU7WUFDbEIsU0FBUyxFQUFFLE9BQU8sQ0FBQyxTQUFTO0FBQzdCLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxNQUFNLFFBQVEsR0FBWTtZQUN4QixFQUFFLEVBQUUsR0FBRyxDQUFDLE1BQU07WUFDZCxTQUFTLEVBQUUsR0FBRyxDQUFDLFNBQVM7WUFDeEIsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsR0FBRyxDQUFDLEVBQUUsSUFBSSxFQUFFLENBQUM7U0FDdEMsQ0FBQTtRQUVELE9BQU87QUFDTCxZQUFBLENBQUMsRUFBRSxRQUFRO0FBQ1gsWUFBQSxDQUFDLEVBQUUsT0FBTztBQUVWLFlBQUEsSUFBSSxFQUFFLElBQUksQ0FBQyxVQUFVLENBQUMsV0FBVyxFQUFFO0FBQ25DLFlBQUEsSUFBSSxFQUFFLE9BQU87WUFDYixRQUFRO1NBQ1QsQ0FBQTtLQUNGO0FBRUQsSUFBQSxNQUFNLGNBQWMsQ0FBRSxRQUF3QixFQUFFLFFBQWtCLEVBQUE7UUFDaEUsTUFBTSxNQUFNLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBQ25ELFFBQUEsTUFBTSxNQUFNLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQztBQUNwQixZQUFBLE1BQU0sRUFBRSxZQUFZO1lBQ3BCLEVBQUUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUM7QUFDckMsU0FBQSxDQUFDLENBQUE7QUFDRixRQUFBLE1BQU0sYUFBYSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUE7UUFFaEMsTUFBTSxNQUFNLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBQzlDLFFBQUEsTUFBTSxNQUFNLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQztBQUNwQixZQUFBLE1BQU0sRUFBRSxPQUFPO1lBQ2YsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQztBQUNyQyxTQUFBLENBQUMsQ0FBQTtBQUNGLFFBQUEsTUFBTSxRQUFRLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQTtBQUUzQixRQUFBLE1BQU0sUUFBUSxHQUFhO1lBQ3pCLEVBQUUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLGFBQWEsQ0FBQyxFQUFFLENBQUM7WUFDekMsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQztZQUNwQyxDQUFDLEVBQUUsUUFBUSxDQUFDLENBQUM7U0FDZCxDQUFBO1FBRUQsT0FBTztBQUNMLFlBQUEsQ0FBQyxFQUFFLFFBQVE7QUFDWCxZQUFBLENBQUMsRUFBRSxRQUFRO0FBRVgsWUFBQSxJQUFJLEVBQUUsUUFBUTtZQUNkLFFBQVE7U0FDVCxDQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0sWUFBWSxDQUFFLFFBQXdCLEVBQUUsU0FBb0IsRUFBQTtRQUNoRSxNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsY0FBYyxDQUFDLENBQUE7QUFDeEQsUUFBQSxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxJQUFJLENBQUMsYUFBYSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUM5RCxNQUFNLFVBQVUsR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7QUFDaEQsUUFBQSxNQUFNLFNBQVMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDO0FBQ3ZCLFlBQUEsTUFBTSxFQUFFLHVCQUF1QjtBQUMvQixZQUFBLFVBQVUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQztBQUM1QyxTQUFBLENBQUMsQ0FBQTtBQUVGLFFBQUEsT0FBTyxJQUFJLENBQUE7S0FDWjtBQUVELElBQUEsTUFBTSxDQUFFLFFBQXdCLEVBQUE7QUFDOUIsUUFBQSxLQUFLLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFBO1FBQ3RCLElBQUksQ0FBQyxXQUFXLEVBQUUsQ0FBQTs7QUFFbEIsUUFBQSxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsQ0FBQTtBQUMvQixRQUFBLElBQUksQ0FBQyxVQUFVLEdBQUcsU0FBUyxDQUFBO0tBQzVCO0FBQ0Y7O01DdkxxQixRQUFRLENBQUE7QUFFN0I7O0FDQUssTUFBTyxZQUFnQyxTQUFRLFFBQVcsQ0FBQTtBQUM5RCxJQUFBLFdBQUEsQ0FBdUIsR0FBd0IsRUFBQTtBQUM3QyxRQUFBLEtBQUssRUFBRSxDQUFBO1FBRGMsSUFBRyxDQUFBLEdBQUEsR0FBSCxHQUFHLENBQXFCO0tBRTlDO0lBRUQsTUFBTSxJQUFJLENBQUUsT0FBVSxFQUFBO0FBQ3BCLFFBQUEsSUFBSSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFBO0FBQ3ZDLFFBQUEsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsQ0FBQTtLQUNmO0FBQ0Y7O0FDRkssTUFBTyxzQkFBdUIsU0FBUSxrQkFBK0MsQ0FBQTtBQUl6RixJQUFBLFdBQUEsQ0FBYSxJQUFvQyxFQUFBO1FBQy9DLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUhILElBQVMsQ0FBQSxTQUFBLEdBQTJCLEVBQUUsQ0FBQTtBQUk5QyxRQUFBLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxFQUFFLE1BQU0sSUFBSSxDQUFBLENBQUEsRUFBSSxTQUFTLENBQUMsWUFBWSxDQUFBLENBQUUsQ0FBQTtLQUMzRDtJQUVTLE1BQU0sZUFBZSxDQUFFLEdBQXlCLEVBQUE7UUFDeEQsTUFBTSxPQUFPLEdBQUcsRUFBRSxDQUFBO0FBQ2xCLFFBQUEsV0FBVyxNQUFNLEtBQUssSUFBSSxHQUFHLEVBQUU7QUFDN0IsWUFBQSxPQUFPLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFBO0FBQ3BCLFNBQUE7UUFFRCxPQUFPLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsUUFBUSxFQUFFLENBQUE7S0FDekM7QUFFUyxJQUFBLE1BQU0sdUJBQXVCLENBQUUsR0FBeUIsRUFBRSxHQUF3QixFQUFBO0FBQzFGLFFBQUEsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUU7QUFDbkIsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHFCQUFxQixDQUFDLENBQUE7QUFDdkMsU0FBQTtRQUVELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUM1QyxNQUFNLE9BQU8sR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFBO0FBQ2hDLFFBQUEsSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsRUFBRSxHQUFHLEVBQUUsT0FBTyxFQUFFLEdBQUcsRUFBRSxJQUFJLFlBQVksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLENBQUE7S0FDbkU7QUFFUyxJQUFBLE1BQU0sd0JBQXdCLENBQ3RDLEdBQXlCLEVBQ3pCLEdBQXdCLEVBQ3hCLGNBQXNCLEVBQUE7UUFFdEIsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxjQUFjLENBQUMsQ0FBQTtBQUM3QyxRQUFBLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxDQUFBO1FBRWxFLE1BQU0sZ0JBQWdCLEdBQUcsTUFBTSxJQUFJLENBQUMsZUFBZSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQ3hELE1BQU0sVUFBVSxHQUFHLE1BQU0sQ0FBQyxZQUFZLENBQUMsZ0JBQWdCLENBQUMsQ0FBQTtRQUN4RCxNQUFNLE9BQU8sR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7UUFDbkQsTUFBTSxXQUFXLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUM3QyxNQUFNLElBQUksR0FBZ0IsSUFBSSxDQUFDLEtBQUssQ0FBQyxXQUFXLENBQUMsQ0FBQTtRQUNqRCxJQUFJLFNBQVMsR0FBUSxFQUFFLENBQUE7QUFDdkIsUUFBQSxNQUFNLElBQUksR0FBZ0IsSUFBSSxDQUFDLElBQUksSUFBSSxFQUFFLENBQUE7UUFDekMsSUFBSSxJQUFJLENBQUMsSUFBSSxLQUFLLFNBQVMsSUFBSSxJQUFJLENBQUMsSUFBSSxLQUFLLEVBQUUsRUFBRTtZQUMvQyxTQUFTLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBYyxDQUFDLENBQUE7QUFDNUMsU0FBQTtRQUVELE1BQU0sT0FBTyxHQUFHLE1BQU07QUFDbkIsYUFBQSxPQUFPLENBQUMsSUFBSSxDQUFDLE9BQU8sSUFBSSxFQUFFLENBQUM7YUFDM0IsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQyxLQUFJO1lBQzFCLENBQUMsQ0FBQyxHQUFHLENBQUMsaUJBQWlCLEVBQUUsQ0FBQyxHQUFHLEtBQUssQ0FBQTtBQUNsQyxZQUFBLE9BQU8sQ0FBQyxDQUFBO0FBQ1YsU0FBQyxFQUFFLEdBQUcsQ0FBQyxPQUFPLENBQUMsQ0FBQTtBQUVqQixRQUFBLE1BQU0sUUFBUSxHQUFHLElBQUksS0FBSyxDQUF1QixHQUFHLEVBQUU7WUFDcEQsR0FBRyxDQUFFLE1BQU0sRUFBRSxDQUFDLEVBQUE7QUFDWixnQkFBQSxRQUFRLENBQUM7QUFDUCxvQkFBQSxLQUFLLEtBQUs7d0JBQ1IsT0FBTyxJQUFJLENBQUMsR0FBRyxDQUFBO0FBRWpCLG9CQUFBLEtBQUssUUFBUTt3QkFDWCxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUE7QUFFcEIsb0JBQUEsS0FBSyxTQUFTO0FBQ1osd0JBQUEsT0FBTyxPQUFPLENBQUE7QUFFaEIsb0JBQUEsS0FBSyxPQUFPO0FBQ1Ysd0JBQUEsT0FBTyxJQUFJLENBQUE7QUFFYixvQkFBQSxLQUFLLE1BQU07QUFDVCx3QkFBQSxPQUFPLFNBQVMsQ0FBQTtBQUVsQixvQkFBQSxLQUFLLGdCQUFnQjtBQUNuQix3QkFBQSxPQUFPLElBQUksQ0FBQTtBQUViLG9CQUFBO0FBQ0Usd0JBQUEsT0FBUSxNQUFjLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDNUIsaUJBQUE7YUFDRjtBQUNGLFNBQUEsQ0FBQyxDQUFBOztRQUdGLEdBQUcsQ0FBQyxHQUFHLEdBQUcsSUFBSSxLQUFLLENBQTZCLEdBQUcsQ0FBQyxHQUFHLEVBQUU7WUFDdkQsS0FBSyxFQUFFLENBQUMsTUFBZ0IsRUFBRSxPQUFPLEVBQUUsU0FBUyxLQUFJO0FBQzlDLGdCQUFBLE1BQU0sVUFBVSxHQUFHLE9BQU8sQ0FBQyxVQUFVLEtBQUssU0FBUyxHQUFHLEdBQUcsR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFBO0FBQzlFLGdCQUFBLElBQUksVUFBVSxJQUFJLEdBQUcsSUFBSSxVQUFVLEdBQUcsR0FBRyxFQUFFO0FBQ3pDLG9CQUFBLE1BQU0sS0FBSyxHQUFHLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUMxQixvQkFBQSxNQUFNLElBQUksR0FBRyxZQUEwQjtBQUNyQyx3QkFBQSxJQUFJLE1BQWtCLENBQUE7QUFDdEIsd0JBQUEsSUFBSSxPQUFPLEtBQUssS0FBSyxRQUFRLEVBQUU7QUFDN0IsNEJBQUEsTUFBTSxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUE7QUFDakMseUJBQUE7NkJBQU0sSUFBSSxLQUFLLFlBQVksTUFBTSxFQUFFOzRCQUNsQyxNQUFNLEdBQUcsS0FBSyxDQUFBO0FBQ2YseUJBQUE7QUFBTSw2QkFBQTtBQUNMLDRCQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsNkJBQTZCLENBQUMsQ0FBQTtBQUMvQyx5QkFBQTt3QkFDRCxNQUFNLFVBQVUsR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUE7d0JBQ2xELE1BQU0sZ0JBQWdCLEdBQUcsTUFBTSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUMsQ0FBQTt3QkFDeEQsR0FBRyxDQUFDLFNBQVMsQ0FBQyxnQkFBZ0IsRUFBRSxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUN4RCx3QkFBQSxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxHQUFHLFNBQVMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUMvRCxxQkFBQyxDQUFBO0FBRUQsb0JBQUEsSUFBSSxFQUFFLENBQUMsS0FBSyxDQUFDLEdBQUcsSUFBTSxFQUFBLE9BQU8sQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUEsRUFBRSxDQUFDLENBQUE7QUFDNUMsaUJBQUE7QUFBTSxxQkFBQTtvQkFDTCxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxHQUFHLFNBQVMsQ0FBQyxDQUFBO0FBQ25DLGlCQUFBO2FBQ0Y7QUFDRixTQUFBLENBQUMsQ0FBQTtRQUVGLE1BQU0sSUFBSSxDQUFDLGFBQWEsQ0FBQyxRQUFRLEVBQUUsR0FBRyxDQUFDLENBQUE7S0FDeEM7QUFFRCxJQUFBLE1BQU0sZUFBZSxDQUFFLEdBQXlCLEVBQUUsR0FBd0IsRUFBQTtBQUN4RSxRQUFBLElBQUksR0FBRyxDQUFDLEdBQUcsS0FBSyxJQUFJLENBQUMsTUFBTSxFQUFFO0FBQzNCLFlBQUEsSUFBSSxHQUFHLENBQUMsTUFBTSxLQUFLLE1BQU0sRUFBRTtBQUN6QixnQkFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHFCQUFxQixDQUFDLENBQUE7QUFDdkMsYUFBQTtBQUNELFlBQUEsSUFBSSxHQUFHLENBQUMsT0FBTyxDQUFDLGFBQWEsS0FBSyxTQUFTLEVBQUU7QUFDM0MsZ0JBQUEsT0FBTyxNQUFNLElBQUksQ0FBQyx3QkFBd0IsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQyxPQUFPLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDaEYsYUFBQTtBQUFNLGlCQUFBO2dCQUNMLE9BQU8sTUFBTSxJQUFJLENBQUMsdUJBQXVCLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0FBQ3BELGFBQUE7QUFDRixTQUFBO0FBQU0sYUFBQTtZQUNMLE1BQU0sSUFBSSxDQUFDLGFBQWEsQ0FBQyxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDbkMsU0FBQTtLQUNGO0FBRU8sSUFBQSxNQUFNLGFBQWEsQ0FBRSxHQUF5QixFQUFFLEdBQXdCLEVBQUE7QUFDOUUsUUFBQSxLQUFLLE1BQU0sUUFBUSxJQUFJLElBQUksQ0FBQyxTQUFTLEVBQUU7QUFDckMsWUFBQSxRQUFRLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0FBQ25CLFNBQUE7S0FDRjtBQUVELElBQUEsR0FBRyxDQUFFLFFBQThCLEVBQUE7QUFDakMsUUFBQSxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQTtLQUM5QjtBQUNGOzs7Ozs7Ozs7Ozs7In0=
