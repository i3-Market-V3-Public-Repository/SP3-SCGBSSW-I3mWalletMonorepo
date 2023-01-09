import * as base64 from '@juanelas/base64';
import pbkdf2Hmac from 'pbkdf2-hmac';
import * as objectSha from 'object-sha';

class BaseTransport {
    async send(masterKey, code, req) {
        throw new Error('this transport cannot send messages');
    }
    finish(protocol) {
        protocol.emit('finished');
    }
}

const PORT_LENGTH = 12;
const DEFAULT_RANDOM_LENGTH = 36;
const DEFAULT_TIMEOUT = 30000;
const PORT_SPACE = 2 ** PORT_LENGTH;
const INITIAL_PORT = 29170;
const NONCE_LENGTH = 128;
const COMMITMENT_LENGTH = 256;

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

class BrowserRandom extends BaseRandom {
    async randomFill(buffer, start, size) {
        const newBuffer = new Uint8Array(size);
        crypto.getRandomValues(newBuffer);
        for (let i = 0; i < size; i++) {
            buffer[start + i] = newBuffer[i];
        }
    }
}
const random = new BrowserRandom();

const NODE_TO_BROWSER_CIPHER_ALGORITHMS = {
    'aes-256-gcm': {
        name: 'AES-GCM',
        tagLength: 16 * 8
    }
};
class Cipher extends BaseCipher {
    async encrypt(message) {
        const iv = new Uint8Array(12);
        await random.randomFill(iv, 0, iv.length);
        const alg = NODE_TO_BROWSER_CIPHER_ALGORITHMS[this.algorithm];
        const cryptoKey = await crypto.subtle.importKey('raw', this.key, alg, false, ['encrypt']);
        const ciphertext = await crypto.subtle.encrypt({
            ...alg,
            iv
        }, cryptoKey, message);
        const buffers = [];
        buffers.push(iv);
        buffers.push(new Uint8Array(ciphertext));
        return bufferUtils.join(...buffers);
    }
    async decrypt(cryptosecuence) {
        const sizes = [];
        switch (this.algorithm) {
            case 'aes-256-gcm':
                sizes[0] = 12;
                break;
        }
        sizes[1] = cryptosecuence.length - sizes[0];
        const [iv, ciphertext] = bufferUtils.split(cryptosecuence, ...sizes);
        const alg = NODE_TO_BROWSER_CIPHER_ALGORITHMS[this.algorithm];
        const cryptoKey = await crypto.subtle.importKey('raw', this.key, alg, false, ['decrypt']);
        const message = await crypto.subtle.decrypt({
            ...alg,
            iv
        }, cryptoKey, ciphertext);
        return new Uint8Array(message);
    }
}

class ECDH extends BaseECDH {
    async generateKeys() {
        this.keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    }
    async getPublicKey() {
        if (this.keys === undefined || this.keys.publicKey === undefined) {
            throw new Error('keys must be initialized fist');
        }
        const publicKey = await crypto.subtle.exportKey('raw', this.keys.publicKey);
        return format.u8Arr2Hex(new Uint8Array(publicKey));
    }
    async deriveBits(publicKeyHex) {
        if (this.keys === undefined || this.keys.privateKey === undefined) {
            throw new Error('keys must be generated first');
        }
        const publicKeyBuffer = format.hex2U8Arr(publicKeyHex);
        const publicKey = await crypto.subtle.importKey('raw', publicKeyBuffer, {
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, []);
        const secret = await crypto.subtle.deriveBits({
            name: 'ECDH',
            public: publicKey
        }, this.keys.privateKey, 256);
        return new Uint8Array(secret);
    }
}

const NODE_TO_BROWSER_HASH_ALGORITHMS = {
    sha256: 'SHA-256'
};
class BrowserDigest extends BaseDigest {
    async digest(algorithm, input) {
        const browserAlgorithm = NODE_TO_BROWSER_HASH_ALGORITHMS[algorithm];
        const buffer = await crypto.subtle.digest(browserAlgorithm, input);
        return new Uint8Array(buffer);
    }
}
const digest = new BrowserDigest();

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
        return base64.encode(arr, true, false);
    },
    base642U8Arr: (b64) => {
        return base64.decode(b64, false);
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
    const salt = new Uint8Array(16);
    const pbkdf2Input = new Uint8Array(32 * 3);
    const fromBuffer = format.hex2U8Arr(from);
    const toBuffer = format.hex2U8Arr(to);
    bufferUtils.insertBytes(secret, pbkdf2Input, 0, 0, 32);
    bufferUtils.insertBytes(fromBuffer, pbkdf2Input, 0, 32, 32);
    bufferUtils.insertBytes(toBuffer, pbkdf2Input, 0, 32 * 2, 32);
    const derivatedSecret = await pbkdf2Hmac(pbkdf2Input, salt, 1, 32);
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
        return await objectSha.digest(this.from);
    }
    async toHash() {
        return await objectSha.digest(this.to);
    }
    static async fromSecret(port, from, to, na, nb, secret) {
        const fromHash = await objectSha.digest(from);
        const toHash = await objectSha.digest(to);
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
        bufferUtils.insertBytes(pka, input, 1, 0, 32);
        bufferUtils.insertBytes(pkb, input, 1, 32, 32);
        bufferUtils.insertBits(nx, input, 0, 2 * 32 * 8, constants.NONCE_LENGTH);
        bufferUtils.insertBits(r, input, 0, 2 * 32 * 8 + constants.NONCE_LENGTH, constants.DEFAULT_RANDOM_LENGTH);
        const hash = await digest.digest('sha256', input);
        return hash;
    }
    async validateAuthData(fullPkeData, fullAuthData) {
        const { cx: receivedCx, nx: receivedNx } = fullAuthData.received;
        const { cx: sentCx, nx: sentNx, r } = fullAuthData.sent;
        const validLengths = receivedCx.length === sentCx.length &&
            receivedNx.length === sentNx.length;
        if (!validLengths) {
            throw new Error('invalid received auth data length');
        }
        const equalCx = receivedCx.every((byte, i) => byte === sentCx[i]);
        if (equalCx) {
            throw new Error('received and sent Cx are the same');
        }
        const expectedCx = await this.computeCx(fullPkeData, receivedNx, r);
        const validCx = expectedCx.every((byte, i) => byte === receivedCx[i]);
        if (!validCx) {
            throw new Error('received a wrong Cx');
        }
    }
    async computeMasterKey(ecdh, fullPkeData, fullAuthData) {
        const nLen = Math.ceil(constants.NONCE_LENGTH / 8);
        const sharedSecret = await ecdh.deriveBits(fullPkeData.received.publicKey);
        const salt = new Uint8Array(16);
        const secretWithContext = new Uint8Array(32 + 2 * nLen + 6 + 32 * 2);
        const masterContext = new Uint8Array([109, 97, 115, 116, 101, 114]);
        const aHash = await objectSha.digest(fullPkeData.a, 'SHA-256');
        const aHashBuffer = format.hex2U8Arr(aHash);
        const bHash = await objectSha.digest(fullPkeData.b, 'SHA-256');
        const bHashBuffer = format.hex2U8Arr(bHash);
        bufferUtils.insertBytes(sharedSecret, secretWithContext, 0, 0, 32);
        bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32, nLen);
        bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32 + nLen, nLen);
        bufferUtils.insertBytes(masterContext, secretWithContext, 0, 32 + 2 * nLen, 6);
        bufferUtils.insertBytes(aHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6, 32);
        bufferUtils.insertBytes(bHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6 + 32, 32);
        const secret = await pbkdf2Hmac(secretWithContext, salt, 1, 32);
        const masterKey = await MasterKey.fromSecret(fullPkeData.port, fullPkeData.sent.id, fullPkeData.received.id, fullAuthData.a.nx, fullAuthData.b.nx, new Uint8Array(secret));
        return masterKey;
    }
    async run() {
        const _run = async () => {
            const ecdh = new ECDH();
            await ecdh.generateKeys();
            const publicKey = await ecdh.getPublicKey();
            const pkeData = await this.transport.prepare(this, publicKey);
            const fullPkeData = await this.transport.publicKeyExchange(this, pkeData);
            const r = await this.computeR(fullPkeData.a.rx, fullPkeData.b.rx);
            const nx = await this.computeNx();
            const cx = await this.computeCx(fullPkeData, nx, r);
            const authData = { r, nx, cx };
            const fullAuthData = await this.transport.authentication(this, authData);
            await this.validateAuthData(fullPkeData, fullAuthData);
            const masterKey = await this.computeMasterKey(ecdh, fullPkeData, fullAuthData);
            const code = await this.transport.verification(this, masterKey);
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
            host: opts.host ?? '::1',
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

function checkIfIPv6(str) {
    const regexExp = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi;
    return regexExp.test(str);
}
class HttpInitiatorTransport extends InitiatorTransport {
    async baseSend(port, httpReq) {
        {
            const host = checkIfIPv6(this.opts.host) ? `[${this.opts.host}]` : this.opts.host;
            const rpcUrl = `http://${host}:${port}/${constants.RPC_URL_PATH}`;
            const resp = await fetch(rpcUrl, httpReq);
            const body = await resp.text();
            return {
                status: resp.status,
                body
            };
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

export { BaseTransport, ConnectionString, HttpInitiatorTransport, HttpResponderTransport, MasterKey, Session, WalletProtocol, constants, defaultCodeGenerator };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC90cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzL3Byb3RvY29sLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9odHRwLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9pbmRleC50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vdHlwZXMudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2Jyb3dzZXIvcmFuZG9tLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9icm93c2VyL2NpcGhlci50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vYnJvd3Nlci9lY2RoLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9icm93c2VyL2RpZ2VzdC50cyIsIi4uLy4uL3NyYy90cy91dGlsL2Zvcm1hdC50cyIsIi4uLy4uL3NyYy90cy91dGlsL2J1ZmZlci50cyIsIi4uLy4uL3NyYy90cy9zdWJqZWN0LnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2V2ZW50LWVtaXR0ZXIudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvbWFzdGVyLWtleS50cyIsIi4uLy4uL3NyYy90cy9wcm90b2NvbC9zZXNzaW9uLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL3Byb3RvY29sLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2Nvbm5lY3Rpb24tc3RyaW5nLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2NvZGUtZ2VuZXJhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9pbml0aWF0b3ItdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtaW5pdGlhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9yZXNwb25kZXItdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9yZXNwb25zZS50cyIsIi4uLy4uL3NyYy90cy90cmFuc3BvcnQvaHR0cC9odHRwLXJlc3BvbnNlLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtcmVzcG9uZGVyLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O01BY3NCLGFBQWEsQ0FBQTtBQU9qQyxJQUFBLE1BQU0sSUFBSSxDQUFFLFNBQW9CLEVBQUUsSUFBZ0IsRUFBRSxHQUFRLEVBQUE7QUFDMUQsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHFDQUFxQyxDQUFDLENBQUE7S0FDdkQ7QUFFRCxJQUFBLE1BQU0sQ0FBRSxRQUF3QixFQUFBO0FBQzlCLFFBQUEsUUFBUSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtLQUMxQjtBQUNGOztBQzNCTSxNQUFNLFdBQVcsR0FBRyxFQUFFLENBQUE7QUFDdEIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUE7QUFDaEMsTUFBTSxlQUFlLEdBQUcsS0FBSyxDQUFBO0FBQzdCLE1BQU0sVUFBVSxHQUFHLENBQUMsSUFBSSxXQUFXLENBQUE7QUFDbkMsTUFBTSxZQUFZLEdBQUcsS0FBSyxDQUFBO0FBRTFCLE1BQU0sWUFBWSxHQUFHLEdBQUcsQ0FBQTtBQUN4QixNQUFNLGlCQUFpQixHQUFHLEdBQUc7Ozs7Ozs7Ozs7Ozs7QUNQN0IsTUFBTSxZQUFZLEdBQUcsNkJBQTZCOzs7Ozs7O0FDRXpELGdCQUFlO0FBQ2IsSUFBQSxHQUFHLGlCQUFpQjtBQUNwQixJQUFBLEdBQUcsYUFBYTtDQUNqQjs7TUNKWSxRQUFRLENBQUE7QUFDbkIsSUFBQSxNQUFNLFlBQVksR0FBQTtBQUNoQixRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztBQUVELElBQUEsTUFBTSxZQUFZLEdBQUE7QUFDaEIsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7SUFFRCxNQUFNLFVBQVUsQ0FBRSxZQUFvQixFQUFBO0FBQ3BDLFFBQUEsTUFB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
