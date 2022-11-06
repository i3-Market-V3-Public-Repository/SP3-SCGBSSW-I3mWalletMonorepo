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
                sizes[0] = 12; // IV Size
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
        const aHash = await objectSha.digest(fullPkeData.a, 'SHA-256');
        const aHashBuffer = format.hex2U8Arr(aHash);
        const bHash = await objectSha.digest(fullPkeData.b, 'SHA-256');
        const bHashBuffer = format.hex2U8Arr(bHash);
        // Prepare input
        bufferUtils.insertBytes(sharedSecret, secretWithContext, 0, 0, 32);
        bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32, nLen);
        bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32 + nLen, nLen);
        bufferUtils.insertBytes(masterContext, secretWithContext, 0, 32 + 2 * nLen, 6);
        bufferUtils.insertBytes(aHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6, 32);
        bufferUtils.insertBytes(bHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6 + 32, 32);
        // Compute master key
        const secret = await pbkdf2Hmac(secretWithContext, salt, 1, 32);
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
            const rpcUrl = this.buildRpcUrl(port);
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

export { BaseTransport, ConnectionString, HttpInitiatorTransport, HttpResponderTransport, MasterKey, Session, WalletProtocol, constants, defaultCodeGenerator };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXNtLmpzIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L3RyYW5zcG9ydC50cyIsIi4uLy4uL3NyYy90cy9jb25zdGFudHMvcHJvdG9jb2wudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzL2h0dHAudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzL2luZGV4LnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by90eXBlcy50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vYnJvd3Nlci9yYW5kb20udHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2Jyb3dzZXIvY2lwaGVyLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9icm93c2VyL2VjZGgudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2Jyb3dzZXIvZGlnZXN0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWwvZm9ybWF0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWwvYnVmZmVyLnRzIiwiLi4vLi4vc3JjL3RzL3N1YmplY3QudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvZXZlbnQtZW1pdHRlci50cyIsIi4uLy4uL3NyYy90cy9wcm90b2NvbC9tYXN0ZXIta2V5LnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL3Nlc3Npb24udHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvcHJvdG9jb2wudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvY29ubmVjdGlvbi1zdHJpbmcudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvY29kZS1nZW5lcmF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L2luaXRpYXRvci10cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L2h0dHAvaHR0cC1pbml0aWF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L3Jlc3BvbmRlci10cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L3Jlc3BvbnNlLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtcmVzcG9uc2UudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L2h0dHAvaHR0cC1yZXNwb25kZXIudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7TUFjc0IsYUFBYSxDQUFBO0FBT2pDLElBQUEsTUFBTSxJQUFJLENBQUUsU0FBb0IsRUFBRSxJQUFnQixFQUFFLEdBQVEsRUFBQTtBQUMxRCxRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMscUNBQXFDLENBQUMsQ0FBQTtLQUN2RDtBQUVELElBQUEsTUFBTSxDQUFFLFFBQXdCLEVBQUE7QUFDOUIsUUFBQSxRQUFRLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFBO0tBQzFCO0FBQ0Y7O0FDM0JNLE1BQU0sV0FBVyxHQUFHLEVBQUUsQ0FBQTtBQUN0QixNQUFNLHFCQUFxQixHQUFHLEVBQUUsQ0FBQTtBQUNoQyxNQUFNLGVBQWUsR0FBRyxLQUFLLENBQUE7QUFDN0IsTUFBTSxVQUFVLEdBQUcsQ0FBQyxJQUFJLFdBQVcsQ0FBQTtBQUNuQyxNQUFNLFlBQVksR0FBRyxLQUFLLENBQUE7QUFFMUIsTUFBTSxZQUFZLEdBQUcsR0FBRyxDQUFBO0FBQ3hCLE1BQU0saUJBQWlCLEdBQUcsR0FBRyxDQUFBOzs7Ozs7Ozs7Ozs7O0FDUDdCLE1BQU0sWUFBWSxHQUFHLDZCQUE2Qjs7Ozs7OztBQ0V6RCxnQkFBZTtBQUNiLElBQUEsR0FBRyxpQkFBaUI7QUFDcEIsSUFBQSxHQUFHLGFBQWE7Q0FDakI7O01DSlksUUFBUSxDQUFBO0FBQ25CLElBQUEsTUFBTSxZQUFZLEdBQUE7QUFDaEIsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7QUFFRCxJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0lBRUQsTUFBTSxVQUFVLENBQUUsWUFBb0IsRUFBQTtBQUNwQyxRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztBQUNGLENBQUE7TUFFWSxVQUFVLENBQUE7QUFDckIsSUFBQSxNQUFNLFVBQVUsQ0FBRSxNQUFrQixFQUFFLEtBQWEsRUFBRSxJQUFZLEVBQUE7QUFDL0QsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7QUFFRCxJQUFBLE1BQU0sY0FBYyxDQUFFLE1BQWtCLEVBQUUsS0FBYSxFQUFFLElBQVksRUFBQTtRQUNuRSxNQUFNLE9BQU8sR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUNuQyxRQUFBLE1BQU0sV0FBVyxHQUFHLElBQUksVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFBO1FBQzNDLE1BQU0sSUFBSSxDQUFDLFVBQVUsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxDQUFBO0FBQzlDLFFBQUEsV0FBVyxDQUFDLFVBQVUsQ0FBQyxXQUFXLEVBQUUsTUFBTSxFQUFFLENBQUMsRUFBRSxLQUFLLEVBQUUsSUFBSSxDQUFDLENBQUE7S0FDNUQ7QUFDRixDQUFBO01BR1ksVUFBVSxDQUFBO0lBQ3JCLFdBQ2tCLENBQUEsU0FBMkIsRUFDM0IsR0FBZSxFQUFBO1FBRGYsSUFBUyxDQUFBLFNBQUEsR0FBVCxTQUFTLENBQWtCO1FBQzNCLElBQUcsQ0FBQSxHQUFBLEdBQUgsR0FBRyxDQUFZO0tBQzVCO0lBRUwsTUFBTSxPQUFPLENBQUUsT0FBbUIsRUFBQTtBQUNoQyxRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztJQUVELE1BQU0sT0FBTyxDQUFFLFVBQXNCLEVBQUE7QUFDbkMsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7QUFDRixDQUFBO01BSVksVUFBVSxDQUFBO0FBQ3JCLElBQUEsTUFBTSxNQUFNLENBQUUsU0FBeUIsRUFBRSxLQUFpQixFQUFBO0FBQ3hELFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0FBQ0Y7O0FDakRELE1BQU0sYUFBYyxTQUFRLFVBQVUsQ0FBQTtBQUNwQyxJQUFBLE1BQU0sVUFBVSxDQUFFLE1BQWtCLEVBQUUsS0FBYSxFQUFFLElBQVksRUFBQTtBQUMvRCxRQUFBLE1BQU0sU0FBUyxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFBO0FBQ3RDLFFBQUEsTUFBTSxDQUFDLGVBQWUsQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUNqQyxLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsSUFBSSxFQUFFLENBQUMsRUFBRSxFQUFFO1lBQzdCLE1BQU0sQ0FBQyxLQUFLLEdBQUcsQ0FBQyxDQUFDLEdBQUcsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQ2pDLFNBQUE7S0FDRjtBQUNGLENBQUE7QUFDTSxNQUFNLE1BQU0sR0FBZSxJQUFJLGFBQWEsRUFBRTs7QUNGckQsTUFBTSxpQ0FBaUMsR0FBcUQ7QUFDMUYsSUFBQSxhQUFhLEVBQUU7QUFDYixRQUFBLElBQUksRUFBRSxTQUFTO1FBQ2YsU0FBUyxFQUFFLEVBQUUsR0FBRyxDQUFDO0FBQ2xCLEtBQUE7Q0FDRixDQUFBO0FBRUssTUFBTyxNQUFPLFNBQVEsVUFBVSxDQUFBO0lBQ3BDLE1BQU0sT0FBTyxDQUFFLE9BQW1CLEVBQUE7QUFDaEMsUUFBQSxNQUFNLEVBQUUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxFQUFFLENBQUMsQ0FBQTtBQUM3QixRQUFBLE1BQU0sTUFBTSxDQUFDLFVBQVUsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUV6QyxNQUFNLEdBQUcsR0FBRyxpQ0FBaUMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUE7UUFDN0QsTUFBTSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FDN0MsS0FBSyxFQUNMLElBQUksQ0FBQyxHQUFHLEVBQ1IsR0FBRyxFQUNILEtBQUssRUFDTCxDQUFDLFNBQVMsQ0FBQyxDQUNaLENBQUE7UUFFRCxNQUFNLFVBQVUsR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO0FBQzdDLFlBQUEsR0FBRyxHQUFHO1lBQ04sRUFBRTtBQUNILFNBQUEsRUFBRSxTQUFTLEVBQUUsT0FBTyxDQUFDLENBQUE7UUFFdEIsTUFBTSxPQUFPLEdBQWlCLEVBQUUsQ0FBQTtBQUNoQyxRQUFBLE9BQU8sQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUE7UUFDaEIsT0FBTyxDQUFDLElBQUksQ0FBQyxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFBO0FBRXhDLFFBQUEsT0FBTyxXQUFXLENBQUMsSUFBSSxDQUFDLEdBQUcsT0FBTyxDQUFDLENBQUE7S0FDcEM7SUFFRCxNQUFNLE9BQU8sQ0FBRSxjQUEwQixFQUFBO1FBQ3ZDLE1BQU0sS0FBSyxHQUFhLEVBQUUsQ0FBQTtRQUMxQixRQUFRLElBQUksQ0FBQyxTQUFTO0FBQ3BCLFlBQUEsS0FBSyxhQUFhO0FBQ2hCLGdCQUFBLEtBQUssQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUE7Z0JBQ2IsTUFBSztBQUNSLFNBQUE7QUFDRCxRQUFBLEtBQUssQ0FBQyxDQUFDLENBQUMsR0FBRyxjQUFjLENBQUMsTUFBTSxHQUFHLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUMzQyxRQUFBLE1BQU0sQ0FBQyxFQUFFLEVBQUUsVUFBVSxDQUFDLEdBQUcsV0FBVyxDQUFDLEtBQUssQ0FBQyxjQUFjLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQTtRQUVwRSxNQUFNLEdBQUcsR0FBRyxpQ0FBaUMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUE7UUFDN0QsTUFBTSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FDN0MsS0FBSyxFQUNMLElBQUksQ0FBQyxHQUFHLEVBQ1IsR0FBRyxFQUNILEtBQUssRUFDTCxDQUFDLFNBQVMsQ0FBQyxDQUNaLENBQUE7UUFFRCxNQUFNLE9BQU8sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO0FBQzFDLFlBQUEsR0FBRyxHQUFHO1lBQ04sRUFBRTtBQUNILFNBQUEsRUFBRSxTQUFTLEVBQUUsVUFBVSxDQUFDLENBQUE7QUFFekIsUUFBQSxPQUFPLElBQUksVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFBO0tBQy9CO0FBQ0Y7O0FDakVLLE1BQU8sSUFBSyxTQUFRLFFBQVEsQ0FBQTtBQUdoQyxJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsSUFBSSxDQUFDLElBQUksR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUFDLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxVQUFVLEVBQUUsT0FBTyxFQUFFLEVBQUUsSUFBSSxFQUFFLENBQUMsV0FBVyxFQUFFLFlBQVksQ0FBQyxDQUFDLENBQUE7S0FDdEg7QUFFRCxJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsSUFBSSxJQUFJLENBQUMsSUFBSSxLQUFLLFNBQVMsSUFBSSxJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsS0FBSyxTQUFTLEVBQUU7QUFDaEUsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLCtCQUErQixDQUFDLENBQUE7QUFDakQsU0FBQTtBQUVELFFBQUEsTUFBTSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxLQUFLLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUMzRSxPQUFPLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxVQUFVLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQTtLQUNuRDtJQUVELE1BQU0sVUFBVSxDQUFFLFlBQW9CLEVBQUE7QUFDcEMsUUFBQSxJQUFJLElBQUksQ0FBQyxJQUFJLEtBQUssU0FBUyxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsVUFBVSxLQUFLLFNBQVMsRUFBRTtBQUNqRSxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsOEJBQThCLENBQUMsQ0FBQTtBQUNoRCxTQUFBO1FBRUQsTUFBTSxlQUFlLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQUN0RCxRQUFBLE1BQU0sU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQzdDLEtBQUssRUFBRSxlQUFlLEVBQUU7QUFDdEIsWUFBQSxJQUFJLEVBQUUsTUFBTTtBQUNaLFlBQUEsVUFBVSxFQUFFLE9BQU87QUFDcEIsU0FBQSxFQUFFLElBQUksRUFBRSxFQUFFLENBQ1osQ0FBQTtRQUVELE1BQU0sTUFBTSxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUM7QUFDNUMsWUFBQSxJQUFJLEVBQUUsTUFBTTtBQUNaLFlBQUEsTUFBTSxFQUFFLFNBQVM7U0FDbEIsRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLFVBQVUsRUFBRSxHQUFHLENBQUMsQ0FBQTtBQUU3QixRQUFBLE9BQU8sSUFBSSxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUE7S0FDOUI7QUFDRjs7QUNyQ0QsTUFBTSwrQkFBK0IsR0FBbUM7QUFDdEUsSUFBQSxNQUFNLEVBQUUsU0FBUztDQUNsQixDQUFBO0FBRUQsTUFBTSxhQUFjLFNBQVEsVUFBVSxDQUFBO0FBQ3BDLElBQUEsTUFBTSxNQUFNLENBQUUsU0FBeUIsRUFBRSxLQUFpQixFQUFBO0FBQ3hELFFBQUEsTUFBTSxnQkFBZ0IsR0FBRywrQkFBK0IsQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUNuRSxRQUFBLE1BQU0sTUFBTSxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsZ0JBQWdCLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFFbEUsUUFBQSxPQUFPLElBQUksVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0tBQzlCO0FBQ0YsQ0FBQTtBQUNNLE1BQU0sTUFBTSxHQUFHLElBQUksYUFBYSxFQUFFOztBQ1psQyxNQUFNLE1BQU0sR0FBRztBQUNwQixJQUFBLFNBQVMsRUFBRSxDQUFDLElBQVksS0FBZ0I7UUFDdEMsT0FBTyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtLQUN0QztBQUVELElBQUEsU0FBUyxFQUFFLENBQUMsR0FBZSxLQUFZO1FBQ3JDLE9BQU8sSUFBSSxXQUFXLEVBQUUsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7S0FDckM7QUFFRCxJQUFBLFNBQVMsRUFBRSxDQUFDLEdBQVcsRUFBRSxHQUFZLEtBQWdCO1FBQ25ELElBQUksR0FBRyxLQUFLLFNBQVMsRUFBRTtZQUNyQixHQUFHLEdBQUcsQ0FBQyxDQUFBO1lBQ1AsT0FBTyxDQUFDLEtBQUssR0FBRyxHQUFHLENBQUMsQ0FBQyxHQUFHLEdBQUcsRUFBRTtBQUMzQixnQkFBQSxHQUFHLEVBQUUsQ0FBQTtBQUNOLGFBQUE7QUFDRixTQUFBO0FBQ0QsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUUvQixJQUFJLElBQUksR0FBRyxHQUFHLENBQUE7QUFDZCxRQUFBLEtBQUssSUFBSSxDQUFDLEdBQUcsR0FBRyxHQUFHLENBQUMsRUFBRSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFO0FBQ2pDLFlBQUEsTUFBTSxRQUFRLEdBQUcsSUFBSSxJQUFJLENBQUMsQ0FBQTtZQUMxQixNQUFNLEdBQUcsR0FBRyxJQUFJLElBQUksUUFBUSxJQUFJLENBQUMsQ0FBQyxDQUFBO0FBQ2xDLFlBQUEsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLEdBQUcsQ0FBQTtZQUVaLElBQUksR0FBRyxRQUFRLENBQUE7QUFDaEIsU0FBQTtBQUVELFFBQUEsT0FBTyxHQUFHLENBQUE7S0FDWDtBQUVELElBQUEsU0FBUyxFQUFFLENBQUMsTUFBa0IsS0FBWTtRQUN4QyxJQUFJLEdBQUcsR0FBRyxDQUFDLENBQUE7QUFDWCxRQUFBLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxNQUFNLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFO0FBQ3RDLFlBQUEsR0FBRyxJQUFJLE1BQU0sQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFBO0FBQzlDLFNBQUE7QUFFRCxRQUFBLE9BQU8sR0FBRyxDQUFBO0tBQ1g7QUFFRCxJQUFBLFNBQVMsRUFBRSxDQUFDLEdBQVcsS0FBZ0I7UUFDckMsTUFBTSxLQUFLLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUNsQyxJQUFJLEtBQUssS0FBSyxJQUFJLEVBQUU7QUFDbEIsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGNBQWMsR0FBRyxDQUFBLENBQUUsQ0FBQyxDQUFBO0FBQ3JDLFNBQUE7QUFFRCxRQUFBLE9BQU8sSUFBSSxVQUFVLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxJQUFJLElBQUksUUFBUSxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUE7S0FDN0Q7QUFFRCxJQUFBLFNBQVMsRUFBRSxDQUFDLEdBQWUsS0FBWTtBQUNyQyxRQUFBLE9BQU8sR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxJQUFJLEtBQUssR0FBRyxHQUFHLElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtLQUMvRTtBQUVELElBQUEsWUFBWSxFQUFFLENBQUMsR0FBZSxLQUFZO1FBQ3hDLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFBO0tBQ3ZDO0FBRUQsSUFBQSxZQUFZLEVBQUUsQ0FBQyxHQUFXLEtBQWdCO1FBQ3hDLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFlLENBQUE7S0FDL0M7Q0FDRjs7QUM3RE0sTUFBTSxXQUFXLEdBQUc7QUFDekIsSUFBQSxJQUFJLEVBQUUsQ0FBQyxHQUFHLElBQWtCLEtBQWdCO1FBQzFDLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQyxDQUFBO0FBQ25ELFFBQUEsTUFBTSxNQUFNLEdBQUcsSUFBSSxVQUFVLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDbkMsSUFBSSxNQUFNLEdBQUcsQ0FBQyxDQUFBO0FBQ2QsUUFBQSxLQUFLLE1BQU0sRUFBRSxJQUFJLElBQUksRUFBRTtBQUNyQixZQUFBLE1BQU0sQ0FBQyxHQUFHLENBQUMsRUFBRSxFQUFFLE1BQU0sQ0FBQyxDQUFBO0FBQ3RCLFlBQUEsTUFBTSxJQUFJLEVBQUUsQ0FBQyxNQUFNLENBQUE7QUFDcEIsU0FBQTtBQUVELFFBQUEsT0FBTyxNQUFNLENBQUE7S0FDZDtBQUVELElBQUEsS0FBSyxFQUFFLENBQUMsTUFBa0IsRUFBRSxHQUFHLEtBQWUsS0FBa0I7UUFDOUQsTUFBTSxJQUFJLEdBQWlCLEVBQUUsQ0FBQTtRQUM3QixJQUFJLEtBQUssR0FBRyxDQUFDLENBQUE7QUFDYixRQUFBLEtBQUssTUFBTSxJQUFJLElBQUksS0FBSyxFQUFFO0FBQ3hCLFlBQUEsSUFBSSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEtBQUssRUFBRSxLQUFLLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQTtZQUM1QyxLQUFLLElBQUksSUFBSSxDQUFBO0FBQ2QsU0FBQTtBQUVELFFBQUEsT0FBTyxJQUFJLENBQUE7S0FDWjtBQUVELElBQUEsV0FBVyxFQUFFLENBQUMsR0FBZSxFQUFFLEdBQWUsRUFBRSxTQUFpQixFQUFFLE9BQWUsRUFBRSxJQUFZLEtBQUk7UUFDbEcsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLElBQUksRUFBRSxDQUFDLEVBQUUsRUFBRTtBQUM3QixZQUFBLEdBQUcsQ0FBQyxDQUFDLEdBQUcsT0FBTyxDQUFDLEdBQUcsR0FBRyxDQUFDLENBQUMsR0FBRyxTQUFTLENBQUMsQ0FBQTtBQUN0QyxTQUFBO0tBQ0Y7QUFFRCxJQUFBLFVBQVUsRUFBRSxDQUFDLEdBQWUsRUFBRSxHQUFlLEVBQUUsU0FBaUIsRUFBRSxPQUFlLEVBQUUsSUFBWSxLQUFJO1FBQ2pHLElBQUksYUFBYSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsU0FBUyxHQUFHLENBQUMsQ0FBQyxDQUFBO0FBQzdDLFFBQUEsSUFBSSxZQUFZLEdBQUcsU0FBUyxHQUFHLENBQUMsQ0FBQTtRQUNoQyxJQUFJLFdBQVcsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUN6QyxRQUFBLElBQUksVUFBVSxHQUFHLE9BQU8sR0FBRyxDQUFDLENBQUE7UUFDNUIsSUFBSSxZQUFZLEdBQUcsR0FBRyxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUMxQyxRQUFBLE1BQU0sV0FBVyxHQUFHLFVBQVUsR0FBRyxZQUFZLENBQUE7UUFFN0MsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLElBQUksRUFBRSxDQUFDLEVBQUUsRUFBRTtBQUM3QixZQUFBLElBQUksT0FBZSxDQUFBO1lBQ25CLElBQUksV0FBVyxJQUFJLENBQUMsRUFBRTtBQUNwQixnQkFBQSxPQUFPLElBQUksQ0FBQyxZQUFZLElBQUksR0FBRyxJQUFJLFlBQVksQ0FBQyxLQUFLLFdBQVcsQ0FBQyxDQUFBO0FBQ2xFLGFBQUE7QUFBTSxpQkFBQTtBQUNMLGdCQUFBLE9BQU8sS0FBSyxZQUFZLElBQUksR0FBRyxJQUFJLFlBQVksQ0FBQyxFQUFFLENBQUE7QUFDbkQsYUFBQTtBQUVELFlBQUEsTUFBTSxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsV0FBVyxDQUFDLEdBQUcsRUFBRSxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksT0FBTyxDQUFDLENBQUE7QUFDcEUsWUFBQSxHQUFHLENBQUMsV0FBVyxDQUFDLEdBQUcsTUFBTSxDQUFBOztBQUd6QixZQUFBLFlBQVksRUFBRSxDQUFBO0FBQ2QsWUFBQSxVQUFVLEVBQUUsQ0FBQTtZQUNaLElBQUksWUFBWSxJQUFJLENBQUMsRUFBRTtBQUNyQixnQkFBQSxhQUFhLEVBQUUsQ0FBQTtnQkFDZixZQUFZLEdBQUcsQ0FBQyxDQUFBO0FBQ2hCLGdCQUFBLFlBQVksR0FBRyxHQUFHLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxDQUFBO0FBQ3ZDLGFBQUE7WUFDRCxJQUFJLFVBQVUsSUFBSSxDQUFDLEVBQUU7QUFDbkIsZ0JBQUEsV0FBVyxFQUFFLENBQUE7Z0JBQ2IsVUFBVSxHQUFHLENBQUMsQ0FBQTtBQUNmLGFBQUE7QUFDRixTQUFBO0tBQ0Y7SUFFRCxXQUFXLEVBQUUsQ0FBQyxHQUFlLEVBQUUsS0FBYSxFQUFFLElBQVksS0FBZ0I7UUFDeEUsTUFBTSxRQUFRLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDcEMsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUNwQyxRQUFBLFdBQVcsQ0FBQyxVQUFVLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsQ0FBQyxFQUFFLElBQUksQ0FBQyxDQUFBO0FBRWhELFFBQUEsT0FBTyxHQUFHLENBQUE7S0FDWDtDQUNGOztNQ3RFWSxPQUFPLENBQUE7QUFJbEIsSUFBQSxJQUFJLE9BQU8sR0FBQTtBQUNULFFBQUEsT0FBTyxJQUFJLENBQUMsYUFBYSxFQUFFLENBQUE7S0FDNUI7QUFFUyxJQUFBLE1BQU0sYUFBYSxHQUFBO1FBQzNCLE9BQU8sTUFBTSxJQUFJLE9BQU8sQ0FBSSxDQUFDLE9BQU8sRUFBRSxNQUFNLEtBQUk7QUFDOUMsWUFBQSxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQTtBQUN0QixZQUFBLElBQUksQ0FBQyxNQUFNLEdBQUcsTUFBTSxDQUFBO0FBQ3RCLFNBQUMsQ0FBQyxDQUFBO0tBQ0g7QUFFRCxJQUFBLElBQUksQ0FBRSxLQUFRLEVBQUE7QUFDWixRQUFBLElBQUksSUFBSSxDQUFDLE9BQU8sSUFBSSxJQUFJLEVBQUU7QUFDeEIsWUFBQSxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO0FBQ3BCLFNBQUE7S0FDRjtBQUVELElBQUEsR0FBRyxDQUFFLE1BQVcsRUFBQTtBQUNkLFFBQUEsSUFBSSxJQUFJLENBQUMsTUFBTSxJQUFJLElBQUksRUFBRTtBQUN2QixZQUFBLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUE7QUFDcEIsU0FBQTtLQUNGO0FBQ0Y7O01DMUJZLFlBQVksQ0FBQTtBQUd2QixJQUFBLFdBQUEsR0FBQTtBQUNFLFFBQUEsSUFBSSxDQUFDLE1BQU0sR0FBRyxFQUFFLENBQUE7S0FDakI7SUFFRCxFQUFFLENBQUUsS0FBYSxFQUFFLEVBQVksRUFBQTtRQUM3QixJQUFJLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEtBQUssU0FBUyxFQUFFO0FBQ3BDLFlBQUEsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsR0FBRyxFQUFFLENBQUE7QUFDeEIsU0FBQTtRQUVELElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxDQUFBO0FBQzNCLFFBQUEsT0FBTyxJQUFJLENBQUE7S0FDWjtBQUVELElBQUEsSUFBSSxDQUFFLEtBQWEsRUFBRSxHQUFHLElBQVMsRUFBQTtRQUMvQixNQUFNLFFBQVEsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ25DLElBQUksUUFBUSxLQUFLLFNBQVMsRUFBRTtBQUMxQixZQUFBLFFBQVEsQ0FBQyxPQUFPLENBQUMsT0FBTyxJQUFJLE9BQU8sQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDLENBQUE7QUFDN0MsWUFBQSxPQUFPLElBQUksQ0FBQTtBQUNaLFNBQUE7QUFDRCxRQUFBLE9BQU8sS0FBSyxDQUFBO0tBQ2I7QUFDRjs7QUNwQkQsTUFBTSxTQUFTLEdBQUcsT0FDaEIsSUFBWSxFQUFFLEVBQVUsRUFBRSxNQUFrQixLQUNyQjs7QUFFdkIsSUFBQSxNQUFNLElBQUksR0FBRyxJQUFJLFVBQVUsQ0FBQyxFQUFFLENBQUMsQ0FBQTtJQUMvQixNQUFNLFdBQVcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxDQUFDLENBQUE7SUFDMUMsTUFBTSxVQUFVLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQTtJQUN6QyxNQUFNLFFBQVEsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLEVBQUUsQ0FBQyxDQUFBOztBQUdyQyxJQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsTUFBTSxFQUFFLFdBQVcsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBQ3RELElBQUEsV0FBVyxDQUFDLFdBQVcsQ0FBQyxVQUFVLEVBQUUsV0FBVyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsRUFBRSxDQUFDLENBQUE7QUFDM0QsSUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLFFBQVEsRUFBRSxXQUFXLEVBQUUsQ0FBQyxFQUFFLEVBQUUsR0FBRyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUE7QUFFN0QsSUFBQSxNQUFNLGVBQWUsR0FBRyxNQUFNLFVBQVUsQ0FBQyxXQUFXLEVBQUUsSUFBSSxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUNsRSxJQUFBLE9BQU8sSUFBSSxVQUFVLENBQUMsZUFBZSxDQUFDLENBQUE7QUFDeEMsQ0FBQyxDQUFBO01BRVksU0FBUyxDQUFBO0FBSXBCLElBQUEsV0FBQSxDQUNrQixJQUFZLEVBQ1osSUFBYyxFQUNkLEVBQVksRUFDWixFQUFjLEVBQ2QsRUFBYyxFQUNwQixNQUFrQixFQUM1QixVQUFzQixFQUN0QixVQUFzQixFQUFBO1FBUE4sSUFBSSxDQUFBLElBQUEsR0FBSixJQUFJLENBQVE7UUFDWixJQUFJLENBQUEsSUFBQSxHQUFKLElBQUksQ0FBVTtRQUNkLElBQUUsQ0FBQSxFQUFBLEdBQUYsRUFBRSxDQUFVO1FBQ1osSUFBRSxDQUFBLEVBQUEsR0FBRixFQUFFLENBQVk7UUFDZCxJQUFFLENBQUEsRUFBQSxHQUFGLEVBQUUsQ0FBWTtRQUNwQixJQUFNLENBQUEsTUFBQSxHQUFOLE1BQU0sQ0FBWTtRQUk1QixJQUFJLENBQUMsTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxVQUFVLENBQUMsQ0FBQTtRQUNuRCxJQUFJLENBQUMsUUFBUSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxVQUFVLENBQUMsQ0FBQTtLQUN0RDtJQUVELE1BQU0sT0FBTyxDQUFFLE9BQW1CLEVBQUE7UUFDaEMsT0FBTyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0tBQzFDO0lBRUQsTUFBTSxPQUFPLENBQUUsVUFBc0IsRUFBQTtRQUNuQyxPQUFPLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7S0FDL0M7SUFFRCxNQUFNLEdBQUE7UUFDSixPQUFPO1lBQ0wsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJO1lBQ2YsRUFBRSxFQUFFLElBQUksQ0FBQyxFQUFFO1lBQ1gsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJO1lBQ2YsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQztZQUNoQyxFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDO1lBQ2hDLE1BQU0sRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUM7U0FDekMsQ0FBQTtLQUNGO0FBRUQsSUFBQSxNQUFNLFFBQVEsR0FBQTtRQUNaLE9BQU8sTUFBTSxTQUFTLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtLQUN6QztBQUVELElBQUEsTUFBTSxNQUFNLEdBQUE7UUFDVixPQUFPLE1BQU0sU0FBUyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUE7S0FDdkM7QUFFRCxJQUFBLGFBQWEsVUFBVSxDQUFFLElBQVksRUFBRSxJQUFjLEVBQUUsRUFBWSxFQUFFLEVBQWMsRUFBRSxFQUFjLEVBQUUsTUFBa0IsRUFBQTtRQUNySCxNQUFNLFFBQVEsR0FBRyxNQUFNLFNBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDN0MsTUFBTSxNQUFNLEdBQUcsTUFBTSxTQUFTLENBQUMsTUFBTSxDQUFDLEVBQUUsQ0FBQyxDQUFBO1FBRXpDLE1BQU0sVUFBVSxHQUFHLE1BQU0sU0FBUyxDQUFDLFFBQVEsRUFBRSxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUE7UUFDNUQsTUFBTSxVQUFVLEdBQUcsTUFBTSxTQUFTLENBQUMsTUFBTSxFQUFFLFFBQVEsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUU1RCxRQUFBLE9BQU8sSUFBSSxTQUFTLENBQUMsSUFBSSxFQUFFLElBQUksRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxNQUFNLEVBQUUsVUFBVSxFQUFFLFVBQVUsQ0FBQyxDQUFBO0tBQzdFO0FBRUQsSUFBQSxhQUFhLFFBQVEsQ0FBRSxJQUFTLEVBQUE7UUFDOUIsTUFBTSxFQUFFLEdBQUcsTUFBTSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUE7UUFDdkMsTUFBTSxFQUFFLEdBQUcsTUFBTSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUE7UUFDdkMsTUFBTSxNQUFNLEdBQUcsTUFBTSxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUE7UUFFL0MsT0FBTyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxNQUFNLENBQUMsQ0FBQTtLQUM1RTtBQUNGOztNQ2xGWSxPQUFPLENBQUE7QUFDbEIsSUFBQSxXQUFBLENBQXVCLFNBQVksRUFBWSxTQUFvQixFQUFZLElBQWdCLEVBQUE7UUFBeEUsSUFBUyxDQUFBLFNBQUEsR0FBVCxTQUFTLENBQUc7UUFBWSxJQUFTLENBQUEsU0FBQSxHQUFULFNBQVMsQ0FBVztRQUFZLElBQUksQ0FBQSxJQUFBLEdBQUosSUFBSSxDQUFZO0tBQUk7SUFFbkcsTUFBTSxJQUFJLENBQUUsT0FBNEIsRUFBQTtBQUN0QyxRQUFBLE9BQU8sTUFBTSxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxFQUFFLElBQUksQ0FBQyxJQUFJLEVBQUUsT0FBTyxDQUFDLENBQUE7S0FDckU7SUFFRCxNQUFNLEdBQUE7UUFDSixPQUFPO0FBQ0wsWUFBQSxTQUFTLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLEVBQUU7WUFDbEMsSUFBSSxFQUFFLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQztTQUNsQyxDQUFBO0tBQ0Y7QUFJRCxJQUFBLGFBQWEsUUFBUSxDQUF1QixzQkFBeUMsRUFBRSxJQUFTLEVBQUE7UUFDOUYsTUFBTSxTQUFTLEdBQUcsTUFBTSxTQUFTLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUMxRCxNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUN4QyxRQUFBLElBQUksU0FBWSxDQUFBO0FBQ2hCLFFBQUEsSUFBSSxPQUFPLHNCQUFzQixLQUFLLFFBQVEsRUFBRTtZQUM5QyxTQUFTLEdBQUcsc0JBQXNCLENBQUE7QUFDbkMsU0FBQTthQUFNLElBQUksc0JBQXNCLFlBQVksUUFBUSxFQUFFO0FBQ3JELFlBQUEsU0FBUyxHQUFHLElBQUksc0JBQXNCLEVBQUUsQ0FBQTtBQUN6QyxTQUFBO0FBQU0sYUFBQTtBQUNMLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQywyREFBMkQsQ0FBQyxDQUFBO0FBQzdFLFNBQUE7UUFFRCxPQUFPLElBQUksT0FBTyxDQUFDLFNBQVMsRUFBRSxTQUFTLEVBQUUsSUFBSSxDQUFDLENBQUE7S0FDL0M7QUFDRjs7QUNmSyxNQUFPLGNBQWdELFNBQVEsWUFBWSxDQUFBO0FBQy9FLElBQUEsV0FBQSxDQUFvQixTQUFZLEVBQUE7QUFDOUIsUUFBQSxLQUFLLEVBQUUsQ0FBQTtRQURXLElBQVMsQ0FBQSxTQUFBLEdBQVQsU0FBUyxDQUFHO0tBRS9CO0FBRUQsSUFBQSxNQUFNLFFBQVEsQ0FBRSxFQUFjLEVBQUUsRUFBYyxFQUFBO0FBQzVDLFFBQUEsT0FBTyxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsS0FBSyxHQUFHLEdBQUcsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7S0FDdkM7QUFFRCxJQUFBLE1BQU0sU0FBUyxHQUFBO0FBQ2IsUUFBQSxNQUFNLElBQUksR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxZQUFZLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDbEQsUUFBQSxNQUFNLEVBQUUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUUvQixRQUFBLE1BQU0sTUFBTSxDQUFDLGNBQWMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQUMxRCxRQUFBLE9BQU8sRUFBRSxDQUFBO0tBQ1Y7QUFFRCxJQUFBLE1BQU0sU0FBUyxDQUFFLE9BQXdCLEVBQUUsRUFBYyxFQUFFLENBQWEsRUFBQTtBQUN0RSxRQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFlBQVksR0FBRyxDQUFDLENBQUMsQ0FBQTtBQUNsRCxRQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLHFCQUFxQixHQUFHLENBQUMsQ0FBQyxDQUFBO0FBQzNELFFBQUEsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0FBQ2pELFFBQUEsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxDQUFBO1FBRWpELE1BQU0sUUFBUSxHQUFHLENBQUMsR0FBRyxFQUFFLEdBQUcsSUFBSSxHQUFHLElBQUksQ0FBQTtBQUNyQyxRQUFBLE1BQU0sS0FBSyxHQUFHLElBQUksVUFBVSxDQUFDLFFBQVEsQ0FBQyxDQUFBOzs7QUFJdEMsUUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLEdBQUcsRUFBRSxLQUFLLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUM3QyxRQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsR0FBRyxFQUFFLEtBQUssRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBQzlDLFFBQUEsV0FBVyxDQUFDLFVBQVUsQ0FBQyxFQUFFLEVBQUUsS0FBSyxFQUFFLENBQUMsRUFBRSxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsRUFBRSxTQUFTLENBQUMsWUFBWSxDQUFDLENBQUE7UUFDeEUsV0FBVyxDQUFDLFVBQVUsQ0FBQyxDQUFDLEVBQUUsS0FBSyxFQUFFLENBQUMsRUFBRSxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsR0FBRyxTQUFTLENBQUMsWUFBWSxFQUFFLFNBQVMsQ0FBQyxxQkFBcUIsQ0FBQyxDQUFBOztRQUd6RyxNQUFNLElBQUksR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUFFLEtBQUssQ0FBQyxDQUFBO0FBQ2pELFFBQUEsT0FBTyxJQUFJLENBQUE7S0FDWjtBQUVELElBQUEsTUFBTSxnQkFBZ0IsQ0FBRSxXQUE0QixFQUFFLFlBQThCLEVBQUE7QUFDbEYsUUFBQSxNQUFNLEVBQUUsRUFBRSxFQUFFLFVBQVUsRUFBRSxFQUFFLEVBQUUsVUFBVSxFQUFFLEdBQUcsWUFBWSxDQUFDLFFBQVEsQ0FBQTtBQUNoRSxRQUFBLE1BQU0sRUFBRSxFQUFFLEVBQUUsTUFBTSxFQUFFLEVBQUUsRUFBRSxNQUFNLEVBQUUsQ0FBQyxFQUFFLEdBQUcsWUFBWSxDQUFDLElBQUksQ0FBQTs7UUFHdkQsTUFBTSxZQUFZLEdBQUcsVUFBVSxDQUFDLE1BQU0sS0FBSyxNQUFNLENBQUMsTUFBTTtBQUN0RCxZQUFBLFVBQVUsQ0FBQyxNQUFNLEtBQUssTUFBTSxDQUFDLE1BQU0sQ0FBQTtRQUNyQyxJQUFJLENBQUMsWUFBWSxFQUFFO0FBQ2pCLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxtQ0FBbUMsQ0FBQyxDQUFBO0FBQ3JELFNBQUE7O1FBR0QsTUFBTSxPQUFPLEdBQUcsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLElBQUksRUFBRSxDQUFDLEtBQUssSUFBSSxLQUFLLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQ2pFLFFBQUEsSUFBSSxPQUFPLEVBQUU7QUFDWCxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsbUNBQW1DLENBQUMsQ0FBQTtBQUNyRCxTQUFBOztBQUdELFFBQUEsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsU0FBUyxDQUFDLFdBQVcsRUFBRSxVQUFVLEVBQUUsQ0FBQyxDQUFDLENBQUE7UUFDbkUsTUFBTSxPQUFPLEdBQUcsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLElBQUksRUFBRSxDQUFDLEtBQUssSUFBSSxLQUFLLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO1FBQ3JFLElBQUksQ0FBQyxPQUFPLEVBQUU7QUFDWixZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLENBQUMsQ0FBQTtBQUN2QyxTQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0sZ0JBQWdCLENBQUUsSUFBVSxFQUFFLFdBQTRCLEVBQUUsWUFBOEIsRUFBQTtBQUM5RixRQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFlBQVksR0FBRyxDQUFDLENBQUMsQ0FBQTs7QUFHbEQsUUFBQSxNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsV0FBVyxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUMxRSxRQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksVUFBVSxDQUFDLEVBQUUsQ0FBQyxDQUFBO0FBQy9CLFFBQUEsTUFBTSxpQkFBaUIsR0FBRyxJQUFJLFVBQVUsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLElBQUksR0FBRyxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFBO1FBQ3BFLE1BQU0sYUFBYSxHQUFHLElBQUksVUFBVSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFBO0FBQ25FLFFBQUEsTUFBTSxLQUFLLEdBQUcsTUFBTSxTQUFTLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUE7UUFDOUQsTUFBTSxXQUFXLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxLQUFLLENBQUMsQ0FBQTtBQUMzQyxRQUFBLE1BQU0sS0FBSyxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFBO1FBQzlELE1BQU0sV0FBVyxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUE7O0FBRzNDLFFBQUEsV0FBVyxDQUFDLFdBQVcsQ0FBQyxZQUFZLEVBQUUsaUJBQWlCLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUNsRSxRQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsaUJBQWlCLEVBQUUsQ0FBQyxFQUFFLEVBQUUsRUFBRSxJQUFJLENBQUMsQ0FBQTtBQUMxRSxRQUFBLFdBQVcsQ0FBQyxXQUFXLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsaUJBQWlCLEVBQUUsQ0FBQyxFQUFFLEVBQUUsR0FBRyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUE7QUFDakYsUUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLGFBQWEsRUFBRSxpQkFBaUIsRUFBRSxDQUFDLEVBQUUsRUFBRSxHQUFHLENBQUMsR0FBRyxJQUFJLEVBQUUsQ0FBQyxDQUFDLENBQUE7QUFDOUUsUUFBQSxXQUFXLENBQUMsV0FBVyxDQUFDLFdBQVcsRUFBRSxpQkFBaUIsRUFBRSxDQUFDLEVBQUUsRUFBRSxHQUFHLENBQUMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFBO1FBQ2pGLFdBQVcsQ0FBQyxXQUFXLENBQUMsV0FBVyxFQUFFLGlCQUFpQixFQUFFLENBQUMsRUFBRSxFQUFFLEdBQUcsQ0FBQyxHQUFHLElBQUksR0FBRyxDQUFDLEdBQUcsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFBOztBQUd0RixRQUFBLE1BQU0sTUFBTSxHQUFHLE1BQU0sVUFBVSxDQUFDLGlCQUFpQixFQUFFLElBQUksRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUE7QUFDL0QsUUFBQSxNQUFNLFNBQVMsR0FBRyxNQUFNLFNBQVMsQ0FBQyxVQUFVLENBQzFDLFdBQVcsQ0FBQyxJQUFJLEVBQ2hCLFdBQVcsQ0FBQyxJQUFJLENBQUMsRUFBRSxFQUNuQixXQUFXLENBQUMsUUFBUSxDQUFDLEVBQUUsRUFDdkIsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQ2pCLFlBQVksQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUNqQixJQUFJLFVBQVUsQ0FBQyxNQUFNLENBQUMsQ0FDdkIsQ0FBQTtBQUNELFFBQUEsT0FBTyxTQUFTLENBQUE7S0FDakI7QUFFRCxJQUFBLE1BQU0sR0FBRyxHQUFBO0FBQ1AsUUFBQSxNQUFNLElBQUksR0FBRyxZQUFnQzs7QUFFM0MsWUFBQSxNQUFNLElBQUksR0FBRyxJQUFJLElBQUksRUFBRSxDQUFBO0FBQ3ZCLFlBQUEsTUFBTSxJQUFJLENBQUMsWUFBWSxFQUFFLENBQUE7QUFDekIsWUFBQSxNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTs7QUFHM0MsWUFBQSxNQUFNLE9BQU8sR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxTQUFTLENBQUMsQ0FBQTs7QUFHN0QsWUFBQSxNQUFNLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxDQUFBOztBQUd6RSxZQUFBLE1BQU0sQ0FBQyxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxXQUFXLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFBO0FBQ2pFLFlBQUEsTUFBTSxFQUFFLEdBQUcsTUFBTSxJQUFJLENBQUMsU0FBUyxFQUFFLENBQUE7QUFDakMsWUFBQSxNQUFNLEVBQUUsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsV0FBVyxFQUFFLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQTtZQUNuRCxNQUFNLFFBQVEsR0FBYSxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLENBQUE7O0FBR3hDLFlBQUEsTUFBTSxZQUFZLEdBQUcsTUFBTSxJQUFJLENBQUMsU0FBUyxDQUFDLGNBQWMsQ0FBQyxJQUFJLEVBQUUsUUFBUSxDQUFDLENBQUE7O1lBR3hFLE1BQU0sSUFBSSxDQUFDLGdCQUFnQixDQUFDLFdBQVcsRUFBRSxZQUFZLENBQUMsQ0FBQTs7QUFHdEQsWUFBQSxNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxJQUFJLEVBQUUsV0FBVyxFQUFFLFlBQVksQ0FBQyxDQUFBO0FBQzlFLFlBQUEsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsU0FBUyxDQUFDLFlBQVksQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLENBQUE7O0FBRy9ELFlBQUEsTUFBTSxPQUFPLEdBQUcsSUFBSSxPQUFPLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxTQUFTLEVBQUUsSUFBSSxDQUFDLENBQUE7QUFDNUQsWUFBQSxJQUFJLENBQUMsSUFBSSxDQUFDLFdBQVcsRUFBRSxTQUFTLENBQUMsQ0FBQTtBQUVqQyxZQUFBLE9BQU8sT0FBTyxDQUFBO0FBQ2hCLFNBQUMsQ0FBQTtBQUVELFFBQUEsT0FBTyxNQUFNLElBQUksRUFBRSxDQUFDLE9BQU8sQ0FBQyxNQUFLO0FBQy9CLFlBQUEsSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUE7QUFDN0IsU0FBQyxDQUFDLENBQUE7S0FDSDtJQUtELEVBQUUsQ0FBRSxLQUFhLEVBQUUsUUFBa0MsRUFBQTtRQUNuRCxPQUFPLEtBQUssQ0FBQyxFQUFFLENBQUMsS0FBSyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0tBQ2pDO0FBS0QsSUFBQSxJQUFJLENBQUUsS0FBYSxFQUFFLEdBQUcsSUFBVyxFQUFBO1FBQ2pDLE9BQU8sS0FBSyxDQUFDLElBQUksQ0FBQyxLQUFLLEVBQUUsR0FBRyxJQUFJLENBQUMsQ0FBQTtLQUNsQztBQUNGOztNQ3ZLWSxnQkFBZ0IsQ0FBQTtJQUMzQixXQUF1QixDQUFBLE1BQWtCLEVBQVksQ0FBUyxFQUFBO1FBQXZDLElBQU0sQ0FBQSxNQUFBLEdBQU4sTUFBTSxDQUFZO1FBQVksSUFBQyxDQUFBLENBQUEsR0FBRCxDQUFDLENBQVE7S0FBSztJQUVuRSxRQUFRLEdBQUE7UUFDTixPQUFPLE1BQU0sQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0tBQ3hDO0lBRUQsV0FBVyxHQUFBO0FBQ1QsUUFBQSxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxXQUFXLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDekQsUUFBQSxNQUFNLGVBQWUsR0FBRyxJQUFJLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUNsQyxRQUFBLE1BQU0sU0FBUyxHQUFHLElBQUksVUFBVSxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBQzlDLFFBQUEsV0FBVyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQyxFQUFFLGVBQWUsRUFBRSxTQUFTLENBQUMsV0FBVyxDQUFDLENBQUE7UUFDOUYsTUFBTSxLQUFLLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUN6QyxRQUFBLE9BQU8sU0FBUyxDQUFDLFlBQVksR0FBRyxLQUFLLENBQUE7S0FDdEM7SUFFRCxTQUFTLEdBQUE7QUFDUCxRQUFBLE9BQU8sV0FBVyxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7S0FDdkQ7QUFFRCxJQUFBLGFBQWEsUUFBUSxDQUFFLElBQVksRUFBRSxDQUFTLEVBQUE7QUFDNUMsUUFBQSxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxXQUFXLElBQUksQ0FBQyxDQUFDLENBQUE7QUFFL0QsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxZQUFZLENBQUMsQ0FBQTtRQUN4QyxNQUFNLE1BQU0sQ0FBQyxjQUFjLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQTtBQUV0QyxRQUFBLE1BQU0sS0FBSyxHQUFHLElBQUksR0FBRyxTQUFTLENBQUMsWUFBWSxDQUFBO1FBQzNDLElBQUksS0FBSyxHQUFHLENBQUMsSUFBSSxLQUFLLEdBQUcsU0FBUyxDQUFDLFVBQVUsRUFBRTtBQUM3QyxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsWUFBWSxJQUFJLENBQUEseUJBQUEsQ0FBMkIsQ0FBQyxDQUFBO0FBQzdELFNBQUE7UUFFRCxNQUFNLFNBQVMsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxDQUFDLENBQUMsQ0FBQTtRQUM1QyxXQUFXLENBQUMsVUFBVSxDQUFDLFNBQVMsRUFBRSxHQUFHLEVBQUUsQ0FBQyxHQUFHLENBQUMsR0FBRyxTQUFTLENBQUMsV0FBVyxFQUFFLENBQUMsRUFBRSxTQUFTLENBQUMsV0FBVyxDQUFDLENBQUE7QUFFL0YsUUFBQSxPQUFPLElBQUksZ0JBQWdCLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQyxDQUFBO0tBQ3BDO0FBRUQsSUFBQSxPQUFPLFVBQVUsQ0FBRSxVQUFrQixFQUFFLENBQVMsRUFBQTtBQUM5QyxRQUFBLE9BQU8sSUFBSSxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO0tBQ2hFO0FBQ0Y7O0FDbENZLE1BQUEsb0JBQW9CLEdBQWtCO0lBQ2pELE1BQU0sUUFBUSxDQUFFLFNBQVMsRUFBQTtBQUN2QixRQUFBLE9BQU8sQ0FBQyxJQUFJLENBQUMsNkVBQTZFLENBQUMsQ0FBQTtBQUMzRixRQUFBLE1BQU0sT0FBTyxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sRUFBRSxDQUFBO1FBQ3hDLE9BQU8sTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUE7S0FDakQ7SUFDRCxNQUFNLFlBQVksQ0FBRSxJQUFJLEVBQUE7UUFDdEIsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUN0QyxRQUFBLE9BQU8sTUFBTSxTQUFTLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQTtLQUNyRDs7O0FDTUcsTUFBZ0Isa0JBQTZCLFNBQVEsYUFBdUIsQ0FBQTtBQU1oRixJQUFBLFdBQUEsQ0FBYSxPQUFrQyxFQUFFLEVBQUE7QUFDL0MsUUFBQSxLQUFLLEVBQUUsQ0FBQTtRQUNQLElBQUksQ0FBQyxJQUFJLEdBQUc7QUFDVixZQUFBLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSSxJQUFJLFdBQVc7WUFDOUIsRUFBRSxFQUFFLElBQUksQ0FBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFO0FBQ3BDLFlBQUEsQ0FBQyxFQUFFLElBQUksQ0FBQyxDQUFDLElBQUksU0FBUyxDQUFDLHFCQUFxQjtZQUM1QyxtQkFBbUIsRUFBRSxJQUFJLENBQUMsbUJBQW1CLEtBQUssWUFBNEI7QUFDNUUsZ0JBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxzQ0FBc0MsQ0FBQyxDQUFBO0FBQ3pELGFBQUMsQ0FBQztTQUNILENBQUE7S0FDRjtBQUlELElBQUEsTUFBTSxPQUFPLENBQUUsUUFBd0IsRUFBRSxTQUFpQixFQUFBO1FBQ3hELE1BQU0sVUFBVSxHQUFHLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsRUFBRSxDQUFBO1FBQ3hELElBQUksVUFBVSxLQUFLLEVBQUUsRUFBRTtBQUNyQixZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMseUJBQXlCLENBQUMsQ0FBQTtBQUMzQyxTQUFBO0FBQ0QsUUFBQSxJQUFJLENBQUMsVUFBVSxHQUFHLGdCQUFnQixDQUFDLFVBQVUsQ0FBQyxVQUFVLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUV0RSxRQUFBLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDdkMsUUFBQSxNQUFNLEVBQUUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUMvQixRQUFBLE1BQU0sTUFBTSxDQUFDLGNBQWMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxFQUFFLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7UUFFL0MsT0FBTztBQUNMLFlBQUEsRUFBRSxFQUFFLElBQUksQ0FBQyxJQUFJLENBQUMsRUFBRTtZQUNoQixTQUFTO0FBQ1QsWUFBQSxFQUFFLEVBQUUsRUFBRTtTQUNQLENBQUE7S0FDRjtBQUVELElBQUEsTUFBTSxpQkFBaUIsQ0FBRSxRQUF3QixFQUFFLE9BQWdCLEVBQUE7QUFDakUsUUFBQSxJQUFJLElBQUksQ0FBQyxVQUFVLEtBQUssU0FBUyxFQUFFO0FBQ2pDLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQywyQkFBMkIsQ0FBQyxDQUFBO0FBQzdDLFNBQUE7QUFFRCxRQUFBLE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBMkI7QUFDaEUsWUFBQSxNQUFNLEVBQUUsbUJBQW1CO0FBQzNCLFlBQUEsTUFBTSxFQUFFLElBQUksQ0FBQyxJQUFJLENBQUMsRUFBRTtZQUNwQixTQUFTLEVBQUUsT0FBTyxDQUFDLFNBQVM7WUFDNUIsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztBQUNwQyxTQUFBLENBQUMsQ0FBQTtBQUVGLFFBQUEsTUFBTSxRQUFRLEdBQVk7WUFDeEIsRUFBRSxFQUFFLFFBQVEsQ0FBQyxNQUFNO1lBQ25CLFNBQVMsRUFBRSxRQUFRLENBQUMsU0FBUztBQUM3QixZQUFBLEVBQUUsRUFBRSxJQUFJLENBQUMsVUFBVSxDQUFDLFNBQVMsRUFBRTtTQUNoQyxDQUFBO1FBRUQsT0FBTztBQUNMLFlBQUEsQ0FBQyxFQUFFLE9BQU87QUFDVixZQUFBLENBQUMsRUFBRSxRQUFRO0FBRVgsWUFBQSxJQUFJLEVBQUUsSUFBSSxDQUFDLFVBQVUsQ0FBQyxXQUFXLEVBQUU7QUFDbkMsWUFBQSxJQUFJLEVBQUUsT0FBTztZQUNiLFFBQVE7U0FDVCxDQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0sY0FBYyxDQUFFLFFBQXdCLEVBQUUsUUFBa0IsRUFBQTtBQUNoRSxRQUFBLE1BQU0sYUFBYSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBb0I7QUFDOUQsWUFBQSxNQUFNLEVBQUUsWUFBWTtZQUNwQixFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDO0FBQ3JDLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQXFCO0FBQzFELFlBQUEsTUFBTSxFQUFFLE9BQU87WUFDZixFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDO0FBQ3JDLFNBQUEsQ0FBQyxDQUFBO0FBQ0YsUUFBQSxNQUFNLFFBQVEsR0FBYTtZQUN6QixFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxhQUFhLENBQUMsRUFBRSxDQUFDO1lBQ3pDLEVBQUUsRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUM7WUFDcEMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDO1NBQ2QsQ0FBQTtRQUVELE9BQU87QUFDTCxZQUFBLENBQUMsRUFBRSxRQUFRO0FBQ1gsWUFBQSxDQUFDLEVBQUU7Z0JBQ0QsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsYUFBYSxDQUFDLEVBQUUsQ0FBQztnQkFDekMsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQztnQkFDcEMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDO0FBQ2QsYUFBQTtBQUVELFlBQUEsSUFBSSxFQUFFLFFBQVE7WUFDZCxRQUFRO1NBQ1QsQ0FBQTtLQUNGO0FBRUQsSUFBQSxNQUFNLFlBQVksQ0FBRSxRQUF3QixFQUFFLFNBQW9CLEVBQUE7QUFDaEUsUUFBQSxNQUFNLGNBQWMsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQStCO0FBQzFFLFlBQUEsTUFBTSxFQUFFLGNBQWM7QUFDdkIsU0FBQSxDQUFDLENBQUE7UUFFRixNQUFNLFlBQVksR0FBRyxNQUFNLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxVQUFVLENBQUMsQ0FBQTtRQUNuRSxNQUFNLElBQUksR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDbEQsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0FBRUQsSUFBQSxNQUFNLENBQUUsUUFBd0IsRUFBQTtBQUM5QixRQUFBLEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDdEIsUUFBQSxJQUFJLENBQUMsVUFBVSxHQUFHLFNBQVMsQ0FBQTtLQUM1QjtBQUNGOztBQ25ISyxNQUFPLHNCQUF1QixTQUFRLGtCQUE2QyxDQUFBO0FBQ3ZGLElBQUEsV0FBVyxDQUFFLElBQVksRUFBQTtBQUN2QixRQUFBLE9BQU8sQ0FBVSxPQUFBLEVBQUEsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUksQ0FBQSxFQUFBLElBQUksQ0FBSSxDQUFBLEVBQUEsU0FBUyxDQUFDLFlBQVksRUFBRSxDQUFBO0tBQ3BFO0FBRUQsSUFBQSxNQUFNLFFBQVEsQ0FBRSxJQUFZLEVBQUUsT0FBb0IsRUFBQTtBQUNoRCxRQUFnQjtZQUNkLE1BQU0sTUFBTSxHQUFHLElBQUksQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLENBQUE7WUFDckMsTUFBTSxJQUFJLEdBQUcsTUFBTSxLQUFLLENBQUMsTUFBTSxFQUFFLE9BQU8sQ0FBQyxDQUFBO0FBQ3pDLFlBQUEsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsSUFBSSxFQUFFLENBQUE7WUFFOUIsT0FBTztnQkFDTCxNQUFNLEVBQUUsSUFBSSxDQUFDLE1BQU07Z0JBQ25CLElBQUk7YUFDTCxDQUFBO0FBQ0YsU0E4QkE7S0FDRjtJQUVELE1BQU0sV0FBVyxDQUFxQixPQUFnQixFQUFBO0FBQ3BELFFBQUEsSUFBSSxJQUFJLENBQUMsVUFBVSxLQUFLLFNBQVMsRUFBRTtBQUNqQyxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsNkNBQTZDLENBQUMsQ0FBQTtBQUMvRCxTQUFBO1FBRUQsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLFVBQVUsQ0FBQyxXQUFXLEVBQUUsQ0FBQTtRQUUxQyxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxFQUFFO0FBQ3JDLFlBQUEsTUFBTSxFQUFFLE1BQU07QUFDZCxZQUFBLE9BQU8sRUFBRTtBQUNQLGdCQUFBLGNBQWMsRUFBRSxrQkFBa0I7QUFDbkMsYUFBQTtBQUNELFlBQUEsSUFBSSxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDO0FBQzlCLFNBQUEsQ0FBQyxDQUFBO1FBRUYsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtLQUM3QjtBQUVELElBQUEsTUFBTSxJQUFJLENBQUUsU0FBb0IsRUFBRSxJQUFnQixFQUFFLEdBQWdCLEVBQUE7QUFDbEUsUUFBQSxNQUFNLE9BQU8sR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQTtRQUNyRCxNQUFNLFVBQVUsR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLENBQUE7UUFFbkQsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxJQUFJLEVBQUU7QUFDL0MsWUFBQSxNQUFNLEVBQUUsTUFBTTtBQUNkLFlBQUEsT0FBTyxFQUFFO0FBQ1AsZ0JBQUEsYUFBYSxFQUFFLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDO0FBQ3RDLGFBQUE7QUFDRCxZQUFBLElBQUksRUFBRSxNQUFNLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQztBQUN0QyxTQUFBLENBQUMsQ0FBQTs7UUFHRixJQUFJLElBQUksQ0FBQyxNQUFNLElBQUksR0FBRyxJQUFJLElBQUksQ0FBQyxNQUFNLElBQUksR0FBRyxFQUFFO1lBQzVDLE1BQU0sY0FBYyxHQUFHLE1BQU0sQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFBO1lBQ3JELE1BQU0sVUFBVSxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxjQUFjLENBQUMsQ0FBQTtZQUMxRCxJQUFJLENBQUMsSUFBSSxHQUFHLE1BQU0sQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDekMsU0FBQTtBQUVELFFBQUEsT0FBTyxJQUFJLENBQUE7S0FDWjtBQUNGOztBQ3hFSyxNQUFnQixrQkFBNkIsU0FBUSxhQUF1QixDQUFBO0FBU2hGLElBQUEsV0FBQSxDQUFhLE9BQWtDLEVBQUUsRUFBQTtBQUMvQyxRQUFBLEtBQUssRUFBRSxDQUFBO1FBQ1AsSUFBSSxDQUFDLElBQUksR0FBRztBQUNWLFlBQUEsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJLElBQUksU0FBUyxDQUFDLFlBQVk7QUFDekMsWUFBQSxPQUFPLEVBQUUsSUFBSSxDQUFDLE9BQU8sSUFBSSxTQUFTLENBQUMsZUFBZTtZQUNsRCxFQUFFLEVBQUUsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUU7QUFDcEMsWUFBQSxDQUFDLEVBQUUsSUFBSSxDQUFDLENBQUMsSUFBSSxTQUFTLENBQUMscUJBQXFCO0FBQzVDLFlBQUEsYUFBYSxFQUFFLElBQUksQ0FBQyxhQUFhLElBQUksb0JBQW9CO1NBQzFELENBQUE7QUFDRCxRQUFBLElBQUksQ0FBQyxVQUFVLEdBQUcsSUFBSSxPQUFPLEVBQUUsQ0FBQTtLQUNoQztBQUVELElBQUEsTUFBTSxPQUFPLENBQUUsUUFBd0IsRUFBRSxJQUFZLEVBQUUsT0FBZSxFQUFBO1FBQ3BFLElBQUksQ0FBQyxXQUFXLEVBQUUsQ0FBQTtBQUVsQixRQUFBLElBQUksQ0FBQyxVQUFVLEdBQUcsTUFBTSxnQkFBZ0IsQ0FBQyxRQUFRLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDcEUsUUFBQSxJQUFJLENBQUMsV0FBVyxHQUFHLFVBQVUsQ0FBQyxNQUFLO1lBQ2pDLElBQUksQ0FBQyxXQUFXLEVBQUUsQ0FBQTtBQUNsQixZQUFBLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUE7U0FDdEIsRUFBRSxPQUFPLENBQUMsQ0FBQTtLQUNaO0lBRUQsV0FBVyxHQUFBO0FBQ1QsUUFBQSxJQUFJLElBQUksQ0FBQyxXQUFXLElBQUksSUFBSSxFQUFFO0FBQzVCLFlBQUEsWUFBWSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUM5QixZQUFBLElBQUksQ0FBQyxXQUFXLEdBQUcsU0FBUyxDQUFBO0FBQzdCLFNBQUE7S0FDRjtBQUVELElBQUEsSUFBSSxTQUFTLEdBQUE7QUFDWCxRQUFBLE9BQU8sSUFBSSxDQUFDLFVBQVUsS0FBSyxTQUFTLENBQUE7S0FDckM7QUFFRCxJQUFBLElBQUksSUFBSSxHQUFBO0FBQ04sUUFBQSxPQUFPLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFBO0tBQ3RCO0FBRUQsSUFBQSxJQUFJLE9BQU8sR0FBQTtBQUNULFFBQUEsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtLQUN6QjtBQUVELElBQUEsTUFBTSxPQUFPLENBQUUsUUFBd0IsRUFBRSxTQUFpQixFQUFBO0FBQ3hELFFBQUEsTUFBTSxJQUFJLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxJQUFJLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUNyRCxJQUFJLElBQUksQ0FBQyxVQUFVLEtBQUssSUFBSSxJQUFJLElBQUksQ0FBQyxVQUFVLEtBQUssU0FBUyxFQUFFO0FBQzdELFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxzQ0FBc0MsQ0FBQyxDQUFBO0FBQ3hELFNBQUE7UUFFRCxRQUFRLENBQUMsSUFBSSxDQUFDLFlBQVksRUFBRSxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7UUFFNUMsT0FBTztBQUNMLFlBQUEsRUFBRSxFQUFFLElBQUksQ0FBQyxJQUFJLENBQUMsRUFBRTtZQUNoQixTQUFTO0FBQ1QsWUFBQSxFQUFFLEVBQUUsSUFBSSxDQUFDLFVBQVUsQ0FBQyxTQUFTLEVBQUU7U0FDaEMsQ0FBQTtLQUNGO0lBRUQsTUFBTSxXQUFXLENBQW1FLE1BQVMsRUFBQTtBQUMzRixRQUFBLE9BQU8sSUFBSSxFQUFFO1lBQ1gsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQTtBQUNoRCxZQUFBLElBQUksVUFBVSxDQUFDLEdBQUcsQ0FBQyxNQUFNLEtBQUssTUFBTSxFQUFFO2dCQUNwQyxTQUFRO0FBQ1QsYUFBQTtBQUVELFlBQUEsT0FBTyxVQUE0QixDQUFBO0FBQ3BDLFNBQUE7S0FDRjtBQUVELElBQUEsTUFBTSxpQkFBaUIsQ0FBRSxRQUF3QixFQUFFLE9BQWdCLEVBQUE7QUFDakUsUUFBQSxJQUFJLElBQUksQ0FBQyxVQUFVLEtBQUssU0FBUyxFQUFFO0FBQ2pDLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxtQ0FBbUMsQ0FBQyxDQUFBO0FBQ3JELFNBQUE7QUFFRCxRQUFBLE1BQU0sRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLG1CQUFtQixDQUFDLENBQUE7UUFDaEUsTUFBTSxHQUFHLENBQUMsSUFBSSxDQUFDO0FBQ2IsWUFBQSxNQUFNLEVBQUUsbUJBQW1CO1lBQzNCLE1BQU0sRUFBRSxPQUFPLENBQUMsRUFBRTtZQUNsQixTQUFTLEVBQUUsT0FBTyxDQUFDLFNBQVM7QUFDN0IsU0FBQSxDQUFDLENBQUE7QUFFRixRQUFBLE1BQU0sUUFBUSxHQUFZO1lBQ3hCLEVBQUUsRUFBRSxHQUFHLENBQUMsTUFBTTtZQUNkLFNBQVMsRUFBRSxHQUFHLENBQUMsU0FBUztZQUN4QixFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsRUFBRSxJQUFJLEVBQUUsQ0FBQztTQUN0QyxDQUFBO1FBRUQsT0FBTztBQUNMLFlBQUEsQ0FBQyxFQUFFLFFBQVE7QUFDWCxZQUFBLENBQUMsRUFBRSxPQUFPO0FBRVYsWUFBQSxJQUFJLEVBQUUsSUFBSSxDQUFDLFVBQVUsQ0FBQyxXQUFXLEVBQUU7QUFDbkMsWUFBQSxJQUFJLEVBQUUsT0FBTztZQUNiLFFBQVE7U0FDVCxDQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0sY0FBYyxDQUFFLFFBQXdCLEVBQUUsUUFBa0IsRUFBQTtRQUNoRSxNQUFNLE1BQU0sR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDbkQsUUFBQSxNQUFNLE1BQU0sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDO0FBQ3BCLFlBQUEsTUFBTSxFQUFFLFlBQVk7WUFDcEIsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQztBQUNyQyxTQUFBLENBQUMsQ0FBQTtBQUNGLFFBQUEsTUFBTSxhQUFhLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQTtRQUVoQyxNQUFNLE1BQU0sR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsT0FBTyxDQUFDLENBQUE7QUFDOUMsUUFBQSxNQUFNLE1BQU0sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDO0FBQ3BCLFlBQUEsTUFBTSxFQUFFLE9BQU87WUFDZixFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDO0FBQ3JDLFNBQUEsQ0FBQyxDQUFBO0FBQ0YsUUFBQSxNQUFNLFFBQVEsR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFBO0FBRTNCLFFBQUEsTUFBTSxRQUFRLEdBQWE7WUFDekIsRUFBRSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsYUFBYSxDQUFDLEVBQUUsQ0FBQztZQUN6QyxFQUFFLEVBQUUsTUFBTSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDO1lBQ3BDLENBQUMsRUFBRSxRQUFRLENBQUMsQ0FBQztTQUNkLENBQUE7UUFFRCxPQUFPO0FBQ0wsWUFBQSxDQUFDLEVBQUUsUUFBUTtBQUNYLFlBQUEsQ0FBQyxFQUFFLFFBQVE7QUFFWCxZQUFBLElBQUksRUFBRSxRQUFRO1lBQ2QsUUFBUTtTQUNULENBQUE7S0FDRjtBQUVELElBQUEsTUFBTSxZQUFZLENBQUUsUUFBd0IsRUFBRSxTQUFvQixFQUFBO1FBQ2hFLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxjQUFjLENBQUMsQ0FBQTtBQUN4RCxRQUFBLE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxDQUFBO1FBQzlELE1BQU0sVUFBVSxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUNoRCxRQUFBLE1BQU0sU0FBUyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUM7QUFDdkIsWUFBQSxNQUFNLEVBQUUsdUJBQXVCO0FBQy9CLFlBQUEsVUFBVSxFQUFFLE1BQU0sQ0FBQyxZQUFZLENBQUMsVUFBVSxDQUFDO0FBQzVDLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0FBRUQsSUFBQSxNQUFNLENBQUUsUUFBd0IsRUFBQTtBQUM5QixRQUFBLEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUE7UUFDdEIsSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFBOztBQUVsQixRQUFBLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQy9CLFFBQUEsSUFBSSxDQUFDLFVBQVUsR0FBRyxTQUFTLENBQUE7S0FDNUI7QUFDRjs7TUN2THFCLFFBQVEsQ0FBQTtBQUU3Qjs7QUNBSyxNQUFPLFlBQWdDLFNBQVEsUUFBVyxDQUFBO0FBQzlELElBQUEsV0FBQSxDQUF1QixHQUF3QixFQUFBO0FBQzdDLFFBQUEsS0FBSyxFQUFFLENBQUE7UUFEYyxJQUFHLENBQUEsR0FBQSxHQUFILEdBQUcsQ0FBcUI7S0FFOUM7SUFFRCxNQUFNLElBQUksQ0FBRSxPQUFVLEVBQUE7QUFDcEIsUUFBQSxJQUFJLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUE7QUFDdkMsUUFBQSxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFBO0tBQ2Y7QUFDRjs7QUNGSyxNQUFPLHNCQUF1QixTQUFRLGtCQUErQyxDQUFBO0FBSXpGLElBQUEsV0FBQSxDQUFhLElBQW9DLEVBQUE7UUFDL0MsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFBO1FBSEgsSUFBUyxDQUFBLFNBQUEsR0FBMkIsRUFBRSxDQUFBO0FBSTlDLFFBQUEsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFJLEVBQUUsTUFBTSxJQUFJLENBQUEsQ0FBQSxFQUFJLFNBQVMsQ0FBQyxZQUFZLENBQUEsQ0FBRSxDQUFBO0tBQzNEO0lBRVMsTUFBTSxlQUFlLENBQUUsR0FBeUIsRUFBQTtRQUN4RCxNQUFNLE9BQU8sR0FBRyxFQUFFLENBQUE7QUFDbEIsUUFBQSxXQUFXLE1BQU0sS0FBSyxJQUFJLEdBQUcsRUFBRTtBQUM3QixZQUFBLE9BQU8sQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUE7QUFDcEIsU0FBQTtRQUVELE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsQ0FBQyxRQUFRLEVBQUUsQ0FBQTtLQUN6QztBQUVTLElBQUEsTUFBTSx1QkFBdUIsQ0FBRSxHQUF5QixFQUFFLEdBQXdCLEVBQUE7QUFDMUYsUUFBQSxJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRTtBQUNuQixZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLENBQUMsQ0FBQTtBQUN2QyxTQUFBO1FBRUQsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsZUFBZSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQzVDLE1BQU0sT0FBTyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUE7QUFDaEMsUUFBQSxJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxFQUFFLEdBQUcsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLElBQUksWUFBWSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsQ0FBQTtLQUNuRTtBQUVTLElBQUEsTUFBTSx3QkFBd0IsQ0FDdEMsR0FBeUIsRUFDekIsR0FBd0IsRUFDeEIsY0FBc0IsRUFBQTtRQUV0QixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLGNBQWMsQ0FBQyxDQUFBO0FBQzdDLFFBQUEsTUFBTSxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLENBQUE7UUFFbEUsTUFBTSxnQkFBZ0IsR0FBRyxNQUFNLElBQUksQ0FBQyxlQUFlLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDeEQsTUFBTSxVQUFVLEdBQUcsTUFBTSxDQUFDLFlBQVksQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFBO1FBQ3hELE1BQU0sT0FBTyxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtRQUNuRCxNQUFNLFdBQVcsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO1FBQzdDLE1BQU0sSUFBSSxHQUFnQixJQUFJLENBQUMsS0FBSyxDQUFDLFdBQVcsQ0FBQyxDQUFBO1FBQ2pELElBQUksU0FBUyxHQUFRLEVBQUUsQ0FBQTtBQUN2QixRQUFBLE1BQU0sSUFBSSxHQUFnQixJQUFJLENBQUMsSUFBSSxJQUFJLEVBQUUsQ0FBQTtRQUN6QyxJQUFJLElBQUksQ0FBQyxJQUFJLEtBQUssU0FBUyxJQUFJLElBQUksQ0FBQyxJQUFJLEtBQUssRUFBRSxFQUFFO1lBQy9DLFNBQVMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFjLENBQUMsQ0FBQTtBQUM1QyxTQUFBO1FBRUQsTUFBTSxPQUFPLEdBQUcsTUFBTTtBQUNuQixhQUFBLE9BQU8sQ0FBQyxJQUFJLENBQUMsT0FBTyxJQUFJLEVBQUUsQ0FBQzthQUMzQixNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFDLEtBQUk7WUFDMUIsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxpQkFBaUIsRUFBRSxDQUFDLEdBQUcsS0FBSyxDQUFBO0FBQ2xDLFlBQUEsT0FBTyxDQUFDLENBQUE7QUFDVixTQUFDLEVBQUUsR0FBRyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBRWpCLFFBQUEsTUFBTSxRQUFRLEdBQUcsSUFBSSxLQUFLLENBQXVCLEdBQUcsRUFBRTtZQUNwRCxHQUFHLENBQUUsTUFBTSxFQUFFLENBQUMsRUFBQTtBQUNaLGdCQUFBLFFBQVEsQ0FBQztBQUNQLG9CQUFBLEtBQUssS0FBSzt3QkFDUixPQUFPLElBQUksQ0FBQyxHQUFHLENBQUE7QUFFakIsb0JBQUEsS0FBSyxRQUFRO3dCQUNYLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQTtBQUVwQixvQkFBQSxLQUFLLFNBQVM7QUFDWix3QkFBQSxPQUFPLE9BQU8sQ0FBQTtBQUVoQixvQkFBQSxLQUFLLE9BQU87QUFDVix3QkFBQSxPQUFPLElBQUksQ0FBQTtBQUViLG9CQUFBLEtBQUssTUFBTTtBQUNULHdCQUFBLE9BQU8sU0FBUyxDQUFBO0FBRWxCLG9CQUFBLEtBQUssZ0JBQWdCO0FBQ25CLHdCQUFBLE9BQU8sSUFBSSxDQUFBO0FBRWIsb0JBQUE7QUFDRSx3QkFBQSxPQUFRLE1BQWMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUM1QixpQkFBQTthQUNGO0FBQ0YsU0FBQSxDQUFDLENBQUE7O1FBR0YsR0FBRyxDQUFDLEdBQUcsR0FBRyxJQUFJLEtBQUssQ0FBNkIsR0FBRyxDQUFDLEdBQUcsRUFBRTtZQUN2RCxLQUFLLEVBQUUsQ0FBQyxNQUFnQixFQUFFLE9BQU8sRUFBRSxTQUFTLEtBQUk7QUFDOUMsZ0JBQUEsTUFBTSxVQUFVLEdBQUcsT0FBTyxDQUFDLFVBQVUsS0FBSyxTQUFTLEdBQUcsR0FBRyxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUE7QUFDOUUsZ0JBQUEsSUFBSSxVQUFVLElBQUksR0FBRyxJQUFJLFVBQVUsR0FBRyxHQUFHLEVBQUU7QUFDekMsb0JBQUEsTUFBTSxLQUFLLEdBQUcsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQzFCLG9CQUFBLE1BQU0sSUFBSSxHQUFHLFlBQTBCO0FBQ3JDLHdCQUFBLElBQUksTUFBa0IsQ0FBQTtBQUN0Qix3QkFBQSxJQUFJLE9BQU8sS0FBSyxLQUFLLFFBQVEsRUFBRTtBQUM3Qiw0QkFBQSxNQUFNLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQyxLQUFLLENBQUMsQ0FBQTtBQUNqQyx5QkFBQTs2QkFBTSxJQUFJLEtBQUssWUFBWSxNQUFNLEVBQUU7NEJBQ2xDLE1BQU0sR0FBRyxLQUFLLENBQUE7QUFDZix5QkFBQTtBQUFNLDZCQUFBO0FBQ0wsNEJBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyw2QkFBNkIsQ0FBQyxDQUFBO0FBQy9DLHlCQUFBO3dCQUNELE1BQU0sVUFBVSxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQTt3QkFDbEQsTUFBTSxnQkFBZ0IsR0FBRyxNQUFNLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxDQUFBO3dCQUN4RCxHQUFHLENBQUMsU0FBUyxDQUFDLGdCQUFnQixFQUFFLGdCQUFnQixDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQ3hELHdCQUFBLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLGdCQUFnQixFQUFFLEdBQUcsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQy9ELHFCQUFDLENBQUE7QUFFRCxvQkFBQSxJQUFJLEVBQUUsQ0FBQyxLQUFLLENBQUMsR0FBRyxJQUFNLEVBQUEsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQSxFQUFFLENBQUMsQ0FBQTtBQUM1QyxpQkFBQTtBQUFNLHFCQUFBO29CQUNMLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLEdBQUcsU0FBUyxDQUFDLENBQUE7QUFDbkMsaUJBQUE7YUFDRjtBQUNGLFNBQUEsQ0FBQyxDQUFBO1FBRUYsTUFBTSxJQUFJLENBQUMsYUFBYSxDQUFDLFFBQVEsRUFBRSxHQUFHLENBQUMsQ0FBQTtLQUN4QztBQUVELElBQUEsTUFBTSxlQUFlLENBQUUsR0FBeUIsRUFBRSxHQUF3QixFQUFBO0FBQ3hFLFFBQUEsSUFBSSxHQUFHLENBQUMsR0FBRyxLQUFLLElBQUksQ0FBQyxNQUFNLEVBQUU7QUFDM0IsWUFBQSxJQUFJLEdBQUcsQ0FBQyxNQUFNLEtBQUssTUFBTSxFQUFFO0FBQ3pCLGdCQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLENBQUMsQ0FBQTtBQUN2QyxhQUFBO0FBQ0QsWUFBQSxJQUFJLEdBQUcsQ0FBQyxPQUFPLENBQUMsYUFBYSxLQUFLLFNBQVMsRUFBRTtBQUMzQyxnQkFBQSxPQUFPLE1BQU0sSUFBSSxDQUFDLHdCQUF3QixDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQTtBQUNoRixhQUFBO0FBQU0saUJBQUE7Z0JBQ0wsT0FBTyxNQUFNLElBQUksQ0FBQyx1QkFBdUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDcEQsYUFBQTtBQUNGLFNBQUE7QUFBTSxhQUFBO1lBQ0wsTUFBTSxJQUFJLENBQUMsYUFBYSxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQTtBQUNuQyxTQUFBO0tBQ0Y7QUFFTyxJQUFBLE1BQU0sYUFBYSxDQUFFLEdBQXlCLEVBQUUsR0FBd0IsRUFBQTtBQUM5RSxRQUFBLEtBQUssTUFBTSxRQUFRLElBQUksSUFBSSxDQUFDLFNBQVMsRUFBRTtBQUNyQyxZQUFBLFFBQVEsQ0FBQyxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDbkIsU0FBQTtLQUNGO0FBRUQsSUFBQSxHQUFHLENBQUUsUUFBOEIsRUFBQTtBQUNqQyxRQUFBLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0tBQzlCO0FBQ0Y7Ozs7In0=
