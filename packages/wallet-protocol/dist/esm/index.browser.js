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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC90cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzL3Byb3RvY29sLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9odHRwLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9pbmRleC50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vdHlwZXMudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2Jyb3dzZXIvcmFuZG9tLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9icm93c2VyL2NpcGhlci50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vYnJvd3Nlci9lY2RoLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9icm93c2VyL2RpZ2VzdC50cyIsIi4uLy4uL3NyYy90cy91dGlsL2Zvcm1hdC50cyIsIi4uLy4uL3NyYy90cy91dGlsL2J1ZmZlci50cyIsIi4uLy4uL3NyYy90cy9zdWJqZWN0LnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2V2ZW50LWVtaXR0ZXIudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvbWFzdGVyLWtleS50cyIsIi4uLy4uL3NyYy90cy9wcm90b2NvbC9zZXNzaW9uLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL3Byb3RvY29sLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2Nvbm5lY3Rpb24tc3RyaW5nLnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL2NvZGUtZ2VuZXJhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9pbml0aWF0b3ItdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtaW5pdGlhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9yZXNwb25kZXItdHJhbnNwb3J0LnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9yZXNwb25zZS50cyIsIi4uLy4uL3NyYy90cy90cmFuc3BvcnQvaHR0cC9odHRwLXJlc3BvbnNlLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtcmVzcG9uZGVyLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O01BY3NCLGFBQWEsQ0FBQTtBQU9qQyxJQUFBLE1BQU0sSUFBSSxDQUFFLFNBQW9CLEVBQUUsSUFBZ0IsRUFBRSxHQUFRLEVBQUE7QUFDMUQsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHFDQUFxQyxDQUFDLENBQUE7S0FDdkQ7QUFFRCxJQUFBLE1BQU0sQ0FBRSxRQUF3QixFQUFBO0FBQzlCLFFBQUEsUUFBUSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtLQUMxQjtBQUNGOztBQzNCTSxNQUFNLFdBQVcsR0FBRyxFQUFFLENBQUE7QUFDdEIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUE7QUFDaEMsTUFBTSxlQUFlLEdBQUcsS0FBSyxDQUFBO0FBQzdCLE1BQU0sVUFBVSxHQUFHLENBQUMsSUFBSSxXQUFXLENBQUE7QUFDbkMsTUFBTSxZQUFZLEdBQUcsS0FBSyxDQUFBO0FBRTFCLE1BQU0sWUFBWSxHQUFHLEdBQUcsQ0FBQTtBQUN4QixNQUFNLGlCQUFpQixHQUFHLEdBQUcsQ0FBQTs7Ozs7Ozs7Ozs7OztBQ1A3QixNQUFNLFlBQVksR0FBRyw2QkFBNkI7Ozs7Ozs7QUNFekQsZ0JBQWU7QUFDYixJQUFBLEdBQUcsaUJBQWlCO0FBQ3BCLElBQUEsR0FBRyxhQUFhO0NBQ2pCOztNQ0pZLFFBQVEsQ0FBQTtBQUNuQixJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0FBRUQsSUFBQSxNQUFNLFlBQVksR0FBQTtBQUNoQixRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztJQUVELE1BQU0sVUFBVSxDQUFFLFlBQW9CLEVBQUE7QUFDcEMsUUFB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
