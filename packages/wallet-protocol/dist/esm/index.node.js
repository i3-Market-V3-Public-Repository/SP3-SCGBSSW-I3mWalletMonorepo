import crypto from 'crypto';
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

class NodeRandom extends BaseRandom {
    async randomFill(buffer, start, size) {
        return await new Promise(resolve => {
            crypto.randomFill(buffer, start, size, () => {
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
        const cryptoKey = crypto.createSecretKey(this.key);
        const cipher = crypto.createCipheriv(this.algorithm, cryptoKey, iv);
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
        const cryptoKey = crypto.createSecretKey(this.key);
        const decipher = crypto.createDecipheriv(this.algorithm, cryptoKey, iv);
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
        this.ecdh = crypto.createECDH('prime256v1');
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
        const hash = crypto.createHash(algorithm);
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
            const http = await import('http');
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

export { BaseTransport, ConnectionString, HttpInitiatorTransport, HttpResponderTransport, MasterKey, Session, WalletProtocol, constants, defaultCodeGenerator };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC90cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzL3Byb3RvY29sLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9odHRwLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy9pbmRleC50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vdHlwZXMudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL25vZGVqcy9yYW5kb20udHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL25vZGVqcy9jaXBoZXIudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL25vZGVqcy9lY2RoLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9ub2RlanMvZGlnZXN0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWwvZm9ybWF0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWwvYnVmZmVyLnRzIiwiLi4vLi4vc3JjL3RzL3N1YmplY3QudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvZXZlbnQtZW1pdHRlci50cyIsIi4uLy4uL3NyYy90cy9wcm90b2NvbC9tYXN0ZXIta2V5LnRzIiwiLi4vLi4vc3JjL3RzL3Byb3RvY29sL3Nlc3Npb24udHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvcHJvdG9jb2wudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvY29ubmVjdGlvbi1zdHJpbmcudHMiLCIuLi8uLi9zcmMvdHMvcHJvdG9jb2wvY29kZS1nZW5lcmF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L2luaXRpYXRvci10cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L2h0dHAvaHR0cC1pbml0aWF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L3Jlc3BvbmRlci10cmFuc3BvcnQudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L3Jlc3BvbnNlLnRzIiwiLi4vLi4vc3JjL3RzL3RyYW5zcG9ydC9odHRwL2h0dHAtcmVzcG9uc2UudHMiLCIuLi8uLi9zcmMvdHMvdHJhbnNwb3J0L2h0dHAvaHR0cC1yZXNwb25kZXIudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O01BY3NCLGFBQWEsQ0FBQTtBQU9qQyxJQUFBLE1BQU0sSUFBSSxDQUFFLFNBQW9CLEVBQUUsSUFBZ0IsRUFBRSxHQUFRLEVBQUE7QUFDMUQsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHFDQUFxQyxDQUFDLENBQUE7S0FDdkQ7QUFFRCxJQUFBLE1BQU0sQ0FBRSxRQUF3QixFQUFBO0FBQzlCLFFBQUEsUUFBUSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtLQUMxQjtBQUNGOztBQzNCTSxNQUFNLFdBQVcsR0FBRyxFQUFFLENBQUE7QUFDdEIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUE7QUFDaEMsTUFBTSxlQUFlLEdBQUcsS0FBSyxDQUFBO0FBQzdCLE1BQU0sVUFBVSxHQUFHLENBQUMsSUFBSSxXQUFXLENBQUE7QUFDbkMsTUFBTSxZQUFZLEdBQUcsS0FBSyxDQUFBO0FBRTFCLE1BQU0sWUFBWSxHQUFHLEdBQUcsQ0FBQTtBQUN4QixNQUFNLGlCQUFpQixHQUFHLEdBQUcsQ0FBQTs7Ozs7Ozs7Ozs7OztBQ1A3QixNQUFNLFlBQVksR0FBRyw2QkFBNkI7Ozs7Ozs7QUNFekQsZ0JBQWU7QUFDYixJQUFBLEdBQUcsaUJBQWlCO0FBQ3BCLElBQUEsR0FBRyxhQUFhO0NBQ2pCOztNQ0pZLFFBQVEsQ0FBQTtBQUNuQixJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO0FBRUQsSUFBQSxNQUFNLFlBQVksR0FBQTtBQUNoQixRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtLQUNuQztJQUVELE1BQU0sVUFBVSxDQUFFLFlBQW9CLEVBQUE7QUFDcEMsUUFBQSxNQUFN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
