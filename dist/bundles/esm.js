const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_INT32 = 2 ** 32;
function concat(...buffers) {
    const size = buffers.reduce((acc, { length }) => acc + length, 0);
    const buf = new Uint8Array(size);
    let i = 0;
    buffers.forEach((buffer) => {
        buf.set(buffer, i);
        i += buffer.length;
    });
    return buf;
}
function p2s(alg, p2sInput) {
    return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf, value, offset) {
    if (value < 0 || value >= MAX_INT32) {
        throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
    }
    buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}
function uint64be(value) {
    const high = Math.floor(value / MAX_INT32);
    const low = value % MAX_INT32;
    const buf = new Uint8Array(8);
    writeUInt32BE(buf, high, 0);
    writeUInt32BE(buf, low, 4);
    return buf;
}
function uint32be(value) {
    const buf = new Uint8Array(4);
    writeUInt32BE(buf, value);
    return buf;
}
function lengthAndInput(input) {
    return concat(uint32be(input.length), input);
}
async function concatKdf(digest, secret, bits, value) {
    const iterations = Math.ceil((bits >> 3) / 32);
    let res;
    for (let iter = 1; iter <= iterations; iter++) {
        const buf = new Uint8Array(4 + secret.length + value.length);
        buf.set(uint32be(iter));
        buf.set(secret, 4);
        buf.set(value, 4 + secret.length);
        if (!res) {
            res = await digest('sha256', buf);
        }
        else {
            res = concat(res, await digest('sha256', buf));
        }
    }
    res = res.slice(0, bits >> 3);
    return res;
}

const encodeBase64 = (input) => {
    let unencoded = input;
    if (typeof unencoded === 'string') {
        unencoded = encoder.encode(unencoded);
    }
    const CHUNK_SIZE = 0x8000;
    const arr = [];
    for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
    }
    return btoa(arr.join(''));
};
const encode = (input) => {
    return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
const decodeBase64 = (encoded) => {
    return new Uint8Array(atob(encoded)
        .split('')
        .map((c) => c.charCodeAt(0)));
};
const decode = (input) => {
    let encoded = input;
    if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
    }
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    try {
        return decodeBase64(encoded);
    }
    catch (_a) {
        throw new TypeError('The input to be decoded is not correctly encoded.');
    }
};

class JOSEError extends Error {
    constructor(message) {
        var _a;
        super(message);
        this.code = 'ERR_JOSE_GENERIC';
        this.name = this.constructor.name;
        (_a = Error.captureStackTrace) === null || _a === void 0 ? void 0 : _a.call(Error, this, this.constructor);
    }
    static get code() {
        return 'ERR_JOSE_GENERIC';
    }
}
class JWTClaimValidationFailed extends JOSEError {
    constructor(message, claim = 'unspecified', reason = 'unspecified') {
        super(message);
        this.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
        this.claim = claim;
        this.reason = reason;
    }
    static get code() {
        return 'ERR_JWT_CLAIM_VALIDATION_FAILED';
    }
}
class JWTExpired extends JOSEError {
    constructor(message, claim = 'unspecified', reason = 'unspecified') {
        super(message);
        this.code = 'ERR_JWT_EXPIRED';
        this.claim = claim;
        this.reason = reason;
    }
    static get code() {
        return 'ERR_JWT_EXPIRED';
    }
}
class JOSEAlgNotAllowed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
    }
    static get code() {
        return 'ERR_JOSE_ALG_NOT_ALLOWED';
    }
}
class JOSENotSupported extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_NOT_SUPPORTED';
    }
    static get code() {
        return 'ERR_JOSE_NOT_SUPPORTED';
    }
}
class JWEDecryptionFailed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWE_DECRYPTION_FAILED';
        this.message = 'decryption operation failed';
    }
    static get code() {
        return 'ERR_JWE_DECRYPTION_FAILED';
    }
}
class JWEInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWE_INVALID';
    }
    static get code() {
        return 'ERR_JWE_INVALID';
    }
}
class JWSInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWS_INVALID';
    }
    static get code() {
        return 'ERR_JWS_INVALID';
    }
}
class JWTInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWT_INVALID';
    }
    static get code() {
        return 'ERR_JWT_INVALID';
    }
}
class JWKInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWK_INVALID';
    }
    static get code() {
        return 'ERR_JWK_INVALID';
    }
}
class JWSSignatureVerificationFailed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
        this.message = 'signature verification failed';
    }
    static get code() {
        return 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
    }
}

var crypto$1 = crypto;
function isCryptoKey(key) {
    try {
        return (key != null &&
            typeof key.extractable === 'boolean' &&
            typeof key.algorithm.name === 'string' &&
            typeof key.type === 'string');
    }
    catch (_a) {
        return false;
    }
}

var random = crypto$1.getRandomValues.bind(crypto$1);

function bitLength$1(alg) {
    switch (alg) {
        case 'A128GCM':
        case 'A128GCMKW':
        case 'A192GCM':
        case 'A192GCMKW':
        case 'A256GCM':
        case 'A256GCMKW':
            return 96;
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            return 128;
        default:
            throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
    }
}
var generateIv = (alg) => random(new Uint8Array(bitLength$1(alg) >> 3));

const checkIvLength = (enc, iv) => {
    if (iv.length << 3 !== bitLength$1(enc)) {
        throw new JWEInvalid('Invalid Initialization Vector length');
    }
};

const checkCekLength = (cek, expected) => {
    if (cek.length << 3 !== expected) {
        throw new JWEInvalid('Invalid Content Encryption Key length');
    }
};

const timingSafeEqual = (a, b) => {
    if (!(a instanceof Uint8Array)) {
        throw new TypeError('First argument must be a buffer');
    }
    if (!(b instanceof Uint8Array)) {
        throw new TypeError('Second argument must be a buffer');
    }
    if (a.length !== b.length) {
        throw new TypeError('Input buffers must have the same length');
    }
    const len = a.length;
    let out = 0;
    let i = -1;
    while (++i < len) {
        out |= a[i] ^ b[i];
    }
    return out === 0;
};

function isCloudflareWorkers() {
    return typeof WebSocketPair === 'function';
}
function isNodeJs() {
    try {
        return process.versions.node !== undefined;
    }
    catch (_a) {
        return false;
    }
}

function unusable(name, prop = 'algorithm.name') {
    return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
    return algorithm.name === name;
}
function getHashLength(hash) {
    return parseInt(hash.name.substr(4), 10);
}
function getNamedCurve(alg) {
    switch (alg) {
        case 'ES256':
            return 'P-256';
        case 'ES384':
            return 'P-384';
        case 'ES512':
            return 'P-521';
        default:
            throw new Error('unreachable');
    }
}
function checkUsage(key, usages) {
    if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
        let msg = 'CryptoKey does not support this operation, its usages must include ';
        if (usages.length > 2) {
            const last = usages.pop();
            msg += `one of ${usages.join(', ')}, or ${last}.`;
        }
        else if (usages.length === 2) {
            msg += `one of ${usages[0]} or ${usages[1]}.`;
        }
        else {
            msg += `${usages[0]}.`;
        }
        throw new TypeError(msg);
    }
}
function checkSigCryptoKey(key, alg, ...usages) {
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512': {
            if (!isAlgorithm(key.algorithm, 'HMAC'))
                throw unusable('HMAC');
            const expected = parseInt(alg.substr(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'RS256':
        case 'RS384':
        case 'RS512': {
            if (!isAlgorithm(key.algorithm, 'RSASSA-PKCS1-v1_5'))
                throw unusable('RSASSA-PKCS1-v1_5');
            const expected = parseInt(alg.substr(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'PS256':
        case 'PS384':
        case 'PS512': {
            if (!isAlgorithm(key.algorithm, 'RSA-PSS'))
                throw unusable('RSA-PSS');
            const expected = parseInt(alg.substr(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case isNodeJs() && 'EdDSA': {
            if (key.algorithm.name !== 'NODE-ED25519' && key.algorithm.name !== 'NODE-ED448')
                throw unusable('NODE-ED25519 or NODE-ED448');
            break;
        }
        case isCloudflareWorkers() && 'EdDSA': {
            if (!isAlgorithm(key.algorithm, 'NODE-ED25519'))
                throw unusable('NODE-ED25519');
            break;
        }
        case 'ES256':
        case 'ES384':
        case 'ES512': {
            if (!isAlgorithm(key.algorithm, 'ECDSA'))
                throw unusable('ECDSA');
            const expected = getNamedCurve(alg);
            const actual = key.algorithm.namedCurve;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.namedCurve');
            break;
        }
        default:
            throw new TypeError('CryptoKey does not support this operation');
    }
    checkUsage(key, usages);
}
function checkEncCryptoKey(key, alg, ...usages) {
    switch (alg) {
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM': {
            if (!isAlgorithm(key.algorithm, 'AES-GCM'))
                throw unusable('AES-GCM');
            const expected = parseInt(alg.substr(1, 3), 10);
            const actual = key.algorithm.length;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.length');
            break;
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            if (!isAlgorithm(key.algorithm, 'AES-KW'))
                throw unusable('AES-KW');
            const expected = parseInt(alg.substr(1, 3), 10);
            const actual = key.algorithm.length;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.length');
            break;
        }
        case 'ECDH-ES':
            if (!isAlgorithm(key.algorithm, 'ECDH'))
                throw unusable('ECDH');
            break;
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW':
            if (!isAlgorithm(key.algorithm, 'PBKDF2'))
                throw unusable('PBKDF2');
            break;
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            if (!isAlgorithm(key.algorithm, 'RSA-OAEP'))
                throw unusable('RSA-OAEP');
            const expected = parseInt(alg.substr(9), 10) || 1;
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        default:
            throw new TypeError('CryptoKey does not support this operation');
    }
    checkUsage(key, usages);
}

var invalidKeyInput = (actual, ...types) => {
    let msg = 'Key must be ';
    if (types.length > 2) {
        const last = types.pop();
        msg += `one of type ${types.join(', ')}, or ${last}.`;
    }
    else if (types.length === 2) {
        msg += `one of type ${types[0]} or ${types[1]}.`;
    }
    else {
        msg += `of type ${types[0]}.`;
    }
    if (actual == null) {
        msg += ` Received ${actual}`;
    }
    else if (typeof actual === 'function' && actual.name) {
        msg += ` Received function ${actual.name}`;
    }
    else if (typeof actual === 'object' && actual != null) {
        if (actual.constructor && actual.constructor.name) {
            msg += ` Received an instance of ${actual.constructor.name}`;
        }
    }
    return msg;
};

var isKeyLike = (key) => {
    return isCryptoKey(key);
};
const types = ['CryptoKey'];

async function cbcDecrypt(enc, cek, ciphertext, iv, tag, aad) {
    if (!(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, 'Uint8Array'));
    }
    const keySize = parseInt(enc.substr(1, 3), 10);
    const encKey = await crypto$1.subtle.importKey('raw', cek.subarray(keySize >> 3), 'AES-CBC', false, ['decrypt']);
    const macKey = await crypto$1.subtle.importKey('raw', cek.subarray(0, keySize >> 3), {
        hash: `SHA-${keySize << 1}`,
        name: 'HMAC',
    }, false, ['sign']);
    const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
    const expectedTag = new Uint8Array((await crypto$1.subtle.sign('HMAC', macKey, macData)).slice(0, keySize >> 3));
    let macCheckPassed;
    try {
        macCheckPassed = timingSafeEqual(tag, expectedTag);
    }
    catch (_a) {
    }
    if (!macCheckPassed) {
        throw new JWEDecryptionFailed();
    }
    let plaintext;
    try {
        plaintext = new Uint8Array(await crypto$1.subtle.decrypt({ iv, name: 'AES-CBC' }, encKey, ciphertext));
    }
    catch (_b) {
    }
    if (!plaintext) {
        throw new JWEDecryptionFailed();
    }
    return plaintext;
}
async function gcmDecrypt(enc, cek, ciphertext, iv, tag, aad) {
    let encKey;
    if (cek instanceof Uint8Array) {
        encKey = await crypto$1.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
    }
    else {
        checkEncCryptoKey(cek, enc, 'decrypt');
        encKey = cek;
    }
    try {
        return new Uint8Array(await crypto$1.subtle.decrypt({
            additionalData: aad,
            iv,
            name: 'AES-GCM',
            tagLength: 128,
        }, encKey, concat(ciphertext, tag)));
    }
    catch (_a) {
        throw new JWEDecryptionFailed();
    }
}
const decrypt$2 = async (enc, cek, ciphertext, iv, tag, aad) => {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, ...types, 'Uint8Array'));
    }
    checkIvLength(enc, iv);
    switch (enc) {
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            if (cek instanceof Uint8Array)
                checkCekLength(cek, parseInt(enc.substr(-3), 10));
            return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            if (cek instanceof Uint8Array)
                checkCekLength(cek, parseInt(enc.substr(1, 3), 10));
            return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);
        default:
            throw new JOSENotSupported('Unsupported JWE Content Encryption Algorithm');
    }
};

const inflate = async () => {
    throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `inflateRaw` decrypt option to provide Inflate Raw implementation.');
};
const deflate = async () => {
    throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `deflateRaw` encrypt option to provide Deflate Raw implementation.');
};

const isDisjoint = (...headers) => {
    const sources = headers.filter(Boolean);
    if (sources.length === 0 || sources.length === 1) {
        return true;
    }
    let acc;
    for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
            acc = new Set(parameters);
            continue;
        }
        for (const parameter of parameters) {
            if (acc.has(parameter)) {
                return false;
            }
            acc.add(parameter);
        }
    }
    return true;
};

function isObjectLike(value) {
    return typeof value === 'object' && value !== null;
}
function isObject$1(input) {
    if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
        return false;
    }
    if (Object.getPrototypeOf(input) === null) {
        return true;
    }
    let proto = input;
    while (Object.getPrototypeOf(proto) !== null) {
        proto = Object.getPrototypeOf(proto);
    }
    return Object.getPrototypeOf(input) === proto;
}

const bogusWebCrypto = [
    { hash: 'SHA-256', name: 'HMAC' },
    true,
    ['sign'],
];

function checkKeySize(key, alg) {
    if (key.algorithm.length !== parseInt(alg.substr(1, 3), 10)) {
        throw new TypeError(`Invalid key size for alg: ${alg}`);
    }
}
function getCryptoKey$2(key, alg, usage) {
    if (isCryptoKey(key)) {
        checkEncCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        return crypto$1.subtle.importKey('raw', key, 'AES-KW', true, [usage]);
    }
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}
const wrap$1 = async (alg, key, cek) => {
    const cryptoKey = await getCryptoKey$2(key, alg, 'wrapKey');
    checkKeySize(cryptoKey, alg);
    const cryptoKeyCek = await crypto$1.subtle.importKey('raw', cek, ...bogusWebCrypto);
    return new Uint8Array(await crypto$1.subtle.wrapKey('raw', cryptoKeyCek, cryptoKey, 'AES-KW'));
};
const unwrap$1 = async (alg, key, encryptedKey) => {
    const cryptoKey = await getCryptoKey$2(key, alg, 'unwrapKey');
    checkKeySize(cryptoKey, alg);
    const cryptoKeyCek = await crypto$1.subtle.unwrapKey('raw', encryptedKey, cryptoKey, 'AES-KW', ...bogusWebCrypto);
    return new Uint8Array(await crypto$1.subtle.exportKey('raw', cryptoKeyCek));
};

const digest = async (algorithm, data) => {
    const subtleDigest = `SHA-${algorithm.substr(-3)}`;
    return new Uint8Array(await crypto$1.subtle.digest(subtleDigest, data));
};

const deriveKey$1 = async (publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) => {
    if (!isCryptoKey(publicKey)) {
        throw new TypeError(invalidKeyInput(publicKey, ...types));
    }
    checkEncCryptoKey(publicKey, 'ECDH-ES');
    if (!isCryptoKey(privateKey)) {
        throw new TypeError(invalidKeyInput(privateKey, ...types));
    }
    checkEncCryptoKey(privateKey, 'ECDH-ES', 'deriveBits', 'deriveKey');
    const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
    if (!privateKey.usages.includes('deriveBits')) {
        throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"');
    }
    const sharedSecret = new Uint8Array(await crypto$1.subtle.deriveBits({
        name: 'ECDH',
        public: publicKey,
    }, privateKey, Math.ceil(parseInt(privateKey.algorithm.namedCurve.substr(-3), 10) / 8) <<
        3));
    return concatKdf(digest, sharedSecret, keyLength, value);
};
const generateEpk = async (key) => {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    return (await crypto$1.subtle.generateKey({ name: 'ECDH', namedCurve: key.algorithm.namedCurve }, true, ['deriveBits'])).privateKey;
};
const ecdhAllowed = (key) => {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    return ['P-256', 'P-384', 'P-521'].includes(key.algorithm.namedCurve);
};

function checkP2s(p2s) {
    if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
        throw new JWEInvalid('PBES2 Salt Input must be 8 or more octets');
    }
}

function getCryptoKey$1(key, alg) {
    if (key instanceof Uint8Array) {
        return crypto$1.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveBits']);
    }
    if (isCryptoKey(key)) {
        checkEncCryptoKey(key, alg, 'deriveBits', 'deriveKey');
        return key;
    }
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}
async function deriveKey(p2s$1, alg, p2c, key) {
    checkP2s(p2s$1);
    const salt = p2s(alg, p2s$1);
    const keylen = parseInt(alg.substr(13, 3), 10);
    const subtleAlg = {
        hash: `SHA-${alg.substr(8, 3)}`,
        iterations: p2c,
        name: 'PBKDF2',
        salt,
    };
    const wrapAlg = {
        length: keylen,
        name: 'AES-KW',
    };
    const cryptoKey = await getCryptoKey$1(key, alg);
    if (cryptoKey.usages.includes('deriveBits')) {
        return new Uint8Array(await crypto$1.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
    }
    if (cryptoKey.usages.includes('deriveKey')) {
        return crypto$1.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ['wrapKey', 'unwrapKey']);
    }
    throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}
const encrypt$2 = async (alg, key, cek, p2c = Math.floor(Math.random() * 2049) + 2048, p2s = random(new Uint8Array(16))) => {
    const derived = await deriveKey(p2s, alg, p2c, key);
    const encryptedKey = await wrap$1(alg.substr(-6), derived, cek);
    return { encryptedKey, p2c, p2s: encode(p2s) };
};
const decrypt$1 = async (alg, key, encryptedKey, p2c, p2s) => {
    const derived = await deriveKey(p2s, alg, p2c, key);
    return unwrap$1(alg.substr(-6), derived, encryptedKey);
};

function subtleRsaEs(alg) {
    switch (alg) {
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512':
            return 'RSA-OAEP';
        default:
            throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
    }
}

var checkKeyLength = (alg, key) => {
    if (alg.startsWith('RS') || alg.startsWith('PS')) {
        const { modulusLength } = key.algorithm;
        if (typeof modulusLength !== 'number' || modulusLength < 2048) {
            throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
        }
    }
};

const encrypt$1 = async (alg, key, cek) => {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    checkEncCryptoKey(key, alg, 'encrypt', 'wrapKey');
    checkKeyLength(alg, key);
    if (key.usages.includes('encrypt')) {
        return new Uint8Array(await crypto$1.subtle.encrypt(subtleRsaEs(alg), key, cek));
    }
    if (key.usages.includes('wrapKey')) {
        const cryptoKeyCek = await crypto$1.subtle.importKey('raw', cek, ...bogusWebCrypto);
        return new Uint8Array(await crypto$1.subtle.wrapKey('raw', cryptoKeyCek, key, subtleRsaEs(alg)));
    }
    throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
};
const decrypt = async (alg, key, encryptedKey) => {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    checkEncCryptoKey(key, alg, 'decrypt', 'unwrapKey');
    checkKeyLength(alg, key);
    if (key.usages.includes('decrypt')) {
        return new Uint8Array(await crypto$1.subtle.decrypt(subtleRsaEs(alg), key, encryptedKey));
    }
    if (key.usages.includes('unwrapKey')) {
        const cryptoKeyCek = await crypto$1.subtle.unwrapKey('raw', encryptedKey, key, subtleRsaEs(alg), ...bogusWebCrypto);
        return new Uint8Array(await crypto$1.subtle.exportKey('raw', cryptoKeyCek));
    }
    throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
};

function bitLength(alg) {
    switch (alg) {
        case 'A128GCM':
            return 128;
        case 'A192GCM':
            return 192;
        case 'A256GCM':
        case 'A128CBC-HS256':
            return 256;
        case 'A192CBC-HS384':
            return 384;
        case 'A256CBC-HS512':
            return 512;
        default:
            throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
    }
}
var generateCek = (alg) => random(new Uint8Array(bitLength(alg) >> 3));

function subtleMapping(jwk) {
    let algorithm;
    let keyUsages;
    switch (jwk.kty) {
        case 'oct': {
            switch (jwk.alg) {
                case 'HS256':
                case 'HS384':
                case 'HS512':
                    algorithm = { name: 'HMAC', hash: `SHA-${jwk.alg.substr(-3)}` };
                    keyUsages = ['sign', 'verify'];
                    break;
                case 'A128CBC-HS256':
                case 'A192CBC-HS384':
                case 'A256CBC-HS512':
                    throw new JOSENotSupported(`${jwk.alg} keys cannot be imported as CryptoKey instances`);
                case 'A128GCM':
                case 'A192GCM':
                case 'A256GCM':
                case 'A128GCMKW':
                case 'A192GCMKW':
                case 'A256GCMKW':
                    algorithm = { name: 'AES-GCM' };
                    keyUsages = ['encrypt', 'decrypt'];
                    break;
                case 'A128KW':
                case 'A192KW':
                case 'A256KW':
                    algorithm = { name: 'AES-KW' };
                    keyUsages = ['wrapKey', 'unwrapKey'];
                    break;
                case 'PBES2-HS256+A128KW':
                case 'PBES2-HS384+A192KW':
                case 'PBES2-HS512+A256KW':
                    algorithm = { name: 'PBKDF2' };
                    keyUsages = ['deriveBits'];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case 'RSA': {
            switch (jwk.alg) {
                case 'PS256':
                case 'PS384':
                case 'PS512':
                    algorithm = { name: 'RSA-PSS', hash: `SHA-${jwk.alg.substr(-3)}` };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'RS256':
                case 'RS384':
                case 'RS512':
                    algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${jwk.alg.substr(-3)}` };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'RSA-OAEP':
                case 'RSA-OAEP-256':
                case 'RSA-OAEP-384':
                case 'RSA-OAEP-512':
                    algorithm = {
                        name: 'RSA-OAEP',
                        hash: `SHA-${parseInt(jwk.alg.substr(-3), 10) || 1}`,
                    };
                    keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case 'EC': {
            switch (jwk.alg) {
                case 'ES256':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ES384':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ES512':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ECDH-ES':
                case 'ECDH-ES+A128KW':
                case 'ECDH-ES+A192KW':
                case 'ECDH-ES+A256KW':
                    algorithm = { name: 'ECDH', namedCurve: jwk.crv };
                    keyUsages = jwk.d ? ['deriveBits'] : [];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case (isCloudflareWorkers() || isNodeJs()) && 'OKP':
            if (jwk.alg !== 'EdDSA') {
                throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            switch (jwk.crv) {
                case 'Ed25519':
                    algorithm = { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case isNodeJs() && 'Ed448':
                    algorithm = { name: 'NODE-ED448', namedCurve: 'NODE-ED448' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "crv" (Subtype of Key Pair) Parameter value');
            }
            break;
        default:
            throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
    }
    return { algorithm, keyUsages };
}
const parse = async (jwk) => {
    var _a, _b;
    const { algorithm, keyUsages } = subtleMapping(jwk);
    const rest = [
        algorithm,
        (_a = jwk.ext) !== null && _a !== void 0 ? _a : false,
        (_b = jwk.key_ops) !== null && _b !== void 0 ? _b : keyUsages,
    ];
    if (algorithm.name === 'PBKDF2') {
        return crypto$1.subtle.importKey('raw', decode(jwk.k), ...rest);
    }
    const keyData = { ...jwk };
    delete keyData.alg;
    return crypto$1.subtle.importKey('jwk', keyData, ...rest);
};
var asKeyObject = parse;

async function importJWK(jwk, alg, octAsKeyObject) {
    if (!isObject$1(jwk)) {
        throw new TypeError('JWK must be an object');
    }
    alg || (alg = jwk.alg);
    if (typeof alg !== 'string' || !alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
    }
    switch (jwk.kty) {
        case 'oct':
            if (typeof jwk.k !== 'string' || !jwk.k) {
                throw new TypeError('missing "k" (Key Value) Parameter value');
            }
            octAsKeyObject !== null && octAsKeyObject !== void 0 ? octAsKeyObject : (octAsKeyObject = jwk.ext !== true);
            if (octAsKeyObject) {
                return asKeyObject({ ...jwk, alg, ext: false });
            }
            return decode(jwk.k);
        case 'RSA':
            if (jwk.oth !== undefined) {
                throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
            }
        case 'EC':
        case 'OKP':
            return asKeyObject({ ...jwk, alg });
        default:
            throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
    }
}

const symmetricTypeCheck = (key) => {
    if (key instanceof Uint8Array)
        return;
    if (!isKeyLike(key)) {
        throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
    }
    if (key.type !== 'secret') {
        throw new TypeError(`${types.join(' or ')} instances for symmetric algorithms must be of type "secret"`);
    }
};
const asymmetricTypeCheck = (key, usage) => {
    if (!isKeyLike(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    if (key.type === 'secret') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithms must not be of type "secret"`);
    }
    if (usage === 'sign' && key.type === 'public') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm signing must be of type "private"`);
    }
    if (usage === 'decrypt' && key.type === 'public') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm decryption must be of type "private"`);
    }
    if (key.algorithm && usage === 'verify' && key.type === 'private') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm verifying must be of type "public"`);
    }
    if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm encryption must be of type "public"`);
    }
};
const checkKeyType = (alg, key, usage) => {
    const symmetric = alg.startsWith('HS') ||
        alg === 'dir' ||
        alg.startsWith('PBES2') ||
        /^A\d{3}(?:GCM)?KW$/.test(alg);
    if (symmetric) {
        symmetricTypeCheck(key);
    }
    else {
        asymmetricTypeCheck(key, usage);
    }
};

async function cbcEncrypt(enc, plaintext, cek, iv, aad) {
    if (!(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, 'Uint8Array'));
    }
    const keySize = parseInt(enc.substr(1, 3), 10);
    const encKey = await crypto$1.subtle.importKey('raw', cek.subarray(keySize >> 3), 'AES-CBC', false, ['encrypt']);
    const macKey = await crypto$1.subtle.importKey('raw', cek.subarray(0, keySize >> 3), {
        hash: `SHA-${keySize << 1}`,
        name: 'HMAC',
    }, false, ['sign']);
    const ciphertext = new Uint8Array(await crypto$1.subtle.encrypt({
        iv,
        name: 'AES-CBC',
    }, encKey, plaintext));
    const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
    const tag = new Uint8Array((await crypto$1.subtle.sign('HMAC', macKey, macData)).slice(0, keySize >> 3));
    return { ciphertext, tag };
}
async function gcmEncrypt(enc, plaintext, cek, iv, aad) {
    let encKey;
    if (cek instanceof Uint8Array) {
        encKey = await crypto$1.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
    }
    else {
        checkEncCryptoKey(cek, enc, 'encrypt');
        encKey = cek;
    }
    const encrypted = new Uint8Array(await crypto$1.subtle.encrypt({
        additionalData: aad,
        iv,
        name: 'AES-GCM',
        tagLength: 128,
    }, encKey, plaintext));
    const tag = encrypted.slice(-16);
    const ciphertext = encrypted.slice(0, -16);
    return { ciphertext, tag };
}
const encrypt = async (enc, plaintext, cek, iv, aad) => {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, ...types, 'Uint8Array'));
    }
    checkIvLength(enc, iv);
    switch (enc) {
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            if (cek instanceof Uint8Array)
                checkCekLength(cek, parseInt(enc.substr(-3), 10));
            return cbcEncrypt(enc, plaintext, cek, iv, aad);
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            if (cek instanceof Uint8Array)
                checkCekLength(cek, parseInt(enc.substr(1, 3), 10));
            return gcmEncrypt(enc, plaintext, cek, iv, aad);
        default:
            throw new JOSENotSupported('Unsupported JWE Content Encryption Algorithm');
    }
};

async function wrap(alg, key, cek, iv) {
    const jweAlgorithm = alg.substr(0, 7);
    iv || (iv = generateIv(jweAlgorithm));
    const { ciphertext: encryptedKey, tag } = await encrypt(jweAlgorithm, cek, key, iv, new Uint8Array(0));
    return { encryptedKey, iv: encode(iv), tag: encode(tag) };
}
async function unwrap(alg, key, encryptedKey, iv, tag) {
    const jweAlgorithm = alg.substr(0, 7);
    return decrypt$2(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}

async function decryptKeyManagement(alg, key, encryptedKey, joseHeader) {
    checkKeyType(alg, key, 'decrypt');
    switch (alg) {
        case 'dir': {
            if (encryptedKey !== undefined)
                throw new JWEInvalid('Encountered unexpected JWE Encrypted Key');
            return key;
        }
        case 'ECDH-ES':
            if (encryptedKey !== undefined)
                throw new JWEInvalid('Encountered unexpected JWE Encrypted Key');
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW': {
            if (!isObject$1(joseHeader.epk))
                throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
            if (!ecdhAllowed(key))
                throw new JOSENotSupported('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
            const epk = await importJWK(joseHeader.epk, alg);
            let partyUInfo;
            let partyVInfo;
            if (joseHeader.apu !== undefined) {
                if (typeof joseHeader.apu !== 'string')
                    throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
                partyUInfo = decode(joseHeader.apu);
            }
            if (joseHeader.apv !== undefined) {
                if (typeof joseHeader.apv !== 'string')
                    throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
                partyVInfo = decode(joseHeader.apv);
            }
            const sharedSecret = await deriveKey$1(epk, key, alg === 'ECDH-ES' ? joseHeader.enc : alg, alg === 'ECDH-ES' ? bitLength(joseHeader.enc) : parseInt(alg.substr(-5, 3), 10), partyUInfo, partyVInfo);
            if (alg === 'ECDH-ES')
                return sharedSecret;
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            return unwrap$1(alg.substr(-6), sharedSecret, encryptedKey);
        }
        case 'RSA1_5':
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            return decrypt(alg, key, encryptedKey);
        }
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            if (typeof joseHeader.p2c !== 'number')
                throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
            if (typeof joseHeader.p2s !== 'string')
                throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
            return decrypt$1(alg, key, encryptedKey, joseHeader.p2c, decode(joseHeader.p2s));
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            return unwrap$1(alg, key, encryptedKey);
        }
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            if (typeof joseHeader.iv !== 'string')
                throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
            if (typeof joseHeader.tag !== 'string')
                throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
            const iv = decode(joseHeader.iv);
            const tag = decode(joseHeader.tag);
            return unwrap(alg, key, encryptedKey, iv, tag);
        }
        default: {
            throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
        }
    }
}

function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
    if (joseHeader.crit !== undefined && protectedHeader.crit === undefined) {
        throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
    }
    if (!protectedHeader || protectedHeader.crit === undefined) {
        return new Set();
    }
    if (!Array.isArray(protectedHeader.crit) ||
        protectedHeader.crit.length === 0 ||
        protectedHeader.crit.some((input) => typeof input !== 'string' || input.length === 0)) {
        throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
    }
    let recognized;
    if (recognizedOption !== undefined) {
        recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
    }
    else {
        recognized = recognizedDefault;
    }
    for (const parameter of protectedHeader.crit) {
        if (!recognized.has(parameter)) {
            throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
        }
        if (joseHeader[parameter] === undefined) {
            throw new Err(`Extension Header Parameter "${parameter}" is missing`);
        }
        else if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
            throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
        }
    }
    return new Set(protectedHeader.crit);
}

const validateAlgorithms = (option, algorithms) => {
    if (algorithms !== undefined &&
        (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== 'string'))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
    }
    if (!algorithms) {
        return undefined;
    }
    return new Set(algorithms);
};

async function flattenedDecrypt(jwe, key, options) {
    var _a;
    if (!isObject$1(jwe)) {
        throw new JWEInvalid('Flattened JWE must be an object');
    }
    if (jwe.protected === undefined && jwe.header === undefined && jwe.unprotected === undefined) {
        throw new JWEInvalid('JOSE Header missing');
    }
    if (typeof jwe.iv !== 'string') {
        throw new JWEInvalid('JWE Initialization Vector missing or incorrect type');
    }
    if (typeof jwe.ciphertext !== 'string') {
        throw new JWEInvalid('JWE Ciphertext missing or incorrect type');
    }
    if (typeof jwe.tag !== 'string') {
        throw new JWEInvalid('JWE Authentication Tag missing or incorrect type');
    }
    if (jwe.protected !== undefined && typeof jwe.protected !== 'string') {
        throw new JWEInvalid('JWE Protected Header incorrect type');
    }
    if (jwe.encrypted_key !== undefined && typeof jwe.encrypted_key !== 'string') {
        throw new JWEInvalid('JWE Encrypted Key incorrect type');
    }
    if (jwe.aad !== undefined && typeof jwe.aad !== 'string') {
        throw new JWEInvalid('JWE AAD incorrect type');
    }
    if (jwe.header !== undefined && !isObject$1(jwe.header)) {
        throw new JWEInvalid('JWE Shared Unprotected Header incorrect type');
    }
    if (jwe.unprotected !== undefined && !isObject$1(jwe.unprotected)) {
        throw new JWEInvalid('JWE Per-Recipient Unprotected Header incorrect type');
    }
    let parsedProt;
    if (jwe.protected) {
        const protectedHeader = decode(jwe.protected);
        try {
            parsedProt = JSON.parse(decoder.decode(protectedHeader));
        }
        catch (_b) {
            throw new JWEInvalid('JWE Protected Header is invalid');
        }
    }
    if (!isDisjoint(parsedProt, jwe.header, jwe.unprotected)) {
        throw new JWEInvalid('JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint');
    }
    const joseHeader = {
        ...parsedProt,
        ...jwe.header,
        ...jwe.unprotected,
    };
    validateCrit(JWEInvalid, new Map(), options === null || options === void 0 ? void 0 : options.crit, parsedProt, joseHeader);
    if (joseHeader.zip !== undefined) {
        if (!parsedProt || !parsedProt.zip) {
            throw new JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
        }
        if (joseHeader.zip !== 'DEF') {
            throw new JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value');
        }
    }
    const { alg, enc } = joseHeader;
    if (typeof alg !== 'string' || !alg) {
        throw new JWEInvalid('missing JWE Algorithm (alg) in JWE Header');
    }
    if (typeof enc !== 'string' || !enc) {
        throw new JWEInvalid('missing JWE Encryption Algorithm (enc) in JWE Header');
    }
    const keyManagementAlgorithms = options && validateAlgorithms('keyManagementAlgorithms', options.keyManagementAlgorithms);
    const contentEncryptionAlgorithms = options &&
        validateAlgorithms('contentEncryptionAlgorithms', options.contentEncryptionAlgorithms);
    if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg)) {
        throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed');
    }
    if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
        throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter not allowed');
    }
    let encryptedKey;
    if (jwe.encrypted_key !== undefined) {
        encryptedKey = decode(jwe.encrypted_key);
    }
    let resolvedKey = false;
    if (typeof key === 'function') {
        key = await key(parsedProt, jwe);
        resolvedKey = true;
    }
    let cek;
    try {
        cek = await decryptKeyManagement(alg, key, encryptedKey, joseHeader);
    }
    catch (err) {
        if (err instanceof TypeError) {
            throw err;
        }
        cek = generateCek(enc);
    }
    const iv = decode(jwe.iv);
    const tag = decode(jwe.tag);
    const protectedHeader = encoder.encode((_a = jwe.protected) !== null && _a !== void 0 ? _a : '');
    let additionalData;
    if (jwe.aad !== undefined) {
        additionalData = concat(protectedHeader, encoder.encode('.'), encoder.encode(jwe.aad));
    }
    else {
        additionalData = protectedHeader;
    }
    let plaintext = await decrypt$2(enc, cek, decode(jwe.ciphertext), iv, tag, additionalData);
    if (joseHeader.zip === 'DEF') {
        plaintext = await ((options === null || options === void 0 ? void 0 : options.inflateRaw) || inflate)(plaintext);
    }
    const result = { plaintext };
    if (jwe.protected !== undefined) {
        result.protectedHeader = parsedProt;
    }
    if (jwe.aad !== undefined) {
        result.additionalAuthenticatedData = decode(jwe.aad);
    }
    if (jwe.unprotected !== undefined) {
        result.sharedUnprotectedHeader = jwe.unprotected;
    }
    if (jwe.header !== undefined) {
        result.unprotectedHeader = jwe.header;
    }
    if (resolvedKey) {
        return { ...result, key };
    }
    return result;
}

async function compactDecrypt(jwe, key, options) {
    if (jwe instanceof Uint8Array) {
        jwe = decoder.decode(jwe);
    }
    if (typeof jwe !== 'string') {
        throw new JWEInvalid('Compact JWE must be a string or Uint8Array');
    }
    const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length, } = jwe.split('.');
    if (length !== 5) {
        throw new JWEInvalid('Invalid Compact JWE');
    }
    const decrypted = await flattenedDecrypt({
        ciphertext: (ciphertext || undefined),
        iv: (iv || undefined),
        protected: protectedHeader || undefined,
        tag: (tag || undefined),
        encrypted_key: encryptedKey || undefined,
    }, key, options);
    const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: decrypted.key };
    }
    return result;
}

const keyToJWK = async (key) => {
    if (key instanceof Uint8Array) {
        return {
            kty: 'oct',
            k: encode(key),
        };
    }
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
    }
    if (!key.extractable) {
        throw new TypeError('non-extractable CryptoKey cannot be exported as a JWK');
    }
    const { ext, key_ops, alg, use, ...jwk } = await crypto$1.subtle.exportKey('jwk', key);
    return jwk;
};
var keyToJWK$1 = keyToJWK;

async function exportJWK(key) {
    return keyToJWK$1(key);
}

async function encryptKeyManagement(alg, enc, key, providedCek, providedParameters = {}) {
    let encryptedKey;
    let parameters;
    let cek;
    checkKeyType(alg, key, 'encrypt');
    switch (alg) {
        case 'dir': {
            cek = key;
            break;
        }
        case 'ECDH-ES':
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW': {
            if (!ecdhAllowed(key)) {
                throw new JOSENotSupported('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
            }
            const { apu, apv } = providedParameters;
            let { epk: ephemeralKey } = providedParameters;
            ephemeralKey || (ephemeralKey = await generateEpk(key));
            const { x, y, crv, kty } = await exportJWK(ephemeralKey);
            const sharedSecret = await deriveKey$1(key, ephemeralKey, alg === 'ECDH-ES' ? enc : alg, alg === 'ECDH-ES' ? bitLength(enc) : parseInt(alg.substr(-5, 3), 10), apu, apv);
            parameters = { epk: { x, y, crv, kty } };
            if (apu)
                parameters.apu = encode(apu);
            if (apv)
                parameters.apv = encode(apv);
            if (alg === 'ECDH-ES') {
                cek = sharedSecret;
                break;
            }
            cek = providedCek || generateCek(enc);
            const kwAlg = alg.substr(-6);
            encryptedKey = await wrap$1(kwAlg, sharedSecret, cek);
            break;
        }
        case 'RSA1_5':
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            cek = providedCek || generateCek(enc);
            encryptedKey = await encrypt$1(alg, key, cek);
            break;
        }
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW': {
            cek = providedCek || generateCek(enc);
            const { p2c, p2s } = providedParameters;
            ({ encryptedKey, ...parameters } = await encrypt$2(alg, key, cek, p2c, p2s));
            break;
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            cek = providedCek || generateCek(enc);
            encryptedKey = await wrap$1(alg, key, cek);
            break;
        }
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW': {
            cek = providedCek || generateCek(enc);
            const { iv } = providedParameters;
            ({ encryptedKey, ...parameters } = await wrap(alg, key, cek, iv));
            break;
        }
        default: {
            throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
        }
    }
    return { cek, encryptedKey, parameters };
}

const unprotected = Symbol();
class FlattenedEncrypt {
    constructor(plaintext) {
        if (!(plaintext instanceof Uint8Array)) {
            throw new TypeError('plaintext must be an instance of Uint8Array');
        }
        this._plaintext = plaintext;
    }
    setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
            throw new TypeError('setKeyManagementParameters can only be called once');
        }
        this._keyManagementParameters = parameters;
        return this;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._sharedUnprotectedHeader) {
            throw new TypeError('setSharedUnprotectedHeader can only be called once');
        }
        this._sharedUnprotectedHeader = sharedUnprotectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
    }
    setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
    }
    setContentEncryptionKey(cek) {
        if (this._cek) {
            throw new TypeError('setContentEncryptionKey can only be called once');
        }
        this._cek = cek;
        return this;
    }
    setInitializationVector(iv) {
        if (this._iv) {
            throw new TypeError('setInitializationVector can only be called once');
        }
        this._iv = iv;
        return this;
    }
    async encrypt(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
            throw new JWEInvalid('either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()');
        }
        if (!isDisjoint(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
            throw new JWEInvalid('JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
            ...this._sharedUnprotectedHeader,
        };
        validateCrit(JWEInvalid, new Map(), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);
        if (joseHeader.zip !== undefined) {
            if (!this._protectedHeader || !this._protectedHeader.zip) {
                throw new JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
            }
            if (joseHeader.zip !== 'DEF') {
                throw new JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value');
            }
        }
        const { alg, enc } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (typeof enc !== 'string' || !enc) {
            throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
        }
        let encryptedKey;
        if (alg === 'dir') {
            if (this._cek) {
                throw new TypeError('setContentEncryptionKey cannot be called when using Direct Encryption');
            }
        }
        else if (alg === 'ECDH-ES') {
            if (this._cek) {
                throw new TypeError('setContentEncryptionKey cannot be called when using Direct Key Agreement');
            }
        }
        let cek;
        {
            let parameters;
            ({ cek, encryptedKey, parameters } = await encryptKeyManagement(alg, enc, key, this._cek, this._keyManagementParameters));
            if (parameters) {
                if (options && unprotected in options) {
                    if (!this._unprotectedHeader) {
                        this.setUnprotectedHeader(parameters);
                    }
                    else {
                        this._unprotectedHeader = { ...this._unprotectedHeader, ...parameters };
                    }
                }
                else {
                    if (!this._protectedHeader) {
                        this.setProtectedHeader(parameters);
                    }
                    else {
                        this._protectedHeader = { ...this._protectedHeader, ...parameters };
                    }
                }
            }
        }
        this._iv || (this._iv = generateIv(enc));
        let additionalData;
        let protectedHeader;
        let aadMember;
        if (this._protectedHeader) {
            protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        }
        else {
            protectedHeader = encoder.encode('');
        }
        if (this._aad) {
            aadMember = encode(this._aad);
            additionalData = concat(protectedHeader, encoder.encode('.'), encoder.encode(aadMember));
        }
        else {
            additionalData = protectedHeader;
        }
        let ciphertext;
        let tag;
        if (joseHeader.zip === 'DEF') {
            const deflated = await ((options === null || options === void 0 ? void 0 : options.deflateRaw) || deflate)(this._plaintext);
            ({ ciphertext, tag } = await encrypt(enc, deflated, cek, this._iv, additionalData));
        }
        else {
            ({ ciphertext, tag } = await encrypt(enc, this._plaintext, cek, this._iv, additionalData));
        }
        const jwe = {
            ciphertext: encode(ciphertext),
            iv: encode(this._iv),
            tag: encode(tag),
        };
        if (encryptedKey) {
            jwe.encrypted_key = encode(encryptedKey);
        }
        if (aadMember) {
            jwe.aad = aadMember;
        }
        if (this._protectedHeader) {
            jwe.protected = decoder.decode(protectedHeader);
        }
        if (this._sharedUnprotectedHeader) {
            jwe.unprotected = this._sharedUnprotectedHeader;
        }
        if (this._unprotectedHeader) {
            jwe.header = this._unprotectedHeader;
        }
        return jwe;
    }
}

function subtleDsa(alg, namedCurve) {
    const length = parseInt(alg.substr(-3), 10);
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            return { hash: `SHA-${length}`, name: 'HMAC' };
        case 'PS256':
        case 'PS384':
        case 'PS512':
            return { hash: `SHA-${length}`, name: 'RSA-PSS', saltLength: length >> 3 };
        case 'RS256':
        case 'RS384':
        case 'RS512':
            return { hash: `SHA-${length}`, name: 'RSASSA-PKCS1-v1_5' };
        case 'ES256':
        case 'ES384':
        case 'ES512':
            return { hash: `SHA-${length}`, name: 'ECDSA', namedCurve };
        case (isCloudflareWorkers() || isNodeJs()) && 'EdDSA':
            return { name: namedCurve, namedCurve };
        default:
            throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
    }
}

function getCryptoKey(alg, key, usage) {
    if (isCryptoKey(key)) {
        checkSigCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        if (!alg.startsWith('HS')) {
            throw new TypeError(invalidKeyInput(key, ...types));
        }
        return crypto$1.subtle.importKey('raw', key, { hash: `SHA-${alg.substr(-3)}`, name: 'HMAC' }, false, [usage]);
    }
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}

const verify = async (alg, key, signature, data) => {
    const cryptoKey = await getCryptoKey(alg, key, 'verify');
    checkKeyLength(alg, cryptoKey);
    const algorithm = subtleDsa(alg, cryptoKey.algorithm.namedCurve);
    try {
        return await crypto$1.subtle.verify(algorithm, cryptoKey, signature, data);
    }
    catch (_a) {
        return false;
    }
};

async function flattenedVerify(jws, key, options) {
    var _a;
    if (!isObject$1(jws)) {
        throw new JWSInvalid('Flattened JWS must be an object');
    }
    if (jws.protected === undefined && jws.header === undefined) {
        throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
    }
    if (jws.protected !== undefined && typeof jws.protected !== 'string') {
        throw new JWSInvalid('JWS Protected Header incorrect type');
    }
    if (jws.payload === undefined) {
        throw new JWSInvalid('JWS Payload missing');
    }
    if (typeof jws.signature !== 'string') {
        throw new JWSInvalid('JWS Signature missing or incorrect type');
    }
    if (jws.header !== undefined && !isObject$1(jws.header)) {
        throw new JWSInvalid('JWS Unprotected Header incorrect type');
    }
    let parsedProt = {};
    if (jws.protected) {
        const protectedHeader = decode(jws.protected);
        try {
            parsedProt = JSON.parse(decoder.decode(protectedHeader));
        }
        catch (_b) {
            throw new JWSInvalid('JWS Protected Header is invalid');
        }
    }
    if (!isDisjoint(parsedProt, jws.header)) {
        throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
    }
    const joseHeader = {
        ...parsedProt,
        ...jws.header,
    };
    const extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options === null || options === void 0 ? void 0 : options.crit, parsedProt, joseHeader);
    let b64 = true;
    if (extensions.has('b64')) {
        b64 = parsedProt.b64;
        if (typeof b64 !== 'boolean') {
            throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
        }
    }
    const { alg } = joseHeader;
    if (typeof alg !== 'string' || !alg) {
        throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    const algorithms = options && validateAlgorithms('algorithms', options.algorithms);
    if (algorithms && !algorithms.has(alg)) {
        throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed');
    }
    if (b64) {
        if (typeof jws.payload !== 'string') {
            throw new JWSInvalid('JWS Payload must be a string');
        }
    }
    else if (typeof jws.payload !== 'string' && !(jws.payload instanceof Uint8Array)) {
        throw new JWSInvalid('JWS Payload must be a string or an Uint8Array instance');
    }
    let resolvedKey = false;
    if (typeof key === 'function') {
        key = await key(parsedProt, jws);
        resolvedKey = true;
    }
    checkKeyType(alg, key, 'verify');
    const data = concat(encoder.encode((_a = jws.protected) !== null && _a !== void 0 ? _a : ''), encoder.encode('.'), typeof jws.payload === 'string' ? encoder.encode(jws.payload) : jws.payload);
    const signature = decode(jws.signature);
    const verified = await verify(alg, key, signature, data);
    if (!verified) {
        throw new JWSSignatureVerificationFailed();
    }
    let payload;
    if (b64) {
        payload = decode(jws.payload);
    }
    else if (typeof jws.payload === 'string') {
        payload = encoder.encode(jws.payload);
    }
    else {
        payload = jws.payload;
    }
    const result = { payload };
    if (jws.protected !== undefined) {
        result.protectedHeader = parsedProt;
    }
    if (jws.header !== undefined) {
        result.unprotectedHeader = jws.header;
    }
    if (resolvedKey) {
        return { ...result, key };
    }
    return result;
}

async function compactVerify(jws, key, options) {
    if (jws instanceof Uint8Array) {
        jws = decoder.decode(jws);
    }
    if (typeof jws !== 'string') {
        throw new JWSInvalid('Compact JWS must be a string or Uint8Array');
    }
    const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');
    if (length !== 3) {
        throw new JWSInvalid('Invalid Compact JWS');
    }
    const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
    const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: verified.key };
    }
    return result;
}

async function generalVerify(jws, key, options) {
    if (!isObject$1(jws)) {
        throw new JWSInvalid('General JWS must be an object');
    }
    if (!Array.isArray(jws.signatures) || !jws.signatures.every(isObject$1)) {
        throw new JWSInvalid('JWS Signatures missing or incorrect type');
    }
    for (const signature of jws.signatures) {
        try {
            return await flattenedVerify({
                header: signature.header,
                payload: jws.payload,
                protected: signature.protected,
                signature: signature.signature,
            }, key, options);
        }
        catch (_a) {
        }
    }
    throw new JWSSignatureVerificationFailed();
}

var epoch = (date) => Math.floor(date.getTime() / 1000);

const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;
const REGEX = /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;
var secs = (str) => {
    const matched = REGEX.exec(str);
    if (!matched) {
        throw new TypeError('Invalid time period format');
    }
    const value = parseFloat(matched[1]);
    const unit = matched[2].toLowerCase();
    switch (unit) {
        case 'sec':
        case 'secs':
        case 'second':
        case 'seconds':
        case 's':
            return Math.round(value);
        case 'minute':
        case 'minutes':
        case 'min':
        case 'mins':
        case 'm':
            return Math.round(value * minute);
        case 'hour':
        case 'hours':
        case 'hr':
        case 'hrs':
        case 'h':
            return Math.round(value * hour);
        case 'day':
        case 'days':
        case 'd':
            return Math.round(value * day);
        case 'week':
        case 'weeks':
        case 'w':
            return Math.round(value * week);
        default:
            return Math.round(value * year);
    }
};

const normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, '');
const checkAudiencePresence = (audPayload, audOption) => {
    if (typeof audPayload === 'string') {
        return audOption.includes(audPayload);
    }
    if (Array.isArray(audPayload)) {
        return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
    }
    return false;
};
var jwtPayload = (protectedHeader, encodedPayload, options = {}) => {
    const { typ } = options;
    if (typ &&
        (typeof protectedHeader.typ !== 'string' ||
            normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
        throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', 'typ', 'check_failed');
    }
    let payload;
    try {
        payload = JSON.parse(decoder.decode(encodedPayload));
    }
    catch (_a) {
    }
    if (!isObject$1(payload)) {
        throw new JWTInvalid('JWT Claims Set must be a top-level JSON object');
    }
    const { issuer } = options;
    if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
        throw new JWTClaimValidationFailed('unexpected "iss" claim value', 'iss', 'check_failed');
    }
    const { subject } = options;
    if (subject && payload.sub !== subject) {
        throw new JWTClaimValidationFailed('unexpected "sub" claim value', 'sub', 'check_failed');
    }
    const { audience } = options;
    if (audience &&
        !checkAudiencePresence(payload.aud, typeof audience === 'string' ? [audience] : audience)) {
        throw new JWTClaimValidationFailed('unexpected "aud" claim value', 'aud', 'check_failed');
    }
    let tolerance;
    switch (typeof options.clockTolerance) {
        case 'string':
            tolerance = secs(options.clockTolerance);
            break;
        case 'number':
            tolerance = options.clockTolerance;
            break;
        case 'undefined':
            tolerance = 0;
            break;
        default:
            throw new TypeError('Invalid clockTolerance option type');
    }
    const { currentDate } = options;
    const now = epoch(currentDate || new Date());
    if (payload.iat !== undefined || options.maxTokenAge) {
        if (typeof payload.iat !== 'number') {
            throw new JWTClaimValidationFailed('"iat" claim must be a number', 'iat', 'invalid');
        }
        if (payload.exp === undefined && payload.iat > now + tolerance) {
            throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', 'iat', 'check_failed');
        }
    }
    if (payload.nbf !== undefined) {
        if (typeof payload.nbf !== 'number') {
            throw new JWTClaimValidationFailed('"nbf" claim must be a number', 'nbf', 'invalid');
        }
        if (payload.nbf > now + tolerance) {
            throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', 'nbf', 'check_failed');
        }
    }
    if (payload.exp !== undefined) {
        if (typeof payload.exp !== 'number') {
            throw new JWTClaimValidationFailed('"exp" claim must be a number', 'exp', 'invalid');
        }
        if (payload.exp <= now - tolerance) {
            throw new JWTExpired('"exp" claim timestamp check failed', 'exp', 'check_failed');
        }
    }
    if (options.maxTokenAge) {
        const age = now - payload.iat;
        const max = typeof options.maxTokenAge === 'number' ? options.maxTokenAge : secs(options.maxTokenAge);
        if (age - tolerance > max) {
            throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', 'iat', 'check_failed');
        }
        if (age < 0 - tolerance) {
            throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', 'iat', 'check_failed');
        }
    }
    return payload;
};

async function jwtVerify(jwt, key, options) {
    var _a;
    const verified = await compactVerify(jwt, key, options);
    if (((_a = verified.protectedHeader.crit) === null || _a === void 0 ? void 0 : _a.includes('b64')) && verified.protectedHeader.b64 === false) {
        throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
    }
    const payload = jwtPayload(verified.protectedHeader, verified.payload, options);
    const result = { payload, protectedHeader: verified.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: verified.key };
    }
    return result;
}

class CompactEncrypt {
    constructor(plaintext) {
        this._flattened = new FlattenedEncrypt(plaintext);
    }
    setContentEncryptionKey(cek) {
        this._flattened.setContentEncryptionKey(cek);
        return this;
    }
    setInitializationVector(iv) {
        this._flattened.setInitializationVector(iv);
        return this;
    }
    setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
    }
    setKeyManagementParameters(parameters) {
        this._flattened.setKeyManagementParameters(parameters);
        return this;
    }
    async encrypt(key, options) {
        const jwe = await this._flattened.encrypt(key, options);
        return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join('.');
    }
}

const sign = async (alg, key, data) => {
    const cryptoKey = await getCryptoKey(alg, key, 'sign');
    checkKeyLength(alg, cryptoKey);
    const signature = await crypto$1.subtle.sign(subtleDsa(alg, cryptoKey.algorithm.namedCurve), cryptoKey, data);
    return new Uint8Array(signature);
};

class FlattenedSign {
    constructor(payload) {
        if (!(payload instanceof Uint8Array)) {
            throw new TypeError('payload must be an instance of Uint8Array');
        }
        this._payload = payload;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
    }
    async sign(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader) {
            throw new JWSInvalid('either setProtectedHeader or setUnprotectedHeader must be called before #sign()');
        }
        if (!isDisjoint(this._protectedHeader, this._unprotectedHeader)) {
            throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
        };
        const extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);
        let b64 = true;
        if (extensions.has('b64')) {
            b64 = this._protectedHeader.b64;
            if (typeof b64 !== 'boolean') {
                throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            }
        }
        const { alg } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        checkKeyType(alg, key, 'sign');
        let payload = this._payload;
        if (b64) {
            payload = encoder.encode(encode(payload));
        }
        let protectedHeader;
        if (this._protectedHeader) {
            protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        }
        else {
            protectedHeader = encoder.encode('');
        }
        const data = concat(protectedHeader, encoder.encode('.'), payload);
        const signature = await sign(alg, key, data);
        const jws = {
            signature: encode(signature),
            payload: '',
        };
        if (b64) {
            jws.payload = decoder.decode(payload);
        }
        if (this._unprotectedHeader) {
            jws.header = this._unprotectedHeader;
        }
        if (this._protectedHeader) {
            jws.protected = decoder.decode(protectedHeader);
        }
        return jws;
    }
}

class CompactSign {
    constructor(payload) {
        this._flattened = new FlattenedSign(payload);
    }
    setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
    }
    async sign(key, options) {
        const jws = await this._flattened.sign(key, options);
        if (jws.payload === undefined) {
            throw new TypeError('use the flattened module for creating JWS with b64: false');
        }
        return `${jws.protected}.${jws.payload}.${jws.signature}`;
    }
}

class IndividualSignature {
    constructor(sig, key, options) {
        this.parent = sig;
        this.key = key;
        this.options = options;
    }
    setProtectedHeader(protectedHeader) {
        if (this.protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this.protectedHeader = protectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this.unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this.unprotectedHeader = unprotectedHeader;
        return this;
    }
    addSignature(...args) {
        return this.parent.addSignature(...args);
    }
    sign(...args) {
        return this.parent.sign(...args);
    }
    done() {
        return this.parent;
    }
}
class GeneralSign {
    constructor(payload) {
        this._signatures = [];
        this._payload = payload;
    }
    addSignature(key, options) {
        const signature = new IndividualSignature(this, key, options);
        this._signatures.push(signature);
        return signature;
    }
    async sign() {
        if (!this._signatures.length) {
            throw new JWSInvalid('at least one signature must be added');
        }
        const jws = {
            signatures: [],
            payload: '',
        };
        for (let i = 0; i < this._signatures.length; i++) {
            const signature = this._signatures[i];
            const flattened = new FlattenedSign(this._payload);
            flattened.setProtectedHeader(signature.protectedHeader);
            flattened.setUnprotectedHeader(signature.unprotectedHeader);
            const { payload, ...rest } = await flattened.sign(signature.key, signature.options);
            if (i === 0) {
                jws.payload = payload;
            }
            else if (jws.payload !== payload) {
                throw new JWSInvalid('inconsistent use of JWS Unencoded Payload Option (RFC7797)');
            }
            jws.signatures.push(rest);
        }
        return jws;
    }
}

class ProduceJWT {
    constructor(payload) {
        if (!isObject$1(payload)) {
            throw new TypeError('JWT Claims Set MUST be an object');
        }
        this._payload = payload;
    }
    setIssuer(issuer) {
        this._payload = { ...this._payload, iss: issuer };
        return this;
    }
    setSubject(subject) {
        this._payload = { ...this._payload, sub: subject };
        return this;
    }
    setAudience(audience) {
        this._payload = { ...this._payload, aud: audience };
        return this;
    }
    setJti(jwtId) {
        this._payload = { ...this._payload, jti: jwtId };
        return this;
    }
    setNotBefore(input) {
        if (typeof input === 'number') {
            this._payload = { ...this._payload, nbf: input };
        }
        else {
            this._payload = { ...this._payload, nbf: epoch(new Date()) + secs(input) };
        }
        return this;
    }
    setExpirationTime(input) {
        if (typeof input === 'number') {
            this._payload = { ...this._payload, exp: input };
        }
        else {
            this._payload = { ...this._payload, exp: epoch(new Date()) + secs(input) };
        }
        return this;
    }
    setIssuedAt(input) {
        if (typeof input === 'undefined') {
            this._payload = { ...this._payload, iat: epoch(new Date()) };
        }
        else {
            this._payload = { ...this._payload, iat: input };
        }
        return this;
    }
}

class SignJWT extends ProduceJWT {
    setProtectedHeader(protectedHeader) {
        this._protectedHeader = protectedHeader;
        return this;
    }
    async sign(key, options) {
        var _a;
        const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
        sig.setProtectedHeader(this._protectedHeader);
        if (Array.isArray((_a = this._protectedHeader) === null || _a === void 0 ? void 0 : _a.crit) &&
            this._protectedHeader.crit.includes('b64') &&
            this._protectedHeader.b64 === false) {
            throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
        }
        return sig.sign(key, options);
    }
}

const check = (value, description) => {
    if (typeof value !== 'string' || !value) {
        throw new JWKInvalid(`${description} missing or invalid`);
    }
};
async function calculateJwkThumbprint(jwk, digestAlgorithm = 'sha256') {
    if (!isObject$1(jwk)) {
        throw new TypeError('JWK must be an object');
    }
    let components;
    switch (jwk.kty) {
        case 'EC':
            check(jwk.crv, '"crv" (Curve) Parameter');
            check(jwk.x, '"x" (X Coordinate) Parameter');
            check(jwk.y, '"y" (Y Coordinate) Parameter');
            components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
            break;
        case 'OKP':
            check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
            check(jwk.x, '"x" (Public Key) Parameter');
            components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
            break;
        case 'RSA':
            check(jwk.e, '"e" (Exponent) Parameter');
            check(jwk.n, '"n" (Modulus) Parameter');
            components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
            break;
        case 'oct':
            check(jwk.k, '"k" (Key Value) Parameter');
            components = { k: jwk.k, kty: jwk.kty };
            break;
        default:
            throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
    }
    const data = encoder.encode(JSON.stringify(components));
    return encode(await digest(digestAlgorithm, data));
}

async function generateSecret$1(alg, options) {
    var _a;
    let length;
    let algorithm;
    let keyUsages;
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            length = parseInt(alg.substr(-3), 10);
            algorithm = { name: 'HMAC', hash: `SHA-${length}`, length };
            keyUsages = ['sign', 'verify'];
            break;
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            length = parseInt(alg.substr(-3), 10);
            return random(new Uint8Array(length >> 3));
        case 'A128KW':
        case 'A192KW':
        case 'A256KW':
            length = parseInt(alg.substring(1, 4), 10);
            algorithm = { name: 'AES-KW', length };
            keyUsages = ['wrapKey', 'unwrapKey'];
            break;
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW':
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            length = parseInt(alg.substring(1, 4), 10);
            algorithm = { name: 'AES-GCM', length };
            keyUsages = ['encrypt', 'decrypt'];
            break;
        default:
            throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
    return crypto$1.subtle.generateKey(algorithm, (_a = options === null || options === void 0 ? void 0 : options.extractable) !== null && _a !== void 0 ? _a : false, keyUsages);
}

async function generateSecret(alg, options) {
    return generateSecret$1(alg, options);
}

/**
 * Absolute value. abs(a)==a if a>=0. abs(a)==-a if a<0
 *
 * @param a
 *
 * @returns The absolute value of a
 */

/**
 * Secure random bytes for both node and browsers. Node version uses crypto.randomBytes() and browser one self.crypto.getRandomValues()
 *
 * @param byteLength - The desired number of random bytes
 * @param forceLength - If we want to force the output to have a bit length of 8*byteLength. It basically forces the msb to be 1
 *
 * @throws {RangeError}
 * byteLength MUST be > 0
 *
 * @returns A promise that resolves to a UInt8Array/Buffer (Browser/Node.js) filled with cryptographically secure random bytes
 */
function randBytes(byteLength, forceLength = false) {
    if (byteLength < 1)
        throw new RangeError('byteLength MUST be > 0');
    return new Promise(function (resolve, reject) {
        { // browser
            const buf = new Uint8Array(byteLength);
            self.crypto.getRandomValues(buf);
            // If fixed length is required we put the first bit to 1 -> to get the necessary bitLength
            if (forceLength)
                buf[0] = buf[0] | 128;
            resolve(buf);
        }
    });
}

async function verifyKeyPair(pubJWK, privJWK, alg) {
    const pubKey = await importJWK(pubJWK, alg);
    const privKey = await importJWK(privJWK, alg);
    const nonce = await randBytes(16);
    const jws = await new GeneralSign(nonce)
        .addSignature(privKey)
        .setProtectedHeader({ alg: privJWK.alg })
        .sign();
    await generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
}

/**
 * Creates a non-repudiable proof for a given data exchange
 * @param issuer - if the issuer of the proof is the origin 'orig' or the destination 'dest' of the data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` should be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
async function createProof(payload, privateJwk) {
    // Check that that the privateKey is the complement to the public key of the issuer
    const publicJwk = JSON.parse(payload.exchange[payload.iss]);
    await verifyKeyPair(publicJwk, privateJwk); // if verification fails it throws an error and the following is not executed
    const privateKey = await importJWK(privateJwk);
    const alg = privateJwk.alg; // if alg wer undefined the previous import throws error
    return await new SignJWT(payload)
        .setProtectedHeader({ alg })
        .setIssuedAt()
        .sign(privateKey);
}

function isObject(val) {
    return (val != null) && (typeof val === 'object') && !(Array.isArray(val));
}
function objectToArraySortedByKey(obj) {
    if (!isObject(obj) && !Array.isArray(obj)) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map((item) => {
            if (Array.isArray(item) || isObject(item)) {
                return objectToArraySortedByKey(item);
            }
            return item;
        });
    }
    // if it is an object convert to array and sort
    return Object.keys(obj) // eslint-disable-line
        .sort()
        .map((key) => {
        return [key, objectToArraySortedByKey(obj[key])];
    });
}
/**
 * If the input object is not an Array, this function converts the object to an array, all the key-values to 2-arrays [key, value] and then sort the array by the keys. All the process is done recursively so objects inside objects or arrays are also ordered. Once the array is created the method returns the JSON.stringify() of the sorted array.
 *
 * @param {object} obj the object
 *
 * @returns {string} a JSON stringify of the created sorted array
 */
function hashable (obj) {
    return JSON.stringify(objectToArraySortedByKey(obj));
}

/**
 * Verify a proof
 * @param proof - a non-repudiable proof in Compact JWS formatted JWT string
 *
 * @param publicJwk - the publicKey as a JWK to use for verifying the signature. If MUST match either orig or dest (the one pointed on the iss field)
 *
 * @param expectedPayloadClaims - The expected values of the proof's payload claims. An example could be:
 * {
 *   proofType: 'PoO',
 *   iss: 'orig',
 *   exchange: {
 *     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
 *     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)
 *     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)
 *     hash_alg: 'SHA-256',
 *     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding
 *     block_commitment: 'iHAdgHDQVo6qaD0KqJ9ZMlVmVA3f3AI6uZG0jFqeu14', // hash of the plaintext block in base64url with no padding
 *     secret_commitment: 'svipVfsi6vsoj3Zk_6LWi3k6mMdQOSSY1OrHGnaM5eA' // hash of the secret that can be used to decrypt the block in base64url with no padding
 *   }
 * }
 *
 * @param dateTolerance - specifies a time window to accept the proof. An example could be
 * {
 *   currentDate: new Date('2021-10-17T03:24:00'), // Date to use when comparing NumericDate claims, defaults to new Date().
 *   clockTolerance: 10  // string|number Expected clock tolerance in seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours")
 * }
 *
 * @returns The JWT protected header and payload if the proof is validated
 */
async function verifyProof(proof, publicJwk, expectedPayloadClaims, dateTolerance) {
    const pubKey = await importJWK(publicJwk);
    const verification = await jwtVerify(proof, pubKey, dateTolerance);
    const payload = verification.payload;
    // Check that that the publicKey is the public key of the issuer
    const issuer = payload.exchange[payload.iss];
    if (hashable(publicJwk) !== hashable(JSON.parse(issuer))) {
        throw new Error(`The proof is issued by ${issuer} instead of ${JSON.stringify(publicJwk)}`);
    }
    for (const key in expectedPayloadClaims) {
        if (payload[key] === undefined)
            throw new Error(`Expected key '${key}' not found in proof`);
        if (key === 'exchange') {
            const expectedDataExchange = expectedPayloadClaims.exchange;
            const dataExchange = payload.exchange;
            checkDataExchange(dataExchange, expectedDataExchange);
        }
        else {
            if (hashable(expectedPayloadClaims[key]) !== hashable(payload[key])) {
                throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedPayloadClaims[key], undefined, 2)}`);
            }
        }
    }
    return (verification);
}
/**
 * Checks whether a dataExchange claims meet the expected ones
 */
function checkDataExchange(dataExchange, expectedDataExchange) {
    // First, let us check that the dataExchange is complete
    const claims = ['id', 'orig', 'dest', 'hashAlg', 'cipherblockDgst', 'blockCommitment', 'blockCommitment', 'secretCommitment', 'schema'];
    for (const claim of claims) {
        if (claim !== 'schema' && (dataExchange[claim] === undefined || dataExchange[claim] === '')) {
            throw new Error(`${claim} is missing on dataExchange.\ndataExchange: ${JSON.stringify(dataExchange, undefined, 2)}`);
        }
    }
    // And now let's check the expected values
    for (const key in expectedDataExchange) {
        if (hashable(expectedDataExchange[key]) !== hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
        }
    }
}

const HASH_ALG = 'SHA-256'; // 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'
const SIGNING_ALG = 'RS256';
const ENC_ALG = 'A256GCM';

/**
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @returns a Compact JWE
 */
async function jweEncrypt(exchangeId, block, secret) {
    // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
    const key = await importJWK(secret);
    return await new CompactEncrypt(block)
        .setProtectedHeader({ alg: 'dir', enc: ENC_ALG, exchangeId, kid: secret.kid })
        .encrypt(key);
}
/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @returns the plaintext
 */
async function jweDecrypt(jwe, secret) {
    const key = await importJWK(secret);
    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [ENC_ALG] });
}

async function sha(input, algorithm = HASH_ALG) {
    const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
    if (!algorithms.includes(algorithm)) {
        throw new RangeError(`Valid hash algorith values are any of ${JSON.stringify(algorithms)}`);
    }
    const encoder = new TextEncoder();
    const hashInput = (typeof input === 'string') ? encoder.encode(input).buffer : input;
    let digest = '';
    {
        const buf = await crypto.subtle.digest(algorithm, hashInput);
        const h = '0123456789abcdef';
        (new Uint8Array(buf)).forEach((v) => {
            digest += h[v >> 4] + h[v & 15];
        });
    }
    return digest;
}

/**
 * Create a random (high entropy) symmetric JWK secret for AES-256-GCM
 *
 * @returns a promise that resolves to a JWK
 */
async function oneTimeSecret() {
    const key = await generateSecret(ENC_ALG, { extractable: true });
    const jwk = await exportJWK(key);
    const thumbprint = await calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = ENC_ALG;
    return jwk;
}

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
class NonRepudiationOrig {
    /**
     * @param exchangeId - the id of this data exchange. It MUST be unique for the same origin and destination
     * @param jwkPairOrig - a pair of private and public keys owned by this entity (non-repudiation orig)
     * @param publicJwkDest - the public key as a JWK of the other peer (non-repudiation dest)
     * @param block - the block of data to transmit in this data exchange
     * @param alg - the enc alg, if not already in the JWKs
     */
    constructor(exchangeId, jwkPairOrig, publicJwkDest, block, alg) {
        this.jwkPairOrig = jwkPairOrig;
        this.publicJwkDest = publicJwkDest;
        if (alg !== undefined) {
            this.jwkPairOrig.privateJwk.alg = alg;
            this.jwkPairOrig.publicJwk.alg = alg;
            this.publicJwkDest.alg = alg;
        }
        else if (this.jwkPairOrig.privateJwk.alg === undefined || this.jwkPairOrig.publicJwk.alg === undefined || this.publicJwkDest.alg === undefined) {
            throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
        }
        this.exchange = {
            id: exchangeId,
            orig: JSON.stringify(this.jwkPairOrig.publicJwk),
            dest: JSON.stringify(this.publicJwkDest),
            hashAlg: HASH_ALG
        };
        this.block = {
            raw: block
        };
        this.checked = false;
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init() {
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        this.block.secret = await oneTimeSecret();
        const secretStr = JSON.stringify(this.block.secret);
        this.block.jwe = await jweEncrypt(this.exchange.id, this.block.raw, this.block.secret);
        this.exchange = {
            ...this.exchange,
            cipherblockDgst: await sha(this.block.jwe, this.exchange.hashAlg),
            blockCommitment: await sha(this.block.raw, this.exchange.hashAlg),
            secretCommitment: await sha(secretStr, this.exchange.hashAlg)
        };
        this.checked = true;
    }
    /**
     * Creates the proof of origin (PoO).
     * Besides returning its value, it is also stored in this.block.poo
     *
     * @returns a compact JWS with the PoO
     */
    async generatePoO() {
        this._checkInit();
        const payload = {
            proofType: 'PoO',
            iss: 'orig',
            exchange: this.exchange
        };
        this.block.poo = await createProof(payload, this.jwkPairOrig.privateJwk);
        return this.block.poo;
    }
    /**
     * Verifies a proof of reception.
     * If verification passes, `por` is added to `this.block`
     *
     * @param por - A PoR in caompact JWS format
     * @returns the verified payload and protected header
     */
    async verifyPoR(por) {
        this._checkInit();
        if (this.block?.poo === undefined) {
            throw new Error('Cannot verify a PoR if not even a PoO have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            pooDgst: await sha(this.block.poo, this.exchange.hashAlg)
        };
        const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims);
        this.block.por = por;
        return verified;
    }
    /**
     * Creates the proof of publication (PoP).
     * Besides returning its value, it is also stored in `this.block.pop`
     *
     * @returns a compact JWS with the PoP
     */
    async generatePoP() {
        this._checkInit();
        if (this.block?.por === undefined) {
            throw new Error('Before computing a PoP, you have first to receive a verify a PoR');
        }
        /**
         * TO-DO: obtain verification code from the blockchain
         */
        const verificationCode = 'verificationCode';
        const payload = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            porDgst: await sha(this.block.por, this.exchange.hashAlg),
            secret: JSON.stringify(this.block.secret),
            verificationCode
        };
        this.block.pop = await createProof(payload, this.jwkPairOrig.privateJwk);
        return this.block.pop;
    }
    _checkInit() {
        if (!this.checked) {
            throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()');
        }
    }
}

/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
class NonRepudiationDest {
    /**
     *
     * @param exchangeId - the id of this data exchange. It MUST be unique for the same origin and destination
     * @param jwkPairDest - a pair of private and public keys owned by this entity (non-repudiation dest)
     * @param publicJwkOrig - the public key as a JWK of the other peer (non-repudiation orig)
     */
    constructor(exchangeId, jwkPairDest, publicJwkOrig) {
        this.jwkPairDest = jwkPairDest;
        this.publicJwkOrig = publicJwkOrig;
        this.exchange = {
            id: exchangeId,
            orig: JSON.stringify(this.publicJwkOrig),
            dest: JSON.stringify(this.jwkPairDest.publicJwk),
            hashAlg: HASH_ALG
        };
        this.checked = false;
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init() {
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        this.checked = true;
    }
    /**
     * Verifies a proof of origin against the received cipherblock.
     * If verification passes, `pop` and `cipherblock` are added to this.block
     *
     * @param poo - a Proof of Origin (PoO) in compact JWS format
     * @param cipherblock - a cipherblock as a JWE
     * @returns the verified payload and protected header
     *
     */
    async verifyPoO(poo, cipherblock) {
        this._checkInit();
        const dataExchange = {
            ...this.exchange,
            cipherblockDgst: await sha(cipherblock, this.exchange.hashAlg)
        };
        const expectedPayloadClaims = {
            proofType: 'PoO',
            iss: 'orig',
            exchange: dataExchange
        };
        const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims);
        this.block = {
            jwe: cipherblock,
            poo: poo
        };
        this.exchange = verified.payload.exchange;
        return verified;
    }
    /**
     * Creates the proof of reception (PoR).
     * Besides returning its value, it is also stored in `this.block.por`
     *
     * @returns a compact JWS with the PoR
     */
    async generatePoR() {
        this._checkInit();
        if (this.block?.poo === undefined) {
            throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO');
        }
        const payload = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            pooDgst: await sha(this.block.poo)
        };
        this.block.por = await createProof(payload, this.jwkPairDest.privateJwk);
        return this.block.por;
    }
    /**
     * Verifies a received Proof of Publication (PoP) with the received secret and verificationCode
     * @param pop - a PoP in compact JWS
     * @param secret - the JWK secret that was used to encrypt the block
     * @param verificationCode - the verification code
     * @returns the verified payload and protected header
     */
    async verifyPoP(pop, secret) {
        this._checkInit();
        if (this.block?.por === undefined) {
            throw new Error('Cannot verify a PoP if not even a PoR have been created');
        }
        /**
         * TO-DO: obtain verification code from the blockchain
         */
        const verificationCode = 'verificationCode';
        const expectedPayloadClaims = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            porDgst: await sha(this.block.por),
            secret: JSON.stringify(secret),
            verificationCode
        };
        const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims);
        this.block.secret = secret;
        this.block.pop = pop;
        return verified;
    }
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     *
     * @throws Error if the previous proofs have not been verified or the decrypted block does not meet the committed one
     */
    async decrypt() {
        this._checkInit();
        if (this.block?.pop === undefined || this.block?.secret === undefined) {
            throw new Error('Cannot decrypt if the PoP/secret has not been verified ');
        }
        const decryptedBlock = (await jweDecrypt(this.block.jwe, this.block.secret)).plaintext;
        const decryptedDgst = await sha(decryptedBlock);
        if (decryptedDgst !== this.exchange.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.raw = decryptedBlock;
        return decryptedBlock;
    }
    _checkInit() {
        if (!this.checked) {
            throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()');
        }
    }
}

export { ENC_ALG, HASH_ALG, NonRepudiationDest, NonRepudiationOrig, SIGNING_ALG, createProof, jweDecrypt, jweEncrypt, oneTimeSecret, sha, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXNtLmpzIiwic291cmNlcyI6WyIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2J1ZmZlcl91dGlscy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Jhc2U2NHVybC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Vycm9ycy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3dlYmNyeXB0by5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JhbmRvbS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXYuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2l2X2xlbmd0aC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2NoZWNrX2Nla19sZW5ndGguanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS90aW1pbmdfc2FmZV9lcXVhbC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Vudi5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY3J5cHRvX2tleS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9pc19rZXlfbGlrZS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RlY3J5cHQuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS96bGliLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pc19kaXNqb2ludC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXNfb2JqZWN0LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYm9ndXMuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9hZXNrdy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RpZ2VzdC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2VjZGhlcy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfcDJzLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcGJlczJrdy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9yc2Flcy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2NoZWNrX2tleV9sZW5ndGguanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9yc2Flcy5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2VrLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvandrX3RvX2tleS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvaW1wb3J0LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jaGVja19rZXlfdHlwZS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2VuY3J5cHQuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2Flc2djbWt3LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9kZWNyeXB0X2tleV9tYW5hZ2VtZW50LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi92YWxpZGF0ZV9jcml0LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9mbGF0dGVuZWQvZGVjcnlwdC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvY29tcGFjdC9kZWNyeXB0LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUva2V5X3RvX2p3ay5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZXhwb3J0LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9mbGF0dGVuZWQvZW5jcnlwdC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9kc2EuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvdmVyaWZ5LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvdmVyaWZ5LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3ZlcmlmeS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC92ZXJpZnkuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2Vwb2NoLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9zZWNzLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9qd3RfY2xhaW1zX3NldC5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3QvdmVyaWZ5LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9jb21wYWN0L2VuY3J5cHQuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9zaWduLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvc2lnbi5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvY29tcGFjdC9zaWduLmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9nZW5lcmFsL3NpZ24uanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvand0L3Byb2R1Y2UuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvand0L3NpZ24uanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandrL3RodW1icHJpbnQuanMiLCIuLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZW5lcmF0ZS5qcyIsIi4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZ2VuZXJhdGVfc2VjcmV0LmpzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL2JpZ2ludC1jcnlwdG8tdXRpbHMvZGlzdC9lc20vaW5kZXguYnJvd3Nlci5qcyIsIi4uLy4uL3NyYy90cy92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vbm9kZV9tb2R1bGVzL29iamVjdC1zaGEvZGlzdC9lc20vaW5kZXguYnJvd3Nlci5qcyIsIi4uLy4uL3NyYy90cy92ZXJpZnlQcm9vZi50cyIsIi4uLy4uL3NyYy90cy9jb25zdGFudHMudHMiLCIuLi8uLi9zcmMvdHMvandlLnRzIiwiLi4vLi4vc3JjL3RzL3NoYS50cyIsIi4uLy4uL3NyYy90cy9vbmVUaW1lU2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uT3JpZy50cyIsIi4uLy4uL3NyYy90cy9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImNyeXB0byIsImJpdExlbmd0aCIsImRlY3J5cHQiLCJpc09iamVjdCIsImdldENyeXB0b0tleSIsIndyYXAiLCJ1bndyYXAiLCJkZXJpdmVLZXkiLCJwMnMiLCJjb25jYXRTYWx0IiwiZW5jcnlwdCIsImJhc2U2NHVybCIsInN1YnRsZUFsZ29yaXRobSIsImRlY29kZUJhc2U2NFVSTCIsIkVDREguZWNkaEFsbG93ZWQiLCJFQ0RILmRlcml2ZUtleSIsImNla0xlbmd0aCIsImFlc0t3IiwicnNhRXMiLCJwYmVzMkt3IiwiYWVzR2NtS3ciLCJrZXlUb0pXSyIsIkVDREguZ2VuZXJhdGVFcGsiLCJnZXRWZXJpZnlLZXkiLCJnZXRTaWduS2V5IiwiZ2VuZXJhdGVTZWNyZXQiLCJnZW5lcmF0ZSJdLCJtYXBwaW5ncyI6IkFBQU8sTUFBTSxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQztBQUNsQyxNQUFNLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDO0FBQ3pD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
