'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var b64 = require('@juanelas/base64');
var bigintConversion = require('bigint-conversion');
var bigintCryptoUtils = require('bigint-crypto-utils');
var elliptic = require('elliptic');
var jose = require('jose');
var objectSha = require('object-sha');
var contractConfig = require('@i3m/non-repudiation-protocol-smart-contract');
var ethers = require('ethers');
var utils = require('ethers/lib/utils');

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

var b64__namespace = /*#__PURE__*/_interopNamespace(b64);
var contractConfig__default = /*#__PURE__*/_interopDefaultLegacy(contractConfig);

class NrError extends Error {
    constructor(error, nrErrors) {
        super(error);
        if (error instanceof NrError) {
            this.nrErrors = error.nrErrors;
            this.add(...nrErrors);
        }
        else {
            this.nrErrors = nrErrors;
        }
    }
    add(...nrErrors) {
        nrErrors.forEach(nrError => this.nrErrors.push(nrError));
    }
}

/**
 * Generates a pair of JWK signing/verification keys
 *
 * @param alg - the signing algorithm to use
 * @param privateKey - an optional private key as a Uint8Array, or a string (hex or base64)
 * @param base - only used when privateKey is a string. Set to true if the privateKey is base64 encoded (standard base64, url-safe bas64 with and without padding are supported)
 * @returns
 */
async function generateKeys(alg, privateKey, base64) {
    const algs = ['ES256', 'ES384', 'ES512'];
    if (!algs.includes(alg))
        throw new NrError(new RangeError(`Invalid signature algorithm '${alg}''. Allowed algorithms are ${algs.toString()}`), ['invalid algorithm']);
    let keyLength;
    let namedCurve;
    switch (alg) {
        case 'ES512':
            namedCurve = 'P-521';
            keyLength = 66;
            break;
        case 'ES384':
            namedCurve = 'P-384';
            keyLength = 48;
            break;
        default:
            namedCurve = 'P-256';
            keyLength = 32;
    }
    let privKeyBuf;
    if (privateKey !== undefined) {
        if (typeof privateKey === 'string') {
            if (base64 === true) {
                privKeyBuf = b64__namespace.decode(privateKey);
            }
            else {
                privKeyBuf = new Uint8Array(bigintConversion.hexToBuf(privateKey));
            }
        }
        else {
            privKeyBuf = privateKey;
        }
    }
    else {
        privKeyBuf = new Uint8Array(await bigintCryptoUtils.randBytes(keyLength));
    }
    const ec = new elliptic.ec('p' + namedCurve.substring(namedCurve.length - 3));
    const ecPriv = ec.keyFromPrivate(privKeyBuf);
    const ecPub = ecPriv.getPublic();
    const xHex = ecPub.getX().toString('hex').padStart(keyLength * 2, '0');
    const yHex = ecPub.getY().toString('hex').padStart(keyLength * 2, '0');
    const dHex = ecPriv.getPrivate('hex').padStart(keyLength * 2, '0');
    const x = b64__namespace.encode(bigintConversion.hexToBuf(xHex), true, false);
    const y = b64__namespace.encode(bigintConversion.hexToBuf(yHex), true, false);
    const d = b64__namespace.encode(bigintConversion.hexToBuf(dHex), true, false);
    const privateJwk = { kty: 'EC', crv: namedCurve, x, y, d, alg };
    const publicJwk = { ...privateJwk };
    delete publicJwk.d;
    return {
        publicJwk,
        privateJwk
    };
}

async function importJwk(jwk, alg) {
    try {
        const key = await jose.importJWK(jwk, alg);
        return key;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

/**
 * Encrypts a block of data to JWE
 *
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
async function jweEncrypt(block, secret, encAlg) {
    // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
    const key = await importJwk(secret);
    let jwe;
    try {
        jwe = await new jose.CompactEncrypt(block)
            .setProtectedHeader({ alg: 'dir', enc: encAlg, kid: secret.kid })
            .encrypt(key);
        return jwe;
    }
    catch (error) {
        throw new NrError(error, ['encryption failed']);
    }
}
/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @param encAlg - the algorithm for encryption
 * @returns the plaintext
 */
async function jweDecrypt(jwe, secret, encAlg = 'A256GCM') {
    const key = await importJwk(secret);
    try {
        return await jose.compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] });
    }
    catch (error) {
        const nrError = new NrError(error, ['decryption failed']);
        throw nrError;
    }
}

/**
 * Decodes and optionally verifies a JWS, and returns the decoded header, payload.
 * @param jws
 * @param publicJwk - either a public key as a JWK or a function that resolves to a JWK. If not provided, the JWS signature is not verified
 */
async function jwsDecode(jws, publicJwk) {
    const regex = /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/;
    const match = jws.match(regex);
    if (match === null) {
        throw new NrError(new Error(`${jws} is not a JWS`), ['not a compact jws']);
    }
    let header;
    let payload;
    try {
        header = JSON.parse(b64__namespace.decode(match[1], true));
        payload = JSON.parse(b64__namespace.decode(match[2], true));
    }
    catch (error) {
        throw new NrError(error, ['invalid format', 'not a compact jws']);
    }
    if (publicJwk !== undefined) {
        const pubJwk = (typeof publicJwk === 'function') ? await publicJwk(header, payload) : publicJwk;
        const pubKey = await importJwk(pubJwk);
        try {
            const verified = await jose.jwtVerify(jws, pubKey);
            return {
                header: verified.protectedHeader,
                payload: verified.payload,
                signer: pubJwk
            };
        }
        catch (error) {
            throw new NrError(error, ['jws verification failed']);
        }
    }
    return { header, payload };
}

function checkTimestamp(timestamp, notBefore, notAfter, tolerance = 2000) {
    if (timestamp < notBefore - tolerance) {
        throw new NrError(new Error(`timestamp ${(new Date(timestamp).toTimeString())} before 'notBefore' ${(new Date(notBefore).toTimeString())} with tolerance of ${tolerance / 1000}s`), ['invalid timestamp']);
    }
    else if (timestamp > notAfter + tolerance) {
        throw new NrError(new Error(`timestamp ${(new Date(timestamp).toTimeString())} after 'notAfter' ${(new Date(notAfter).toTimeString())} with tolerance of ${tolerance / 1000}s`), ['invalid timestamp']);
    }
}

function isObject(v) {
    return Object.prototype.toString.call(v) === '[object Object]';
}
function jsonSort(obj) {
    if (Array.isArray(obj)) {
        return obj.sort().map(jsonSort); // eslint-disable-line
    }
    else if (isObject(obj)) {
        return Object
            .keys(obj)
            .sort()
            .reduce(function (a, k) {
            a[k] = jsonSort(obj[k]);
            return a;
        }, {});
    }
    return obj;
}

function parseHex(a, prefix0x = false, byteLength) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/);
    if (hexMatch == null) {
        throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format']);
    }
    let hex = hexMatch[2].toLocaleLowerCase();
    if (byteLength !== undefined) {
        if (byteLength < hex.length / 2) {
            throw new NrError(new RangeError(`expected byte length ${byteLength} < input hex byte length ${Math.ceil(hex.length / 2)}`), ['invalid format']);
        }
        hex = hex.padStart(byteLength * 2, '0');
    }
    return (prefix0x) ? '0x' + hex : hex;
}

async function parseJwk(jwk, stringify) {
    try {
        await importJwk(jwk, jwk.alg);
        const sortedJwk = jsonSort(jwk);
        return (stringify) ? JSON.stringify(sortedJwk) : sortedJwk;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

async function sha(input, algorithm) {
    const algorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
    if (!algorithms.includes(algorithm)) {
        throw new NrError(new RangeError(`Valid hash algorith values are any of ${JSON.stringify(algorithms)}`), ['invalid algorithm']);
    }
    const encoder = new TextEncoder();
    const hashInput = (typeof input === 'string') ? encoder.encode(input).buffer : input;
    try {
        let digest;
        if (false) ;
        else {
            const nodeAlg = algorithm.toLowerCase().replace('-', '');
            digest = new Uint8Array(require('crypto').createHash(nodeAlg).update(Buffer.from(hashInput)).digest()); // eslint-disable-line
        }
        return digest;
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
    }
}

/**
 * Create a JWK random (high entropy) symmetric secret
 *
 * @param encAlg - the encryption algorithm
 * @param secret - and optional seed as Uint8Array or string (hex or base64)
 * @param base64 - if a secret is provided as a string, sets base64 decoding. It supports standard, url-safe base64 with and without padding (autodetected).
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */
async function oneTimeSecret(encAlg, secret, base64) {
    let key;
    let secretLength;
    switch (encAlg) {
        case 'A128GCM':
            secretLength = 16;
            break;
        case 'A256GCM':
            secretLength = 32;
            break;
        default:
            throw new NrError(new Error(`Invalid encAlg '${encAlg}'. Supported values are: ${['A128GCM', 'A256GCM'].toString()}`), ['invalid algorithm']);
    }
    if (secret !== undefined) {
        if (typeof secret === 'string') {
            if (base64 === true) {
                key = b64__namespace.decode(secret);
            }
            else {
                key = new Uint8Array(bigintConversion.hexToBuf(parseHex(secret, undefined, secretLength)));
            }
        }
        else {
            key = secret;
        }
        if (key.length !== secretLength) {
            throw new NrError(new RangeError(`Expected secret length ${secretLength} does not meet provided one ${key.length}`), ['invalid key']);
        }
    }
    else {
        try {
            key = await jose.generateSecret(encAlg, { extractable: true });
        }
        catch (error) {
            throw new NrError(error, ['unexpected error']);
        }
    }
    const jwk = await jose.exportJWK(key);
    // const thumbprint: string = await calculateJwkThumbprint(jwk)
    // jwk.kid = thumbprint
    jwk.alg = encAlg;
    return { jwk: jwk, hex: bigintConversion.bufToHex(b64.decode(jwk.k)) };
}

async function verifyKeyPair(pubJWK, privJWK) {
    if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
        throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg');
    }
    const pubKey = await importJwk(pubJWK);
    const privKey = await importJwk(privJWK);
    try {
        const nonce = await bigintCryptoUtils.randBytes(16);
        const jws = await new jose.GeneralSign(nonce)
            .addSignature(privKey)
            .setProtectedHeader({ alg: privJWK.alg })
            .sign();
        await jose.generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
    }
}

/**
 * Returns the exchangeId of the data exchange. The id is computed hashing an object with
 * all the properties of the data exchange but the id.
 *   id = BASE64URL(SHA256(hashable(dataExchangeButId)))
 * @param exchange - a complete data exchange without an id
 * @returns the exchange id in hexadecimal
 */
async function exchangeId(exchange) {
    return b64__namespace.encode(await sha(objectSha.hashable(exchange), 'SHA-256'), true, false);
}

const HASH_ALGS = ['SHA-256', 'SHA-384', 'SHA-512'];
const SIGNING_ALGS = ['ES256', 'ES384', 'ES512']; // ECDSA with secp256k1 (ES256K) Edwards Curve DSA are not supported in browsers
const ENC_ALGS = ['A128GCM', 'A256GCM']; // A192GCM is not supported in browsers

function parseTimestamp(timestamp) {
    if ((new Date(timestamp)).getTime() > 0) {
        return Number(timestamp);
    }
    else {
        throw new NrError(new Error('invalid timestamp'), ['invalid timestamp']);
    }
}
async function parseAgreement(agreement) {
    const parsedAgreement = { ...agreement };
    const agreementClaims = Object.keys(parsedAgreement);
    if (agreementClaims.length < 10 || agreementClaims.length > 11) {
        throw new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format']);
    }
    for (const key of agreementClaims) {
        switch (key) {
            case 'orig':
            case 'dest':
                parsedAgreement[key] = await parseJwk(JSON.parse(agreement[key]), true);
                break;
            case 'ledgerContractAddress':
            case 'ledgerSignerAddress':
                parsedAgreement[key] = parseHex(parsedAgreement[key], true);
                break;
            case 'pooToPorDelay':
            case 'pooToPopDelay':
            case 'pooToSecretDelay':
                parsedAgreement[key] = parseTimestamp(parsedAgreement[key]);
                break;
            case 'hashAlg':
                if (!HASH_ALGS.includes(parsedAgreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'encAlg':
                if (!ENC_ALGS.includes(parsedAgreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'signingAlg':
                if (!SIGNING_ALGS.includes(parsedAgreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'schema':
                break;
            default:
                throw new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format']);
        }
    }
    return parsedAgreement;
}

/**
 * Creates a non-repudiable proof for a given data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` shall be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
async function createProof(payload, privateJwk) {
    if (payload.iss === undefined) {
        throw new Error('Payload iss should be set to either "orig" or "dest"');
    }
    // Check that that the privateKey is the complement to the public key of the issuer
    const publicJwk = JSON.parse(payload.exchange[payload.iss]);
    await verifyKeyPair(publicJwk, privateJwk); // if verification fails it throws an error and the following is not executed
    const privateKey = await importJwk(privateJwk);
    const alg = privateJwk.alg; // if alg were undefined verifyKeyPair would have thrown an error
    const proofPayload = {
        ...payload,
        iat: Math.floor(Date.now() / 1000)
    };
    const jws = await new jose.SignJWT(proofPayload)
        .setProtectedHeader({ alg })
        .setIssuedAt(proofPayload.iat)
        .sign(privateKey);
    return {
        jws,
        payload: proofPayload
    };
}

/**
 * Verify a proof
 * @param proof - a non-repudiable proof in Compact JWS formatted JWT string
 *
 * @param expectedPayloadClaims - The expected values of the proof's payload claims. An expected value of '' can be use to just check that the claim is in the payload. An example could be:
 * {
 *   proofType: 'PoO',
 *   iss: 'orig',
 *   exchange: {
 *     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
 *     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)
 *     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)
 *     hash_alg: 'SHA-256',
 *     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding
 *     block_commitment: '', // hash of the plaintext block in base64url with no padding
 *     secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding
 *   }
 * }
 *
 * @param options - specifies a time window to accept the proof
 *
 * @returns The JWT protected header and payload if the proof is validated
 */
async function verifyProof(proof, expectedPayloadClaims, options) {
    const publicJwk = JSON.parse(expectedPayloadClaims.exchange[expectedPayloadClaims.iss]);
    const verification = await jwsDecode(proof, publicJwk);
    if (verification.payload.iss === undefined) {
        throw new Error('Property "iss" missing');
    }
    if (verification.payload.iat === undefined) {
        throw new Error('Property claim iat missing');
    }
    if (options !== undefined) {
        const timestamp = (options.timestamp === 'iat') ? verification.payload.iat * 1000 : options.timestamp;
        const notBefore = (options.notBefore === 'iat') ? verification.payload.iat * 1000 : options.notBefore;
        const notAfter = (options.notAfter === 'iat') ? verification.payload.iat * 1000 : options.notAfter;
        checkTimestamp(timestamp, notBefore, notAfter, options.tolerance);
    }
    const payload = verification.payload;
    // Check that the publicKey is the public key of the issuer
    const issuer = payload.exchange[payload.iss];
    if (objectSha.hashable(publicJwk) !== objectSha.hashable(JSON.parse(issuer))) {
        throw new Error(`The proof is issued by ${issuer} instead of ${JSON.stringify(publicJwk)}`);
    }
    const expectedClaimsDict = expectedPayloadClaims;
    for (const key in expectedClaimsDict) {
        if (payload[key] === undefined)
            throw new Error(`Expected key '${key}' not found in proof`);
        if (key === 'exchange') {
            const expectedDataExchange = expectedPayloadClaims.exchange;
            const dataExchange = payload.exchange;
            checkDataExchange(dataExchange, expectedDataExchange);
        }
        else if (expectedClaimsDict[key] !== '' && objectSha.hashable(expectedClaimsDict[key]) !== objectSha.hashable(payload[key])) {
            throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedClaimsDict[key], undefined, 2)}`);
        }
    }
    return verification;
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
        if (expectedDataExchange[key] !== '' && objectSha.hashable(expectedDataExchange[key]) !== objectSha.hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
        }
    }
}

async function verifyPor(por, wallet, connectionTimeout = 10) {
    const { payload: porPayload } = await jwsDecode(por);
    const exchange = porPayload.exchange;
    const dataExchangePreview = { ...exchange };
    // @ts-expect-error
    delete dataExchangePreview.id;
    const expectedExchangeId = await exchangeId(dataExchangePreview);
    if (expectedExchangeId !== exchange.id) {
        throw new NrError(new Error('data exchange integrity failed'), ['dataExchange integrity violated']);
    }
    const destPublicJwk = JSON.parse(exchange.dest);
    const origPublicJwk = JSON.parse(exchange.orig);
    let pooPayload;
    try {
        const verified = await verifyProof(porPayload.poo, {
            iss: 'orig',
            proofType: 'PoO',
            exchange
        });
        pooPayload = verified.payload;
    }
    catch (error) {
        throw new NrError(error, ['invalid poo']);
    }
    try {
        await verifyProof(por, {
            iss: 'dest',
            proofType: 'PoR',
            exchange
        }, {
            timestamp: 'iat',
            notBefore: pooPayload.iat * 1000,
            notAfter: pooPayload.iat * 1000 + exchange.pooToPorDelay
        });
    }
    catch (error) {
        throw new NrError(error, ['invalid por']);
    }
    let secretHex, iat;
    try {
        const secret = await wallet.getSecretFromLedger(exchange.ledgerSignerAddress, exchange.id, connectionTimeout);
        secretHex = secret.hex;
        iat = secret.iat;
    }
    catch (error) {
        throw new NrError(error, ['cannot verify']);
    }
    try {
        checkTimestamp(iat * 1000, porPayload.iat * 1000, pooPayload.iat * 1000 + exchange.pooToSecretDelay);
    }
    catch (error) {
        throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(pooPayload.iat * 1000 + exchange.pooToSecretDelay)).toUTCString()}`, ['secret not published in time']);
    }
    return {
        pooPayload,
        porPayload,
        secretHex,
        destPublicJwk,
        origPublicJwk
    };
}

/**
 * Checks the completeness of a given data exchange by verifying the PoR in the verification request using the secret downloaded from the ledger
 *
 * @param verificationRequest
 * @param wallet
 * @returns
 */
async function checkCompleteness(verificationRequest, wallet, connectionTimeout = 10) {
    let vrPayload;
    try {
        const decoded = await jwsDecode(verificationRequest);
        vrPayload = decoded.payload;
    }
    catch (error) {
        throw new NrError(error, ['invalid verification request']);
    }
    let destPublicJwk, origPublicJwk, pooPayload, porPayload;
    try {
        const verified = await verifyPor(vrPayload.por, wallet, connectionTimeout);
        destPublicJwk = verified.destPublicJwk;
        origPublicJwk = verified.origPublicJwk;
        pooPayload = verified.pooPayload;
        porPayload = verified.porPayload;
    }
    catch (error) {
        throw new NrError(error, ['invalid por', 'invalid verification request']);
    }
    try {
        await jwsDecode(verificationRequest, (vrPayload.iss === 'dest') ? destPublicJwk : origPublicJwk);
    }
    catch (error) {
        throw new NrError(error, ['invalid verification request']);
    }
    return {
        pooPayload,
        porPayload,
        vrPayload,
        destPublicJwk,
        origPublicJwk
    };
}

/**
 * Check if the cipherblock in the disputeRequest is the one agreed for the dataExchange, and if it could be decrypted with the secret published on the ledger for that dataExchange.
 *
 * @param disputeRequest a dispute request as a compact JWS
 * @param wallet
 * @returns
 */
async function checkDecryption(disputeRequest, wallet) {
    const { payload: drPayload } = await jwsDecode(disputeRequest);
    const { destPublicJwk, origPublicJwk, secretHex, pooPayload, porPayload } = await verifyPor(drPayload.por, wallet);
    try {
        await jwsDecode(disputeRequest, destPublicJwk);
    }
    catch (error) {
        if (error instanceof NrError) {
            error.add('invalid dispute request');
        }
        throw error;
    }
    const cipherblockDgst = b64__namespace.encode(await sha(drPayload.cipherblock, porPayload.exchange.hashAlg), true, false);
    if (cipherblockDgst !== porPayload.exchange.cipherblockDgst) {
        throw new NrError(new Error('cipherblock does not meet the committed (and already accepted) one'), ['invalid dispute request']);
    }
    await jweDecrypt(drPayload.cipherblock, (await (oneTimeSecret(porPayload.exchange.encAlg, secretHex))).jwk);
    /**
     * TO-DO: check schema!
     */
    return {
        pooPayload,
        porPayload,
        drPayload,
        destPublicJwk,
        origPublicJwk
    };
}

/**
 * The base class that should be instantiated in order to create a Conflict Resolver instance.
 * The Conflict Resolver is an external entity that can:
 *  1. verify the completeness of a data exchange that used the non-repudiation protocol;
 *  2. resolve a dispute when a consumer states that she/he cannot decrypt the data received
 */
class ConflictResolver {
    /**
     *
     * @param jwkPair a pair of public/private keys in JWK format
     * @param dltAgent a DLT agent providing read-only access to the non-repudiation protocol smart contract
     */
    constructor(jwkPair, dltAgent) {
        this.jwkPair = jwkPair;
        this.dltAgent = dltAgent;
        this.initialized = new Promise((resolve, reject) => {
            this.init().then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    /**
     * Initialize this instance.
     */
    async init() {
        await verifyKeyPair(this.jwkPair.publicJwk, this.jwkPair.privateJwk);
    }
    /**
     * Checks if a give data exchange has completed succesfully
     *
     * @param verificationRequest
     * @returns a signed resolution
     */
    async resolveCompleteness(verificationRequest) {
        await this.initialized;
        const { payload: vrPayload } = await jwsDecode(verificationRequest);
        let porPayload;
        try {
            const decoded = await jwsDecode(vrPayload.por);
            porPayload = decoded.payload;
        }
        catch (error) {
            throw new NrError(error, ['invalid por']);
        }
        const verificationResolution = {
            ...await this._resolution(vrPayload.dataExchangeId, porPayload.exchange[vrPayload.iss]),
            resolution: 'not completed',
            type: 'verification'
        };
        try {
            await checkCompleteness(verificationRequest, this.dltAgent);
            verificationResolution.resolution = 'completed';
        }
        catch (error) {
            if (!(error instanceof NrError) ||
                error.nrErrors.includes('invalid verification request') || error.nrErrors.includes('unexpected error')) {
                throw error;
            }
        }
        const privateKey = await jose.importJWK(this.jwkPair.privateJwk);
        return await new jose.SignJWT(verificationResolution)
            .setProtectedHeader({ alg: this.jwkPair.privateJwk.alg })
            .setIssuedAt(verificationResolution.iat)
            .sign(privateKey);
    }
    /**
     * Checks if the cipherblock provided in a data exchange can be decrypted
     * with the published secret.
     *
     * @todo Check also data schema
     *
     * @param disputeRequest
     * @returns a signed resolution
     */
    async resolveDispute(disputeRequest) {
        await this.initialized;
        const { payload: drPayload } = await jwsDecode(disputeRequest);
        let porPayload;
        try {
            const decoded = await jwsDecode(drPayload.por);
            porPayload = decoded.payload;
        }
        catch (error) {
            throw new NrError(error, ['invalid por']);
        }
        const disputeResolution = {
            ...await this._resolution(drPayload.dataExchangeId, porPayload.exchange[drPayload.iss]),
            resolution: 'denied',
            type: 'dispute'
        };
        try {
            await checkDecryption(disputeRequest, this.dltAgent);
        }
        catch (error) {
            if (error instanceof NrError && error.nrErrors.includes('decryption failed')) {
                disputeResolution.resolution = 'accepted';
            }
            else {
                throw new NrError(error, ['cannot verify']);
            }
        }
        const privateKey = await jose.importJWK(this.jwkPair.privateJwk);
        return await new jose.SignJWT(disputeResolution)
            .setProtectedHeader({ alg: this.jwkPair.privateJwk.alg })
            .setIssuedAt(disputeResolution.iat)
            .sign(privateKey);
    }
    async _resolution(dataExchangeId, sub) {
        return {
            proofType: 'resolution',
            dataExchangeId,
            iat: Math.floor(Date.now() / 1000),
            iss: await parseJwk(this.jwkPair.publicJwk, true),
            sub
        };
    }
}

async function generateVerificationRequest(iss, dataExchangeId, por, privateJwk) {
    const payload = {
        proofType: 'request',
        iss,
        dataExchangeId,
        por,
        type: 'verificationRequest',
        iat: Math.floor(Date.now() / 1000)
    };
    const privateKey = await jose.importJWK(privateJwk);
    return await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: privateJwk.alg })
        .setIssuedAt(payload.iat)
        .sign(privateKey);
}

async function verifyResolution(resolution, pubJwk) {
    return await jwsDecode(resolution, pubJwk ?? ((header, payload) => {
        return JSON.parse(payload.iss);
    }));
}

var index$2 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    checkCompleteness: checkCompleteness,
    checkDecryption: checkDecryption,
    ConflictResolver: ConflictResolver,
    generateVerificationRequest: generateVerificationRequest,
    verifyPor: verifyPor,
    verifyResolution: verifyResolution
});

const defaultDltConfig = {
    gasLimit: 12500000,
    contract: contractConfig__default["default"]
};

/**
 * An abstract class that should be implemeneted by any agent providing connection to the smart contract of the non-repudiation protocol.
 */
class NrpDltAgent {
}

/**
 * A NRP DLT agent using the well known ethers.io library and, if required, wallet (for publishing secrets)
 */
class EthersIoAgent extends NrpDltAgent {
    constructor(dltConfig) {
        super();
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        this.provider = new ethers.ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
        this.contract = new ethers.ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider);
    }
    async getContractAddress() {
        return this.contract.address;
    }
}

/**
 * A DLT agent for the NRP dest using ethers.io.
 */
class EthersIoAgentDest extends EthersIoAgent {
    async getSecretFromLedger(signerAddress, exchangeId, timeout) {
        let secretBn = ethers.ethers.BigNumber.from(0);
        let timestampBn = ethers.ethers.BigNumber.from(0);
        const exchangeIdHex = parseHex(bigintConversion.bufToHex(b64__namespace.decode(exchangeId)), true);
        let counter = 0;
        do {
            try {
                ({ secret: secretBn, timestamp: timestampBn } = await this.contract.registry(parseHex(signerAddress, true), exchangeIdHex));
            }
            catch (error) {
                throw new NrError(error, ['cannot contact the ledger']);
            }
            if (secretBn.isZero()) {
                counter++;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        } while (secretBn.isZero() && counter < timeout);
        if (secretBn.isZero()) {
            throw new NrError(new Error(`timeout of ${timeout}s exceeded when querying the ledger and secret still not published`), ['secret not published']);
        }
        const hex = parseHex(secretBn.toHexString(), false);
        const iat = timestampBn.toNumber();
        return { hex, iat };
    }
}

class I3mWalletAgentDest extends EthersIoAgentDest {
}

/**
 * A DLT agent for the NRP orig using ethers.io.
 */
class EthersIoAgentOrig extends EthersIoAgent {
    constructor(dltConfig, privateKey) {
        super(dltConfig);
        /**
        * The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain
        */
        this.count = -1;
        let privKey;
        if (privateKey === undefined) {
            privKey = bigintCryptoUtils.randBytesSync(32);
        }
        else {
            privKey = (typeof privateKey === 'string') ? new Uint8Array(bigintConversion.hexToBuf(privateKey)) : privateKey;
        }
        const signingKey = new utils.SigningKey(privKey);
        this.signer = new ethers.Wallet(signingKey, this.provider);
    }
    /**
     * Publish the secret for a given data exchange on the ledger.
     *
     * @param secretHex - the secret in hexadecimal
     * @param exchangeId - the exchange id
     *
     * @returns a receipt of the deployment. In Ethereum-like DLTs it contains the transaction hash, which can be used to track the transaction on the ledger, and the nonce of the transaction
     */
    async deploySecret(secretHex, exchangeId) {
        const secret = ethers.ethers.BigNumber.from(parseHex(secretHex, true));
        const exchangeIdHex = parseHex(bigintConversion.bufToHex(b64__namespace.decode(exchangeId)), true);
        const unsignedTx = await this.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: this.dltConfig.gasLimit });
        unsignedTx.nonce = await this.nextNonce();
        unsignedTx.gasPrice = await this.signer.provider.getGasPrice();
        unsignedTx.chainId = (await this.signer.provider.getNetwork()).chainId;
        const signedTx = await this.signer.signTransaction(unsignedTx);
        const setRegistryTx = await this.signer.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
        return setRegistryTx.hash;
    }
    async getAddress() {
        return this.signer.address;
    }
    async nextNonce() {
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending'); // Nonce of the next transaction to be published (including nonces in pending state)
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

/**
 * A NRP DLT agent using ethers.io for reading from the smart contract and the i3m-wallet for signing transactions to the smart contract
 */
class I3mWalletAgent extends EthersIoAgent {
    constructor(session, did, dltConfig) {
        super(dltConfig);
        this.session = session;
        this.did = did;
    }
}

/**
 * A DLT agent for the NRP orig using ethers.io library and the i3m-wallet for signing transactions to the DLT
 */
class I3mWalletAgentOrig extends I3mWalletAgent {
    constructor() {
        super(...arguments);
        /**
        * The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain
        */
        this.count = -1;
    }
    async deploySecret(secretHex, exchangeId) {
        const secret = ethers.ethers.BigNumber.from(parseHex(secretHex, true));
        const exchangeIdHex = parseHex(bigintConversion.bufToHex(b64__namespace.decode(exchangeId)), true);
        const unsignedTx = await this.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: this.dltConfig.gasLimit });
        unsignedTx.nonce = await this.nextNonce();
        unsignedTx.gasLimit = unsignedTx.gasLimit?._hex;
        unsignedTx.gasPrice = (await this.provider.getGasPrice())._hex;
        unsignedTx.chainId = (await this.provider.getNetwork()).chainId;
        const address = await this.getAddress();
        unsignedTx.from = parseHex(address, true);
        const response = await this.session.send({
            url: `/identities/${this.did}/sign`,
            init: {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: 'Transaction',
                    data: unsignedTx
                })
            }
        });
        if (response.status !== 200) {
            throw new Error(response.body);
        }
        const json = JSON.parse(response.body);
        const signedTx = json.signature;
        const setRegistryTx = await this.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
        // const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
        return setRegistryTx.hash;
    }
    async getAddress() {
        const response = await this.session.send({
            url: `/identities/${this.did}/info`,
            init: {
                method: 'GET'
            }
        });
        const json = JSON.parse(response.body);
        return json.addresses[0]; // TODO: in the future there could be more than one address per DID
    }
    async nextNonce() {
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending'); // Nonce of the next transaction to be published (including nonces in pending state)
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

var index$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EthersIoAgentDest: EthersIoAgentDest,
    I3mWalletAgentDest: I3mWalletAgentDest,
    EthersIoAgentOrig: EthersIoAgentOrig,
    I3mWalletAgentOrig: I3mWalletAgentOrig
});

/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
class NonRepudiationDest {
    /**
     * @param agreement - a DataExchangeAgreement
     * @param privateJwk - the private key that will be used to sign the proofs
     * @param dltAgent - a DLT agent providing read connection to the ledger
     */
    constructor(agreement, privateJwk, dltAgent) {
        this.initialized = new Promise((resolve, reject) => {
            this.asyncConstructor(agreement, privateJwk, dltAgent).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async asyncConstructor(agreement, privateJwk, dltAgent) {
        this.agreement = await parseAgreement(agreement);
        this.jwkPairDest = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.dest)
        };
        this.publicJwkOrig = JSON.parse(agreement.orig);
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        this.dltAgent = dltAgent;
        const contractAddress = parseHex(await this.dltAgent.getContractAddress(), true);
        if (this.agreement.ledgerContractAddress !== contractAddress) {
            throw new Error(`Contract address ${contractAddress} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
        }
        this.block = {};
    }
    /**
     * Verifies a proof of origin against the received cipherblock.
     * If verification passes, `pop` and `cipherblock` are added to this.block
     *
     * @param poo - a Proof of Origin (PoO) in compact JWS format
     * @param cipherblock - a cipherblock as a JWE
     * @param options - time verification options
     * @returns the verified payload and protected header
     *
     */
    async verifyPoO(poo, cipherblock, options) {
        await this.initialized;
        const cipherblockDgst = b64__namespace.encode(await sha(cipherblock, this.agreement.hashAlg), true, false);
        const { payload } = await jwsDecode(poo);
        const dataExchangePreview = {
            ...this.agreement,
            cipherblockDgst,
            blockCommitment: payload.exchange.blockCommitment,
            secretCommitment: payload.exchange.secretCommitment
        };
        const dataExchange = {
            ...dataExchangePreview,
            id: await exchangeId(dataExchangePreview)
        };
        const expectedPayloadClaims = {
            proofType: 'PoO',
            iss: 'orig',
            exchange: dataExchange
        };
        const currentTimestamp = Date.now();
        const opts = {
            timestamp: currentTimestamp,
            notBefore: 'iat',
            notAfter: 'iat',
            ...options
        };
        const verified = await verifyProof(poo, expectedPayloadClaims, opts);
        this.block = {
            jwe: cipherblock,
            poo: {
                jws: poo,
                payload: verified.payload
            }
        };
        this.exchange = verified.payload.exchange;
        return verified;
    }
    /**
     * Creates the proof of reception (PoR).
     * Besides returning its value, it is also stored in `this.block.por`
     *
     * @returns the PoR as a compact JWS along with its decoded payload
     */
    async generatePoR() {
        await this.initialized;
        if (this.exchange === undefined || this.block.poo === undefined) {
            throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO');
        }
        const payload = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            poo: this.block.poo.jws
        };
        this.block.por = await createProof(payload, this.jwkPairDest.privateJwk);
        return this.block.por;
    }
    /**
     * Verifies a received Proof of Publication (PoP) and returns the secret
     * @param pop - a PoP in compact JWS
     * @param options - time related options for verification
     * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
     */
    async verifyPoP(pop, options) {
        await this.initialized;
        if (this.exchange === undefined || this.block.por === undefined || this.block.poo === undefined) {
            throw new Error('Cannot verify a PoP if not even a PoR have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            por: this.block.por.jws,
            secret: '',
            verificationCode: ''
        };
        const opts = {
            timestamp: Date.now(),
            notBefore: 'iat',
            notAfter: this.block.poo.payload.iat * 1000 + this.exchange.pooToPopDelay,
            ...options
        };
        const verified = await verifyProof(pop, expectedPayloadClaims, opts);
        const secret = JSON.parse(verified.payload.secret);
        this.block.secret = {
            hex: bigintConversion.bufToHex(b64__namespace.decode(secret.k)),
            jwk: secret
        };
        this.block.pop = {
            jws: pop,
            payload: verified.payload
        };
        return verified;
    }
    /**
     * Just in case the PoP is not received, the secret can be downloaded from the ledger.
     * The secret should be downloaded before poo.iat + pooToPop max delay.
     *
     * @returns the secret
     */
    async getSecretFromLedger() {
        await this.initialized;
        if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
            throw new Error('Cannot get secret if a PoR has not been sent before');
        }
        const currentTimestamp = Date.now();
        const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay;
        const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000);
        const { hex: secretHex, iat } = await this.dltAgent.getSecretFromLedger(this.agreement.ledgerSignerAddress, this.exchange.id, timeout);
        this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex);
        try {
            checkTimestamp(iat * 1000, this.block.por.payload.iat * 1000, this.block.poo.payload.iat * 1000 + this.exchange.pooToSecretDelay);
        }
        catch (error) {
            throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`, ['secret not published in time']);
        }
        return this.block.secret;
    }
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     */
    async decrypt() {
        await this.initialized;
        if (this.exchange === undefined) {
            throw new Error('No agreed exchange');
        }
        if (this.block.secret?.jwk === undefined) {
            throw new Error('Cannot decrypt without the secret');
        }
        if (this.block.jwe === undefined) {
            throw new Error('No cipherblock to decrypt');
        }
        const decryptedBlock = (await jweDecrypt(this.block.jwe, this.block.secret.jwk)).plaintext;
        const decryptedDgst = b64__namespace.encode(await sha(decryptedBlock, this.agreement.hashAlg), true, false);
        if (decryptedDgst !== this.exchange.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.raw = decryptedBlock;
        return decryptedBlock;
    }
    /**
     * Generates a verification request that can be used to query the
     * Conflict-Resolver Service for completeness of the non-repudiation protocol
     *
     * @returns the verification request as a compact JWS signed with 'dest's private key
     */
    async generateVerificationRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange');
        }
        return await generateVerificationRequest('dest', this.exchange.id, this.block.por.jws, this.jwkPairDest.privateJwk);
    }
    /**
     * Generates a dispute request that can be used to query the
     * Conflict-Resolver Service regarding impossibility to decrypt the cipherblock with the received secret
     *
     * @returns the dispute request as a compact JWS signed with 'dest's private key
     */
    async generateDisputeRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.block.jwe === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange and have received the cipherblock');
        }
        const payload = {
            proofType: 'request',
            iss: 'dest',
            por: this.block.por.jws,
            type: 'disputeRequest',
            cipherblock: this.block.jwe,
            iat: Math.floor(Date.now() / 1000),
            dataExchangeId: this.exchange.id
        };
        const privateKey = await importJwk(this.jwkPairDest.privateJwk);
        try {
            const jws = await new jose.SignJWT(payload)
                .setProtectedHeader({ alg: this.jwkPairDest.privateJwk.alg })
                .setIssuedAt(payload.iat)
                .sign(privateKey);
            return jws;
        }
        catch (error) {
            throw new NrError(error, ['unexpected error']);
        }
    }
}

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
class NonRepudiationOrig {
    /**
     * @param agreement - a DataExchangeAgreement
     * @param privateJwk - the private key that will be used to sign the proofs
     * @param block - the block of data to transmit in this data exchange
     * @param dltAgent - a DLT agent providing read-write connection to NRP smart contract
     */
    constructor(agreement, privateJwk, block, dltAgent) {
        this.jwkPairOrig = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.orig)
        };
        this.publicJwkDest = JSON.parse(agreement.dest);
        // @ts-expect-error I will end assigning the complete Block in the async init()
        this.block = {
            raw: block
        };
        this.initialized = new Promise((resolve, reject) => {
            this.init(agreement, dltAgent).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async init(agreement, dltAgent) {
        this.agreement = await parseAgreement(agreement);
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        const secret = await oneTimeSecret(this.agreement.encAlg);
        this.block = {
            ...this.block,
            secret,
            jwe: await jweEncrypt(this.block.raw, secret.jwk, this.agreement.encAlg)
        };
        const cipherblockDgst = b64__namespace.encode(await sha(this.block.jwe, this.agreement.hashAlg), true, false);
        const blockCommitment = b64__namespace.encode(await sha(this.block.raw, this.agreement.hashAlg), true, false);
        const secretCommitment = b64__namespace.encode(await sha(new Uint8Array(bigintConversion.hexToBuf(this.block.secret.hex)), this.agreement.hashAlg), true, false);
        const dataExchangePreview = {
            ...this.agreement,
            cipherblockDgst,
            blockCommitment,
            secretCommitment
        };
        const id = await exchangeId(dataExchangePreview);
        this.exchange = {
            ...dataExchangePreview,
            id
        };
        await this._dltSetup(dltAgent);
    }
    async _dltSetup(dltAgent) {
        this.dltAgent = dltAgent;
        const signerAddress = parseHex(await this.dltAgent.getAddress(), true);
        if (signerAddress !== this.exchange.ledgerSignerAddress) {
            throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address ${signerAddress} derived from the provided private key`);
        }
        const contractAddress = parseHex(await this.dltAgent.getContractAddress(), true);
        if (contractAddress !== parseHex(this.agreement.ledgerContractAddress, true)) {
            throw new Error(`Contract address in use ${contractAddress} does not meet the agreed one ${this.agreement.ledgerContractAddress}`);
        }
    }
    /**
     * Creates the proof of origin (PoO).
     * Besides returning its value, it is also stored in this.block.poo
     *
     * @returns a compact JWS with the PoO along with its decoded payload
     */
    async generatePoO() {
        await this.initialized;
        this.block.poo = await createProof({
            proofType: 'PoO',
            iss: 'orig',
            exchange: this.exchange
        }, this.jwkPairOrig.privateJwk);
        return this.block.poo;
    }
    /**
     * Verifies a proof of reception.
     * If verification passes, `por` is added to `this.block`
     *
     * @param por - A PoR in caompact JWS format
     * @param options - time-related verifications
     * @returns the verified payload and protected header
     */
    async verifyPoR(por, options) {
        await this.initialized;
        if (this.block.poo === undefined) {
            throw new Error('Cannot verify a PoR if not even a PoO have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            poo: this.block.poo.jws
        };
        const pooTs = this.block.poo.payload.iat * 1000;
        const opts = {
            timestamp: Date.now(),
            notBefore: pooTs,
            notAfter: pooTs + this.exchange.pooToPorDelay,
            ...options
        };
        const verified = await verifyProof(por, expectedPayloadClaims, opts);
        this.block.por = {
            jws: por,
            payload: verified.payload
        };
        return this.block.por;
    }
    /**
     * Creates the proof of publication (PoP).
     * Besides returning its value, it is also stored in `this.block.pop`
     *
     * @returns a compact JWS with the PoP
     */
    async generatePoP() {
        await this.initialized;
        if (this.block.por === undefined) {
            throw new Error('Before computing a PoP, you have first to have received and verified the PoR');
        }
        const verificationCode = await this.dltAgent.deploySecret(this.block.secret.hex, this.exchange.id);
        const payload = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            por: this.block.por.jws,
            secret: JSON.stringify(this.block.secret.jwk),
            verificationCode
        };
        this.block.pop = await createProof(payload, this.jwkPairOrig.privateJwk);
        return this.block.pop;
    }
    /**
     * Generates a verification request that can be used to query the
     * Conflict-Resolver Service for completeness of the non-repudiation protocol
     *
     * @returns the verification request as a compact JWS signed with 'orig's private key
     */
    async generateVerificationRequest() {
        await this.initialized;
        if (this.block.por === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange');
        }
        return await generateVerificationRequest('orig', this.exchange.id, this.block.por.jws, this.jwkPairOrig.privateJwk);
    }
}

var index = /*#__PURE__*/Object.freeze({
    __proto__: null,
    NonRepudiationDest: NonRepudiationDest,
    NonRepudiationOrig: NonRepudiationOrig
});

exports.ConflictResolution = index$2;
exports.ENC_ALGS = ENC_ALGS;
exports.EthersIoAgentDest = EthersIoAgentDest;
exports.EthersIoAgentOrig = EthersIoAgentOrig;
exports.HASH_ALGS = HASH_ALGS;
exports.I3mWalletAgentDest = I3mWalletAgentDest;
exports.I3mWalletAgentOrig = I3mWalletAgentOrig;
exports.NonRepudiationProtocol = index;
exports.NrError = NrError;
exports.SIGNING_ALGS = SIGNING_ALGS;
exports.Signers = index$1;
exports.checkTimestamp = checkTimestamp;
exports.createProof = createProof;
exports.defaultDltConfig = defaultDltConfig;
exports.exchangeId = exchangeId;
exports.generateKeys = generateKeys;
exports.importJwk = importJwk;
exports.jsonSort = jsonSort;
exports.jweDecrypt = jweDecrypt;
exports.jweEncrypt = jweEncrypt;
exports.jwsDecode = jwsDecode;
exports.oneTimeSecret = oneTimeSecret;
exports.parseAgreement = parseAgreement;
exports.parseHex = parseHex;
exports.parseJwk = parseJwk;
exports.sha = sha;
exports.verifyKeyPair = verifyKeyPair;
exports.verifyProof = verifyProof;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMvTnJFcnJvci50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vZ2VuZXJhdGVLZXlzLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9pbXBvcnRKd2sudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandzRGVjb2RlLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3RpbWVzdGFtcHMudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvanNvblNvcnQudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VIZXgudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VKd2sudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvc2hhLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9vbmVUaW1lU2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL2V4Y2hhbmdlL2V4Y2hhbmdlSWQudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzLnRzIiwiLi4vLi4vc3JjL3RzL2V4Y2hhbmdlL2NoZWNrQWdyZWVtZW50LnRzIiwiLi4vLi4vc3JjL3RzL3Byb29mcy9jcmVhdGVQcm9vZi50cyIsIi4uLy4uL3NyYy90cy9wcm9vZnMvdmVyaWZ5UHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi92ZXJpZnlQb3IudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9jaGVja0NvbXBsZXRlbmVzcy50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL2NoZWNrRGVjcnlwdGlvbi50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL0NvbmZsaWN0UmVzb2x2ZXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9nZW5lcmF0ZVZlcmlmaWNhdGlvblJlcXVlc3QudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi92ZXJpZnlSZXNvbHV0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9kZWZhdWx0RGx0Q29uZmlnLnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvTnJwRGx0QWdlbnQudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9FdGhlcnNJb0FnZW50LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvZGVzdC9FdGhlcnNJb0FnZW50RGVzdC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL2Rlc3QvSTNtV2FsbGV0QWdlbnREZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvb3JpZy9FdGhlcnNJb0FnZW50T3JpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL0kzbVdhbGxldEFnZW50LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvb3JpZy9JM21XYWxsZXRBZ2VudE9yaWcudHMiLCIuLi8uLi9zcmMvdHMvbm9uLXJlcHVkaWF0aW9uLXByb3RvY29sL05vblJlcHVkaWF0aW9uRGVzdC50cyIsIi4uLy4uL3NyYy90cy9ub24tcmVwdWRpYXRpb24tcHJvdG9jb2wvTm9uUmVwdWRpYXRpb25PcmlnLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJiNjQiLCJoZXhUb0J1ZiIsInJhbmRCeXRlcyIsIkVjIiwiaW1wb3J0SldLam9zZSIsIkNvbXBhY3RFbmNyeXB0IiwiY29tcGFjdERlY3J5cHQiLCJqd3RWZXJpZnkiLCJnZW5lcmF0ZVNlY3JldCIsImV4cG9ydEpXSyIsImJ1ZlRvSGV4IiwiYmFzZTY0ZGVjb2RlIiwiR2VuZXJhbFNpZ24iLCJnZW5lcmFsVmVyaWZ5IiwiaGFzaGFibGUiLCJTaWduSldUIiwiaW1wb3J0SldLIiwiY29udHJhY3RDb25maWciLCJldGhlcnMiLCJyYW5kQnl0ZXNTeW5jIiwiU2lnbmluZ0tleSIsIldhbGxldCJdLCJtYXBwaW5ncyI6Ijs7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
