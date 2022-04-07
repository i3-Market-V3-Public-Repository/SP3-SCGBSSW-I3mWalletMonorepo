'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var b64 = require('@juanelas/base64');
var bigintConversion = require('bigint-conversion');
var bigintCryptoUtils = require('bigint-crypto-utils');
var elliptic = require('elliptic');
var jose = require('jose');
var objectSha = require('object-sha');
var ethers = require('ethers');
var contractConfig = require('@i3m/non-repudiation-protocol-smart-contract');
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
                key = new Uint8Array(bigintConversion.hexToBuf(secret));
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

function parseHex(a, prefix0x = false) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/);
    if (hexMatch == null) {
        throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format']);
    }
    const hex = hexMatch[2].toLocaleLowerCase();
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

/** TO-DO: Could the json be imported from an npm package? */
const defaultDltConfig = {
    gasLimit: 12500000,
    rpcProviderUrl: '***REMOVED***',
    disable: false,
    contract: contractConfig__default["default"]
};

/**
 * An abstract class that should be implemeneted by any signer for the ledger.
 * A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation
 */
class WalletAgent {
}

/**
 * A ledger signer using an ethers.io Wallet.
 */
class EthersWalletAgent extends WalletAgent {
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
 * A ledger signer using an ethers.io Wallet.
 */
class EthersWalletAgentDest extends EthersWalletAgent {
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

class I3mWalletAgentDest extends EthersWalletAgentDest {
}

/**
 * A ledger signer using an ethers.io Wallet.
 */
class EthersWalletAgentOrig extends EthersWalletAgent {
    constructor(privateKey, dltConfig) {
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
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress()); // Nonce of the next transaction to be published (there could be already sent transactions that are not published)
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        console.log(`next nonce = ${this.count}; last published nonce = ${publishedCount - 1}`);
        return this.count;
    }
}

class I3mWalletAgent extends EthersWalletAgent {
    constructor(session, did, dltConfig) {
        super(dltConfig);
        this.session = session;
        this.did = did;
    }
}

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
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress()); // Nonce of the next transaction to be published (there could be already sent transactions that are not published)
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

var index$2 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EthersWalletAgentDest: EthersWalletAgentDest,
    I3mWalletAgentDest: I3mWalletAgentDest,
    EthersWalletAgentOrig: EthersWalletAgentOrig,
    I3mWalletAgentOrig: I3mWalletAgentOrig
});

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
     * @param walletAgent a wallet agent providing read-only access to the non-repudiation protocol smart contract
     */
    constructor(jwkPair, walletAgent) {
        this.jwkPair = jwkPair;
        if (walletAgent !== undefined) {
            this.wallet = walletAgent;
        }
        else {
            this.wallet = new EthersWalletAgentDest();
        }
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
            await checkCompleteness(verificationRequest, this.wallet);
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
            await checkDecryption(disputeRequest, this.wallet);
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

var index$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    checkCompleteness: checkCompleteness,
    checkDecryption: checkDecryption,
    ConflictResolver: ConflictResolver,
    generateVerificationRequest: generateVerificationRequest,
    verifyPor: verifyPor,
    verifyResolution: verifyResolution
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
     * @param walletAgent - a wallet agent providing read connection to the ledger
     */
    constructor(agreement, privateJwk, walletAgent) {
        this.initialized = new Promise((resolve, reject) => {
            this.asyncConstructor(agreement, privateJwk, walletAgent).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async asyncConstructor(agreement, privateJwk, walletAgent) {
        this.agreement = await parseAgreement(agreement);
        this.jwkPairDest = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.dest)
        };
        this.publicJwkOrig = JSON.parse(agreement.orig);
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        if (walletAgent !== undefined) {
            this.wallet = walletAgent;
        }
        else {
            this.wallet = new EthersWalletAgentDest();
        }
        const contractAddress = parseHex(await this.wallet.getContractAddress(), true);
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
        const { hex: secretHex, iat } = await this.wallet.getSecretFromLedger(this.agreement.ledgerSignerAddress, this.exchange.id, timeout);
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
    constructor(agreement, privateJwk, block, walletAgentOrPrivKey) {
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
            this.init(agreement, walletAgentOrPrivKey).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async init(agreement, walletAgentOrPrivKey) {
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
        await this._dltSetup(walletAgentOrPrivKey);
    }
    async _dltSetup(walletAgentOrPrivKey) {
        if (typeof walletAgentOrPrivKey === 'string') {
            this.wallet = new EthersWalletAgentOrig(walletAgentOrPrivKey);
        }
        else {
            this.wallet = walletAgentOrPrivKey;
        }
        const signerAddress = parseHex(await this.wallet.getAddress(), true);
        if (signerAddress !== this.exchange.ledgerSignerAddress) {
            throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address ${signerAddress} derived from the provided private key`);
        }
        const contractAddress = parseHex(await this.wallet.getContractAddress(), true);
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
        const verificationCode = await this.wallet.deploySecret(this.block.secret.hex, this.exchange.id);
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

exports.ConflictResolution = index$1;
exports.ENC_ALGS = ENC_ALGS;
exports.EthersWalletAgentDest = EthersWalletAgentDest;
exports.EthersWalletAgentOrig = EthersWalletAgentOrig;
exports.HASH_ALGS = HASH_ALGS;
exports.I3mWalletAgentDest = I3mWalletAgentDest;
exports.I3mWalletAgentOrig = I3mWalletAgentOrig;
exports.NonRepudiationProtocol = index;
exports.NrError = NrError;
exports.SIGNING_ALGS = SIGNING_ALGS;
exports.Signers = index$2;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMvTnJFcnJvci50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vZ2VuZXJhdGVLZXlzLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9pbXBvcnRKd2sudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandzRGVjb2RlLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9vbmVUaW1lU2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3RpbWVzdGFtcHMudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvanNvblNvcnQudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VIZXgudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VKd2sudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvc2hhLnRzIiwiLi4vLi4vc3JjL3RzL2V4Y2hhbmdlL2V4Y2hhbmdlSWQudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzLnRzIiwiLi4vLi4vc3JjL3RzL2V4Y2hhbmdlL2NoZWNrQWdyZWVtZW50LnRzIiwiLi4vLi4vc3JjL3RzL3Byb29mcy9jcmVhdGVQcm9vZi50cyIsIi4uLy4uL3NyYy90cy9wcm9vZnMvdmVyaWZ5UHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi92ZXJpZnlQb3IudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9jaGVja0NvbXBsZXRlbmVzcy50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL2NoZWNrRGVjcnlwdGlvbi50cyIsIi4uLy4uL3NyYy90cy9kbHQvZGVmYXVsdERsdENvbmZpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9XYWxsZXRBZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9FdGhlcnNXYWxsZXRBZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9kZXN0L0V0aGVyc1dhbGxldEFnZW50RGVzdC50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9kZXN0L0kzbVdhbGxldEFnZW50RGVzdC50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9vcmlnL0V0aGVyc1dhbGxldEFnZW50T3JpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9JM21XYWxsZXRBZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvd2FsbGV0LWFnZW50cy9vcmlnL0kzbVdhbGxldEFnZW50T3JpZy50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL0NvbmZsaWN0UmVzb2x2ZXIudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9nZW5lcmF0ZVZlcmlmaWNhdGlvblJlcXVlc3QudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi92ZXJpZnlSZXNvbHV0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL25vbi1yZXB1ZGlhdGlvbi1wcm90b2NvbC9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiLCIuLi8uLi9zcmMvdHMvbm9uLXJlcHVkaWF0aW9uLXByb3RvY29sL05vblJlcHVkaWF0aW9uT3JpZy50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiYjY0IiwiaGV4VG9CdWYiLCJyYW5kQnl0ZXMiLCJFYyIsImltcG9ydEpXS2pvc2UiLCJDb21wYWN0RW5jcnlwdCIsImNvbXBhY3REZWNyeXB0Iiwiand0VmVyaWZ5IiwiZ2VuZXJhdGVTZWNyZXQiLCJleHBvcnRKV0siLCJidWZUb0hleCIsImJhc2U2NGRlY29kZSIsIkdlbmVyYWxTaWduIiwiZ2VuZXJhbFZlcmlmeSIsImhhc2hhYmxlIiwiU2lnbkpXVCIsImNvbnRyYWN0Q29uZmlnIiwiZXRoZXJzIiwicmFu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QU0sQ0FBQyxTQUFTLEVBQUUsQ0FBQTtJQUVoQyxNQUFNLElBQUksR0FBRyxLQUFLLENBQUMsSUFBSSxFQUFFLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDLFFBQVEsQ0FBQyxTQUFTLEdBQUcsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0lBQ3RFLE1BQU0sSUFBSSxHQUFHLEtBQUssQ0FBQyxJQUFJLEVBQUUsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDdEUsSUFBQSxNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLFFBQVEsQ0FBQyxTQUFTLEdBQUcsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0FBRWxFLElBQUEsTUFBTSxDQUFDLEdBQUdILGNBQUcsQ0FBQyxNQUFNLENBQUNDLHlCQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFBO0FBQ2pELElBQUEsTUFBTSxDQUFDLEdBQUdELGNBQUcsQ0FBQyxNQUFNLENBQUNDLHlCQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFBO0FBQ2pELElBQUEsTUFBTSxDQUFDLEdBQUdELGNBQUcsQ0FBQyxNQUFNLENBQUNDLHlCQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFBO0FBRWpELElBQUEsTUFBTSxVQUFVLEdBQVEsRUFBRSxHQUFHLEVBQUUsSUFBSSxFQUFFLEdBQUcsRUFBRSxVQUFVLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsR0FBRyxFQUFFLENBQUE7QUFFcEUsSUFBQSxNQUFNLFNBQVMsR0FBUSxFQUFFLEdBQUcsVUFBVSxFQUFFLENBQUE7SUFDeEMsT0FBTyxTQUFTLENBQUMsQ0FBQyxDQUFBO0lBRWxCLE9BQU87UUFDTCxTQUFTO1FBQ1QsVUFBVTtLQUNYLENBQUE7QUFD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
