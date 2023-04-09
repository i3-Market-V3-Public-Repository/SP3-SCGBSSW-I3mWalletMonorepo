import * as b64 from '@juanelas/base64';
import { decode } from '@juanelas/base64';
import { hexToBuf, parseHex as parseHex$1, bufToHex } from 'bigint-conversion';
import { randBytes, randBytesSync } from 'bigint-crypto-utils';
import elliptic from 'elliptic';
import { importJWK, CompactEncrypt, decodeProtectedHeader, compactDecrypt, jwtVerify, generateSecret, exportJWK, GeneralSign, generalVerify, SignJWT } from 'jose';
import { hashable } from 'object-sha';
import { ethers, Wallet } from 'ethers';
import { SigningKey } from 'ethers/lib/utils';
import Ajv from 'ajv-draft-04';
import addFormats from 'ajv-formats';
import _ from 'lodash';

const HASH_ALGS = ['SHA-256', 'SHA-384', 'SHA-512'];
const SIGNING_ALGS = ['ES256', 'ES384', 'ES512'];
const ENC_ALGS = ['A128GCM', 'A256GCM'];
const KEY_AGREEMENT_ALGS = ['ECDH-ES'];

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
        const errors = this.nrErrors.concat(nrErrors);
        this.nrErrors = [...(new Set(errors))];
    }
}

const { ec: Ec } = elliptic;
async function generateKeys(alg, privateKey, base64) {
    if (!SIGNING_ALGS.includes(alg))
        throw new NrError(new RangeError(`Invalid signature algorithm '${alg}''. Allowed algorithms are ${SIGNING_ALGS.toString()}`), ['invalid algorithm']);
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
                privKeyBuf = b64.decode(privateKey);
            }
            else {
                privKeyBuf = new Uint8Array(hexToBuf(privateKey));
            }
        }
        else {
            privKeyBuf = privateKey;
        }
    }
    else {
        privKeyBuf = new Uint8Array(await randBytes(keyLength));
    }
    const ec = new Ec('p' + namedCurve.substring(namedCurve.length - 3));
    const ecPriv = ec.keyFromPrivate(privKeyBuf);
    const ecPub = ecPriv.getPublic();
    const xHex = ecPub.getX().toString('hex').padStart(keyLength * 2, '0');
    const yHex = ecPub.getY().toString('hex').padStart(keyLength * 2, '0');
    const dHex = ecPriv.getPrivate('hex').padStart(keyLength * 2, '0');
    const x = b64.encode(hexToBuf(xHex), true, false);
    const y = b64.encode(hexToBuf(yHex), true, false);
    const d = b64.encode(hexToBuf(dHex), true, false);
    const privateJwk = { kty: 'EC', crv: namedCurve, x, y, d, alg };
    const publicJwk = { ...privateJwk };
    delete publicJwk.d;
    return {
        publicJwk,
        privateJwk
    };
}

async function importJwk(jwk, alg) {
    const jwkAlg = alg === undefined ? jwk.alg : alg;
    const algs = ENC_ALGS.concat(SIGNING_ALGS).concat(KEY_AGREEMENT_ALGS);
    if (!algs.includes(jwkAlg)) {
        throw new NrError('invalid alg. Must be one of: ' + algs.join(','), ['invalid algorithm']);
    }
    try {
        const key = await importJWK(jwk, alg);
        if (key === undefined || key === null) {
            throw new NrError(new Error('failed importing keys'), ['invalid key']);
        }
        return key;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

async function jweEncrypt(block, secretOrPublicKey, encAlg) {
    let alg;
    let enc;
    const jwk = { ...secretOrPublicKey };
    if (ENC_ALGS.includes(secretOrPublicKey.alg)) {
        alg = 'dir';
        enc = encAlg !== undefined ? encAlg : secretOrPublicKey.alg;
    }
    else if (SIGNING_ALGS.concat(KEY_AGREEMENT_ALGS).includes(secretOrPublicKey.alg)) {
        if (encAlg === undefined) {
            throw new NrError('An encryption algorith encAlg for content encryption should be provided. Allowed values are: ' + ENC_ALGS.join(','), ['encryption failed']);
        }
        enc = encAlg;
        alg = 'ECDH-ES';
        jwk.alg = alg;
    }
    else {
        throw new NrError(`Not a valid symmetric or assymetric alg: ${secretOrPublicKey.alg}`, ['encryption failed', 'invalid key', 'invalid algorithm']);
    }
    const key = await importJwk(jwk);
    let jwe;
    try {
        jwe = await new CompactEncrypt(block)
            .setProtectedHeader({ alg, enc, kid: secretOrPublicKey.kid })
            .encrypt(key);
        return jwe;
    }
    catch (error) {
        throw new NrError(error, ['encryption failed']);
    }
}
async function jweDecrypt(jwe, secretOrPrivateKey) {
    try {
        const jwk = { ...secretOrPrivateKey };
        const { alg, enc } = decodeProtectedHeader(jwe);
        if (alg === undefined || enc === undefined) {
            throw new NrError('missing enc or alg in jwe header', ['invalid format']);
        }
        if (alg === 'ECDH-ES') {
            jwk.alg = alg;
        }
        const key = await importJwk(jwk);
        return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [enc] });
    }
    catch (error) {
        const nrError = new NrError(error, ['decryption failed']);
        throw nrError;
    }
}

async function jwsDecode(jws, publicJwk) {
    const regex = /^([a-zA-Z0-9_-]+)\.{1,2}([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/;
    const match = jws.match(regex);
    if (match === null) {
        throw new NrError(new Error(`${jws} is not a JWS`), ['not a compact jws']);
    }
    let header;
    let payload;
    try {
        header = JSON.parse(b64.decode(match[1], true));
        payload = JSON.parse(b64.decode(match[2], true));
    }
    catch (error) {
        throw new NrError(error, ['invalid format', 'not a compact jws']);
    }
    if (publicJwk !== undefined) {
        const pubJwk = (typeof publicJwk === 'function') ? await publicJwk(header, payload) : publicJwk;
        const pubKey = await importJwk(pubJwk);
        try {
            const verified = await jwtVerify(jws, pubKey);
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

function algByteLength(alg) {
    const algs = ENC_ALGS.concat(HASH_ALGS).concat(SIGNING_ALGS);
    if (algs.includes(alg)) {
        return Number(alg.match(/\d{3}/)[0]) / 8;
    }
    throw new NrError('unsupported algorithm', ['invalid algorithm']);
}

async function oneTimeSecret(encAlg, secret, base64) {
    let key;
    if (!ENC_ALGS.includes(encAlg)) {
        throw new NrError(new Error(`Invalid encAlg '${encAlg}'. Supported values are: ${ENC_ALGS.toString()}`), ['invalid algorithm']);
    }
    const secretLength = algByteLength(encAlg);
    if (secret !== undefined) {
        if (typeof secret === 'string') {
            if (base64 === true) {
                key = b64.decode(secret);
            }
            else {
                const parsedSecret = parseHex$1(secret, false);
                if (parsedSecret !== parseHex$1(secret, false, secretLength)) {
                    throw new NrError(new RangeError(`Expected hex length ${secretLength * 2} does not meet provided one ${parsedSecret.length / 2}`), ['invalid key']);
                }
                key = new Uint8Array(hexToBuf(secret));
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
            key = await generateSecret(encAlg, { extractable: true });
        }
        catch (error) {
            throw new NrError(error, ['unexpected error']);
        }
    }
    const jwk = await exportJWK(key);
    jwk.alg = encAlg;
    return { jwk: jwk, hex: bufToHex(decode(jwk.k), false, secretLength) };
}

async function verifyKeyPair(pubJWK, privJWK) {
    if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
        throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg');
    }
    const pubKey = await importJwk(pubJWK);
    const privKey = await importJwk(privJWK);
    try {
        const nonce = await randBytes(16);
        const jws = await new GeneralSign(nonce)
            .addSignature(privKey)
            .setProtectedHeader({ alg: privJWK.alg })
            .sign();
        await generalVerify(jws, pubKey);
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
        return obj.sort().map(jsonSort);
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
    try {
        return parseHex$1(a, prefix0x, byteLength);
    }
    catch (error) {
        throw new NrError(error, ['invalid format']);
    }
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
    const algorithms = HASH_ALGS;
    if (!algorithms.includes(algorithm)) {
        throw new NrError(new RangeError(`Valid hash algorith values are any of ${JSON.stringify(algorithms)}`), ['invalid algorithm']);
    }
    const encoder = new TextEncoder();
    const hashInput = (typeof input === 'string') ? encoder.encode(input).buffer : input;
    try {
        let digest;
        if (true) {
            digest = new Uint8Array(await crypto.subtle.digest(algorithm, hashInput));
        }
        return digest;
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
    }
}

function parseAddress(a) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]{40})$/);
    if (hexMatch == null) {
        throw new RangeError('incorrect address format');
    }
    try {
        const hex = parseHex(a, true, 20);
        return ethers.utils.getAddress(hex);
    }
    catch (error) {
        throw new NrError(error, ['invalid EIP-55 address']);
    }
}

function getDltAddress(didOrKeyInHex) {
    const didRegEx = /^did:ethr:(\w+:)?(0x[0-9a-fA-F]{40}[0-9a-fA-F]{26}?)$/;
    const match = didOrKeyInHex.match(didRegEx);
    const key = (match !== null) ? match[match.length - 1] : didOrKeyInHex;
    try {
        return ethers.utils.computeAddress(key);
    }
    catch (error) {
        throw new NrError('no a DID or a valid public or private key', ['invalid format']);
    }
}

async function exchangeId(exchange) {
    return b64.encode(await sha(hashable(exchange), 'SHA-256'), true, false);
}

async function createProof(payload, privateJwk) {
    if (payload.iss === undefined) {
        throw new Error('Payload iss should be set to either "orig" or "dest"');
    }
    const publicJwk = JSON.parse(payload.exchange[payload.iss]);
    await verifyKeyPair(publicJwk, privateJwk);
    const privateKey = await importJwk(privateJwk);
    const alg = privateJwk.alg;
    const proofPayload = {
        ...payload,
        iat: Math.floor(Date.now() / 1000)
    };
    const jws = await new SignJWT(proofPayload)
        .setProtectedHeader({ alg })
        .setIssuedAt(proofPayload.iat)
        .sign(privateKey);
    return {
        jws,
        payload: proofPayload
    };
}

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
    const issuer = payload.exchange[payload.iss];
    if (hashable(publicJwk) !== hashable(JSON.parse(issuer))) {
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
        else if (expectedClaimsDict[key] !== '' && hashable(expectedClaimsDict[key]) !== hashable(payload[key])) {
            throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedClaimsDict[key], undefined, 2)}`);
        }
    }
    return verification;
}
function checkDataExchange(dataExchange, expectedDataExchange) {
    const claims = ['id', 'orig', 'dest', 'hashAlg', 'cipherblockDgst', 'blockCommitment', 'blockCommitment', 'secretCommitment', 'schema'];
    for (const claim of claims) {
        if (claim !== 'schema' && (dataExchange[claim] === undefined || dataExchange[claim] === '')) {
            throw new Error(`${claim} is missing on dataExchange.\ndataExchange: ${JSON.stringify(dataExchange, undefined, 2)}`);
        }
    }
    for (const key in expectedDataExchange) {
        if (expectedDataExchange[key] !== '' && hashable(expectedDataExchange[key]) !== hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
        }
    }
}

async function verifyPor(por, wallet, connectionTimeout = 10) {
    const { payload: porPayload } = await jwsDecode(por);
    const exchange = porPayload.exchange;
    const dataExchangePreview = { ...exchange };
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
        const secret = await wallet.getSecretFromLedger(algByteLength(exchange.encAlg), exchange.ledgerSignerAddress, exchange.id, connectionTimeout);
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
    const cipherblockDgst = b64.encode(await sha(drPayload.cipherblock, porPayload.exchange.hashAlg), true, false);
    if (cipherblockDgst !== porPayload.exchange.cipherblockDgst) {
        throw new NrError(new Error('cipherblock does not meet the committed (and already accepted) one'), ['invalid dispute request']);
    }
    await jweDecrypt(drPayload.cipherblock, (await (oneTimeSecret(porPayload.exchange.encAlg, secretHex))).jwk);
    return {
        pooPayload,
        porPayload,
        drPayload,
        destPublicJwk,
        origPublicJwk
    };
}

class ConflictResolver {
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
    async init() {
        await verifyKeyPair(this.jwkPair.publicJwk, this.jwkPair.privateJwk);
    }
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
        const privateKey = await importJWK(this.jwkPair.privateJwk);
        return await new SignJWT(verificationResolution)
            .setProtectedHeader({ alg: this.jwkPair.privateJwk.alg })
            .setIssuedAt(verificationResolution.iat)
            .sign(privateKey);
    }
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
        const privateKey = await importJWK(this.jwkPair.privateJwk);
        return await new SignJWT(disputeResolution)
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
    const privateKey = await importJWK(privateJwk);
    return await new SignJWT(payload)
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
    ConflictResolver: ConflictResolver,
    checkCompleteness: checkCompleteness,
    checkDecryption: checkDecryption,
    generateVerificationRequest: generateVerificationRequest,
    verifyPor: verifyPor,
    verifyResolution: verifyResolution
});

var address="0x8d407A1722633bDD1dcf221474be7a44C05d7c2F";var abi=[{anonymous:false,inputs:[{indexed:false,internalType:"address",name:"sender",type:"address"},{indexed:false,internalType:"uint256",name:"dataExchangeId",type:"uint256"},{indexed:false,internalType:"uint256",name:"timestamp",type:"uint256"},{indexed:false,internalType:"uint256",name:"secret",type:"uint256"}],name:"Registration",type:"event"},{inputs:[{internalType:"address",name:"",type:"address"},{internalType:"uint256",name:"",type:"uint256"}],name:"registry",outputs:[{internalType:"uint256",name:"timestamp",type:"uint256"},{internalType:"uint256",name:"secret",type:"uint256"}],stateMutability:"view",type:"function"},{inputs:[{internalType:"uint256",name:"_dataExchangeId",type:"uint256"},{internalType:"uint256",name:"_secret",type:"uint256"}],name:"setRegistry",outputs:[],stateMutability:"nonpayable",type:"function"}];var transactionHash="0x6a3828f8fe232819dc40ca66f93930b3bd1619db31a67ec34b44446b3e7c8289";var receipt={to:null,from:"0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903",contractAddress:"0x8d407A1722633bDD1dcf221474be7a44C05d7c2F",transactionIndex:0,gasUsed:"253928",logsBloom:"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",blockHash:"0x0118672bb9b27679e616831d056d36291dd20cfe88c3ee2abd8f2dfce579cad4",transactionHash:"0x6a3828f8fe232819dc40ca66f93930b3bd1619db31a67ec34b44446b3e7c8289",logs:[],blockNumber:119389,cumulativeGasUsed:"253928",status:1,byzantium:true};var args=[];var solcInputHash="c528a37588793ef74285d75e08d6b8eb";var metadata="{\"compiler\":{\"version\":\"0.8.4+commit.c7e474f2\"},\"language\":\"Solidity\",\"output\":{\"abi\":[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"dataExchangeId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"secret\",\"type\":\"uint256\"}],\"name\":\"Registration\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"registry\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"secret\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_dataExchangeId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_secret\",\"type\":\"uint256\"}],\"name\":\"setRegistry\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\"devdoc\":{\"kind\":\"dev\",\"methods\":{},\"version\":1},\"userdoc\":{\"kind\":\"user\",\"methods\":{},\"version\":1}},\"settings\":{\"compilationTarget\":{\"contracts/NonRepudiation.sol\":\"NonRepudiation\"},\"evmVersion\":\"istanbul\",\"libraries\":{},\"metadata\":{\"bytecodeHash\":\"ipfs\",\"useLiteralContent\":true},\"optimizer\":{\"enabled\":false,\"runs\":200},\"remappings\":[]},\"sources\":{\"contracts/NonRepudiation.sol\":{\"content\":\"//SPDX-License-Identifier: Unlicense\\npragma solidity ^0.8.0;\\n\\ncontract NonRepudiation {\\n    struct Proof {\\n        uint256 timestamp;\\n        uint256 secret;\\n    }\\n    mapping(address => mapping (uint256 => Proof)) public registry;\\n    event Registration(address sender, uint256 dataExchangeId, uint256 timestamp, uint256 secret);\\n\\n    function setRegistry(uint256 _dataExchangeId, uint256 _secret) public {\\n        require(registry[msg.sender][_dataExchangeId].secret == 0);\\n        registry[msg.sender][_dataExchangeId] = Proof(block.timestamp, _secret);\\n        emit Registration(msg.sender, _dataExchangeId, block.timestamp, _secret);\\n    }\\n}\\n\",\"keccak256\":\"0x8d371257a9b03c9102f158323e61f56ce49dd8489bd92c5a7d8abc3d9f6f8399\",\"license\":\"Unlicense\"}},\"version\":1}";var bytecode="0x608060405234801561001057600080fd5b506103a2806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b6100556004803603810190610050919061023a565b610088565b005b610071600480360381019061006c91906101fe565b6101a3565b60405161007f9291906102d9565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060010154146100e757600080fd5b6040518060400160405280428152602001828152506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060008201518160000155602082015181600101559050507faa58599838af2e5e0f3251cfbb4eac5d5d447ded49f6b0ac28d6b44098224e63338342846040516101979493929190610294565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150508060000154908060010154905082565b6000813590506101e38161033e565b92915050565b6000813590506101f881610355565b92915050565b6000806040838503121561021157600080fd5b600061021f858286016101d4565b9250506020610230858286016101e9565b9150509250929050565b6000806040838503121561024d57600080fd5b600061025b858286016101e9565b925050602061026c858286016101e9565b9150509250929050565b61027f81610302565b82525050565b61028e81610334565b82525050565b60006080820190506102a96000830187610276565b6102b66020830186610285565b6102c36040830185610285565b6102d06060830184610285565b95945050505050565b60006040820190506102ee6000830185610285565b6102fb6020830184610285565b9392505050565b600061030d82610314565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b61034781610302565b811461035257600080fd5b50565b61035e81610334565b811461036957600080fd5b5056fea26469706673582212204fd0fc653fb487221da9a14a4ca5d5499f9e9bc7b27ac8ab0f8d397fd6e3148564736f6c63430008040033";var deployedBytecode="0x608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b6100556004803603810190610050919061023a565b610088565b005b610071600480360381019061006c91906101fe565b6101a3565b60405161007f9291906102d9565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060010154146100e757600080fd5b6040518060400160405280428152602001828152506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060008201518160000155602082015181600101559050507faa58599838af2e5e0f3251cfbb4eac5d5d447ded49f6b0ac28d6b44098224e63338342846040516101979493929190610294565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150508060000154908060010154905082565b6000813590506101e38161033e565b92915050565b6000813590506101f881610355565b92915050565b6000806040838503121561021157600080fd5b600061021f858286016101d4565b9250506020610230858286016101e9565b9150509250929050565b6000806040838503121561024d57600080fd5b600061025b858286016101e9565b925050602061026c858286016101e9565b9150509250929050565b61027f81610302565b82525050565b61028e81610334565b82525050565b60006080820190506102a96000830187610276565b6102b66020830186610285565b6102c36040830185610285565b6102d06060830184610285565b95945050505050565b60006040820190506102ee6000830185610285565b6102fb6020830184610285565b9392505050565b600061030d82610314565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b61034781610302565b811461035257600080fd5b50565b61035e81610334565b811461036957600080fd5b5056fea26469706673582212204fd0fc653fb487221da9a14a4ca5d5499f9e9bc7b27ac8ab0f8d397fd6e3148564736f6c63430008040033";var devdoc={kind:"dev",methods:{},version:1};var userdoc={kind:"user",methods:{},version:1};var storageLayout={storage:[{astId:13,contract:"contracts/NonRepudiation.sol:NonRepudiation",label:"registry",offset:0,slot:"0",type:"t_mapping(t_address,t_mapping(t_uint256,t_struct(Proof)6_storage))"}],types:{t_address:{encoding:"inplace",label:"address",numberOfBytes:"20"},"t_mapping(t_address,t_mapping(t_uint256,t_struct(Proof)6_storage))":{encoding:"mapping",key:"t_address",label:"mapping(address => mapping(uint256 => struct NonRepudiation.Proof))",numberOfBytes:"32",value:"t_mapping(t_uint256,t_struct(Proof)6_storage)"},"t_mapping(t_uint256,t_struct(Proof)6_storage)":{encoding:"mapping",key:"t_uint256",label:"mapping(uint256 => struct NonRepudiation.Proof)",numberOfBytes:"32",value:"t_struct(Proof)6_storage"},"t_struct(Proof)6_storage":{encoding:"inplace",label:"struct NonRepudiation.Proof",members:[{astId:3,contract:"contracts/NonRepudiation.sol:NonRepudiation",label:"timestamp",offset:0,slot:"0",type:"t_uint256"},{astId:5,contract:"contracts/NonRepudiation.sol:NonRepudiation",label:"secret",offset:0,slot:"1",type:"t_uint256"}],numberOfBytes:"64"},t_uint256:{encoding:"inplace",label:"uint256",numberOfBytes:"32"}}};var contractConfig = {address:address,abi:abi,transactionHash:transactionHash,receipt:receipt,args:args,solcInputHash:solcInputHash,metadata:metadata,bytecode:bytecode,deployedBytecode:deployedBytecode,devdoc:devdoc,userdoc:userdoc,storageLayout:storageLayout};

const defaultDltConfig = {
    gasLimit: 12500000,
    contract: contractConfig
};

async function getSecretFromLedger(contract, signerAddress, exchangeId, timeout, secretLength) {
    let secretBn = ethers.BigNumber.from(0);
    let timestampBn = ethers.BigNumber.from(0);
    const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId)), true);
    let counter = 0;
    do {
        try {
            ({ secret: secretBn, timestamp: timestampBn } = await contract.registry(parseHex(signerAddress, true), exchangeIdHex));
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
    const hex = parseHex(secretBn.toHexString(), false, secretLength);
    const iat = timestampBn.toNumber();
    return { hex, iat };
}
async function secretUnisgnedTransaction(secretHex, exchangeId, agent) {
    const secret = ethers.BigNumber.from(parseHex(secretHex, true));
    const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId)), true);
    const unsignedTx = await agent.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: agent.dltConfig.gasLimit });
    unsignedTx.nonce = await agent.nextNonce();
    unsignedTx.gasLimit = unsignedTx.gasLimit?._hex;
    unsignedTx.gasPrice = (await agent.provider.getGasPrice())._hex;
    unsignedTx.chainId = (await agent.provider.getNetwork()).chainId;
    const address = await agent.getAddress();
    unsignedTx.from = parseHex(address, true);
    return unsignedTx;
}

class NrpDltAgent {
}

class EthersIoAgent extends NrpDltAgent {
    constructor(dltConfig) {
        super();
        this.initialized = new Promise((resolve, reject) => {
            if (dltConfig !== null && typeof dltConfig === 'object' && typeof dltConfig.then === 'function') {
                dltConfig.then(dltConfig2 => {
                    this.dltConfig = {
                        ...defaultDltConfig,
                        ...dltConfig2
                    };
                    this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
                    this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider);
                    resolve(true);
                }).catch((reason) => reject(reason));
            }
            else {
                this.dltConfig = {
                    ...defaultDltConfig,
                    ...dltConfig
                };
                this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
                this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider);
                resolve(true);
            }
        });
    }
    async getContractAddress() {
        await this.initialized;
        return this.contract.address;
    }
}

class EthersIoAgentDest extends EthersIoAgent {
    async getSecretFromLedger(secretLength, signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout, secretLength);
    }
}

class I3mWalletAgent extends EthersIoAgent {
    constructor(wallet, did, dltConfig) {
        const dltConfigPromise = new Promise((resolve, reject) => {
            wallet.providerinfo.get().then((providerInfo) => {
                const rpcProviderUrl = providerInfo.rpcUrl;
                if (rpcProviderUrl === undefined) {
                    reject(new Error('wallet is not connected to RPC endpoint'));
                }
                else {
                    resolve({
                        ...dltConfig,
                        rpcProviderUrl
                    });
                }
            }).catch((reason) => { reject(reason); });
        });
        super(dltConfigPromise);
        this.wallet = wallet;
        this.did = did;
    }
}

class I3mWalletAgentDest extends I3mWalletAgent {
    async getSecretFromLedger(secretLength, signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout, secretLength);
    }
}

class I3mServerWalletAgent extends EthersIoAgent {
    constructor(serverWallet, did, dltConfig) {
        const dltConfigPromise = new Promise((resolve, reject) => {
            serverWallet.providerinfoGet().then((providerInfo) => {
                const rpcProviderUrl = providerInfo.rpcUrl;
                if (rpcProviderUrl === undefined) {
                    reject(new Error('wallet is not connected to RPC endpoint'));
                }
                else {
                    resolve({
                        ...dltConfig,
                        rpcProviderUrl
                    });
                }
            }).catch((reason) => { reject(reason); });
        });
        super(dltConfigPromise);
        this.wallet = serverWallet;
        this.did = did;
    }
}

class I3mServerWalletAgentDest extends I3mServerWalletAgent {
    async getSecretFromLedger(secretLength, signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout, secretLength);
    }
}

class EthersIoAgentOrig extends EthersIoAgent {
    constructor(dltConfig, privateKey) {
        super(dltConfig);
        this.count = -1;
        let privKey;
        if (privateKey === undefined) {
            privKey = randBytesSync(32);
        }
        else {
            privKey = (typeof privateKey === 'string') ? new Uint8Array(hexToBuf(privateKey)) : privateKey;
        }
        const signingKey = new SigningKey(privKey);
        this.signer = new Wallet(signingKey, this.provider);
    }
    async deploySecret(secretHex, exchangeId) {
        await this.initialized;
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const signedTx = await this.signer.signTransaction(unsignedTx);
        const setRegistryTx = await this.signer.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        await this.initialized;
        return this.signer.address;
    }
    async nextNonce() {
        await this.initialized;
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending');
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

class I3mWalletAgentOrig extends I3mWalletAgent {
    constructor() {
        super(...arguments);
        this.count = -1;
    }
    async deploySecret(secretHex, exchangeId) {
        await this.initialized;
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const response = await this.wallet.identities.sign({ did: this.did }, {
            type: 'Transaction',
            data: unsignedTx
        });
        const signedTx = response.signature;
        const setRegistryTx = await this.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        await this.initialized;
        const json = await this.wallet.identities.info({ did: this.did });
        if (json.addresses === undefined) {
            throw new NrError(new Error('no addresses for did ' + this.did), ['unexpected error']);
        }
        return json.addresses[0];
    }
    async nextNonce() {
        await this.initialized;
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending');
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

class I3mServerWalletAgentOrig extends I3mServerWalletAgent {
    constructor() {
        super(...arguments);
        this.count = -1;
    }
    async deploySecret(secretHex, exchangeId) {
        await this.initialized;
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const signedTx = (await this.wallet.identitySign({ did: this.did }, { type: 'Transaction', data: unsignedTx })).signature;
        const setRegistryTx = await this.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        await this.initialized;
        const json = await this.wallet.identityInfo({ did: this.did });
        if (json.addresses === undefined) {
            throw new NrError(`Can't get address for did: ${this.did}`, ['unexpected error']);
        }
        return json.addresses[0];
    }
    async nextNonce() {
        await this.initialized;
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending');
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

var index$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EthersIoAgentDest: EthersIoAgentDest,
    EthersIoAgentOrig: EthersIoAgentOrig,
    I3mServerWalletAgentDest: I3mServerWalletAgentDest,
    I3mServerWalletAgentOrig: I3mServerWalletAgentOrig,
    I3mWalletAgentDest: I3mWalletAgentDest,
    I3mWalletAgentOrig: I3mWalletAgentOrig
});

var openapi="3.0.3";var info={version:"v2",title:"i3M-Wallet Developers API",description:"i3M-Wallet Developers API that can be used to interact with the i3M-Wallet. In production it is encapsulated inside a secure connection. Please use the @i3m/wallet-protocol-api to interact with the wallet.",license:{name:"EUPL-1.2",url:"https://joinup.ec.europa.eu/sites/default/files/custom-page/attachment/2020-03/EUPL-1.2%20EN.txt"},contact:{name:"Juan Hernández Serrano",email:"j.hernandez@upc.edu",url:"https://github.com/juanelas"}};var tags=[{name:"identities",description:"Endpoints to manage identities (DIDs).\n"},{name:"resources",description:"Besides identities, the wallet MAY securely store arbitrary resources in a secure vault, which may be selectively disclosed upon request. Currently storing verifiable credentials\n"},{name:"selectiveDisclosure",description:"Ednpoints for the selective disclosure process (used to present verifiable credentials)\n"},{name:"transaction",description:"Endpoints for deploying signed transactions to the DLT the wallet is connected to.\n"},{name:"utils",description:"Additional helpler functions\n"}];var paths={"/identities":{get:{summary:"List all DIDs",operationId:"identityList","x-eov-operation-handler":"identities",tags:["identities"],parameters:[{"in":"query",name:"alias",schema:{type:"string",description:"An alias for the identity"}}],responses:{"200":{description:"An array of identities",content:{"application/json":{schema:{title:"IdentityListInput",description:"A list of DIDs",type:"array",items:{type:"object",properties:{did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["did"]}}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}},post:{summary:"Create an account",operationId:"identityCreate","x-eov-operation-handler":"identities",tags:["identities"],requestBody:{description:"Create a DID.",required:false,content:{"application/json":{schema:{title:"IdentityCreateInput",description:"Besides the here defined options, provider specific properties should be added here if necessary, e.g. \"path\" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).\n",type:"object",properties:{alias:{type:"string"}},additionalProperties:true}}}},responses:{"201":{description:"the ID and type of the created account",content:{"application/json":{schema:{title:"IdentityCreateOutput",description:"It returns the account id and type\n",type:"object",properties:{did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["did"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/identities/select":{get:{summary:"Gets an identity selected by the user.",operationId:"identitySelect","x-eov-operation-handler":"identities",tags:["identities"],parameters:[{"in":"query",name:"reason",schema:{type:"string",description:"Message to show to the user with the reason to pick an identity"}}],responses:{"200":{description:"Selected identity",content:{"application/json":{schema:{title:"IdentitySelectOutput",type:"object",properties:{did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["did"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/identities/{did}/sign":{post:{summary:"Signs a message",operationId:"identitySign","x-eov-operation-handler":"identities",tags:["identities"],parameters:[{"in":"path",name:"did",schema:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},required:true}],requestBody:{description:"Data to sign.",required:true,content:{"application/json":{schema:{title:"SignInput",oneOf:[{title:"SignTransaction",type:"object",properties:{type:{"enum":["Transaction"]},data:{title:"Transaction",type:"object",additionalProperties:true,properties:{from:{type:"string"},to:{type:"string"},nonce:{type:"number"}}}},required:["type","data"]},{title:"SignRaw",type:"object",properties:{type:{"enum":["Raw"]},data:{type:"object",properties:{payload:{description:"Base64Url encoded data to sign",type:"string",pattern:"^[A-Za-z0-9_-]+$"}},required:["payload"]}},required:["type","data"]},{title:"SignJWT",type:"object",properties:{type:{"enum":["JWT"]},data:{type:"object",properties:{header:{description:"header fields to be added to the JWS header. \"alg\" and \"kid\" will be ignored since they are automatically added by the wallet.",type:"object",additionalProperties:true},payload:{description:"A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.",type:"object",additionalProperties:true}},required:["payload"]}},required:["type","data"]}]}}}},responses:{"200":{description:"Signed data",content:{"application/json":{schema:{title:"SignOutput",type:"object",properties:{signature:{type:"string"}},required:["signature"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/identities/{did}/info":{get:{summary:"Gets extra information of an identity.",operationId:"identityInfo","x-eov-operation-handler":"identities",tags:["identities"],parameters:[{"in":"path",name:"did",schema:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},required:true}],responses:{"200":{description:"Identity data",content:{"application/json":{schema:{title:"Identity Data",type:"object",properties:{did:{type:"string",example:"did:ethr:i3m:0x03142f480f831e835822fc0cd35726844a7069d28df58fb82037f1598812e1ade8"},alias:{type:"string",example:"identity1"},provider:{type:"string",example:"did:ethr:i3m"},addresses:{type:"array",items:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},example:["0x8646cAcF516de1292be1D30AB68E7Ea51e9B1BE7"]}},required:["did"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/identities/{did}/deploy-tx":{post:{summary:"Signs and deploys a transaction",operationId:"identityDeployTransaction","x-eov-operation-handler":"identities",tags:["identities"],parameters:[{"in":"path",name:"did",schema:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},required:true}],requestBody:{description:"Transaction to sign and deploy",required:true,content:{"application/json":{schema:{title:"Transaction",type:"object",additionalProperties:true,properties:{from:{type:"string"},to:{type:"string"},nonce:{type:"number"}}}}}},responses:{"200":{description:"Selected identity",content:{"application/json":{schema:{title:"Receipt",type:"object",properties:{receipt:{type:"string"}},required:["receipt"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/resources":{get:{summary:"Lists the resources that match the filter specified in the query parameters.",operationId:"resourceList","x-eov-operation-handler":"resources",tags:["resources"],parameters:[{"in":"query",name:"type",example:"Contract",required:false,schema:{type:"string","enum":["VerifiableCredential","Object","KeyPair","Contract","DataExchange","NonRepudiationProof"]},description:"Filter the resources by resource type."},{"in":"query",name:"identity",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863",allowEmptyValue:true,required:false,schema:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},description:"Filter the resource associated to an identity DID. Send empty value to get all the resources that are not associated to any identity."},{"in":"query",name:"parentResource",required:false,schema:{type:"string"},description:"Get only resources with the given parent resource id."}],responses:{"200":{description:"A paged array of resources. Only the props requested will be returned. Security policies may prevent some props from being returned.",content:{"application/json":{schema:{title:"ResourceListOutput",description:"A list of resources",type:"array",items:{title:"Resource",anyOf:[{title:"VerifiableCredential",type:"object",properties:{type:{example:"VerifiableCredential","enum":["VerifiableCredential"]},name:{type:"string",example:"Resource name"},resource:{type:"object",properties:{"@context":{type:"array",items:{type:"string"},example:["https://www.w3.org/2018/credentials/v1"]},id:{type:"string",example:"http://example.edu/credentials/1872"},type:{type:"array",items:{type:"string"},example:["VerifiableCredential"]},issuer:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["id"]},issuanceDate:{type:"string",format:"date-time",example:"2021-06-10T19:07:28.000Z"},credentialSubject:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["id"],additionalProperties:true},proof:{type:"object",properties:{type:{type:"string","enum":["JwtProof2020"]}},required:["type"],additionalProperties:true}},additionalProperties:true,required:["@context","type","issuer","issuanceDate","credentialSubject","proof"]}},required:["type","resource"]},{title:"ObjectResource",type:"object",properties:{type:{example:"Object","enum":["Object"]},name:{type:"string",example:"Resource name"},parentResource:{type:"string"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",additionalProperties:true}},required:["type","resource"]},{title:"JWK pair",type:"object",properties:{type:{example:"KeyPair","enum":["KeyPair"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["keyPair"]}},required:["type","resource"]},{title:"Contract",type:"object",properties:{type:{example:"Contract","enum":["Contract"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{dataSharingAgreement:{type:"object",required:["dataOfferingDescription","parties","purpose","duration","intendedUse","licenseGrant","dataStream","personalData","pricingModel","dataExchangeAgreement","signatures"],properties:{dataOfferingDescription:{type:"object",required:["dataOfferingId","version","active"],properties:{dataOfferingId:{type:"string"},version:{type:"integer"},category:{type:"string"},active:{type:"boolean"},title:{type:"string"}}},parties:{type:"object",required:["providerDid","consumerDid"],properties:{providerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},consumerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}}},purpose:{type:"string"},duration:{type:"object",required:["creationDate","startDate","endDate"],properties:{creationDate:{type:"integer"},startDate:{type:"integer"},endDate:{type:"integer"}}},intendedUse:{type:"object",required:["processData","shareDataWithThirdParty","editData"],properties:{processData:{type:"boolean"},shareDataWithThirdParty:{type:"boolean"},editData:{type:"boolean"}}},licenseGrant:{type:"object",required:["transferable","exclusiveness","paidUp","revocable","processing","modifying","analyzing","storingData","storingCopy","reproducing","distributing","loaning","selling","renting","furtherLicensing","leasing"],properties:{transferable:{type:"boolean"},exclusiveness:{type:"boolean"},paidUp:{type:"boolean"},revocable:{type:"boolean"},processing:{type:"boolean"},modifying:{type:"boolean"},analyzing:{type:"boolean"},storingData:{type:"boolean"},storingCopy:{type:"boolean"},reproducing:{type:"boolean"},distributing:{type:"boolean"},loaning:{type:"boolean"},selling:{type:"boolean"},renting:{type:"boolean"},furtherLicensing:{type:"boolean"},leasing:{type:"boolean"}}},dataStream:{type:"boolean"},personalData:{type:"boolean"},pricingModel:{type:"object",required:["basicPrice","currency","hasFreePrice"],properties:{paymentType:{type:"string"},pricingModelName:{type:"string"},basicPrice:{type:"number",format:"float"},currency:{type:"string"},fee:{type:"number",format:"float"},hasPaymentOnSubscription:{type:"object",properties:{paymentOnSubscriptionName:{type:"string"},paymentType:{type:"string"},timeDuration:{type:"string"},description:{type:"string"},repeat:{type:"string"},hasSubscriptionPrice:{type:"number"}}},hasFreePrice:{type:"object",properties:{hasPriceFree:{type:"boolean"}}}}},dataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},signatures:{type:"object",required:["providerSignature","consumerSignature"],properties:{providerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},consumerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"}}}}},keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["dataSharingAgreement"]}},required:["type","resource"]},{title:"NonRepudiationProof",type:"object",properties:{type:{example:"NonRepudiationProof","enum":["NonRepudiationProof"]},name:{type:"string",example:"Resource name"},resource:{description:"a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"}},required:["type","resource"]},{title:"DataExchangeResource",type:"object",properties:{type:{example:"DataExchange","enum":["DataExchange"]},name:{type:"string",example:"Resource name"},resource:{allOf:[{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},{type:"object",properties:{cipherblockDgst:{type:"string",description:"hash of the cipherblock in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},blockCommitment:{type:"string",description:"hash of the plaintext block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},secretCommitment:{type:"string",description:"ash of the secret that can be used to decrypt the block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"}},required:["cipherblockDgst","blockCommitment","secretCommitment"]}]}},required:["type","resource"]}]}}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}},post:{summary:"Create a resource",operationId:"resourceCreate","x-eov-operation-handler":"resources",tags:["resources"],requestBody:{description:"Create a resource. Nowadays it only supports storage of verifiable credentials.",content:{"application/json":{schema:{title:"Resource",anyOf:[{title:"VerifiableCredential",type:"object",properties:{type:{example:"VerifiableCredential","enum":["VerifiableCredential"]},name:{type:"string",example:"Resource name"},resource:{type:"object",properties:{"@context":{type:"array",items:{type:"string"},example:["https://www.w3.org/2018/credentials/v1"]},id:{type:"string",example:"http://example.edu/credentials/1872"},type:{type:"array",items:{type:"string"},example:["VerifiableCredential"]},issuer:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["id"]},issuanceDate:{type:"string",format:"date-time",example:"2021-06-10T19:07:28.000Z"},credentialSubject:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["id"],additionalProperties:true},proof:{type:"object",properties:{type:{type:"string","enum":["JwtProof2020"]}},required:["type"],additionalProperties:true}},additionalProperties:true,required:["@context","type","issuer","issuanceDate","credentialSubject","proof"]}},required:["type","resource"]},{title:"ObjectResource",type:"object",properties:{type:{example:"Object","enum":["Object"]},name:{type:"string",example:"Resource name"},parentResource:{type:"string"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",additionalProperties:true}},required:["type","resource"]},{title:"JWK pair",type:"object",properties:{type:{example:"KeyPair","enum":["KeyPair"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["keyPair"]}},required:["type","resource"]},{title:"Contract",type:"object",properties:{type:{example:"Contract","enum":["Contract"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{dataSharingAgreement:{type:"object",required:["dataOfferingDescription","parties","purpose","duration","intendedUse","licenseGrant","dataStream","personalData","pricingModel","dataExchangeAgreement","signatures"],properties:{dataOfferingDescription:{type:"object",required:["dataOfferingId","version","active"],properties:{dataOfferingId:{type:"string"},version:{type:"integer"},category:{type:"string"},active:{type:"boolean"},title:{type:"string"}}},parties:{type:"object",required:["providerDid","consumerDid"],properties:{providerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},consumerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}}},purpose:{type:"string"},duration:{type:"object",required:["creationDate","startDate","endDate"],properties:{creationDate:{type:"integer"},startDate:{type:"integer"},endDate:{type:"integer"}}},intendedUse:{type:"object",required:["processData","shareDataWithThirdParty","editData"],properties:{processData:{type:"boolean"},shareDataWithThirdParty:{type:"boolean"},editData:{type:"boolean"}}},licenseGrant:{type:"object",required:["transferable","exclusiveness","paidUp","revocable","processing","modifying","analyzing","storingData","storingCopy","reproducing","distributing","loaning","selling","renting","furtherLicensing","leasing"],properties:{transferable:{type:"boolean"},exclusiveness:{type:"boolean"},paidUp:{type:"boolean"},revocable:{type:"boolean"},processing:{type:"boolean"},modifying:{type:"boolean"},analyzing:{type:"boolean"},storingData:{type:"boolean"},storingCopy:{type:"boolean"},reproducing:{type:"boolean"},distributing:{type:"boolean"},loaning:{type:"boolean"},selling:{type:"boolean"},renting:{type:"boolean"},furtherLicensing:{type:"boolean"},leasing:{type:"boolean"}}},dataStream:{type:"boolean"},personalData:{type:"boolean"},pricingModel:{type:"object",required:["basicPrice","currency","hasFreePrice"],properties:{paymentType:{type:"string"},pricingModelName:{type:"string"},basicPrice:{type:"number",format:"float"},currency:{type:"string"},fee:{type:"number",format:"float"},hasPaymentOnSubscription:{type:"object",properties:{paymentOnSubscriptionName:{type:"string"},paymentType:{type:"string"},timeDuration:{type:"string"},description:{type:"string"},repeat:{type:"string"},hasSubscriptionPrice:{type:"number"}}},hasFreePrice:{type:"object",properties:{hasPriceFree:{type:"boolean"}}}}},dataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},signatures:{type:"object",required:["providerSignature","consumerSignature"],properties:{providerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},consumerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"}}}}},keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["dataSharingAgreement"]}},required:["type","resource"]},{title:"NonRepudiationProof",type:"object",properties:{type:{example:"NonRepudiationProof","enum":["NonRepudiationProof"]},name:{type:"string",example:"Resource name"},resource:{description:"a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"}},required:["type","resource"]},{title:"DataExchangeResource",type:"object",properties:{type:{example:"DataExchange","enum":["DataExchange"]},name:{type:"string",example:"Resource name"},resource:{allOf:[{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},{type:"object",properties:{cipherblockDgst:{type:"string",description:"hash of the cipherblock in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},blockCommitment:{type:"string",description:"hash of the plaintext block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},secretCommitment:{type:"string",description:"ash of the secret that can be used to decrypt the block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"}},required:["cipherblockDgst","blockCommitment","secretCommitment"]}]}},required:["type","resource"]}]}}}},responses:{"201":{description:"the ID and type of the created resource",content:{"application/json":{schema:{type:"object",properties:{id:{type:"string"}},required:["id"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/disclosure/{jwt}":{get:{summary:"Request selective disclosure of resources",operationId:"selectiveDisclosure","x-eov-operation-handler":"disclosure",tags:["selectiveDisclosure"],parameters:[{"in":"path",name:"jwt",schema:{type:"string",pattern:"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"},required:true,description:"A JWT containing a selective disclosure object. The payload MUST contain:\n\n```json\n{\n  \"type\": \"selectiveDisclosureReq\", // MUST be selectiveDisclosureReq\n  \"iss\": \"did:\", // the DID of the OIDC Provider\n  \"aud\": \"\", // DID of the OIDC RP\n  \"iat\": 4354535,\t// The time of issuance\n  \"exp\": 3452345, // [OPTIONAL] Expiration time of JWT\n  callback: \"https://...\", // Callback URL for returning the response to a request\n  resources: [\n    { \"id\": \"id\", \"mandatory\": true, \"iss\": [ { did: or url:} ], \"reason\": \"\" }\n  ]\n}\n```\n"}],responses:{"200":{description:"Disclosure ok (mandatory claims provided)",content:{"application/json":{schema:{type:"object",properties:{jwt:{type:"string"}}}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/transaction/deploy":{post:{summary:"Deploy a signed transaction",operationId:"transactionDeploy","x-eov-operation-handler":"transaction",tags:["transaction"],requestBody:{description:"Create a resource.",content:{"application/json":{schema:{title:"SignedTransaction",description:"A list of resources",type:"object",properties:{transaction:{type:"string",pattern:"^0x(?:[A-Fa-f0-9])+$"}}}}}},responses:{"200":{description:"Deployment OK"},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/did-jwt/verify":{post:{summary:"Use the wallet to verify a JWT. The Wallet only supports DID issuers and the 'ES256K1' algorithm. Useful to verify JWT created by another wallet instance.\n",operationId:"didJwtVerify","x-eov-operation-handler":"did-jwt",tags:["utils"],requestBody:{description:"Verify a JWT resolving the public key from the signer DID and optionally check values for expected payload claims",required:true,content:{"application/json":{schema:{type:"object",properties:{jwt:{type:"string",pattern:"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",example:"eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJmaWVsZDEiOiJzYWRzYWQ3NSIsImZpZWxkMiI6ImFmZnNhczlmODdzIiwiaXNzIjoiZGlkOmV0aHI6aTNtOjB4MDNmOTcwNjRhMzUzZmFmNWRkNTQwYWE2N2I2OTE2YmY1NmMwOWM1MGNjODAzN2E0NTNlNzg1ODdmMjdmYjg4ZTk0IiwiaWF0IjoxNjY1NDAwMzYzfQ.IpQ7WprvDMk6QWcJXuPBazat-2657dWIK-iGvOOB5oAhAmMqDBm8OEtKordqeqcEWwhWw_C7_ziMMZkPz1JIkw"},expectedPayloadClaims:{type:"object",additionalProperties:true,description:"The expected values of the proof's payload claims. An expected value of '' can be used to just check that the claim is in the payload. An example could be:\n\n```json\n{\n  iss: 'orig',\n  exchange: {\n    id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',\n    orig: '{\"kty\":\"EC\",\"x\":\"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY\",\"y\":\"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0\",\"crv\":\"P-256\"}', // Public key in JSON.stringify(JWK) of the block origin (sender)\n    dest: '{\"kty\":\"EC\",\"x\":\"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA\",\"y\":\"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY\",\"crv\":\"P-256\"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)\n    hash_alg: 'SHA-256',\n    cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding\n    block_commitment: '', // hash of the plaintext block in base64url with no padding\n    secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding\n  }\n}\n```\n"}},required:["jwt"]}}}},responses:{"200":{description:"A verification object. If `verification` equals `success` all checkings have passed; if it is `failed`, you can access the error message in `error`. Unless the JWT decoding fails (invalid format), the decoded JWT payload can be accessed in `payload`.\n\nExample of success:\n\n```json\n{\n  \"verification\": \"success\",\n  \"payload\": {\n    \"iss\": \"did:ethr:i3m:0x02d846307c9fd53106eb20db5a774c4b71f25c59c7bc423990f942e3fdb02c5898\",\n    \"iat\": 1665138018,\n    \"action\": \"buy 1457adf6\"\n  }\n}\n```\n\nExample of failure:\n\n```json\n{\n  \"verification\": \"failed\",\n  \"error\": \"invalid_jwt: JWT iss is required\"\n  \"payload\": {\n    \"iat\": 1665138018,\n    \"action\": \"buy 1457adf6\"\n  }\n}\n```\n",content:{"application/json":{schema:{title:"VerificationOutput",type:"object",properties:{verification:{type:"string","enum":["success","failed"],description:"whether verification has been successful or has failed"},error:{type:"string",description:"error message if verification failed"},decodedJwt:{description:"the decoded JWT"}},required:["verification"]}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}},"/providerinfo":{get:{summary:"Gets info of the DLT provider the wallet is using",operationId:"providerinfoGet","x-eov-operation-handler":"providerinfo",tags:["utils"],responses:{"200":{description:"A JSON object with information of the DLT provider currently in use.",content:{"application/json":{schema:{title:"ProviderData",description:"A JSON object with information of the DLT provider currently in use.",type:"object",properties:{provider:{type:"string",example:"did:ethr:i3m"},network:{type:"string",example:"i3m"},rpcUrl:{type:"string",example:"http://95.211.3.250:8545"}},additionalProperties:true}}}},"default":{description:"unexpected error",content:{"application/json":{schema:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}}}}}}}}};var components={schemas:{IdentitySelectOutput:{title:"IdentitySelectOutput",type:"object",properties:{did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["did"]},SignInput:{title:"SignInput",oneOf:[{title:"SignTransaction",type:"object",properties:{type:{"enum":["Transaction"]},data:{title:"Transaction",type:"object",additionalProperties:true,properties:{from:{type:"string"},to:{type:"string"},nonce:{type:"number"}}}},required:["type","data"]},{title:"SignRaw",type:"object",properties:{type:{"enum":["Raw"]},data:{type:"object",properties:{payload:{description:"Base64Url encoded data to sign",type:"string",pattern:"^[A-Za-z0-9_-]+$"}},required:["payload"]}},required:["type","data"]},{title:"SignJWT",type:"object",properties:{type:{"enum":["JWT"]},data:{type:"object",properties:{header:{description:"header fields to be added to the JWS header. \"alg\" and \"kid\" will be ignored since they are automatically added by the wallet.",type:"object",additionalProperties:true},payload:{description:"A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.",type:"object",additionalProperties:true}},required:["payload"]}},required:["type","data"]}]},SignRaw:{title:"SignRaw",type:"object",properties:{type:{"enum":["Raw"]},data:{type:"object",properties:{payload:{description:"Base64Url encoded data to sign",type:"string",pattern:"^[A-Za-z0-9_-]+$"}},required:["payload"]}},required:["type","data"]},SignTransaction:{title:"SignTransaction",type:"object",properties:{type:{"enum":["Transaction"]},data:{title:"Transaction",type:"object",additionalProperties:true,properties:{from:{type:"string"},to:{type:"string"},nonce:{type:"number"}}}},required:["type","data"]},SignJWT:{title:"SignJWT",type:"object",properties:{type:{"enum":["JWT"]},data:{type:"object",properties:{header:{description:"header fields to be added to the JWS header. \"alg\" and \"kid\" will be ignored since they are automatically added by the wallet.",type:"object",additionalProperties:true},payload:{description:"A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.",type:"object",additionalProperties:true}},required:["payload"]}},required:["type","data"]},Transaction:{title:"Transaction",type:"object",additionalProperties:true,properties:{from:{type:"string"},to:{type:"string"},nonce:{type:"number"}}},SignOutput:{title:"SignOutput",type:"object",properties:{signature:{type:"string"}},required:["signature"]},Receipt:{title:"Receipt",type:"object",properties:{receipt:{type:"string"}},required:["receipt"]},SignTypes:{title:"SignTypes",type:"string","enum":["Transaction","Raw","JWT"]},IdentityListInput:{title:"IdentityListInput",description:"A list of DIDs",type:"array",items:{type:"object",properties:{did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["did"]}},IdentityCreateInput:{title:"IdentityCreateInput",description:"Besides the here defined options, provider specific properties should be added here if necessary, e.g. \"path\" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).\n",type:"object",properties:{alias:{type:"string"}},additionalProperties:true},IdentityCreateOutput:{title:"IdentityCreateOutput",description:"It returns the account id and type\n",type:"object",properties:{did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["did"]},ResourceListOutput:{title:"ResourceListOutput",description:"A list of resources",type:"array",items:{title:"Resource",anyOf:[{title:"VerifiableCredential",type:"object",properties:{type:{example:"VerifiableCredential","enum":["VerifiableCredential"]},name:{type:"string",example:"Resource name"},resource:{type:"object",properties:{"@context":{type:"array",items:{type:"string"},example:["https://www.w3.org/2018/credentials/v1"]},id:{type:"string",example:"http://example.edu/credentials/1872"},type:{type:"array",items:{type:"string"},example:["VerifiableCredential"]},issuer:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["id"]},issuanceDate:{type:"string",format:"date-time",example:"2021-06-10T19:07:28.000Z"},credentialSubject:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["id"],additionalProperties:true},proof:{type:"object",properties:{type:{type:"string","enum":["JwtProof2020"]}},required:["type"],additionalProperties:true}},additionalProperties:true,required:["@context","type","issuer","issuanceDate","credentialSubject","proof"]}},required:["type","resource"]},{title:"ObjectResource",type:"object",properties:{type:{example:"Object","enum":["Object"]},name:{type:"string",example:"Resource name"},parentResource:{type:"string"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",additionalProperties:true}},required:["type","resource"]},{title:"JWK pair",type:"object",properties:{type:{example:"KeyPair","enum":["KeyPair"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["keyPair"]}},required:["type","resource"]},{title:"Contract",type:"object",properties:{type:{example:"Contract","enum":["Contract"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{dataSharingAgreement:{type:"object",required:["dataOfferingDescription","parties","purpose","duration","intendedUse","licenseGrant","dataStream","personalData","pricingModel","dataExchangeAgreement","signatures"],properties:{dataOfferingDescription:{type:"object",required:["dataOfferingId","version","active"],properties:{dataOfferingId:{type:"string"},version:{type:"integer"},category:{type:"string"},active:{type:"boolean"},title:{type:"string"}}},parties:{type:"object",required:["providerDid","consumerDid"],properties:{providerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},consumerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}}},purpose:{type:"string"},duration:{type:"object",required:["creationDate","startDate","endDate"],properties:{creationDate:{type:"integer"},startDate:{type:"integer"},endDate:{type:"integer"}}},intendedUse:{type:"object",required:["processData","shareDataWithThirdParty","editData"],properties:{processData:{type:"boolean"},shareDataWithThirdParty:{type:"boolean"},editData:{type:"boolean"}}},licenseGrant:{type:"object",required:["transferable","exclusiveness","paidUp","revocable","processing","modifying","analyzing","storingData","storingCopy","reproducing","distributing","loaning","selling","renting","furtherLicensing","leasing"],properties:{transferable:{type:"boolean"},exclusiveness:{type:"boolean"},paidUp:{type:"boolean"},revocable:{type:"boolean"},processing:{type:"boolean"},modifying:{type:"boolean"},analyzing:{type:"boolean"},storingData:{type:"boolean"},storingCopy:{type:"boolean"},reproducing:{type:"boolean"},distributing:{type:"boolean"},loaning:{type:"boolean"},selling:{type:"boolean"},renting:{type:"boolean"},furtherLicensing:{type:"boolean"},leasing:{type:"boolean"}}},dataStream:{type:"boolean"},personalData:{type:"boolean"},pricingModel:{type:"object",required:["basicPrice","currency","hasFreePrice"],properties:{paymentType:{type:"string"},pricingModelName:{type:"string"},basicPrice:{type:"number",format:"float"},currency:{type:"string"},fee:{type:"number",format:"float"},hasPaymentOnSubscription:{type:"object",properties:{paymentOnSubscriptionName:{type:"string"},paymentType:{type:"string"},timeDuration:{type:"string"},description:{type:"string"},repeat:{type:"string"},hasSubscriptionPrice:{type:"number"}}},hasFreePrice:{type:"object",properties:{hasPriceFree:{type:"boolean"}}}}},dataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},signatures:{type:"object",required:["providerSignature","consumerSignature"],properties:{providerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},consumerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"}}}}},keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["dataSharingAgreement"]}},required:["type","resource"]},{title:"NonRepudiationProof",type:"object",properties:{type:{example:"NonRepudiationProof","enum":["NonRepudiationProof"]},name:{type:"string",example:"Resource name"},resource:{description:"a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"}},required:["type","resource"]},{title:"DataExchangeResource",type:"object",properties:{type:{example:"DataExchange","enum":["DataExchange"]},name:{type:"string",example:"Resource name"},resource:{allOf:[{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},{type:"object",properties:{cipherblockDgst:{type:"string",description:"hash of the cipherblock in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},blockCommitment:{type:"string",description:"hash of the plaintext block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},secretCommitment:{type:"string",description:"ash of the secret that can be used to decrypt the block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"}},required:["cipherblockDgst","blockCommitment","secretCommitment"]}]}},required:["type","resource"]}]}},Resource:{title:"Resource",anyOf:[{title:"VerifiableCredential",type:"object",properties:{type:{example:"VerifiableCredential","enum":["VerifiableCredential"]},name:{type:"string",example:"Resource name"},resource:{type:"object",properties:{"@context":{type:"array",items:{type:"string"},example:["https://www.w3.org/2018/credentials/v1"]},id:{type:"string",example:"http://example.edu/credentials/1872"},type:{type:"array",items:{type:"string"},example:["VerifiableCredential"]},issuer:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["id"]},issuanceDate:{type:"string",format:"date-time",example:"2021-06-10T19:07:28.000Z"},credentialSubject:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["id"],additionalProperties:true},proof:{type:"object",properties:{type:{type:"string","enum":["JwtProof2020"]}},required:["type"],additionalProperties:true}},additionalProperties:true,required:["@context","type","issuer","issuanceDate","credentialSubject","proof"]}},required:["type","resource"]},{title:"ObjectResource",type:"object",properties:{type:{example:"Object","enum":["Object"]},name:{type:"string",example:"Resource name"},parentResource:{type:"string"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",additionalProperties:true}},required:["type","resource"]},{title:"JWK pair",type:"object",properties:{type:{example:"KeyPair","enum":["KeyPair"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["keyPair"]}},required:["type","resource"]},{title:"Contract",type:"object",properties:{type:{example:"Contract","enum":["Contract"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{dataSharingAgreement:{type:"object",required:["dataOfferingDescription","parties","purpose","duration","intendedUse","licenseGrant","dataStream","personalData","pricingModel","dataExchangeAgreement","signatures"],properties:{dataOfferingDescription:{type:"object",required:["dataOfferingId","version","active"],properties:{dataOfferingId:{type:"string"},version:{type:"integer"},category:{type:"string"},active:{type:"boolean"},title:{type:"string"}}},parties:{type:"object",required:["providerDid","consumerDid"],properties:{providerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},consumerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}}},purpose:{type:"string"},duration:{type:"object",required:["creationDate","startDate","endDate"],properties:{creationDate:{type:"integer"},startDate:{type:"integer"},endDate:{type:"integer"}}},intendedUse:{type:"object",required:["processData","shareDataWithThirdParty","editData"],properties:{processData:{type:"boolean"},shareDataWithThirdParty:{type:"boolean"},editData:{type:"boolean"}}},licenseGrant:{type:"object",required:["transferable","exclusiveness","paidUp","revocable","processing","modifying","analyzing","storingData","storingCopy","reproducing","distributing","loaning","selling","renting","furtherLicensing","leasing"],properties:{transferable:{type:"boolean"},exclusiveness:{type:"boolean"},paidUp:{type:"boolean"},revocable:{type:"boolean"},processing:{type:"boolean"},modifying:{type:"boolean"},analyzing:{type:"boolean"},storingData:{type:"boolean"},storingCopy:{type:"boolean"},reproducing:{type:"boolean"},distributing:{type:"boolean"},loaning:{type:"boolean"},selling:{type:"boolean"},renting:{type:"boolean"},furtherLicensing:{type:"boolean"},leasing:{type:"boolean"}}},dataStream:{type:"boolean"},personalData:{type:"boolean"},pricingModel:{type:"object",required:["basicPrice","currency","hasFreePrice"],properties:{paymentType:{type:"string"},pricingModelName:{type:"string"},basicPrice:{type:"number",format:"float"},currency:{type:"string"},fee:{type:"number",format:"float"},hasPaymentOnSubscription:{type:"object",properties:{paymentOnSubscriptionName:{type:"string"},paymentType:{type:"string"},timeDuration:{type:"string"},description:{type:"string"},repeat:{type:"string"},hasSubscriptionPrice:{type:"number"}}},hasFreePrice:{type:"object",properties:{hasPriceFree:{type:"boolean"}}}}},dataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},signatures:{type:"object",required:["providerSignature","consumerSignature"],properties:{providerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},consumerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"}}}}},keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["dataSharingAgreement"]}},required:["type","resource"]},{title:"NonRepudiationProof",type:"object",properties:{type:{example:"NonRepudiationProof","enum":["NonRepudiationProof"]},name:{type:"string",example:"Resource name"},resource:{description:"a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"}},required:["type","resource"]},{title:"DataExchangeResource",type:"object",properties:{type:{example:"DataExchange","enum":["DataExchange"]},name:{type:"string",example:"Resource name"},resource:{allOf:[{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},{type:"object",properties:{cipherblockDgst:{type:"string",description:"hash of the cipherblock in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},blockCommitment:{type:"string",description:"hash of the plaintext block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},secretCommitment:{type:"string",description:"ash of the secret that can be used to decrypt the block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"}},required:["cipherblockDgst","blockCommitment","secretCommitment"]}]}},required:["type","resource"]}]},VerifiableCredential:{title:"VerifiableCredential",type:"object",properties:{type:{example:"VerifiableCredential","enum":["VerifiableCredential"]},name:{type:"string",example:"Resource name"},resource:{type:"object",properties:{"@context":{type:"array",items:{type:"string"},example:["https://www.w3.org/2018/credentials/v1"]},id:{type:"string",example:"http://example.edu/credentials/1872"},type:{type:"array",items:{type:"string"},example:["VerifiableCredential"]},issuer:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},additionalProperties:true,required:["id"]},issuanceDate:{type:"string",format:"date-time",example:"2021-06-10T19:07:28.000Z"},credentialSubject:{type:"object",properties:{id:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["id"],additionalProperties:true},proof:{type:"object",properties:{type:{type:"string","enum":["JwtProof2020"]}},required:["type"],additionalProperties:true}},additionalProperties:true,required:["@context","type","issuer","issuanceDate","credentialSubject","proof"]}},required:["type","resource"]},ObjectResource:{title:"ObjectResource",type:"object",properties:{type:{example:"Object","enum":["Object"]},name:{type:"string",example:"Resource name"},parentResource:{type:"string"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",additionalProperties:true}},required:["type","resource"]},KeyPair:{title:"JWK pair",type:"object",properties:{type:{example:"KeyPair","enum":["KeyPair"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["keyPair"]}},required:["type","resource"]},Contract:{title:"Contract",type:"object",properties:{type:{example:"Contract","enum":["Contract"]},name:{type:"string",example:"Resource name"},identity:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},resource:{type:"object",properties:{dataSharingAgreement:{type:"object",required:["dataOfferingDescription","parties","purpose","duration","intendedUse","licenseGrant","dataStream","personalData","pricingModel","dataExchangeAgreement","signatures"],properties:{dataOfferingDescription:{type:"object",required:["dataOfferingId","version","active"],properties:{dataOfferingId:{type:"string"},version:{type:"integer"},category:{type:"string"},active:{type:"boolean"},title:{type:"string"}}},parties:{type:"object",required:["providerDid","consumerDid"],properties:{providerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},consumerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}}},purpose:{type:"string"},duration:{type:"object",required:["creationDate","startDate","endDate"],properties:{creationDate:{type:"integer"},startDate:{type:"integer"},endDate:{type:"integer"}}},intendedUse:{type:"object",required:["processData","shareDataWithThirdParty","editData"],properties:{processData:{type:"boolean"},shareDataWithThirdParty:{type:"boolean"},editData:{type:"boolean"}}},licenseGrant:{type:"object",required:["transferable","exclusiveness","paidUp","revocable","processing","modifying","analyzing","storingData","storingCopy","reproducing","distributing","loaning","selling","renting","furtherLicensing","leasing"],properties:{transferable:{type:"boolean"},exclusiveness:{type:"boolean"},paidUp:{type:"boolean"},revocable:{type:"boolean"},processing:{type:"boolean"},modifying:{type:"boolean"},analyzing:{type:"boolean"},storingData:{type:"boolean"},storingCopy:{type:"boolean"},reproducing:{type:"boolean"},distributing:{type:"boolean"},loaning:{type:"boolean"},selling:{type:"boolean"},renting:{type:"boolean"},furtherLicensing:{type:"boolean"},leasing:{type:"boolean"}}},dataStream:{type:"boolean"},personalData:{type:"boolean"},pricingModel:{type:"object",required:["basicPrice","currency","hasFreePrice"],properties:{paymentType:{type:"string"},pricingModelName:{type:"string"},basicPrice:{type:"number",format:"float"},currency:{type:"string"},fee:{type:"number",format:"float"},hasPaymentOnSubscription:{type:"object",properties:{paymentOnSubscriptionName:{type:"string"},paymentType:{type:"string"},timeDuration:{type:"string"},description:{type:"string"},repeat:{type:"string"},hasSubscriptionPrice:{type:"number"}}},hasFreePrice:{type:"object",properties:{hasPriceFree:{type:"boolean"}}}}},dataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},signatures:{type:"object",required:["providerSignature","consumerSignature"],properties:{providerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},consumerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"}}}}},keyPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]}},required:["dataSharingAgreement"]}},required:["type","resource"]},DataExchangeResource:{title:"DataExchangeResource",type:"object",properties:{type:{example:"DataExchange","enum":["DataExchange"]},name:{type:"string",example:"Resource name"},resource:{allOf:[{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},{type:"object",properties:{cipherblockDgst:{type:"string",description:"hash of the cipherblock in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},blockCommitment:{type:"string",description:"hash of the plaintext block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},secretCommitment:{type:"string",description:"ash of the secret that can be used to decrypt the block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"}},required:["cipherblockDgst","blockCommitment","secretCommitment"]}]}},required:["type","resource"]},NonRepudiationProof:{title:"NonRepudiationProof",type:"object",properties:{type:{example:"NonRepudiationProof","enum":["NonRepudiationProof"]},name:{type:"string",example:"Resource name"},resource:{description:"a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"}},required:["type","resource"]},ResourceId:{type:"object",properties:{id:{type:"string"}},required:["id"]},ResourceType:{type:"string","enum":["VerifiableCredential","Object","KeyPair","Contract","DataExchange","NonRepudiationProof"]},SignedTransaction:{title:"SignedTransaction",description:"A list of resources",type:"object",properties:{transaction:{type:"string",pattern:"^0x(?:[A-Fa-f0-9])+$"}}},DecodedJwt:{title:"JwtPayload",type:"object",properties:{header:{type:"object",properties:{typ:{type:"string","enum":["JWT"]},alg:{type:"string","enum":["ES256K"]}},required:["typ","alg"],additionalProperties:true},payload:{type:"object",properties:{iss:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}},required:["iss"],additionalProperties:true},signature:{type:"string",format:"^[A-Za-z0-9_-]+$"},data:{type:"string",format:"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",description:"<base64url(header)>.<base64url(payload)>"}},required:["signature","data"]},VerificationOutput:{title:"VerificationOutput",type:"object",properties:{verification:{type:"string","enum":["success","failed"],description:"whether verification has been successful or has failed"},error:{type:"string",description:"error message if verification failed"},decodedJwt:{description:"the decoded JWT"}},required:["verification"]},ProviderData:{title:"ProviderData",description:"A JSON object with information of the DLT provider currently in use.",type:"object",properties:{provider:{type:"string",example:"did:ethr:i3m"},network:{type:"string",example:"i3m"},rpcUrl:{type:"string",example:"http://95.211.3.250:8545"}},additionalProperties:true},EthereumAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},did:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},IdentityData:{title:"Identity Data",type:"object",properties:{did:{type:"string",example:"did:ethr:i3m:0x03142f480f831e835822fc0cd35726844a7069d28df58fb82037f1598812e1ade8"},alias:{type:"string",example:"identity1"},provider:{type:"string",example:"did:ethr:i3m"},addresses:{type:"array",items:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},example:["0x8646cAcF516de1292be1D30AB68E7Ea51e9B1BE7"]}},required:["did"]},ApiError:{type:"object",title:"Error",required:["code","message"],properties:{code:{type:"integer",format:"int32"},message:{type:"string"}}},JwkPair:{type:"object",properties:{privateJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"},publicJwk:{type:"string",description:"A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).\n",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"}},required:["privateJwk","publicJwk"]},CompactJWS:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},DataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},DataSharingAgreement:{type:"object",required:["dataOfferingDescription","parties","purpose","duration","intendedUse","licenseGrant","dataStream","personalData","pricingModel","dataExchangeAgreement","signatures"],properties:{dataOfferingDescription:{type:"object",required:["dataOfferingId","version","active"],properties:{dataOfferingId:{type:"string"},version:{type:"integer"},category:{type:"string"},active:{type:"boolean"},title:{type:"string"}}},parties:{type:"object",required:["providerDid","consumerDid"],properties:{providerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"},consumerDid:{description:"a DID using the ethr resolver",type:"string",pattern:"^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",example:"did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"}}},purpose:{type:"string"},duration:{type:"object",required:["creationDate","startDate","endDate"],properties:{creationDate:{type:"integer"},startDate:{type:"integer"},endDate:{type:"integer"}}},intendedUse:{type:"object",required:["processData","shareDataWithThirdParty","editData"],properties:{processData:{type:"boolean"},shareDataWithThirdParty:{type:"boolean"},editData:{type:"boolean"}}},licenseGrant:{type:"object",required:["transferable","exclusiveness","paidUp","revocable","processing","modifying","analyzing","storingData","storingCopy","reproducing","distributing","loaning","selling","renting","furtherLicensing","leasing"],properties:{transferable:{type:"boolean"},exclusiveness:{type:"boolean"},paidUp:{type:"boolean"},revocable:{type:"boolean"},processing:{type:"boolean"},modifying:{type:"boolean"},analyzing:{type:"boolean"},storingData:{type:"boolean"},storingCopy:{type:"boolean"},reproducing:{type:"boolean"},distributing:{type:"boolean"},loaning:{type:"boolean"},selling:{type:"boolean"},renting:{type:"boolean"},furtherLicensing:{type:"boolean"},leasing:{type:"boolean"}}},dataStream:{type:"boolean"},personalData:{type:"boolean"},pricingModel:{type:"object",required:["basicPrice","currency","hasFreePrice"],properties:{paymentType:{type:"string"},pricingModelName:{type:"string"},basicPrice:{type:"number",format:"float"},currency:{type:"string"},fee:{type:"number",format:"float"},hasPaymentOnSubscription:{type:"object",properties:{paymentOnSubscriptionName:{type:"string"},paymentType:{type:"string"},timeDuration:{type:"string"},description:{type:"string"},repeat:{type:"string"},hasSubscriptionPrice:{type:"number"}}},hasFreePrice:{type:"object",properties:{hasPriceFree:{type:"boolean"}}}}},dataExchangeAgreement:{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},signatures:{type:"object",required:["providerSignature","consumerSignature"],properties:{providerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"},consumerSignature:{title:"CompactJWS",type:"string",pattern:"^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"}}}}},DataExchange:{allOf:[{type:"object",required:["orig","dest","encAlg","signingAlg","hashAlg","ledgerContractAddress","ledgerSignerAddress","pooToPorDelay","pooToPopDelay","pooToSecretDelay"],properties:{orig:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"},dest:{type:"string",description:"A stringified JWK with alphabetically sorted claims",example:"{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"},encAlg:{type:"string","enum":["A128GCM","A256GCM"],example:"A256GCM"},signingAlg:{type:"string","enum":["ES256","ES384","ES512"],example:"ES256"},hashAlg:{type:"string","enum":["SHA-256","SHA-384","SHA-512"],example:"SHA-256"},ledgerContractAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},ledgerSignerAddress:{description:"Ethereum Address in EIP-55 format (with checksum)",type:"string",pattern:"^0x([0-9A-Fa-f]){40}$",example:"0x71C7656EC7ab88b098defB751B7401B5f6d8976F"},pooToPorDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and verified PoR",type:"integer",minimum:1,example:10000},pooToPopDelay:{description:"Maximum acceptable time in milliseconds between issued PoO and issued PoP",type:"integer",minimum:1,example:20000},pooToSecretDelay:{description:"Maximum acceptable time between issued PoO and secret published on the ledger",type:"integer",minimum:1,example:180000},schema:{description:"A stringified JSON-LD schema describing the data format",type:"string"}}},{type:"object",properties:{cipherblockDgst:{type:"string",description:"hash of the cipherblock in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},blockCommitment:{type:"string",description:"hash of the plaintext block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"},secretCommitment:{type:"string",description:"ash of the secret that can be used to decrypt the block in base64url with no padding",pattern:"^[a-zA-Z0-9_-]+$"}},required:["cipherblockDgst","blockCommitment","secretCommitment"]}]}}};var spec = {openapi:openapi,info:info,tags:tags,paths:paths,components:components};

var id="https://spec.openapis.org/oas/3.0/schema/2021-09-28";var $schema="http://json-schema.org/draft-04/schema#";var description="The description of OpenAPI v3.0.x documents, as defined by https://spec.openapis.org/oas/v3.0.3";var type="object";var required=["openapi","info","paths"];var properties={openapi:{type:"string",pattern:"^3\\.0\\.\\d(-.+)?$"},info:{$ref:"#/definitions/Info"},externalDocs:{$ref:"#/definitions/ExternalDocumentation"},servers:{type:"array",items:{$ref:"#/definitions/Server"}},security:{type:"array",items:{$ref:"#/definitions/SecurityRequirement"}},tags:{type:"array",items:{$ref:"#/definitions/Tag"},uniqueItems:true},paths:{$ref:"#/definitions/Paths"},components:{$ref:"#/definitions/Components"}};var patternProperties={"^x-":{}};var additionalProperties=false;var definitions={Reference:{type:"object",required:["$ref"],patternProperties:{"^\\$ref$":{type:"string",format:"uri-reference"}}},Info:{type:"object",required:["title","version"],properties:{title:{type:"string"},description:{type:"string"},termsOfService:{type:"string",format:"uri-reference"},contact:{$ref:"#/definitions/Contact"},license:{$ref:"#/definitions/License"},version:{type:"string"}},patternProperties:{"^x-":{}},additionalProperties:false},Contact:{type:"object",properties:{name:{type:"string"},url:{type:"string",format:"uri-reference"},email:{type:"string",format:"email"}},patternProperties:{"^x-":{}},additionalProperties:false},License:{type:"object",required:["name"],properties:{name:{type:"string"},url:{type:"string",format:"uri-reference"}},patternProperties:{"^x-":{}},additionalProperties:false},Server:{type:"object",required:["url"],properties:{url:{type:"string"},description:{type:"string"},variables:{type:"object",additionalProperties:{$ref:"#/definitions/ServerVariable"}}},patternProperties:{"^x-":{}},additionalProperties:false},ServerVariable:{type:"object",required:["default"],properties:{"enum":{type:"array",items:{type:"string"}},"default":{type:"string"},description:{type:"string"}},patternProperties:{"^x-":{}},additionalProperties:false},Components:{type:"object",properties:{schemas:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]}}},responses:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/Response"}]}}},parameters:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/Parameter"}]}}},examples:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/Example"}]}}},requestBodies:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/RequestBody"}]}}},headers:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/Header"}]}}},securitySchemes:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/SecurityScheme"}]}}},links:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/Link"}]}}},callbacks:{type:"object",patternProperties:{"^[a-zA-Z0-9\\.\\-_]+$":{oneOf:[{$ref:"#/definitions/Reference"},{$ref:"#/definitions/Callback"}]}}}},patternProperties:{"^x-":{}},additionalProperties:false},Schema:{type:"object",properties:{title:{type:"string"},multipleOf:{type:"number",minimum:0,exclusiveMinimum:true},maximum:{type:"number"},exclusiveMaximum:{type:"boolean","default":false},minimum:{type:"number"},exclusiveMinimum:{type:"boolean","default":false},maxLength:{type:"integer",minimum:0},minLength:{type:"integer",minimum:0,"default":0},pattern:{type:"string",format:"regex"},maxItems:{type:"integer",minimum:0},minItems:{type:"integer",minimum:0,"default":0},uniqueItems:{type:"boolean","default":false},maxProperties:{type:"integer",minimum:0},minProperties:{type:"integer",minimum:0,"default":0},required:{type:"array",items:{type:"string"},minItems:1,uniqueItems:true},"enum":{type:"array",items:{},minItems:1,uniqueItems:false},type:{type:"string","enum":["array","boolean","integer","number","object","string"]},not:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]},allOf:{type:"array",items:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]}},oneOf:{type:"array",items:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]}},anyOf:{type:"array",items:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]}},items:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]},properties:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]}},additionalProperties:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"},{type:"boolean"}],"default":true},description:{type:"string"},format:{type:"string"},"default":{},nullable:{type:"boolean","default":false},discriminator:{$ref:"#/definitions/Discriminator"},readOnly:{type:"boolean","default":false},writeOnly:{type:"boolean","default":false},example:{},externalDocs:{$ref:"#/definitions/ExternalDocumentation"},deprecated:{type:"boolean","default":false},xml:{$ref:"#/definitions/XML"}},patternProperties:{"^x-":{}},additionalProperties:false},Discriminator:{type:"object",required:["propertyName"],properties:{propertyName:{type:"string"},mapping:{type:"object",additionalProperties:{type:"string"}}}},XML:{type:"object",properties:{name:{type:"string"},namespace:{type:"string",format:"uri"},prefix:{type:"string"},attribute:{type:"boolean","default":false},wrapped:{type:"boolean","default":false}},patternProperties:{"^x-":{}},additionalProperties:false},Response:{type:"object",required:["description"],properties:{description:{type:"string"},headers:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Header"},{$ref:"#/definitions/Reference"}]}},content:{type:"object",additionalProperties:{$ref:"#/definitions/MediaType"}},links:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Link"},{$ref:"#/definitions/Reference"}]}}},patternProperties:{"^x-":{}},additionalProperties:false},MediaType:{type:"object",properties:{schema:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]},example:{},examples:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Example"},{$ref:"#/definitions/Reference"}]}},encoding:{type:"object",additionalProperties:{$ref:"#/definitions/Encoding"}}},patternProperties:{"^x-":{}},additionalProperties:false,allOf:[{$ref:"#/definitions/ExampleXORExamples"}]},Example:{type:"object",properties:{summary:{type:"string"},description:{type:"string"},value:{},externalValue:{type:"string",format:"uri-reference"}},patternProperties:{"^x-":{}},additionalProperties:false},Header:{type:"object",properties:{description:{type:"string"},required:{type:"boolean","default":false},deprecated:{type:"boolean","default":false},allowEmptyValue:{type:"boolean","default":false},style:{type:"string","enum":["simple"],"default":"simple"},explode:{type:"boolean"},allowReserved:{type:"boolean","default":false},schema:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]},content:{type:"object",additionalProperties:{$ref:"#/definitions/MediaType"},minProperties:1,maxProperties:1},example:{},examples:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Example"},{$ref:"#/definitions/Reference"}]}}},patternProperties:{"^x-":{}},additionalProperties:false,allOf:[{$ref:"#/definitions/ExampleXORExamples"},{$ref:"#/definitions/SchemaXORContent"}]},Paths:{type:"object",patternProperties:{"^\\/":{$ref:"#/definitions/PathItem"},"^x-":{}},additionalProperties:false},PathItem:{type:"object",properties:{$ref:{type:"string"},summary:{type:"string"},description:{type:"string"},servers:{type:"array",items:{$ref:"#/definitions/Server"}},parameters:{type:"array",items:{oneOf:[{$ref:"#/definitions/Parameter"},{$ref:"#/definitions/Reference"}]},uniqueItems:true}},patternProperties:{"^(get|put|post|delete|options|head|patch|trace)$":{$ref:"#/definitions/Operation"},"^x-":{}},additionalProperties:false},Operation:{type:"object",required:["responses"],properties:{tags:{type:"array",items:{type:"string"}},summary:{type:"string"},description:{type:"string"},externalDocs:{$ref:"#/definitions/ExternalDocumentation"},operationId:{type:"string"},parameters:{type:"array",items:{oneOf:[{$ref:"#/definitions/Parameter"},{$ref:"#/definitions/Reference"}]},uniqueItems:true},requestBody:{oneOf:[{$ref:"#/definitions/RequestBody"},{$ref:"#/definitions/Reference"}]},responses:{$ref:"#/definitions/Responses"},callbacks:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Callback"},{$ref:"#/definitions/Reference"}]}},deprecated:{type:"boolean","default":false},security:{type:"array",items:{$ref:"#/definitions/SecurityRequirement"}},servers:{type:"array",items:{$ref:"#/definitions/Server"}}},patternProperties:{"^x-":{}},additionalProperties:false},Responses:{type:"object",properties:{"default":{oneOf:[{$ref:"#/definitions/Response"},{$ref:"#/definitions/Reference"}]}},patternProperties:{"^[1-5](?:\\d{2}|XX)$":{oneOf:[{$ref:"#/definitions/Response"},{$ref:"#/definitions/Reference"}]},"^x-":{}},minProperties:1,additionalProperties:false},SecurityRequirement:{type:"object",additionalProperties:{type:"array",items:{type:"string"}}},Tag:{type:"object",required:["name"],properties:{name:{type:"string"},description:{type:"string"},externalDocs:{$ref:"#/definitions/ExternalDocumentation"}},patternProperties:{"^x-":{}},additionalProperties:false},ExternalDocumentation:{type:"object",required:["url"],properties:{description:{type:"string"},url:{type:"string",format:"uri-reference"}},patternProperties:{"^x-":{}},additionalProperties:false},ExampleXORExamples:{description:"Example and examples are mutually exclusive",not:{required:["example","examples"]}},SchemaXORContent:{description:"Schema and content are mutually exclusive, at least one is required",not:{required:["schema","content"]},oneOf:[{required:["schema"]},{required:["content"],description:"Some properties are not allowed if content is present",allOf:[{not:{required:["style"]}},{not:{required:["explode"]}},{not:{required:["allowReserved"]}},{not:{required:["example"]}},{not:{required:["examples"]}}]}]},Parameter:{type:"object",properties:{name:{type:"string"},"in":{type:"string"},description:{type:"string"},required:{type:"boolean","default":false},deprecated:{type:"boolean","default":false},allowEmptyValue:{type:"boolean","default":false},style:{type:"string"},explode:{type:"boolean"},allowReserved:{type:"boolean","default":false},schema:{oneOf:[{$ref:"#/definitions/Schema"},{$ref:"#/definitions/Reference"}]},content:{type:"object",additionalProperties:{$ref:"#/definitions/MediaType"},minProperties:1,maxProperties:1},example:{},examples:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Example"},{$ref:"#/definitions/Reference"}]}}},patternProperties:{"^x-":{}},additionalProperties:false,required:["name","in"],allOf:[{$ref:"#/definitions/ExampleXORExamples"},{$ref:"#/definitions/SchemaXORContent"},{$ref:"#/definitions/ParameterLocation"}]},ParameterLocation:{description:"Parameter location",oneOf:[{description:"Parameter in path",required:["required"],properties:{"in":{"enum":["path"]},style:{"enum":["matrix","label","simple"],"default":"simple"},required:{"enum":[true]}}},{description:"Parameter in query",properties:{"in":{"enum":["query"]},style:{"enum":["form","spaceDelimited","pipeDelimited","deepObject"],"default":"form"}}},{description:"Parameter in header",properties:{"in":{"enum":["header"]},style:{"enum":["simple"],"default":"simple"}}},{description:"Parameter in cookie",properties:{"in":{"enum":["cookie"]},style:{"enum":["form"],"default":"form"}}}]},RequestBody:{type:"object",required:["content"],properties:{description:{type:"string"},content:{type:"object",additionalProperties:{$ref:"#/definitions/MediaType"}},required:{type:"boolean","default":false}},patternProperties:{"^x-":{}},additionalProperties:false},SecurityScheme:{oneOf:[{$ref:"#/definitions/APIKeySecurityScheme"},{$ref:"#/definitions/HTTPSecurityScheme"},{$ref:"#/definitions/OAuth2SecurityScheme"},{$ref:"#/definitions/OpenIdConnectSecurityScheme"}]},APIKeySecurityScheme:{type:"object",required:["type","name","in"],properties:{type:{type:"string","enum":["apiKey"]},name:{type:"string"},"in":{type:"string","enum":["header","query","cookie"]},description:{type:"string"}},patternProperties:{"^x-":{}},additionalProperties:false},HTTPSecurityScheme:{type:"object",required:["scheme","type"],properties:{scheme:{type:"string"},bearerFormat:{type:"string"},description:{type:"string"},type:{type:"string","enum":["http"]}},patternProperties:{"^x-":{}},additionalProperties:false,oneOf:[{description:"Bearer",properties:{scheme:{type:"string",pattern:"^[Bb][Ee][Aa][Rr][Ee][Rr]$"}}},{description:"Non Bearer",not:{required:["bearerFormat"]},properties:{scheme:{not:{type:"string",pattern:"^[Bb][Ee][Aa][Rr][Ee][Rr]$"}}}}]},OAuth2SecurityScheme:{type:"object",required:["type","flows"],properties:{type:{type:"string","enum":["oauth2"]},flows:{$ref:"#/definitions/OAuthFlows"},description:{type:"string"}},patternProperties:{"^x-":{}},additionalProperties:false},OpenIdConnectSecurityScheme:{type:"object",required:["type","openIdConnectUrl"],properties:{type:{type:"string","enum":["openIdConnect"]},openIdConnectUrl:{type:"string",format:"uri-reference"},description:{type:"string"}},patternProperties:{"^x-":{}},additionalProperties:false},OAuthFlows:{type:"object",properties:{implicit:{$ref:"#/definitions/ImplicitOAuthFlow"},password:{$ref:"#/definitions/PasswordOAuthFlow"},clientCredentials:{$ref:"#/definitions/ClientCredentialsFlow"},authorizationCode:{$ref:"#/definitions/AuthorizationCodeOAuthFlow"}},patternProperties:{"^x-":{}},additionalProperties:false},ImplicitOAuthFlow:{type:"object",required:["authorizationUrl","scopes"],properties:{authorizationUrl:{type:"string",format:"uri-reference"},refreshUrl:{type:"string",format:"uri-reference"},scopes:{type:"object",additionalProperties:{type:"string"}}},patternProperties:{"^x-":{}},additionalProperties:false},PasswordOAuthFlow:{type:"object",required:["tokenUrl","scopes"],properties:{tokenUrl:{type:"string",format:"uri-reference"},refreshUrl:{type:"string",format:"uri-reference"},scopes:{type:"object",additionalProperties:{type:"string"}}},patternProperties:{"^x-":{}},additionalProperties:false},ClientCredentialsFlow:{type:"object",required:["tokenUrl","scopes"],properties:{tokenUrl:{type:"string",format:"uri-reference"},refreshUrl:{type:"string",format:"uri-reference"},scopes:{type:"object",additionalProperties:{type:"string"}}},patternProperties:{"^x-":{}},additionalProperties:false},AuthorizationCodeOAuthFlow:{type:"object",required:["authorizationUrl","tokenUrl","scopes"],properties:{authorizationUrl:{type:"string",format:"uri-reference"},tokenUrl:{type:"string",format:"uri-reference"},refreshUrl:{type:"string",format:"uri-reference"},scopes:{type:"object",additionalProperties:{type:"string"}}},patternProperties:{"^x-":{}},additionalProperties:false},Link:{type:"object",properties:{operationId:{type:"string"},operationRef:{type:"string",format:"uri-reference"},parameters:{type:"object",additionalProperties:{}},requestBody:{},description:{type:"string"},server:{$ref:"#/definitions/Server"}},patternProperties:{"^x-":{}},additionalProperties:false,not:{description:"Operation Id and Operation Ref are mutually exclusive",required:["operationId","operationRef"]}},Callback:{type:"object",additionalProperties:{$ref:"#/definitions/PathItem"},patternProperties:{"^x-":{}}},Encoding:{type:"object",properties:{contentType:{type:"string"},headers:{type:"object",additionalProperties:{oneOf:[{$ref:"#/definitions/Header"},{$ref:"#/definitions/Reference"}]}},style:{type:"string","enum":["form","spaceDelimited","pipeDelimited","deepObject"]},explode:{type:"boolean"},allowReserved:{type:"boolean","default":false}},additionalProperties:false}};var jsonSchema = {id:id,$schema:$schema,description:description,type:type,required:required,properties:properties,patternProperties:patternProperties,additionalProperties:additionalProperties,definitions:definitions};

function parseTimestamp(timestamp) {
    if ((new Date(timestamp)).getTime() > 0) {
        return Number(timestamp);
    }
    else {
        throw new NrError(new Error('invalid timestamp'), ['invalid timestamp']);
    }
}
async function validateDataSharingAgreementSchema(agreement) {
    const errors = [];
    const ajv = new Ajv({ strictSchema: false, removeAdditional: 'all' });
    ajv.addMetaSchema(jsonSchema);
    addFormats(ajv);
    const schema = spec.components.schemas.DataSharingAgreement;
    try {
        const validate = ajv.compile(schema);
        const clonedAgreement = _.cloneDeep(agreement);
        const valid = validate(agreement);
        if (!valid) {
            if (validate.errors !== null && validate.errors !== undefined && validate.errors.length > 0) {
                validate.errors.forEach(error => {
                    errors.push(new NrError(`[${error.instancePath}] ${error.message ?? 'unknown'}`, ['invalid format']));
                });
            }
        }
        if (hashable(clonedAgreement) !== hashable(agreement)) {
            errors.push(new NrError('Additional claims beyond the schema are not supported', ['invalid format']));
        }
    }
    catch (error) {
        errors.push(new NrError(error, ['invalid format']));
    }
    return errors;
}
async function validateDataExchange(dataExchange) {
    const errors = [];
    try {
        const { id, ...dataExchangeButId } = dataExchange;
        if (id !== await exchangeId(dataExchangeButId)) {
            errors.push(new NrError('Invalid dataExchange id', ['cannot verify', 'invalid format']));
        }
        const { blockCommitment, secretCommitment, cipherblockDgst, ...dataExchangeAgreement } = dataExchangeButId;
        const deaErrors = await validateDataExchangeAgreement(dataExchangeAgreement);
        if (deaErrors.length > 0) {
            deaErrors.forEach((error) => {
                errors.push(error);
            });
        }
    }
    catch (error) {
        errors.push(new NrError('Invalid dataExchange', ['cannot verify', 'invalid format']));
    }
    return errors;
}
async function validateDataExchangeAgreement(agreement) {
    const errors = [];
    const agreementClaims = Object.keys(agreement);
    if (agreementClaims.length < 10 || agreementClaims.length > 11) {
        errors.push(new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format']));
    }
    for (const key of agreementClaims) {
        let parsedAddress;
        switch (key) {
            case 'orig':
            case 'dest':
                try {
                    if (agreement[key] !== await parseJwk(JSON.parse(agreement[key]), true)) {
                        errors.push(new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be alphabetically sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose.\n${agreement[key]}`, ['invalid key', 'invalid format']));
                    }
                }
                catch (error) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be alphabetically sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose.`, ['invalid key', 'invalid format']));
                }
                break;
            case 'ledgerContractAddress':
            case 'ledgerSignerAddress':
                try {
                    parsedAddress = parseAddress(agreement[key]);
                    if (agreement[key] !== parsedAddress) {
                        errors.push(new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}. Did you mean ${parsedAddress} instead?`, ['invalid EIP-55 address', 'invalid format']));
                    }
                }
                catch (error) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}.`, ['invalid EIP-55 address', 'invalid format']));
                }
                break;
            case 'pooToPorDelay':
            case 'pooToPopDelay':
            case 'pooToSecretDelay':
                try {
                    if (agreement[key] !== parseTimestamp(agreement[key])) {
                        errors.push(new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid timestamp', 'invalid format']));
                    }
                }
                catch (error) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid timestamp', 'invalid format']));
                }
                break;
            case 'hashAlg':
                if (!HASH_ALGS.includes(agreement[key])) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid hash algorithm '${agreement[key]}'. It must be one of: ${HASH_ALGS.join(', ')}`, ['invalid algorithm']));
                }
                break;
            case 'encAlg':
                if (!ENC_ALGS.includes(agreement[key])) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid encryption algorithm '${agreement[key]}'. It must be one of: ${ENC_ALGS.join(', ')}`, ['invalid algorithm']));
                }
                break;
            case 'signingAlg':
                if (!SIGNING_ALGS.includes(agreement[key])) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid signing algorithm '${agreement[key]}'. It must be one of: ${SIGNING_ALGS.join(', ')}`, ['invalid algorithm']));
                }
                break;
            case 'schema':
                break;
            default:
                errors.push(new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format']));
        }
    }
    return errors;
}

class NonRepudiationDest {
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
        const errors = await validateDataExchangeAgreement(agreement);
        if (errors.length > 0) {
            const errorMsg = [];
            let nrErrors = [];
            errors.forEach((error) => {
                errorMsg.push(error.message);
                nrErrors = nrErrors.concat(error.nrErrors);
            });
            nrErrors = [...(new Set(nrErrors))];
            throw new NrError('Resource has not been validated:\n' + errorMsg.join('\n'), nrErrors);
        }
        this.agreement = agreement;
        this.jwkPairDest = {
            privateJwk,
            publicJwk: JSON.parse(agreement.dest)
        };
        this.publicJwkOrig = JSON.parse(agreement.orig);
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        this.dltAgent = dltAgent;
        const contractAddress = await this.dltAgent.getContractAddress();
        if (this.agreement.ledgerContractAddress !== contractAddress) {
            throw new Error(`Contract address ${contractAddress} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
        }
        this.block = {};
    }
    async verifyPoO(poo, cipherblock, options) {
        await this.initialized;
        const cipherblockDgst = b64.encode(await sha(cipherblock, this.agreement.hashAlg), true, false);
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
            hex: bufToHex(b64.decode(secret.k)),
            jwk: secret
        };
        this.block.pop = {
            jws: pop,
            payload: verified.payload
        };
        return verified;
    }
    async getSecretFromLedger() {
        await this.initialized;
        if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
            throw new Error('Cannot get secret if a PoR has not been sent before');
        }
        const currentTimestamp = Date.now();
        const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay;
        const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000);
        const { hex: secretHex, iat } = await this.dltAgent.getSecretFromLedger(algByteLength(this.agreement.encAlg), this.agreement.ledgerSignerAddress, this.exchange.id, timeout);
        this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex);
        try {
            checkTimestamp(iat * 1000, this.block.por.payload.iat * 1000, this.block.poo.payload.iat * 1000 + this.exchange.pooToSecretDelay);
        }
        catch (error) {
            throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`, ['secret not published in time']);
        }
        return this.block.secret;
    }
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
        const decryptedDgst = b64.encode(await sha(decryptedBlock, this.agreement.hashAlg), true, false);
        if (decryptedDgst !== this.exchange.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.raw = decryptedBlock;
        return decryptedBlock;
    }
    async generateVerificationRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange');
        }
        return await generateVerificationRequest('dest', this.exchange.id, this.block.por.jws, this.jwkPairDest.privateJwk);
    }
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
            const jws = await new SignJWT(payload)
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

class NonRepudiationOrig {
    constructor(agreement, privateJwk, block, dltAgent) {
        this.jwkPairOrig = {
            privateJwk,
            publicJwk: JSON.parse(agreement.orig)
        };
        this.publicJwkDest = JSON.parse(agreement.dest);
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
        const errors = await validateDataExchangeAgreement(agreement);
        if (errors.length > 0) {
            const errorMsg = [];
            let nrErrors = [];
            errors.forEach((error) => {
                errorMsg.push(error.message);
                nrErrors = nrErrors.concat(error.nrErrors);
            });
            nrErrors = [...(new Set(nrErrors))];
            throw new NrError('Resource has not been validated:\n' + errorMsg.join('\n'), nrErrors);
        }
        this.agreement = agreement;
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        const secret = await oneTimeSecret(this.agreement.encAlg);
        this.block = {
            ...this.block,
            secret,
            jwe: await jweEncrypt(this.block.raw, secret.jwk, this.agreement.encAlg)
        };
        const cipherblockDgst = b64.encode(await sha(this.block.jwe, this.agreement.hashAlg), true, false);
        const blockCommitment = b64.encode(await sha(this.block.raw, this.agreement.hashAlg), true, false);
        const secretCommitment = b64.encode(await sha(new Uint8Array(hexToBuf(this.block.secret.hex)), this.agreement.hashAlg), true, false);
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
        const signerAddress = await this.dltAgent.getAddress();
        if (signerAddress !== this.exchange.ledgerSignerAddress) {
            throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address ${signerAddress} derived from the provided private key`);
        }
        const contractAddress = await this.dltAgent.getContractAddress();
        if (contractAddress !== parseHex(this.agreement.ledgerContractAddress, true)) {
            throw new Error(`Contract address in use ${contractAddress} does not meet the agreed one ${this.agreement.ledgerContractAddress}`);
        }
    }
    async generatePoO() {
        await this.initialized;
        this.block.poo = await createProof({
            proofType: 'PoO',
            iss: 'orig',
            exchange: this.exchange
        }, this.jwkPairOrig.privateJwk);
        return this.block.poo;
    }
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

export { index$2 as ConflictResolution, ENC_ALGS, EthersIoAgentDest, EthersIoAgentOrig, HASH_ALGS, I3mServerWalletAgentDest, I3mServerWalletAgentOrig, I3mWalletAgentDest, I3mWalletAgentOrig, KEY_AGREEMENT_ALGS, index as NonRepudiationProtocol, NrError, SIGNING_ALGS, index$1 as Signers, checkTimestamp, createProof, defaultDltConfig, exchangeId, generateKeys, getDltAddress, importJwk, jsonSort, jweDecrypt, jweEncrypt, jwsDecode, oneTimeSecret, parseAddress, parseHex, parseJwk, sha, validateDataExchange, validateDataExchangeAgreement, validateDataSharingAgreementSchema, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy50cyIsIi4uLy4uL3NyYy90cy9lcnJvcnMvTnJFcnJvci50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vZ2VuZXJhdGVLZXlzLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9pbXBvcnRKd2sudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandzRGVjb2RlLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2FsZ0J5dGVMZW5ndGgudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvdGltZXN0YW1wcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9qc29uU29ydC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUp3ay50cyIsIi4uLy4uL3NyYy90cy91dGlscy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VBZGRyZXNzLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2dldERsdEFkZHJlc3MudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvZXhjaGFuZ2VJZC50cyIsIi4uLy4uL3NyYy90cy9wcm9vZnMvY3JlYXRlUHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvcHJvb2ZzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vdmVyaWZ5UG9yLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vY2hlY2tDb21wbGV0ZW5lc3MudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9jaGVja0RlY3J5cHRpb24udHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9Db25mbGljdFJlc29sdmVyLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vZ2VuZXJhdGVWZXJpZmljYXRpb25SZXF1ZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vdmVyaWZ5UmVzb2x1dGlvbi50cyIsIi4uLy4uL3NyYy90cy9kbHQvZGVmYXVsdERsdENvbmZpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL3NlY3JldC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL05ycERsdEFnZW50LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvRXRoZXJzSW9BZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL2Rlc3QvRXRoZXJzSW9BZ2VudERlc3QudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9JM21XYWxsZXRBZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL2Rlc3QvSTNtV2FsbGV0QWdlbnREZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvSTNtU2VydmVyV2FsbGV0QWdlbnQudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9kZXN0L0kzbVNlcnZlcldhbGxldEFnZW50RGVzdC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL29yaWcvRXRoZXJzSW9BZ2VudE9yaWcudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9vcmlnL0kzbVdhbGxldEFnZW50T3JpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL29yaWcvSTNtU2VydmVyV2FsbGV0QWdlbnRPcmlnLnRzIiwiLi4vLi4vc3JjL3RzL2V4Y2hhbmdlL2NoZWNrQWdyZWVtZW50LnRzIiwiLi4vLi4vc3JjL3RzL25vbi1yZXB1ZGlhdGlvbi1wcm90b2NvbC9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiLCIuLi8uLi9zcmMvdHMvbm9uLXJlcHVkaWF0aW9uLXByb3RvY29sL05vblJlcHVkaWF0aW9uT3JpZy50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiaW1wb3J0SldLam9zZSIsInBhcnNlSGV4IiwiYmFzZTY0ZGVjb2RlIiwiYmNQYXJzZUhleCIsImdldFNlY3JldCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7OztBQUFhLE1BQUEsU0FBUyxHQUFHLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQVU7QUFDdEQsTUFBQSxZQUFZLEdBQUcsQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBVTtNQUNuRCxRQUFRLEdBQUcsQ0FBQyxTQUFTLEVBQUUsU0FBUyxFQUFVO0FBQzFDLE1BQUEsa0JBQWtCLEdBQUcsQ0FBQyxTQUFTOztBQ0R0QyxNQUFPLE9BQVEsU0FBUSxLQUFLLENBQUE7SUFHaEMsV0FBYSxDQUFBLEtBQVUsRUFBRSxRQUF1QixFQUFBO1FBQzlDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNaLElBQUksS0FBSyxZQUFZLE9BQU8sRUFBRTtBQUM1QixZQUFBLElBQUksQ0FBQyxRQUFRLEdBQUcsS0FBSyxDQUFDLFFBQVEsQ0FBQTtBQUM5QixZQUFBLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxRQUFRLENBQUMsQ0FBQTtBQUN0QixTQUFBO0FBQU0sYUFBQTtBQUNMLFlBQUEsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUE7QUFDekIsU0FBQTtLQUNGO0lBRUQsR0FBRyxDQUFFLEdBQUcsUUFBdUIsRUFBQTtRQUM3QixNQUFNLE1BQU0sR0FBRyxJQUFJLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUM3QyxRQUFBLElBQUksQ0FBQyxRQUFRLEdBQUcsQ0FBQyxJQUFJLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTtLQUN2QztBQUNGOztBQ1hELE1BQU0sRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsUUFBUSxDQUFBO0FBU3BCLGVBQWUsWUFBWSxDQUFFLEdBQWUsRUFBRSxVQUFnQyxFQUFFLE1BQWdCLEVBQUE7QUFDckcsSUFBQSxJQUFJLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUM7UUFBRSxNQUFNLElBQUksT0FBTyxDQUFDLElBQUksVUFBVSxDQUFDLENBQUEsNkJBQUEsRUFBZ0MsR0FBRyxDQUE4QiwyQkFBQSxFQUFBLFlBQVksQ0FBQyxRQUFRLEVBQUUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFFckwsSUFBQSxJQUFJLFNBQWlCLENBQUE7QUFDckIsSUFBQSxJQUFJLFVBQWtCLENBQUE7QUFDdEIsSUFBQSxRQUFRLEdBQUc7QUFDVCxRQUFBLEtBQUssT0FBTztZQUNWLFVBQVUsR0FBRyxPQUFPLENBQUE7WUFDcEIsU0FBUyxHQUFHLEVBQUUsQ0FBQTtZQUNkLE1BQUs7QUFDUCxRQUFBLEtBQUssT0FBTztZQUNWLFVBQVUsR0FBRyxPQUFPLENBQUE7WUFDcEIsU0FBUyxHQUFHLEVBQUUsQ0FBQTtZQUNkLE1BQUs7QUFDUCxRQUFBO1lBQ0UsVUFBVSxHQUFHLE9BQU8sQ0FBQTtZQUNwQixTQUFTLEdBQUcsRUFBRSxDQUFBO0FBQ2pCLEtBQUE7QUFFRCxJQUFBLElBQUksVUFBa0MsQ0FBQTtJQUN0QyxJQUFJLFVBQVUsS0FBSyxTQUFTLEVBQUU7QUFDNUIsUUFBQSxJQUFJLE9BQU8sVUFBVSxLQUFLLFFBQVEsRUFBRTtZQUNsQyxJQUFJLE1BQU0sS0FBSyxJQUFJLEVBQUU7QUFDbkIsZ0JBQUEsVUFBVSxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFlLENBQUE7QUFDbEQsYUFBQTtBQUFNLGlCQUFBO2dCQUNMLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQTtBQUNsRCxhQUFBO0FBQ0YsU0FBQTtBQUFNLGFBQUE7WUFDTCxVQUFVLEdBQUcsVUFBVSxDQUFBO0FBQ3hCLFNBQUE7QUFDRixLQUFBO0FBQU0sU0FBQTtRQUNMLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNLFNBQVMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFBO0FBQ3hELEtBQUE7QUFFRCxJQUFBLE1BQU0sRUFBRSxHQUFHLElBQUksRUFBRSxDQUFDLEdBQUcsR0FBRyxVQUFVLENBQUMsU0FBUyxDQUFDLFVBQVUsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUNwRSxNQUFNLE1BQU0sR0FBRyxFQUFFLENBQUMsY0FBYyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQzVDLElBQUEsTUFBTSxLQUFLLEdBQUcsTUFBTSxDQUFDLFNBQVMsRUFBRSxDQUFBO0lBRWhDLE1BQU0sSUFBSSxHQUFHLEtBQUssQ0FBQyxJQUFJLEVBQUUsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7SUFDdEUsTUFBTSxJQUFJLEdBQUcsS0FBSyxDQUFDLElBQUksRUFBRSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxRQUFRLENBQUMsU0FBUyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQTtBQUN0RSxJQUFBLE1BQU0sSUFBSSxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFFbEUsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFFakQsSUFBQSxNQUFNLFVB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
