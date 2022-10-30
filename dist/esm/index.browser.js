import * as b64 from '@juanelas/base64';
import { decode } from '@juanelas/base64';
import { hexToBuf, bufToHex } from 'bigint-conversion';
import { randBytes, randBytesSync } from 'bigint-crypto-utils';
import elliptic from 'elliptic';
import { importJWK, CompactEncrypt, compactDecrypt, jwtVerify, generateSecret, exportJWK, GeneralSign, generalVerify, SignJWT } from 'jose';
import { ethers, Wallet } from 'ethers';
import { hashable } from 'object-sha';
import { SigningKey } from 'ethers/lib/utils';

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

const { ec: Ec } = elliptic;
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
    try {
        const key = await importJWK(jwk, alg);
        return key;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

async function jweEncrypt(block, secret, encAlg) {
    const key = await importJwk(secret);
    let jwe;
    try {
        jwe = await new CompactEncrypt(block)
            .setProtectedHeader({ alg: 'dir', enc: encAlg, kid: secret.kid })
            .encrypt(key);
        return jwe;
    }
    catch (error) {
        throw new NrError(error, ['encryption failed']);
    }
}
async function jweDecrypt(jwe, secret, encAlg = 'A256GCM') {
    const key = await importJwk(secret);
    try {
        return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] });
    }
    catch (error) {
        const nrError = new NrError(error, ['decryption failed']);
        throw nrError;
    }
}

async function jwsDecode(jws, publicJwk) {
    const regex = /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/;
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
    const hexMatch = a.match(/^(0x)?(([\da-fA-F][\da-fA-F])+)$/);
    if (hexMatch == null) {
        throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format']);
    }
    let hex = hexMatch[2];
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
        if (true) {
            digest = new Uint8Array(await crypto.subtle.digest(algorithm, hashInput));
        }'crypto'
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
    const hex = hexMatch[2];
    return ethers.utils.getAddress('0x' + hex);
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
                key = b64.decode(secret);
            }
            else {
                key = new Uint8Array(hexToBuf(parseHex(secret, undefined, secretLength)));
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
    return { jwk: jwk, hex: bufToHex(decode(jwk.k)) };
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

async function exchangeId(exchange) {
    return b64.encode(await sha(hashable(exchange), 'SHA-256'), true, false);
}

const HASH_ALGS = ['SHA-256', 'SHA-384', 'SHA-512'];
const SIGNING_ALGS = ['ES256', 'ES384', 'ES512'];
const ENC_ALGS = ['A128GCM', 'A256GCM'];

function parseTimestamp(timestamp) {
    if ((new Date(timestamp)).getTime() > 0) {
        return Number(timestamp);
    }
    else {
        throw new NrError(new Error('invalid timestamp'), ['invalid timestamp']);
    }
}
async function validateAgreement(agreement) {
    const agreementClaims = Object.keys(agreement);
    if (agreementClaims.length < 10 || agreementClaims.length > 11) {
        throw new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format']);
    }
    for (const key of agreementClaims) {
        let parsedAddress;
        switch (key) {
            case 'orig':
            case 'dest':
                if (agreement[key] !== await parseJwk(JSON.parse(agreement[key]), true)) {
                    throw new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose`, ['invalid key', 'invalid format']);
                }
                break;
            case 'ledgerContractAddress':
            case 'ledgerSignerAddress':
                try {
                    parsedAddress = parseAddress(agreement[key]);
                }
                catch (error) {
                    throw new NrError(error.message, ['invalid format']);
                }
                if (agreement[key] !== parsedAddress) {
                    throw new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}. Did you mean ${parsedAddress} instead?`, ['invalid format']);
                }
                break;
            case 'pooToPorDelay':
            case 'pooToPopDelay':
            case 'pooToSecretDelay':
                if (agreement[key] !== parseTimestamp(agreement[key])) {
                    throw new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid format']);
                }
                break;
            case 'hashAlg':
                if (!HASH_ALGS.includes(agreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'encAlg':
                if (!ENC_ALGS.includes(agreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'signingAlg':
                if (!SIGNING_ALGS.includes(agreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'schema':
                break;
            default:
                throw new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format']);
        }
    }
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
    checkCompleteness: checkCompleteness,
    checkDecryption: checkDecryption,
    ConflictResolver: ConflictResolver,
    generateVerificationRequest: generateVerificationRequest,
    verifyPor: verifyPor,
    verifyResolution: verifyResolution
});

var address = "0x8d407A1722633bDD1dcf221474be7a44C05d7c2F";
var abi = [
	{
		anonymous: false,
		inputs: [
			{
				indexed: false,
				internalType: "address",
				name: "sender",
				type: "address"
			},
			{
				indexed: false,
				internalType: "uint256",
				name: "dataExchangeId",
				type: "uint256"
			},
			{
				indexed: false,
				internalType: "uint256",
				name: "timestamp",
				type: "uint256"
			},
			{
				indexed: false,
				internalType: "uint256",
				name: "secret",
				type: "uint256"
			}
		],
		name: "Registration",
		type: "event"
	},
	{
		inputs: [
			{
				internalType: "address",
				name: "",
				type: "address"
			},
			{
				internalType: "uint256",
				name: "",
				type: "uint256"
			}
		],
		name: "registry",
		outputs: [
			{
				internalType: "uint256",
				name: "timestamp",
				type: "uint256"
			},
			{
				internalType: "uint256",
				name: "secret",
				type: "uint256"
			}
		],
		stateMutability: "view",
		type: "function"
	},
	{
		inputs: [
			{
				internalType: "uint256",
				name: "_dataExchangeId",
				type: "uint256"
			},
			{
				internalType: "uint256",
				name: "_secret",
				type: "uint256"
			}
		],
		name: "setRegistry",
		outputs: [
		],
		stateMutability: "nonpayable",
		type: "function"
	}
];
var transactionHash = "0x6a3828f8fe232819dc40ca66f93930b3bd1619db31a67ec34b44446b3e7c8289";
var receipt = {
	to: null,
	from: "0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903",
	contractAddress: "0x8d407A1722633bDD1dcf221474be7a44C05d7c2F",
	transactionIndex: 0,
	gasUsed: "253928",
	logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	blockHash: "0x0118672bb9b27679e616831d056d36291dd20cfe88c3ee2abd8f2dfce579cad4",
	transactionHash: "0x6a3828f8fe232819dc40ca66f93930b3bd1619db31a67ec34b44446b3e7c8289",
	logs: [
	],
	blockNumber: 119389,
	cumulativeGasUsed: "253928",
	status: 1,
	byzantium: true
};
var args = [
];
var solcInputHash = "c528a37588793ef74285d75e08d6b8eb";
var metadata = "{\"compiler\":{\"version\":\"0.8.4+commit.c7e474f2\"},\"language\":\"Solidity\",\"output\":{\"abi\":[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"dataExchangeId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"secret\",\"type\":\"uint256\"}],\"name\":\"Registration\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"registry\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"secret\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_dataExchangeId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_secret\",\"type\":\"uint256\"}],\"name\":\"setRegistry\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\"devdoc\":{\"kind\":\"dev\",\"methods\":{},\"version\":1},\"userdoc\":{\"kind\":\"user\",\"methods\":{},\"version\":1}},\"settings\":{\"compilationTarget\":{\"contracts/NonRepudiation.sol\":\"NonRepudiation\"},\"evmVersion\":\"istanbul\",\"libraries\":{},\"metadata\":{\"bytecodeHash\":\"ipfs\",\"useLiteralContent\":true},\"optimizer\":{\"enabled\":false,\"runs\":200},\"remappings\":[]},\"sources\":{\"contracts/NonRepudiation.sol\":{\"content\":\"//SPDX-License-Identifier: Unlicense\\npragma solidity ^0.8.0;\\n\\ncontract NonRepudiation {\\n    struct Proof {\\n        uint256 timestamp;\\n        uint256 secret;\\n    }\\n    mapping(address => mapping (uint256 => Proof)) public registry;\\n    event Registration(address sender, uint256 dataExchangeId, uint256 timestamp, uint256 secret);\\n\\n    function setRegistry(uint256 _dataExchangeId, uint256 _secret) public {\\n        require(registry[msg.sender][_dataExchangeId].secret == 0);\\n        registry[msg.sender][_dataExchangeId] = Proof(block.timestamp, _secret);\\n        emit Registration(msg.sender, _dataExchangeId, block.timestamp, _secret);\\n    }\\n}\\n\",\"keccak256\":\"0x8d371257a9b03c9102f158323e61f56ce49dd8489bd92c5a7d8abc3d9f6f8399\",\"license\":\"Unlicense\"}},\"version\":1}";
var bytecode = "0x608060405234801561001057600080fd5b506103a2806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b6100556004803603810190610050919061023a565b610088565b005b610071600480360381019061006c91906101fe565b6101a3565b60405161007f9291906102d9565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060010154146100e757600080fd5b6040518060400160405280428152602001828152506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060008201518160000155602082015181600101559050507faa58599838af2e5e0f3251cfbb4eac5d5d447ded49f6b0ac28d6b44098224e63338342846040516101979493929190610294565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150508060000154908060010154905082565b6000813590506101e38161033e565b92915050565b6000813590506101f881610355565b92915050565b6000806040838503121561021157600080fd5b600061021f858286016101d4565b9250506020610230858286016101e9565b9150509250929050565b6000806040838503121561024d57600080fd5b600061025b858286016101e9565b925050602061026c858286016101e9565b9150509250929050565b61027f81610302565b82525050565b61028e81610334565b82525050565b60006080820190506102a96000830187610276565b6102b66020830186610285565b6102c36040830185610285565b6102d06060830184610285565b95945050505050565b60006040820190506102ee6000830185610285565b6102fb6020830184610285565b9392505050565b600061030d82610314565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b61034781610302565b811461035257600080fd5b50565b61035e81610334565b811461036957600080fd5b5056fea26469706673582212204fd0fc653fb487221da9a14a4ca5d5499f9e9bc7b27ac8ab0f8d397fd6e3148564736f6c63430008040033";
var deployedBytecode = "0x608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b6100556004803603810190610050919061023a565b610088565b005b610071600480360381019061006c91906101fe565b6101a3565b60405161007f9291906102d9565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060010154146100e757600080fd5b6040518060400160405280428152602001828152506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002060008201518160000155602082015181600101559050507faa58599838af2e5e0f3251cfbb4eac5d5d447ded49f6b0ac28d6b44098224e63338342846040516101979493929190610294565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150508060000154908060010154905082565b6000813590506101e38161033e565b92915050565b6000813590506101f881610355565b92915050565b6000806040838503121561021157600080fd5b600061021f858286016101d4565b9250506020610230858286016101e9565b9150509250929050565b6000806040838503121561024d57600080fd5b600061025b858286016101e9565b925050602061026c858286016101e9565b9150509250929050565b61027f81610302565b82525050565b61028e81610334565b82525050565b60006080820190506102a96000830187610276565b6102b66020830186610285565b6102c36040830185610285565b6102d06060830184610285565b95945050505050565b60006040820190506102ee6000830185610285565b6102fb6020830184610285565b9392505050565b600061030d82610314565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b61034781610302565b811461035257600080fd5b50565b61035e81610334565b811461036957600080fd5b5056fea26469706673582212204fd0fc653fb487221da9a14a4ca5d5499f9e9bc7b27ac8ab0f8d397fd6e3148564736f6c63430008040033";
var devdoc = {
	kind: "dev",
	methods: {
	},
	version: 1
};
var userdoc = {
	kind: "user",
	methods: {
	},
	version: 1
};
var storageLayout = {
	storage: [
		{
			astId: 13,
			contract: "contracts/NonRepudiation.sol:NonRepudiation",
			label: "registry",
			offset: 0,
			slot: "0",
			type: "t_mapping(t_address,t_mapping(t_uint256,t_struct(Proof)6_storage))"
		}
	],
	types: {
		t_address: {
			encoding: "inplace",
			label: "address",
			numberOfBytes: "20"
		},
		"t_mapping(t_address,t_mapping(t_uint256,t_struct(Proof)6_storage))": {
			encoding: "mapping",
			key: "t_address",
			label: "mapping(address => mapping(uint256 => struct NonRepudiation.Proof))",
			numberOfBytes: "32",
			value: "t_mapping(t_uint256,t_struct(Proof)6_storage)"
		},
		"t_mapping(t_uint256,t_struct(Proof)6_storage)": {
			encoding: "mapping",
			key: "t_uint256",
			label: "mapping(uint256 => struct NonRepudiation.Proof)",
			numberOfBytes: "32",
			value: "t_struct(Proof)6_storage"
		},
		"t_struct(Proof)6_storage": {
			encoding: "inplace",
			label: "struct NonRepudiation.Proof",
			members: [
				{
					astId: 3,
					contract: "contracts/NonRepudiation.sol:NonRepudiation",
					label: "timestamp",
					offset: 0,
					slot: "0",
					type: "t_uint256"
				},
				{
					astId: 5,
					contract: "contracts/NonRepudiation.sol:NonRepudiation",
					label: "secret",
					offset: 0,
					slot: "1",
					type: "t_uint256"
				}
			],
			numberOfBytes: "64"
		},
		t_uint256: {
			encoding: "inplace",
			label: "uint256",
			numberOfBytes: "32"
		}
	}
};
var contractConfig = {
	address: address,
	abi: abi,
	transactionHash: transactionHash,
	receipt: receipt,
	args: args,
	solcInputHash: solcInputHash,
	metadata: metadata,
	bytecode: bytecode,
	deployedBytecode: deployedBytecode,
	devdoc: devdoc,
	userdoc: userdoc,
	storageLayout: storageLayout
};

const defaultDltConfig = {
    gasLimit: 12500000,
    contract: contractConfig
};

async function getSecretFromLedger(contract, signerAddress, exchangeId, timeout) {
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
    const hex = parseHex(secretBn.toHexString(), false);
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
    async getSecretFromLedger(signerAddress, exchangeId, timeout) {
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout);
    }
}

class I3mWalletAgent extends EthersIoAgent {
    constructor(wallet, did, dltConfig) {
        const dltConfigPromise = new Promise((resolve, reject) => {
            wallet.providerinfo.get().then((providerInfo) => {
                const rpcProviderUrl = providerInfo.rpcUrl;
                if (rpcProviderUrl === undefined) {
                    reject(new Error('wallet is not connected to RRP endpoint'));
                }
                else {
                    resolve({
                        ...dltConfig,
                        rpcProviderUrl: rpcProviderUrl
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
    async getSecretFromLedger(signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout);
    }
}

class I3mServerWalletAgent extends EthersIoAgent {
    constructor(serverWallet, did, dltConfig) {
        const dltConfigPromise = new Promise((resolve, reject) => {
            serverWallet.providerinfoGet().then((providerInfo) => {
                const rpcProviderUrl = providerInfo.rpcUrl;
                if (rpcProviderUrl === undefined) {
                    reject(new Error('wallet is not connected to RRP endpoint'));
                }
                else {
                    resolve({
                        ...dltConfig,
                        rpcProviderUrl: rpcProviderUrl
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
    async getSecretFromLedger(signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout);
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
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const signedTx = await this.signer.signTransaction(unsignedTx);
        const setRegistryTx = await this.signer.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        return this.signer.address;
    }
    async nextNonce() {
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
    I3mWalletAgentDest: I3mWalletAgentDest,
    I3mServerWalletAgentDest: I3mServerWalletAgentDest,
    EthersIoAgentOrig: EthersIoAgentOrig,
    I3mWalletAgentOrig: I3mWalletAgentOrig,
    I3mServerWalletAgentOrig: I3mServerWalletAgentOrig
});

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
        await validateAgreement(agreement);
        this.agreement = agreement;
        this.jwkPairDest = {
            privateJwk: privateJwk,
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
            privateJwk: privateJwk,
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
        await validateAgreement(agreement);
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

export { index$2 as ConflictResolution, ENC_ALGS, EthersIoAgentDest, EthersIoAgentOrig, HASH_ALGS, I3mServerWalletAgentDest, I3mServerWalletAgentOrig, I3mWalletAgentDest, I3mWalletAgentOrig, index as NonRepudiationProtocol, NrError, SIGNING_ALGS, index$1 as Signers, checkTimestamp, createProof, defaultDltConfig, exchangeId, generateKeys, getDltAddress, importJwk, jsonSort, jweDecrypt, jweEncrypt, jwsDecode, oneTimeSecret, parseAddress, parseHex, parseJwk, sha, validateAgreement, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2Vycm9ycy9OckVycm9yLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9nZW5lcmF0ZUtleXMudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2ltcG9ydEp3ay50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandlLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9qd3NEZWNvZGUudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvdGltZXN0YW1wcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9qc29uU29ydC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUp3ay50cyIsIi4uLy4uL3NyYy90cy91dGlscy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VBZGRyZXNzLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2dldERsdEFkZHJlc3MudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvZXhjaGFuZ2VJZC50cyIsIi4uLy4uL3NyYy90cy9jb25zdGFudHMudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvY2hlY2tBZ3JlZW1lbnQudHMiLCIuLi8uLi9zcmMvdHMvcHJvb2ZzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL3Byb29mcy92ZXJpZnlQcm9vZi50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL3ZlcmlmeVBvci50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL2NoZWNrQ29tcGxldGVuZXNzLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vY2hlY2tEZWNyeXB0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vQ29uZmxpY3RSZXNvbHZlci50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL2dlbmVyYXRlVmVyaWZpY2F0aW9uUmVxdWVzdC50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL3ZlcmlmeVJlc29sdXRpb24udHMiLCIuLi8uLi9zcmMvdHMvZGx0L2RlZmF1bHREbHRDb25maWcudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9zZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9OcnBEbHRBZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL0V0aGVyc0lvQWdlbnQudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9kZXN0L0V0aGVyc0lvQWdlbnREZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvSTNtV2FsbGV0QWdlbnQudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9kZXN0L0kzbVdhbGxldEFnZW50RGVzdC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL0kzbVNlcnZlcldhbGxldEFnZW50LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvZGVzdC9JM21TZXJ2ZXJXYWxsZXRBZ2VudERlc3QudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9vcmlnL0V0aGVyc0lvQWdlbnRPcmlnLnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvb3JpZy9JM21XYWxsZXRBZ2VudE9yaWcudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9vcmlnL0kzbVNlcnZlcldhbGxldEFnZW50T3JpZy50cyIsIi4uLy4uL3NyYy90cy9ub24tcmVwdWRpYXRpb24tcHJvdG9jb2wvTm9uUmVwdWRpYXRpb25EZXN0LnRzIiwiLi4vLi4vc3JjL3RzL25vbi1yZXB1ZGlhdGlvbi1wcm90b2NvbC9Ob25SZXB1ZGlhdGlvbk9yaWcudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImltcG9ydEpXS2pv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RUFBRSxDQUFBO0lBRWhDLE1BQU0sSUFBSSxHQUFHLEtBQUssQ0FBQyxJQUFJLEVBQUUsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7SUFDdEUsTUFBTSxJQUFJLEdBQUcsS0FBSyxDQUFDLElBQUksRUFBRSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxRQUFRLENBQUMsU0FBUyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQTtBQUN0RSxJQUFBLE1BQU0sSUFBSSxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFFbEUsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFFakQsSUFBQSxNQUFNLFVBQVUsR0FBUSxFQUFFLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxHQUFHLEVBQUUsQ0FBQTtBQUVwRSxJQUFBLE1BQU0sU0FBUyxHQUFRLEVBQUUsR0FBRyxVQUFVLEVBQUUsQ0FBQTtJQUN4QyxPQUFPLFNBQVMsQ0FBQyxDQUFDLENBQUE7SUFFbEIsT0FBTztRQUNMLFNBQVM7UUFDVCxVQUFVO0tBQ1gsQ0FBQTtBQUNIOztBQ3BFTyxlQUFlLFNBQVMsQ0FB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
