'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jose = require('jose');
var bigintCryptoUtils = require('bigint-crypto-utils');
var bigintConversion = require('bigint-conversion');
var objectSha = require('object-sha');

async function verifyKeyPair(pubJWK, privJWK, alg) {
    const pubKey = await jose.importJWK(pubJWK, alg);
    const privKey = await jose.importJWK(privJWK, alg);
    const nonce = await bigintCryptoUtils.randBytes(16);
    const jws = await new jose.GeneralSign(nonce)
        .addSignature(privKey)
        .setProtectedHeader({ alg: privJWK.alg })
        .sign();
    const { payload } = await jose.generalVerify(jws, pubKey);
    if (bigintConversion.bufToHex(payload) !== bigintConversion.bufToHex(nonce)) {
        throw new Error(`verified nonce ${bigintConversion.bufToHex(payload)} does not meet the one challenged ${bigintConversion.bufToHex(nonce)}`);
    }
}

/**
 * Creates a non-repudiable proof for a given data exchange
 * @param issuer - if the issuer of the proof is the origin 'orig' or the destination 'dest' of the data exchange
 * @param payload - it must contain a 'dataExchange' the issuer 'iss' (either point to the origin 'orig' or the destination 'dest' of the data exchange) of the proof and any specific proof key-values
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
async function createProof(payload, privateJwk) {
    // Check that that the privateKey is the complement to the public key of the issuer
    const publicJwk = JSON.parse(payload.dataExchange[payload.iss]);
    await verifyKeyPair(publicJwk, privateJwk); // if verification fails it throws an error and the following is not executed
    const privateKey = await jose.importJWK(privateJwk);
    const alg = privateJwk.alg;
    if (alg === undefined) {
        throw new Error('Private key does not have the alg property:\n' + JSON.stringify(privateJwk, undefined, 2));
    }
    return await new jose.SignJWT(payload)
        .setProtectedHeader({ alg })
        .setIssuedAt()
        .sign(privateKey);
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
 *   dateExchange: {
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
    const pubKey = await jose.importJWK(publicJwk);
    const verification = await jose.jwtVerify(proof, pubKey, dateTolerance);
    const payload = verification.payload;
    // Check that that the publicKey is the public key of the issuer
    const issuer = payload.dataExchange[payload.iss];
    if (objectSha.hashable(publicJwk) !== objectSha.hashable(JSON.parse(issuer))) {
        throw new Error(`The proof is issued by ${issuer} instead of ${JSON.stringify(publicJwk)}`);
    }
    for (const key in expectedPayloadClaims) {
        if (payload[key] === undefined)
            throw new Error(`Expected key '${key}' not found in proof`);
        if (key === 'dataExchange') {
            const expectedDataExchange = expectedPayloadClaims.dataExchange;
            const dataExchange = payload.dataExchange;
            checkDataExchange(dataExchange, expectedDataExchange);
        }
        else {
            if (objectSha.hashable(expectedPayloadClaims[key]) !== objectSha.hashable(payload[key])) {
                throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedPayloadClaims[key], undefined, 2)}`);
            }
        }
    }
    return (verification);
}
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
        if (objectSha.hashable(expectedDataExchange[key]) !== objectSha.hashable(dataExchange[key])) {
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
    const key = await jose.importJWK(secret);
    return await new jose.CompactEncrypt(block)
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
    const key = await jose.importJWK(secret);
    return await jose.compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [ENC_ALG] });
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
        const nodeAlg = algorithm.toLowerCase().replace('-', '');
        digest = require('crypto').createHash(nodeAlg).update(Buffer.from(hashInput)).digest('hex'); // eslint-disable-line
    }
    return digest;
}

/**
 * Create a random (high entropy) symmetric JWK secret for AES-256-GCM
 *
 * @returns a promise that resolves to a JWK
 */
async function oneTimeSecret() {
    const key = await jose.generateSecret(ENC_ALG, { extractable: true });
    const jwk = await jose.exportJWK(key);
    const thumbprint = await jose.calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = ENC_ALG;
    return jwk;
}

class NonRepudiationOrig {
    constructor(dataExchangeId, jwkPairOrig, publicJwkDest, block, alg) {
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
        this.dataExchange = {
            id: dataExchangeId,
            orig: JSON.stringify(this.jwkPairOrig.publicJwk),
            dest: JSON.stringify(this.publicJwkDest),
            hashAlg: HASH_ALG
        };
        this.block = {
            raw: block
        };
        this.checked = false;
    }
    async init() {
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        this.block.secret = await oneTimeSecret();
        const secretStr = JSON.stringify(this.block.secret);
        this.block.jwe = await jweEncrypt(this.dataExchange.id, this.block.raw, this.block.secret);
        this.dataExchange = {
            ...this.dataExchange,
            cipherblockDgst: await sha(this.block.jwe, this.dataExchange.hashAlg),
            blockCommitment: await sha(this.block.raw, this.dataExchange.hashAlg),
            secretCommitment: await sha(secretStr, this.dataExchange.hashAlg)
        };
        this.checked = true;
    }
    /**
     * Creates the proof of origin (PoO) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.poo
     *
     */
    async generatePoO() {
        this._checkInit();
        const payload = {
            proofType: 'PoO',
            iss: 'orig',
            dataExchange: this.dataExchange
        };
        this.block.poo = await createProof(payload, this.jwkPairOrig.privateJwk);
        return this.block.poo;
    }
    async verifyPoR(por) {
        this._checkInit();
        if (this.block?.poo === undefined) {
            throw new Error('Cannot verify a PoR if not even a PoO have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoR',
            iss: 'dest',
            dataExchange: this.dataExchange,
            pooDgst: await sha(this.block.poo, this.dataExchange.hashAlg)
        };
        const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims);
        this.block.por = por;
        return verified;
    }
    async generatePoP(verificationCode) {
        this._checkInit();
        if (this.block?.por === undefined) {
            throw new Error('Before computing a PoP, you have first to receive a verify a PoR');
        }
        const payload = {
            proofType: 'PoP',
            iss: 'orig',
            dataExchange: this.dataExchange,
            porDgst: await sha(this.block.por, this.dataExchange.hashAlg),
            secret: JSON.stringify(this.block.secret),
            verificationCode: verificationCode
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

class NonRepudiationDest {
    constructor(dataExchangeId, jwkPairDest, publicJwkOrig) {
        this.jwkPairDest = jwkPairDest;
        this.publicJwkOrig = publicJwkOrig;
        this.dataExchange = {
            id: dataExchangeId,
            orig: JSON.stringify(this.publicJwkOrig),
            dest: JSON.stringify(this.jwkPairDest.publicJwk),
            hashAlg: HASH_ALG
        };
        this.checked = false;
    }
    async init() {
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        this.checked = true;
    }
    async verifyPoO(poo, cipherblock) {
        this._checkInit();
        const dataExchange = {
            ...this.dataExchange,
            cipherblockDgst: await sha(cipherblock, this.dataExchange.hashAlg)
        };
        const expectedPayloadClaims = {
            proofType: 'PoO',
            iss: 'orig',
            dataExchange
        };
        const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims);
        this.block = {
            jwe: cipherblock,
            poo: poo
        };
        this.dataExchange = verified.payload.dataExchange;
        return verified;
    }
    /**
     * Creates the proof of reception (PoR) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.por
     *
     */
    async generatePoR() {
        this._checkInit();
        if (this.block?.poo === undefined) {
            throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO');
        }
        const payload = {
            proofType: 'PoR',
            iss: 'dest',
            dataExchange: this.dataExchange,
            pooDgst: await sha(this.block.poo)
        };
        this.block.por = await createProof(payload, this.jwkPairDest.privateJwk);
        return this.block.por;
    }
    async verifyPoPAndDecrypt(pop, secret, verificationCode) {
        this._checkInit();
        if (this.block?.por === undefined) {
            throw new Error('Cannot verify a PoP if not even a PoR have been created');
        }
        const decryptedBlock = (await jweDecrypt(this.block.jwe, JSON.parse(secret))).plaintext;
        const decryptedDgst = await sha(decryptedBlock);
        if (decryptedDgst !== this.dataExchange.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.secret = JSON.parse(secret);
        this.block.decrypted = decryptedBlock;
        const expectedPayloadClaims = {
            proofType: 'PoP',
            iss: 'orig',
            dataExchange: this.dataExchange,
            porDgst: await sha(this.block.por),
            secret,
            verificationCode
        };
        const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims);
        this.block.pop = pop;
        return { verified, decryptedBlock };
    }
    _checkInit() {
        if (!this.checked) {
            throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()');
        }
    }
}

exports.ENC_ALG = ENC_ALG;
exports.HASH_ALG = HASH_ALG;
exports.NonRepudiationDest = NonRepudiationDest;
exports.NonRepudiationOrig = NonRepudiationOrig;
exports.SIGNING_ALG = SIGNING_ALG;
exports.createProof = createProof;
exports.jweDecrypt = jweDecrypt;
exports.jweEncrypt = jweEncrypt;
exports.oneTimeSecret = oneTimeSecret;
exports.sha = sha;
exports.verifyKeyPair = verifyKeyPair;
exports.verifyProof = verifyProof;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy50cyIsIi4uLy4uL3NyYy90cy9qd2UudHMiLCIuLi8uLi9zcmMvdHMvc2hhLnRzIiwiLi4vLi4vc3JjL3RzL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvTm9uUmVwdWRpYXRpb25PcmlnLnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uRGVzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiaW1wb3J0SldLIiwicmFuZEJ5dGVzIiwiR2VuZXJhbFNpZ24iLCJnZW5lcmFsVmVyaWZ5IiwiYnVmVG9IZXgiLCJTaWduSldUIiwiand0VmVyaWZ5IiwiaGFzaGFibGUiLCJDb21wYWN0RW5jcnlwdCIsImNvbXBhY3REZWNyeXB0IiwiZ2VuZXJhdGVTZWNyZXQiLCJleHBvcnRKV0siLCJjYWxjdWxhdGVKd2tUaHVtYnByaW50Il0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFJTyxlQUFlLGFBQWEsQ0FBRSxNQUFXLEVBQUUsT0FBWSxFQUFFLEdBQVk7SUFDMUUsTUFBTSxNQUFNLEdBQUcsTUFBTUEsY0FBUyxDQUFDLE1BQU0sRUFBRSxHQUFHLENBQUMsQ0FBQTtJQUMzQyxNQUFNLE9BQU8sR0FBRyxNQUFNQSxjQUFTLENBQUMsT0FBTyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0lBQzdDLE1BQU0sS0FBSyxHQUFHLE1BQU1DLDJCQUFTLENBQUMsRUFBRSxDQUFDLENBQUE7SUFDakMsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJQyxnQkFBVyxDQUFDLEtBQUssQ0FBQztTQUNyQyxZQUFZLENBQUMsT0FBTyxDQUFDO1NBQ3JCLGtCQUFrQixDQUFDLEVBQUUsR0FBRyxFQUFFLE9BQU8sQ0FB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
