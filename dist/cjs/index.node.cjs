'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jose = require('jose');
var bigintCryptoUtils = require('bigint-crypto-utils');
var objectSha = require('object-sha');

async function verifyKeyPair(pubJWK, privJWK, alg) {
    const pubKey = await jose.importJWK(pubJWK, alg);
    const privKey = await jose.importJWK(privJWK, alg);
    const nonce = await bigintCryptoUtils.randBytes(16);
    const jws = await new jose.GeneralSign(nonce)
        .addSignature(privKey)
        .setProtectedHeader({ alg: privJWK.alg })
        .sign();
    await jose.generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
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
    const privateKey = await jose.importJWK(privateJwk);
    const alg = privateJwk.alg; // if alg wer undefined the previous import throws error
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
    const pubKey = await jose.importJWK(publicJwk);
    const verification = await jose.jwtVerify(proof, pubKey, dateTolerance);
    const payload = verification.payload;
    // Check that that the publicKey is the public key of the issuer
    const issuer = payload.exchange[payload.iss];
    if (objectSha.hashable(publicJwk) !== objectSha.hashable(JSON.parse(issuer))) {
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
            if (objectSha.hashable(expectedPayloadClaims[key]) !== objectSha.hashable(payload[key])) {
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy50cyIsIi4uLy4uL3NyYy90cy9qd2UudHMiLCIuLi8uLi9zcmMvdHMvc2hhLnRzIiwiLi4vLi4vc3JjL3RzL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvTm9uUmVwdWRpYXRpb25PcmlnLnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uRGVzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiaW1wb3J0SldLIiwicmFuZEJ5dGVzIiwiR2VuZXJhbFNpZ24iLCJnZW5lcmFsVmVyaWZ5IiwiU2lnbkpXVCIsImp3dFZlcmlmeSIsImhhc2hhYmxlIiwiQ29tcGFjdEVuY3J5cHQiLCJjb21wYWN0RGVjcnlwdCIsImdlbmVyYXRlU2VjcmV0IiwiZXhwb3J0SldLIiwiY2FsY3VsYXRlSndrVGh1bWJwcmludCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7QUFHTyxlQUFlLGFBQWEsQ0FBRSxNQUFXLEVBQUUsT0FBWSxFQUFFLEdBQVk7SUFDMUUsTUFBTSxNQUFNLEdBQUcsTUFBTUEsY0FBUyxDQUFDLE1BQU0sRUFBRSxHQUFHLENBQUMsQ0FBQTtJQUMzQyxNQUFNLE9BQU8sR0FBRyxNQUFNQSxjQUFTLENBQUMsT0FBTyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0lBQzdDLE1BQU0sS0FBSyxHQUFHLE1BQU1DLDJCQUFTLENBQUMsRUFBRSxDQUFDLENBQUE7SUFDakMsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJQyxnQkFBVyxDQUFDLEtBQUssQ0FBQztTQUNyQyxZQUFZLENBQUMsT0FBTyxDQUFDO1NBQ3JCLGtCQUFrQixDQUFDLEVBQUUsR0FBRyxFQUFFLE9BQU8sQ0FBQyxHQUFHLEVBQUUs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
