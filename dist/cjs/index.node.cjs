'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var generateSecret = require('jose/util/generate_secret');
var fromKeyLike = require('jose/jwk/from_key_like');
var CompactEncrypt = require('jose/jwe/compact/encrypt');
var calculateThumbprint = require('jose/jwk/thumbprint');
var parseJwk = require('jose/jwk/parse');
var CompactSign = require('jose/jws/compact/sign');
var compactDecrypt = require('jose/jwe/compact/decrypt');
var compactVerify = require('jose/jws/compact/verify');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var generateSecret__default = /*#__PURE__*/_interopDefaultLegacy(generateSecret);
var fromKeyLike__default = /*#__PURE__*/_interopDefaultLegacy(fromKeyLike);
var CompactEncrypt__default = /*#__PURE__*/_interopDefaultLegacy(CompactEncrypt);
var calculateThumbprint__default = /*#__PURE__*/_interopDefaultLegacy(calculateThumbprint);
var parseJwk__default = /*#__PURE__*/_interopDefaultLegacy(parseJwk);
var CompactSign__default = /*#__PURE__*/_interopDefaultLegacy(CompactSign);
var compactDecrypt__default = /*#__PURE__*/_interopDefaultLegacy(compactDecrypt);
var compactVerify__default = /*#__PURE__*/_interopDefaultLegacy(compactVerify);

const sha = async function (input, algorithm = 'SHA-256') {
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
};

// TODO decide a fixed delay for the protocol
const IAT_DELAY = 5000;
/**
 * Validate Proof or Request using the Provider Public Key
 */
const validatePoR = async (publicKey, poR, poO) => {
    const poRpayload = await decodePor(publicKey, poR);
    const hashPooDgst = await sha(poO);
    if (hashPooDgst !== poRpayload.exchange.poo_dgst) {
        throw new Error('the hashed proof of origin received does not correspond to the poo_dgst parameter in the proof of origin');
    }
    else if (Date.now() - poRpayload.iat > IAT_DELAY) {
        throw new Error('timestamp error');
    }
    else {
        return true;
    }
};
/**
 * Decode Proof of Reception with Consumer public key
 */
const decodePor = async (publicKey, poR) => {
    const { payload } = await compactVerify__default['default'](poR, publicKey).catch((e) => {
        throw new Error(`PoR: ${String(e)}`);
    });
    const decodedPoOPayload = JSON.parse(new TextDecoder().decode(payload).toString());
    return decodedPoOPayload;
};
/**
 * Validate Proof or Origin using the Consumer Public Key
 */
const validatePoO = async (publicKey, poO, cipherblock) => {
    const poOpayload = await decodePoo(publicKey, poO);
    const hashedCipherBlock = await sha(cipherblock);
    if (poOpayload.exchange.cipherblock_dgst !== hashedCipherBlock) {
        throw new Error('the cipherblock_dgst parameter in the proof of origin does not correspond to hash of the cipherblock received by the provider');
    }
    else if (Date.now() - poOpayload.iat > IAT_DELAY) {
        throw new Error('timestamp error');
    }
    else {
        return true;
    }
};
/**
 * Decode Proof of Origin with Provider public key
 */
const decodePoo = async (publicKey, poO) => {
    const { payload } = await compactVerify__default['default'](poO, publicKey).catch((e) => {
        throw new Error('PoO ' + String(e));
    });
    const decodedPoOPayload = JSON.parse(new TextDecoder().decode(payload).toString());
    return decodedPoOPayload;
};
/**
 * Validate Proof of Publication using the Backplain Public Key
 */
const validatePoP = async (publicKeyBackplain, publicKeyProvider, poP, jwk, poO) => {
    await compactVerify__default['default'](poP, publicKeyBackplain).catch((e) => {
        throw new Error('PoP ' + String(e));
    });
    const poOPayload = await decodePoo(publicKeyProvider, poO);
    const hashedJwk = await sha(JSON.stringify(jwk));
    if (poOPayload.exchange.key_commitment === hashedJwk) {
        return true;
    }
    else {
        throw new Error('hashed key not correspond to poO key_commitment parameter');
    }
};
/**
 * Decrypt the cipherblock received
 */
const decryptCipherblock = async (chiperblock, jwk) => {
    const decoder = new TextDecoder();
    const key = await parseJwk__default['default'](jwk, 'A256GCM'); // TODO: ENC_ALG
    const { plaintext } = await compactDecrypt__default['default'](chiperblock, key);
    return decoder.decode(plaintext);
};
/**
 * Validate the cipherblock
 */
const validateCipherblock = async (publicKey, chiperblock, jwk, poO) => {
    const decodedCipherBlock = await decryptCipherblock(chiperblock, jwk);
    const hashedDecodedCipherBlock = await sha(decodedCipherBlock);
    if (hashedDecodedCipherBlock === poO.exchange.block_commitment) {
        // TODO check also block_description
        return true;
    }
    else {
        throw new Error('hashed CipherBlock not correspond to block_commitment parameter included in the proof of origin');
    }
};

const SIGNING_ALG = 'ES256';
/**
 * Create Proof of Origin and sign with Provider private key
 */
const createPoO = async (privateKey, block, providerId, consumerId, exchangeId, blockId, jwk) => {
    const input = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block);
    const key = await parseJwk__default['default'](jwk);
    const cipherblock = await new CompactEncrypt__default['default'](input)
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .encrypt(key);
    const hashCipherblock = await sha(cipherblock);
    const hashBlock = await sha(input);
    const hashKey = await sha(JSON.stringify(jwk));
    const proof = {
        iss: providerId,
        sub: consumerId,
        iat: Date.now(),
        exchange: {
            id: exchangeId,
            orig: providerId,
            dest: consumerId,
            block_id: blockId,
            block_desc: 'description',
            hash_alg: 'sha256',
            cipherblock_dgst: hashCipherblock,
            block_commitment: hashBlock,
            key_commitment: hashKey
        }
    };
    const signedProof = await signProof(privateKey, proof);
    return { cipherblock: cipherblock, poO: signedProof };
};
/**
 * Create random (high entropy)\none time symmetric JWK secret
 */
const createJwk = async () => {
    let key;
    {
        // TODO: get algo from ENC_ALG
        key = await generateSecret__default['default']('A256GCM');
    }
    const jwk = await fromKeyLike__default['default'](key);
    const thumbprint = await calculateThumbprint__default['default'](jwk);
    jwk.kid = thumbprint;
    jwk.alg = 'A256GCM';
    return jwk;
};
/**
 * Sign a proof with private key
 */
const signProof = async (privateKey, proof) => {
    const jwt = new TextEncoder().encode(JSON.stringify(proof));
    const jws = await new CompactSign__default['default'](jwt)
        .setProtectedHeader({ alg: SIGNING_ALG })
        .sign(privateKey);
    return jws;
};
/**
 * Create Proof of Receipt and sign with Consumer private key
 */
const createPoR = async (privateKey, poO, providerId, consumerId, exchangeId) => {
    const hashPooDgst = await sha(poO);
    const proof = {
        iss: providerId,
        sub: consumerId,
        iat: Date.now(),
        exchange: {
            poo_dgst: hashPooDgst,
            hash_alg: 'sha256',
            exchangeId: exchangeId
        }
    };
    const signedProof = await signProof(privateKey, proof);
    return signedProof;
};
/**
 *
 * Prepare block to be send to the Backplain API
 */
const createBlockchainProof = async (publicKey, poO, poR, jwk) => {
    const decodedPoO = await decodePoo(publicKey, poO);
    const privateStorage = {
        availability: 'privateStorage',
        permissions: {
            view: [decodedPoO.exchange.orig, decodedPoO.exchange.dest]
        },
        type: 'dict',
        id: decodedPoO.exchange.id,
        content: { [decodedPoO.exchange.block_id]: { poO: poO, poR: poR } }
    };
    const blockchain = {
        availability: 'blockchain',
        type: 'jwk',
        content: { [jwk.kid]: jwk } // eslint-disable-line
    };
    return { privateStorage, blockchain };
};

exports.SIGNING_ALG = SIGNING_ALG;
exports.createBlockchainProof = createBlockchainProof;
exports.createJwk = createJwk;
exports.createPoO = createPoO;
exports.createPoR = createPoR;
exports.decodePoo = decodePoo;
exports.decodePor = decodePor;
exports.decryptCipherblock = decryptCipherblock;
exports.sha = sha;
exports.signProof = signProof;
exports.validateCipherblock = validateCipherblock;
exports.validatePoO = validatePoO;
exports.validatePoP = validatePoP;
exports.validatePoR = validatePoR;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvdmFsaWRhdGVQcm9vZnMudHMiLCIuLi8uLi9zcmMvdHMvY3JlYXRlUHJvb2ZzLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJjb21wYWN0VmVyaWZ5IiwicGFyc2VKd2siLCJjb21wYWN0RGVjcnlwdCIsIkNvbXBhY3RFbmNyeXB0IiwiZ2VuZXJhdGVTZWNyZXQiLCJmcm9tS2V5TGlrZSIsImNhbGN1bGF0ZVRodW1icHJpbnQiLCJDb21wYWN0U2lnbiJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O01BQU0sR0FBRyxHQUFHLGdCQUFnQixLQUF3QixFQUFFLFNBQVMsR0FBRyxTQUFTO0lBQ3pFLE1BQU0sVUFBVSxHQUFHLENBQUMsT0FBTyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxDQUFDLENBQUE7SUFDN0QsSUFBSSxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUU7UUFDbkMsTUFBTSxJQUFJLFVBQVUsQ0FBQyx5Q0FBeUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxVQUFVLENBQUMsRUFBRSxDQUFDLENBQUE7S0FDNUY7SUFFRCxNQUFNLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFBO0lBQ2pDLE1BQU0sU0FBUyxHQUFHLENBQUMsT0FBTyxLQUFLLEtBQUssUUFBUSxJQUFJLE9BQU8sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsTUFBTSxHQUFHLEtBQUssQ0FBQTtJQUVwRixJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUE7SUFPUjtRQUNMLE1BQU0sT0FBTyxHQUFHLFNBQVMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFBO1FBQ3hELE1BQU0sR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUMsVUFBVSxDQUFDLE9B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
