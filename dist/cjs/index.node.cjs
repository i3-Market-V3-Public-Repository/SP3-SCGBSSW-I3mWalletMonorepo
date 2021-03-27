'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var generateSecret = require('jose/util/generate_secret');
var fromKeyLike = require('jose/jwk/from_key_like');
var CompactEncrypt = require('jose/jwe/compact/encrypt');
var calculateThumbprint = require('jose/jwk/thumbprint');
var parseJwk = require('jose/jwk/parse');
var CompactSign = require('jose/jws/compact/sign');
var crypto = require('crypto');
var compactDecrypt = require('jose/jwe/compact/decrypt');
var compactVerify = require('jose/jws/compact/verify');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var generateSecret__default = /*#__PURE__*/_interopDefaultLegacy(generateSecret);
var fromKeyLike__default = /*#__PURE__*/_interopDefaultLegacy(fromKeyLike);
var CompactEncrypt__default = /*#__PURE__*/_interopDefaultLegacy(CompactEncrypt);
var calculateThumbprint__default = /*#__PURE__*/_interopDefaultLegacy(calculateThumbprint);
var parseJwk__default = /*#__PURE__*/_interopDefaultLegacy(parseJwk);
var CompactSign__default = /*#__PURE__*/_interopDefaultLegacy(CompactSign);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var compactDecrypt__default = /*#__PURE__*/_interopDefaultLegacy(compactDecrypt);
var compactVerify__default = /*#__PURE__*/_interopDefaultLegacy(compactVerify);

// TODO decide a fixed delay for the protocol
const IAT_DELAY = 5000;
/**
 * Validate Proof or Request using the Provider Public Key
 */
const validatePoR = async (publicKey, poR, poO) => {
    const poRpayload = await decodePor(publicKey, poR);
    const hashPooDgst = crypto__default['default'].createHash('sha256').update(poO).digest('hex');
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
    const hashedCipherBlock = crypto__default['default'].createHash('sha256').update(cipherblock).digest('hex');
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
    const hashedJwk = crypto__default['default'].createHash('sha256').update(JSON.stringify(jwk)).digest('hex');
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
    const key = await parseJwk__default['default'](jwk, 'HS256');
    const { plaintext } = await compactDecrypt__default['default'](chiperblock, key);
    return decoder.decode(plaintext);
};
/**
 * Validate the cipherblock
 */
const validateCipherblock = async (publicKey, chiperblock, jwk, poO) => {
    const decodedCipherBlock = await decryptCipherblock(chiperblock, jwk);
    const hashedDecodedCipherBlock = crypto__default['default']
        .createHash('sha256')
        .update(decodedCipherBlock)
        .digest('hex');
    if (hashedDecodedCipherBlock === poO.exchange.block_commitment) {
        // TODO check also block_description
        return true;
    }
    else {
        throw new Error('hashed CipherBlock not correspond to block_commitment parameter included in the proof of origin');
    }
};

/**
 * Create Proof of Origin and sign with Provider private key
 */
const createPoO = async (privateKey, block, providerId, consumerId, exchangeId, blockId, jwk) => {
    const input = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block);
    const key = await parseJwk__default['default'](jwk);
    const cipherblock = await new CompactEncrypt__default['default'](input)
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .encrypt(key);
    const hashCipherblock = crypto__default['default']
        .createHash('sha256')
        .update(cipherblock)
        .digest('hex');
    const hashBlock = crypto__default['default'].createHash('sha256').update(input).digest('hex');
    const hashKey = crypto__default['default']
        .createHash('sha256')
        .update(JSON.stringify(jwk), 'utf8')
        .digest('hex');
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
    const key = await generateSecret__default['default']('HS256');
    const jwk = await fromKeyLike__default['default'](key);
    const thumbprint = await calculateThumbprint__default['default'](jwk);
    jwk.kid = thumbprint;
    jwk.alg = 'HS256';
    return jwk;
};
/**
 * Sign a proof with private key
 */
const signProof = async (privateKey, proof) => {
    const jwt = new TextEncoder().encode(JSON.stringify(proof));
    const jws = await new CompactSign__default['default'](jwt)
        .setProtectedHeader({ alg: 'EdDSA' })
        .sign(privateKey);
    return jws;
};
/**
 * Create Proof of Receipt and sign with Consumer private key
 */
const createPoR = async (privateKey, poO, providerId, consumerId, exchangeId) => {
    const hashPooDgst = crypto__default['default'].createHash('sha256').update(poO).digest('hex');
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

exports.createBlockchainProof = createBlockchainProof;
exports.createJwk = createJwk;
exports.createPoO = createPoO;
exports.createPoR = createPoR;
exports.decodePoo = decodePoo;
exports.decodePor = decodePor;
exports.decryptCipherblock = decryptCipherblock;
exports.signProof = signProof;
exports.validateCipherblock = validateCipherblock;
exports.validatePoO = validatePoO;
exports.validatePoP = validatePoP;
exports.validatePoR = validatePoR;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy92YWxpZGF0ZVByb29mcy50cyIsIi4uLy4uL3NyYy90cy9jcmVhdGVQcm9vZnMudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImNyeXB0byIsImNvbXBhY3RWZXJpZnkiLCJwYXJzZUp3ayIsImNvbXBhY3REZWNyeXB0IiwiQ29tcGFjdEVuY3J5cHQiLCJnZW5lcmF0ZVNlY3JldCIsImZyb21LZXlMaWtlIiwiY2FsY3VsYXRlVGh1bWJwcmludCIsIkNvbXBhY3RTaWduIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQU9BO0FBQ0EsTUFBTSxTQUFTLEdBQUcsSUFBSSxDQUFBO0FBRXRCOzs7TUFHTSxXQUFXLEdBQUcsT0FBTyxTQUFrQixFQUFFLEdBQVcsRUFBRSxHQUFXO0lBQ3JFLE1BQU0sVUFBVSxHQUFRLE1BQU0sU0FBUyxDQUFDLFNBQVMsRUFBRSxHQUFHLENBQUMsQ0FBQTtJQUN2RCxNQUFNLFdBQVcsR0FBV0EsMEJBQU0sQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQTtJQUVqRixJQUFJLFdBQVcsS0FBSyxVQUFVLENBQUMsUUFBUSxDQUFDLFFBQVEsRUFBRTtRQUNoRCxNQUFNLElBQUksS0FBSyxDQUFDLDBHQUEwRyxDQUFDLENBQUE7S0FDNUg7U0FBTSxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUUsR0FBRyxVQUFVLENBQUMsR0FBRyxHQUFHLFNBQVMsRUFBRTtRQUNsRCxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUE7S0FDbkM7U0FBTTtRQUNMLE9BQU8sSUFBSSxDQUFBO0tBQ1o7QUFDSCxFQUFDO0FBRUQ7OztNQUdNLFNBQVMsR0FBRyxPQUFPLFNBQWtCLEVBQUUsR0FBVztJQUN0RCxNQUFNLEVBQUUsT0FBTyxFQUFF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
