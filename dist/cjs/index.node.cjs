'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jose = require('jose');

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
    const { payload } = await jose.compactVerify(poR, publicKey).catch((e) => {
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
    const { payload } = await jose.compactVerify(poO, publicKey).catch((e) => {
        throw new Error('PoO ' + String(e));
    });
    const decodedPoOPayload = JSON.parse(new TextDecoder().decode(payload).toString());
    return decodedPoOPayload;
};
/**
 * Validate Proof of Publication using the Backplain Public Key
 */
const validatePoP = (publicKeyBackplain, publicKeyProvider, poP, jwk, poO) => {
    return new Promise((resolve, reject) => {
        jose.compactVerify(poP, publicKeyBackplain).catch((e) => {
            reject(new Error('PoP ' + String(e)));
        });
        decodePoo(publicKeyProvider, poO)
            .then((poOPayload) => {
            sha(JSON.stringify(jwk))
                .then(hashedJwk => {
                if (poOPayload.exchange.key_commitment === hashedJwk) {
                    resolve(true);
                }
                else {
                    reject(new Error('hashed key not correspond to poO key_commitment parameter'));
                }
            })
                .catch(reason => reject(reason));
        })
            .catch(reason => reject(reason));
    });
};
/**
 * Decrypt the cipherblock received
 */
const decryptCipherblock = async (chiperblock, jwk) => {
    const decoder = new TextDecoder();
    const key = await jose.importJWK(jwk, 'A256GCM'); // TODO: ENC_ALG
    const { plaintext } = await jose.compactDecrypt(chiperblock, key);
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
 *
 * Create Proof of Origin and sign with Provider private key
 *
 * @param privateKey - private key of the signer/issuer
 * @param block - the blocks asdfsdfsd
 * @param providerId
 * @param consumerId
 * @param exchangeId
 * @param blockId
 * @param jwk
 * @returns
 */
const createPoO = async (privateKey, block, providerId, consumerId, exchangeId, blockId, jwk) => {
    const input = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block);
    const key = await jose.importJWK(jwk);
    const cipherblock = await new jose.CompactEncrypt(input)
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
 * Create a random (high entropy) symmetric JWK secret
 *
 * @returns a promise that resolves to a JWK
 */
const createJwk = async () => {
    let key;
    {
        // TODO: get algo from ENC_ALG
        key = await jose.generateSecret('A256GCM');
    }
    const jwk = await jose.exportJWK(key);
    const thumbprint = await jose.calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = 'A256GCM';
    return jwk;
};
/**
 * Sign a proof with private key
 */
const signProof = async (privateKey, proof) => {
    const jwt = new TextEncoder().encode(JSON.stringify(proof));
    const jws = await new jose.CompactSign(jwt)
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvdmFsaWRhdGVQcm9vZnMudHMiLCIuLi8uLi9zcmMvdHMvY3JlYXRlUHJvb2ZzLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJjb21wYWN0VmVyaWZ5IiwiaW1wb3J0SldLIiwiY29tcGFjdERlY3J5cHQiLCJDb21wYWN0RW5jcnlwdCIsImdlbmVyYXRlU2VjcmV0IiwiZXhwb3J0SldLIiwiY2FsY3VsYXRlSndrVGh1bWJwcmludCIsIkNvbXBhY3RTaWduIl0sIm1hcHBpbmdzIjoiOzs7Ozs7TUFBTSxHQUFHLEdBQUcsZ0JBQWdCLEtBQXdCLEVBQUUsU0FBUyxHQUFHLFNBQVM7SUFDekUsTUFBTSxVQUFVLEdBQUcsQ0FBQyxPQUFPLEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLENBQUMsQ0FBQTtJQUM3RCxJQUFJLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsRUFBRTtRQUNuQyxNQUFNLElBQUksVUFBVSxDQUFDLHlDQUF5QyxJQUFJLENBQUMsU0FBUyxDQUFDLFVBQVUsQ0FBQyxFQUFFLENBQUMsQ0FBQTtLQUM1RjtJQUVELE1BQU0sT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUE7SUFDakMsTUFBTSxTQUFTLEdBQUcsQ0FBQyxPQUFPLEtBQUssS0FBSyxRQUFRLElBQUksT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxNQUFNLEdBQUcsS0FBSyxDQUFBO0lBRXBGLElBQUksTUFBTSxHQUFHLEVBQUUsQ0FBQTtJQU9SO1FBQ0wsTUFBTSxPQUFPLEdBQUcsU0FBUyxDQUFDLFdBQVcsRUFBRSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsRUFBRSxDQUFDLENBQUE7UUFDeEQsTUFBTSxHQUFHLE9BQU8sQ0FBQyxRQUFRLENBQUMsQ0FBQyxVQUFVLENBQUMsT0FBTyxDQUFDLENBQUMsTUFB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
