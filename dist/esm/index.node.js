import { compactVerify, importJWK, compactDecrypt, CompactEncrypt, generateSecret, exportJWK, calculateJwkThumbprint, CompactSign } from 'jose';

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
    const { payload } = await compactVerify(poR, publicKey).catch((e) => {
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
    const { payload } = await compactVerify(poO, publicKey).catch((e) => {
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
        compactVerify(poP, publicKeyBackplain).catch((e) => {
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
    const key = await importJWK(jwk, 'A256GCM'); // TODO: ENC_ALG
    const { plaintext } = await compactDecrypt(chiperblock, key);
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
    const key = await importJWK(jwk);
    const cipherblock = await new CompactEncrypt(input)
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
        key = await generateSecret('A256GCM');
    }
    const jwk = await exportJWK(key);
    const thumbprint = await calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = 'A256GCM';
    return jwk;
};
/**
 * Sign a proof with private key
 */
const signProof = async (privateKey, proof) => {
    const jwt = new TextEncoder().encode(JSON.stringify(proof));
    const jws = await new CompactSign(jwt)
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

export { SIGNING_ALG, createBlockchainProof, createJwk, createPoO, createPoR, decodePoo, decodePor, decryptCipherblock, sha, signProof, validateCipherblock, validatePoO, validatePoP, validatePoR };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3NoYS50cyIsIi4uLy4uL3NyYy90cy92YWxpZGF0ZVByb29mcy50cyIsIi4uLy4uL3NyYy90cy9jcmVhdGVQcm9vZnMudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O01BQU0sR0FBRyxHQUFHLGdCQUFnQixLQUF3QixFQUFFLFNBQVMsR0FBRyxTQUFTO0lBQ3pFLE1BQU0sVUFBVSxHQUFHLENBQUMsT0FBTyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsU0FBUyxDQUFDLENBQUE7SUFDN0QsSUFBSSxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUU7UUFDbkMsTUFBTSxJQUFJLFVBQVUsQ0FBQyx5Q0FBeUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxVQUFVLENBQUMsRUFBRSxDQUFDLENBQUE7S0FDNUY7SUFFRCxNQUFNLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFBO0lBQ2pDLE1BQU0sU0FBUyxHQUFHLENBQUMsT0FBTyxLQUFLLEtBQUssUUFBUSxJQUFJLE9BQU8sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsTUFBTSxHQUFHLEtBQUssQ0FBQTtJQUVwRixJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUE7SUFPUjtRQUNMLE1BQU0sT0FBTyxHQUFHLFNBQVMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFBO1FBQ3hELE1BQU0sR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFBO0tBQzVGO0lBQ0QsT0FBTyxNQUFNLENBQUE7QUFDZjs7QUNqQkE7QUFDQSxNQUFNLFNBQVMsR0FBRyxJQUFJ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
