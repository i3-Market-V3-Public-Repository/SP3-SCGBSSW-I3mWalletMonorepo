import generateSecret from 'jose/util/generate_secret';
import fromKeyLike from 'jose/jwk/from_key_like';
import CompactEncrypt from 'jose/jwe/compact/encrypt';
import calculateThumbprint from 'jose/jwk/thumbprint';
import parseJwk from 'jose/jwk/parse';
import CompactSign from 'jose/jws/compact/sign';
import crypto from 'crypto';
import compactDecrypt from 'jose/jwe/compact/decrypt';
import compactVerify from 'jose/jws/compact/verify';

// TODO decide a fixed delay for the protocol
const IAT_DELAY = 5000;
/**
 * Validate Proof or Request using the Provider Public Key
 */
const validatePoR = async (publicKey, poR, poO) => {
    const poRpayload = await decodePor(publicKey, poR);
    const hashPooDgst = crypto.createHash('sha256').update(poO).digest('hex');
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
    const hashedCipherBlock = crypto.createHash('sha256').update(cipherblock).digest('hex');
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
const validatePoP = async (publicKeyBackplain, publicKeyProvider, poP, jwk, poO) => {
    await compactVerify(poP, publicKeyBackplain).catch((e) => {
        throw new Error('PoP ' + String(e));
    });
    const poOPayload = await decodePoo(publicKeyProvider, poO);
    const hashedJwk = crypto.createHash('sha256').update(JSON.stringify(jwk)).digest('hex');
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
    const key = await parseJwk(jwk, 'HS256');
    const { plaintext } = await compactDecrypt(chiperblock, key);
    return decoder.decode(plaintext);
};
/**
 * Validate the cipherblock
 */
const validateCipherblock = async (publicKey, chiperblock, jwk, poO) => {
    const decodedCipherBlock = await decryptCipherblock(chiperblock, jwk);
    const hashedDecodedCipherBlock = crypto
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
    const key = await parseJwk(jwk);
    const cipherblock = await new CompactEncrypt(input)
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .encrypt(key);
    const hashCipherblock = crypto
        .createHash('sha256')
        .update(cipherblock)
        .digest('hex');
    const hashBlock = crypto.createHash('sha256').update(input).digest('hex');
    const hashKey = crypto
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
    const key = await generateSecret('HS256');
    const jwk = await fromKeyLike(key);
    const thumbprint = await calculateThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = 'HS256';
    return jwk;
};
/**
 * Sign a proof with private key
 */
const signProof = async (privateKey, proof) => {
    const jwt = new TextEncoder().encode(JSON.stringify(proof));
    const jws = await new CompactSign(jwt)
        .setProtectedHeader({ alg: 'EdDSA' })
        .sign(privateKey);
    return jws;
};
/**
 * Create Proof of Receipt and sign with Consumer private key
 */
const createPoR = async (privateKey, poO, providerId, consumerId, exchangeId) => {
    const hashPooDgst = crypto.createHash('sha256').update(poO).digest('hex');
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

export { createBlockchainProof, createJwk, createPoO, createPoR, decodePoo, decodePor, decryptCipherblock, signProof, validateCipherblock, validatePoO, validatePoP, validatePoR };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3ZhbGlkYXRlUHJvb2ZzLnRzIiwiLi4vLi4vc3JjL3RzL2NyZWF0ZVByb29mcy50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQU9BO0FBQ0EsTUFBTSxTQUFTLEdBQUcsSUFBSSxDQUFBO0FBRXRCOzs7TUFHTSxXQUFXLEdBQUcsT0FBTyxTQUFrQixFQUFFLEdBQVcsRUFBRSxHQUFXO0lBQ3JFLE1BQU0sVUFBVSxHQUFRLE1BQU0sU0FBUyxDQUFDLFNBQVMsRUFBRSxHQUFHLENBQUMsQ0FBQTtJQUN2RCxNQUFNLFdBQVcsR0FBVyxNQUFNLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUE7SUFFakYsSUFBSSxXQUFXLEtBQUssVUFBVSxDQUFDLFFBQVEsQ0FBQyxRQUFRLEVBQUU7UUFDaEQsTUFBTSxJQUFJLEtBQUssQ0FBQywwR0FBMEcsQ0FBQyxDQUFBO0tBQzVIO1NBQU0sSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFLEdBQUcsVUFBVSxDQUFDLEdBQUcsR0FBRyxTQUFTLEVBQUU7UUFDbEQsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0tBQ25DO1NBQU07UUFDTCxPQUFPLElBQUksQ0FBQTtLQUNaO0FBQ0gsRUFBQztBQUVEOzs7TUFHTSxTQUFTLEdBQUcsT0FBTyxTQUFrQixFQUFFLEdBQVc7SUFDdEQsTUFBTSxFQUFFLE9BQU8sRUFBRSxHQUFHLE1BQU0sYUFBYSxDQUFDLEdBQUcsRUFBRSxTQUFTLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDO1FBQzlELE1BQU0sSUFBSSxLQUFLLENBQUMsUUFBUSxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFBO0tBQ3JDLENBQUMsQ0FBQTtJQUNGLE1B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
