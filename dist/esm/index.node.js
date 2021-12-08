import { importJWK, GeneralSign, generalVerify, SignJWT, CompactEncrypt, compactDecrypt, generateSecret, exportJWK, jwtVerify } from 'jose';
import { randBytes } from 'bigint-crypto-utils';
import { hexToBuf, bufToHex } from 'bigint-conversion';
import * as b64 from '@juanelas/base64';
import { decode } from '@juanelas/base64';
import { ec } from 'elliptic';
import { ethers } from 'ethers';
import { hashable } from 'object-sha';

async function verifyKeyPair(pubJWK, privJWK) {
    if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
        throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg');
    }
    const pubKey = await importJWK(pubJWK);
    const privKey = await importJWK(privJWK);
    const nonce = await randBytes(16);
    const jws = await new GeneralSign(nonce)
        .addSignature(privKey)
        .setProtectedHeader({ alg: privJWK.alg })
        .sign();
    await generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
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
    const privateKey = await importJWK(privateJwk);
    const alg = privateJwk.alg; // if alg were undefined verifyKeyPair would have thrown an error
    payload.iat = Math.floor(Date.now() / 1000);
    const jws = await new SignJWT(payload)
        .setProtectedHeader({ alg })
        .setIssuedAt(payload.iat)
        .sign(privateKey);
    return {
        jws,
        payload: payload
    };
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
        throw new RangeError(`Invalid signature algorithm '${alg}''. Allowed algorithms are ${algs.toString()}`);
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
    const ec$1 = new ec('p' + namedCurve.substring(namedCurve.length - 3));
    const ecPriv = ec$1.keyFromPrivate(privKeyBuf);
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

/**
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
async function jweEncrypt(block, secret, encAlg) {
    // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
    const key = await importJWK(secret);
    return await new CompactEncrypt(block)
        .setProtectedHeader({ alg: 'dir', enc: encAlg, kid: secret.kid })
        .encrypt(key);
}
/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @param encAlg - the algorithm for encryption
 * @returns the plaintext
 */
async function jweDecrypt(jwe, secret, encAlg = 'A256GCM') {
    const key = await importJWK(secret);
    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] });
}

function checkIssuedAt(iat, timestampVerifyOptions) {
    const parsedOptions = timestampVerifyOptions ?? {};
    iat = iat * 1000; // iat is in seconds
    if (parsedOptions.clockToleranceMs === undefined)
        delete parsedOptions.clockToleranceMs;
    if (parsedOptions.currentTimestamp === undefined)
        delete parsedOptions.currentTimestamp;
    if (parsedOptions.expectedTimestampInterval === undefined)
        delete parsedOptions.expectedTimestampInterval;
    const currentTimestamp = Date.now();
    const options = {
        currentTimestamp,
        expectedTimestampInterval: {
            min: currentTimestamp,
            max: currentTimestamp
        },
        clockToleranceMs: 10000,
        ...parsedOptions
    };
    if (options.currentTimestamp < iat - options.clockToleranceMs) {
        throw new Error('Current date is before the proof\'s "iat"');
    }
    if (options.currentTimestamp < options.expectedTimestampInterval.min - options.clockToleranceMs) {
        throw new Error('iat < expected minimum reception time');
    }
    if (options.currentTimestamp > options.expectedTimestampInterval.max + options.clockToleranceMs) {
        throw new Error('iat < expected maximum reeption Time');
    }
}

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

/** TO-DO: Could the json be imported from an npm package? */
const defaultDltConfig = {
    gasLimit: 12500000,
    rpcProviderUrl: '***REMOVED***',
    disable: false,
    contract: contractConfig
};

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
            throw new Error(`Invalid encAlg '${encAlg}'. Supported values are: ${['A128GCM', 'A256GCM'].toString()}`);
    }
    if (secret !== undefined) {
        if (typeof secret === 'string') {
            if (base64 === true) {
                key = b64.decode(secret);
            }
            else {
                key = new Uint8Array(hexToBuf(secret));
            }
        }
        else {
            key = secret;
        }
        if (key.length !== secretLength) {
            throw new RangeError(`Expected secret length ${secretLength} does not meet provided one ${key.length}`);
        }
    }
    else {
        key = await generateSecret(encAlg, { extractable: true });
    }
    const jwk = await exportJWK(key);
    // const thumbprint: string = await calculateJwkThumbprint(jwk)
    // jwk.kid = thumbprint
    jwk.alg = encAlg;
    return { jwk: jwk, hex: bufToHex(decode(jwk.k)) };
}

async function sha(input, algorithm) {
    const algorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
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

function parseHex(a) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/);
    if (hexMatch == null) {
        throw RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\'');
    }
    return hexMatch[2].toLocaleLowerCase();
}

/**
 * Verify a proof
 * @param proof - a non-repudiable proof in Compact JWS formatted JWT string
 *
 * @param publicJwk - the publicKey as a JWK to use for verifying the signature. If MUST match either orig or dest (the one pointed on the iss field)
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
 * @param timestampVerifyOptions - specifies a time window to accept the proof
 *
 * @returns The JWT protected header and payload if the proof is validated
 */
async function verifyProof(proof, publicJwk, expectedPayloadClaims, timestampVerifyOptions) {
    const pubKey = await importJWK(publicJwk);
    const verification = await jwtVerify(proof, pubKey);
    if (verification.payload.iss === undefined) {
        throw new Error('Property "iss" missing');
    }
    if (verification.payload.iat === undefined) {
        throw new Error('Property claim iat missing');
    }
    checkIssuedAt(verification.payload.iat, timestampVerifyOptions);
    const payload = verification.payload;
    // Check that the publicKey is the public key of the issuer
    const issuer = payload.exchange[payload.iss];
    if (hashable(publicJwk) !== hashable(JSON.parse(issuer))) {
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
        else if (expectedPayloadClaims[key] !== '' && hashable(expectedPayloadClaims[key]) !== hashable(payload[key])) {
            throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedPayloadClaims[key], undefined, 2)}`);
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
        if (expectedDataExchange[key] !== '' && hashable(expectedDataExchange[key]) !== hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
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
     * @param agreement - a DataExchangeAgreement
     * @param privateJwk - the private key that will be used to sign the proofs
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     */
    constructor(agreement, privateJwk, dltConfig) {
        this.jwkPairDest = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.dest)
        };
        this.publicJwkOrig = JSON.parse(agreement.orig);
        this.agreement = {
            ...agreement,
            ledgerContractAddress: parseHex(agreement.ledgerContractAddress),
            ledgerSignerAddress: parseHex(agreement.ledgerSignerAddress)
        };
        this.block = {};
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        this._dltSetup();
        this.initialized = new Promise((resolve, reject) => {
            this.init().then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    _dltSetup() {
        if (!this.dltConfig.disable) {
            const rpcProvider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
            if (this.agreement.ledgerContractAddress !== parseHex(this.dltConfig.contract.address)) {
                throw new Error(`Contract address ${parseHex(this.dltConfig.contract.address)} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
            }
            this.dltContract = new ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, rpcProvider);
        }
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init() {
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
    }
    /**
     * Verifies a proof of origin against the received cipherblock.
     * If verification passes, `pop` and `cipherblock` are added to this.block
     *
     * @param poo - a Proof of Origin (PoO) in compact JWS format
     * @param cipherblock - a cipherblock as a JWE
     * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
     * @param currentDate - check the PoO as it were checked in this date
     * @returns the verified payload and protected header
     *
     */
    async verifyPoO(poo, cipherblock, clockToleranceMs, currentDate) {
        await this.initialized;
        const cipherblockDgst = await sha(cipherblock, this.agreement.hashAlg);
        const id = await sha(hashable({ ...this.agreement, cipherblockDgst }), 'SHA-256');
        const dataExchange = {
            ...this.agreement,
            id,
            cipherblockDgst
        };
        const expectedPayloadClaims = {
            proofType: 'PoO',
            iss: 'orig',
            exchange: dataExchange
        };
        const proofVerifyOptions = {};
        if (clockToleranceMs !== undefined)
            proofVerifyOptions.clockToleranceMs = clockToleranceMs;
        if (currentDate !== undefined)
            proofVerifyOptions.currentTimestamp = currentDate.valueOf();
        const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims, proofVerifyOptions);
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
     * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
     * @param currentDate - check the proof as it were checked in this date
     * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
     */
    async verifyPoP(pop, clockToleranceMs, currentDate) {
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
        const proofVerifyOptions = {
            expectedTimestampInterval: {
                min: this.block.poo?.payload.iat * 1000,
                max: this.block.poo?.payload.iat * 1000 + this.exchange.pooToPopDelay
            }
        };
        if (clockToleranceMs !== undefined)
            proofVerifyOptions.clockToleranceMs = clockToleranceMs;
        if (currentDate !== undefined)
            proofVerifyOptions.currentTimestamp = currentDate.valueOf();
        const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims, proofVerifyOptions);
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
    /**
     * Just in case the PoP is not received, the secret can be downloaded from the ledger.
     * The secret should be downloaded before poo.iat + pooTopop max delay.
     *
     * @returns the secret
     */
    async getSecretFromLedger() {
        if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
            throw new Error('Cannot get secret if a PoR has not been sent before');
        }
        const currentTimestamp = Date.now();
        const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay;
        const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000);
        let secretBn = ethers.BigNumber.from(0);
        let timestampBn = ethers.BigNumber.from(0);
        let counter = 0;
        do {
            ({ secret: secretBn, timestamp: timestampBn } = await this.dltContract.registry(this.agreement.ledgerSignerAddress, `0x${this.exchange.id}`));
            if (secretBn.isZero()) {
                counter++;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        } while (secretBn.isZero() && counter < timeout);
        if (secretBn.isZero()) {
            throw new Error(`timeout of ${timeout}s exceeded when querying the ledger`);
        }
        const secretHex = secretBn.toHexString();
        const iat = timestampBn.toNumber();
        this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex);
        try {
            checkIssuedAt(iat, {
                clockToleranceMs: 0,
                expectedTimestampInterval: {
                    min: this.block.poo.payload.iat * 1000,
                    max: this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay
                }
            });
        }
        catch (error) {
            throw new Error(`Although the secret has been obtained (you can try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`);
        }
        return this.block.secret;
    }
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     *
     * @throws Error if the previous proofs have not been verified or the decrypted block does not meet the committed one
     */
    async decrypt() {
        await this.initialized;
        if (this.block.secret?.jwk === undefined) {
            throw new Error('Cannot decrypt without the secret');
        }
        if (this.block.jwe === undefined) {
            throw new Error('No cipherblock to decrypt');
        }
        const decryptedBlock = (await jweDecrypt(this.block.jwe, this.block.secret.jwk)).plaintext;
        const decryptedDgst = await sha(decryptedBlock, this.agreement.hashAlg);
        if (decryptedDgst !== this.exchange?.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.raw = decryptedBlock;
        return decryptedBlock;
    }
}

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
class NonRepudiationOrig {
    /**
     * @param agreement - a DataExchangeAgreement
     * @param privateJwk - the private key that will be used to sign the proofs
     * @param block - the block of data to transmit in this data exchange
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     * @param privateLedgerKeyHex - the private key (d parameter) as a hexadecimal string used to sign transactions to the ledger. If not provided, it is assumed that is the same as privateJwk
     */
    constructor(agreement, privateJwk, block, dltConfig, privateLedgerKeyHex) {
        this.jwkPairOrig = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.orig)
        };
        this.publicJwkDest = JSON.parse(agreement.dest);
        this.agreement = {
            ...agreement,
            ledgerContractAddress: parseHex(agreement.ledgerContractAddress),
            ledgerSignerAddress: parseHex(agreement.ledgerSignerAddress)
        };
        // @ts-expect-error I will end assigning the complete Block in the async init()
        this.block = {
            raw: block
        };
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        const privDltKeyHex = (privateLedgerKeyHex !== undefined) ? parseHex(privateLedgerKeyHex) : undefined;
        this.initialized = new Promise((resolve, reject) => {
            this.init(privDltKeyHex).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init(privateLedgerKeyHex) {
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        const secret = await oneTimeSecret(this.agreement.encAlg);
        this.block = {
            ...this.block,
            secret,
            jwe: await jweEncrypt(this.block.raw, secret.jwk, this.agreement.encAlg)
        };
        const cipherblockDgst = await sha(this.block.jwe, this.agreement.hashAlg);
        const id = await sha(hashable({ ...this.agreement, cipherblockDgst }), 'SHA-256');
        this.exchange = {
            ...this.agreement,
            id,
            cipherblockDgst,
            blockCommitment: await sha(this.block.raw, this.agreement.hashAlg),
            secretCommitment: await sha(new Uint8Array(hexToBuf(this.block.secret.hex)), this.agreement.hashAlg)
        };
        await this._dltSetup(privateLedgerKeyHex);
    }
    async _dltSetup(privateLedgerKeyHex) {
        if (!this.dltConfig.disable) {
            const rpcProvider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
            if (this.jwkPairOrig.privateJwk.d === undefined) {
                throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key');
            }
            const privateKey = (privateLedgerKeyHex !== undefined)
                ? new Uint8Array(hexToBuf(privateLedgerKeyHex))
                : b64.decode(this.jwkPairOrig.privateJwk.d);
            const signingKey = new ethers.utils.SigningKey(privateKey);
            const signer = new ethers.Wallet(signingKey, rpcProvider);
            const signerAddress = parseHex(await signer.getAddress());
            if (signerAddress !== this.exchange.ledgerSignerAddress) {
                throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address associated to the provided private key ${signerAddress}`);
            }
            if (this.agreement.ledgerContractAddress !== parseHex(this.dltConfig.contract.address)) {
                throw new Error(`Contract address ${parseHex(this.dltConfig.contract.address)} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
            }
            this.dltContract = new ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, signer);
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
     * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
     * @param currentDate - check the proof as it were checked in this date
     * @returns the verified payload and protected header
     */
    async verifyPoR(por, clockToleranceMs, currentDate) {
        await this.initialized;
        if (this.block?.poo === undefined) {
            throw new Error('Cannot verify a PoR if not even a PoO have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            poo: this.block.poo.jws
        };
        const proofVerifyOptions = {
            expectedTimestampInterval: {
                min: this.block.poo?.payload.iat * 1000,
                max: this.block.poo?.payload.iat * 1000 + this.exchange.pooToPopDelay
            }
        };
        if (clockToleranceMs !== undefined)
            proofVerifyOptions.clockToleranceMs = clockToleranceMs;
        if (currentDate !== undefined)
            proofVerifyOptions.currentTimestamp = currentDate.valueOf();
        const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims, proofVerifyOptions);
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
        let verificationCode = 'verificationCode';
        if (!this.dltConfig.disable) {
            const secret = ethers.BigNumber.from(`0x${this.block.secret.hex}`);
            // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
            const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit });
            verificationCode = setRegistryTx.hash;
            // TO-DO: I would say that we can remove the next wait
            // await setRegistryTx.wait()
        }
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
}

export { NonRepudiationDest, NonRepudiationOrig, createProof, generateKeys, jweDecrypt, jweEncrypt, oneTimeSecret, parseHex, sha, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvY3JlYXRlUHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvZ2VuZXJhdGVLZXlzLnRzIiwiLi4vLi4vc3JjL3RzL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9jaGVja1RpbWVzdGFtcC50cyIsIi4uLy4uL3NyYy90cy9kZWZhdWx0RGx0Q29uZmlnLnRzIiwiLi4vLi4vc3JjL3RzL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvc2hhLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uRGVzdC50cyIsIi4uLy4uL3NyYy90cy9Ob25SZXB1ZGlhdGlvbk9yaWcudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImVjIiwiRWMiLCJiYXNlNjRkZWNvZGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUlPLGVBQWUsYUFBYSxDQUFFLE1BQVcsRUFBRSxPQUFZO0lBQzVELElBQUksTUFBTSxDQUFDLEdBQUcsS0FBSyxTQUFTLElBQUksT0FBTyxDQUFDLEdBQUcsS0FBSyxTQUFTLElBQUksTUFBTSxDQUFDLEdBQUcsS0FBSyxPQUFPLENBQUMsR0FBRyxFQUFFO1FBQ3ZGLE1BQU0sSUFBSSxLQUFLLENBQUMsMEVBQTBFLENBQUMsQ0FBQTtLQUM1RjtJQUNELE1BQU0sTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFBO0lBQ3RDLE1BQU0sT0FBTyxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0lBQ3hDLE1BQU0sS0FBSyxHQUFHLE1BQU0sU0FBUyxDQUFDLEVBQUUsQ0FBQyxDQUFBO0lBQ2pDLE1BQU0sR0FBRyxHQUFHLE1BQU0sSUFBSSxXQUFXLENBQUMsS0FBSyxDQUFDO1NBQ3JDLFlBQVks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
