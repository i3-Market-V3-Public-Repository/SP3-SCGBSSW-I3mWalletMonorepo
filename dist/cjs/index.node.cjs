'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jose = require('jose');
var bigintCryptoUtils = require('bigint-crypto-utils');
var bigintConversion = require('bigint-conversion');
var b64 = require('@juanelas/base64');
var elliptic = require('elliptic');
var ethers = require('ethers');
var objectSha = require('object-sha');

function _interopNamespace(e) {
    if (e && e.__esModule) return e;
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () { return e[k]; }
                });
            }
        });
    }
    n["default"] = e;
    return Object.freeze(n);
}

var b64__namespace = /*#__PURE__*/_interopNamespace(b64);

async function verifyKeyPair(pubJWK, privJWK) {
    if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
        throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg');
    }
    const pubKey = await jose.importJWK(pubJWK);
    const privKey = await jose.importJWK(privJWK);
    const nonce = await bigintCryptoUtils.randBytes(16);
    const jws = await new jose.GeneralSign(nonce)
        .addSignature(privKey)
        .setProtectedHeader({ alg: privJWK.alg })
        .sign();
    await jose.generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
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
    const privateKey = await jose.importJWK(privateJwk);
    const alg = privateJwk.alg; // if alg were undefined verifyKeyPair would have thrown an error
    payload.iat = Math.floor(Date.now() / 1000);
    const jws = await new jose.SignJWT(payload)
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
                privKeyBuf = b64__namespace.decode(privateKey);
            }
            else {
                privKeyBuf = new Uint8Array(bigintConversion.hexToBuf(privateKey));
            }
        }
        else {
            privKeyBuf = privateKey;
        }
    }
    else {
        privKeyBuf = new Uint8Array(await bigintCryptoUtils.randBytes(keyLength));
    }
    const ec = new elliptic.ec('p' + namedCurve.substring(namedCurve.length - 3));
    const ecPriv = ec.keyFromPrivate(privKeyBuf);
    const ecPub = ecPriv.getPublic();
    const xHex = ecPub.getX().toString('hex').padStart(keyLength * 2, '0');
    const yHex = ecPub.getY().toString('hex').padStart(keyLength * 2, '0');
    const dHex = ecPriv.getPrivate('hex').padStart(keyLength * 2, '0');
    const x = b64__namespace.encode(bigintConversion.hexToBuf(xHex), true, false);
    const y = b64__namespace.encode(bigintConversion.hexToBuf(yHex), true, false);
    const d = b64__namespace.encode(bigintConversion.hexToBuf(dHex), true, false);
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
    const key = await jose.importJWK(secret);
    return await new jose.CompactEncrypt(block)
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
    const key = await jose.importJWK(secret);
    return await jose.compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] });
}

var address = "0x7B7C7c0c8952d1BDB7E4D90B1B7b7C48c13355D1";
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
				name: "",
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
var transactionHash = "0xc5893d949c2f0e15b9fdc81a614422767c6027992b92dc090d34ea8376c6a79f";
var receipt = {
	to: null,
	from: "0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903",
	contractAddress: "0x7B7C7c0c8952d1BDB7E4D90B1B7b7C48c13355D1",
	transactionIndex: 0,
	gasUsed: "235574",
	logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	blockHash: "0xd89ff96a8815646c586db267e1e829bbf1934c73c7b5b65bdf921604a706953b",
	transactionHash: "0xc5893d949c2f0e15b9fdc81a614422767c6027992b92dc090d34ea8376c6a79f",
	logs: [
	],
	blockNumber: 110833,
	cumulativeGasUsed: "235574",
	status: 1,
	byzantium: true
};
var args = [
];
var solcInputHash = "fa99dbc561556e730ddad9bdcf162967";
var metadata = "{\"compiler\":{\"version\":\"0.8.4+commit.c7e474f2\"},\"language\":\"Solidity\",\"output\":{\"abi\":[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"dataExchangeId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"secret\",\"type\":\"uint256\"}],\"name\":\"Registration\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"registry\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_dataExchangeId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_secret\",\"type\":\"uint256\"}],\"name\":\"setRegistry\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\"devdoc\":{\"kind\":\"dev\",\"methods\":{},\"version\":1},\"userdoc\":{\"kind\":\"user\",\"methods\":{},\"version\":1}},\"settings\":{\"compilationTarget\":{\"contracts/NonRepudiation.sol\":\"NonRepudiation\"},\"evmVersion\":\"istanbul\",\"libraries\":{},\"metadata\":{\"bytecodeHash\":\"ipfs\",\"useLiteralContent\":true},\"optimizer\":{\"enabled\":false,\"runs\":200},\"remappings\":[]},\"sources\":{\"contracts/NonRepudiation.sol\":{\"content\":\"//SPDX-License-Identifier: Unlicense\\npragma solidity ^0.8.0;\\n\\ncontract NonRepudiation {\\n    mapping(address => mapping (uint256 => uint256)) public registry;\\n    event Registration(address sender, uint256 dataExchangeId, uint256 secret);\\n\\n    function setRegistry(uint256 _dataExchangeId, uint256 _secret) public {\\n        require(registry[msg.sender][_dataExchangeId] == 0);\\n        registry[msg.sender][_dataExchangeId] = _secret;\\n        emit Registration(msg.sender, _dataExchangeId, _secret);\\n    }\\n}\\n\",\"keccak256\":\"0x4de6bfe24e978d02e4bc36e8891a9503b0e418b6726103716fa7ced46350df96\",\"license\":\"Unlicense\"}},\"version\":1}";
var bytecode = "0x608060405234801561001057600080fd5b5061034d806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b61005560048036038101906100509190610201565b610087565b005b610071600480360381019061006c91906101c5565b610176565b60405161007e9190610292565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002054146100e357600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000848152602001908152602001600020819055507f0d6d8be58ef6918a4e19027a89943222bc99e02d838bd0b3e41004fd72d7f34433838360405161016a9392919061025b565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150505481565b6000813590506101aa816102e9565b92915050565b6000813590506101bf81610300565b92915050565b600080604083850312156101d857600080fd5b60006101e68582860161019b565b92505060206101f7858286016101b0565b9150509250929050565b6000806040838503121561021457600080fd5b6000610222858286016101b0565b9250506020610233858286016101b0565b9150509250929050565b610246816102ad565b82525050565b610255816102df565b82525050565b6000606082019050610270600083018661023d565b61027d602083018561024c565b61028a604083018461024c565b949350505050565b60006020820190506102a7600083018461024c565b92915050565b60006102b8826102bf565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6102f2816102ad565b81146102fd57600080fd5b50565b610309816102df565b811461031457600080fd5b5056fea26469706673582212206004e0c3b99c52db1b84221e9cca886d1eb418b718da57ba025235b5d40fcc6c64736f6c63430008040033";
var deployedBytecode = "0x608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b61005560048036038101906100509190610201565b610087565b005b610071600480360381019061006c91906101c5565b610176565b60405161007e9190610292565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002054146100e357600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000848152602001908152602001600020819055507f0d6d8be58ef6918a4e19027a89943222bc99e02d838bd0b3e41004fd72d7f34433838360405161016a9392919061025b565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150505481565b6000813590506101aa816102e9565b92915050565b6000813590506101bf81610300565b92915050565b600080604083850312156101d857600080fd5b60006101e68582860161019b565b92505060206101f7858286016101b0565b9150509250929050565b6000806040838503121561021457600080fd5b6000610222858286016101b0565b9250506020610233858286016101b0565b9150509250929050565b610246816102ad565b82525050565b610255816102df565b82525050565b6000606082019050610270600083018661023d565b61027d602083018561024c565b61028a604083018461024c565b949350505050565b60006020820190506102a7600083018461024c565b92915050565b60006102b8826102bf565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6102f2816102ad565b81146102fd57600080fd5b50565b610309816102df565b811461031457600080fd5b5056fea26469706673582212206004e0c3b99c52db1b84221e9cca886d1eb418b718da57ba025235b5d40fcc6c64736f6c63430008040033";
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
			astId: 7,
			contract: "contracts/NonRepudiation.sol:NonRepudiation",
			label: "registry",
			offset: 0,
			slot: "0",
			type: "t_mapping(t_address,t_mapping(t_uint256,t_uint256))"
		}
	],
	types: {
		t_address: {
			encoding: "inplace",
			label: "address",
			numberOfBytes: "20"
		},
		"t_mapping(t_address,t_mapping(t_uint256,t_uint256))": {
			encoding: "mapping",
			key: "t_address",
			label: "mapping(address => mapping(uint256 => uint256))",
			numberOfBytes: "32",
			value: "t_mapping(t_uint256,t_uint256)"
		},
		"t_mapping(t_uint256,t_uint256)": {
			encoding: "mapping",
			key: "t_uint256",
			label: "mapping(uint256 => uint256)",
			numberOfBytes: "32",
			value: "t_uint256"
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
                key = b64__namespace.decode(secret);
            }
            else {
                key = new Uint8Array(bigintConversion.hexToBuf(secret));
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
        key = await jose.generateSecret(encAlg, { extractable: true });
    }
    const jwk = await jose.exportJWK(key);
    // const thumbprint: string = await calculateJwkThumbprint(jwk)
    // jwk.kid = thumbprint
    jwk.alg = encAlg;
    return { jwk: jwk, hex: bigintConversion.bufToHex(b64.decode(jwk.k)) };
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
    const pubKey = await jose.importJWK(publicJwk);
    const verification = await jose.jwtVerify(proof, pubKey);
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
        else if (expectedPayloadClaims[key] !== '' && objectSha.hashable(expectedPayloadClaims[key]) !== objectSha.hashable(payload[key])) {
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
        if (expectedDataExchange[key] !== '' && objectSha.hashable(expectedDataExchange[key]) !== objectSha.hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
        }
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
        this.agreement = agreement;
        // @ts-expect-error I will end assigning the complete Block in the async init()
        this.block = {
            raw: block
        };
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        this.initialized = new Promise((resolve, reject) => {
            this.init(privateLedgerKeyHex).then(() => {
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
        const id = await sha(objectSha.hashable({ ...this.agreement, cipherblockDgst }), 'SHA-256');
        this.exchange = {
            ...this.agreement,
            id,
            cipherblockDgst,
            blockCommitment: await sha(this.block.raw, this.agreement.hashAlg),
            secretCommitment: await sha(new Uint8Array(bigintConversion.hexToBuf(this.block.secret.hex)), this.agreement.hashAlg)
        };
        await this._dltSetup(privateLedgerKeyHex);
    }
    async _dltSetup(privateLedgerKeyHex) {
        if (!this.dltConfig.disable) {
            const rpcProvider = new ethers.ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
            if (this.jwkPairOrig.privateJwk.d === undefined) {
                throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key');
            }
            const privateKey = (privateLedgerKeyHex !== undefined)
                ? new Uint8Array(bigintConversion.hexToBuf(privateLedgerKeyHex))
                : b64__namespace.decode(this.jwkPairOrig.privateJwk.d);
            const signingKey = new ethers.ethers.utils.SigningKey(privateKey);
            const signer = new ethers.ethers.Wallet(signingKey, rpcProvider);
            const signerAddress = await signer.getAddress();
            if (signerAddress !== this.exchange.ledgerSignerAddress) {
                throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address associated to the provided private key ${signerAddress}`);
            }
            if (this.agreement.ledgerContractAddress !== this.dltConfig.contract.address) {
                throw new Error(`Contract address ${this.dltConfig.contract.address} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
            }
            this.dltContract = new ethers.ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, signer);
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
            const secret = ethers.ethers.BigNumber.from(`0x${this.block.secret.hex}`);
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
        this.agreement = agreement;
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
            const rpcProvider = new ethers.ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
            if (this.agreement.ledgerContractAddress !== this.dltConfig.contract.address) {
                throw new Error(`Contract address ${this.dltConfig.contract.address} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
            }
            this.dltContract = new ethers.ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, rpcProvider);
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
        const id = await sha(objectSha.hashable({ ...this.agreement, cipherblockDgst }), 'SHA-256');
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
            hex: bigintConversion.bufToHex(b64__namespace.decode(secret.k)),
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
        let secretBn = ethers.ethers.BigNumber.from(0);
        let counter = 0;
        do {
            secretBn = await this.dltContract.registry(this.agreement.ledgerSignerAddress, `0x${this.exchange.id}`);
            if (secretBn.isZero()) {
                counter++;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        } while (secretBn.isZero() && counter < timeout);
        if (secretBn.isZero()) {
            throw new Error(`timeout of ${timeout}s exceeded when querying the ledger`);
        }
        const secretHex = secretBn.toHexString();
        this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex);
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

exports.NonRepudiationDest = NonRepudiationDest;
exports.NonRepudiationOrig = NonRepudiationOrig;
exports.createProof = createProof;
exports.generateKeys = generateKeys;
exports.jweDecrypt = jweDecrypt;
exports.jweEncrypt = jweEncrypt;
exports.oneTimeSecret = oneTimeSecret;
exports.sha = sha;
exports.verifyKeyPair = verifyKeyPair;
exports.verifyProof = verifyProof;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2dlbmVyYXRlS2V5cy50cyIsIi4uLy4uL3NyYy90cy9qd2UudHMiLCIuLi8uLi9zcmMvdHMvZGVmYXVsdERsdENvbmZpZy50cyIsIi4uLy4uL3NyYy90cy9vbmVUaW1lU2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL3NoYS50cyIsIi4uLy4uL3NyYy90cy9jaGVja1RpbWVzdGFtcC50cyIsIi4uLy4uL3NyYy90cy92ZXJpZnlQcm9vZi50cyIsIi4uLy4uL3NyYy90cy9Ob25SZXB1ZGlhdGlvbk9yaWcudHMiLCIuLi8uLi9zcmMvdHMvTm9uUmVwdWRpYXRpb25EZXN0LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJpbXBvcnRKV0siLCJyYW5kQnl0ZXMiLCJHZW5lcmFsU2lnbiIsImdlbmVyYWxWZXJpZnkiLCJTaWduSldUIiwiYjY0IiwiaGV4VG9CdWYiLCJFYyIsIkNvbXBhY3RFbmNyeXB0IiwiY29tcGFjdERlY3J5cHQiLCJnZW5lcmF0ZVNlY3JldCIsImV4cG9ydEpXSyIsImJ1ZlRvSGV4IiwiYmFzZTY0ZGVjb2RlIiwiand0VmVyaWZ5IiwiaGFzaGFibGUiLCJldGhlcnMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBSU8sZUFBZSxhQUFhLENBQUUsTUFBVyxFQUFFLE9BQVk7SUFDNUQsSUFBSSxNQUFNLENBQUMsR0FBRyxLQUFLLFNBQVMsSUFBSSxPQUFPLENBQUMsR0FBRyxLQUFLLFNBQVMsSUFBSSxNQUFNLENBQUMsR0FBRyxLQUFLLE9BQU8sQ0FBQyxHQUFHLEVBQUU7UUFDdkYsTUFBTSxJQUFJLEtBQUssQ0FBQywwRUFBMEUsQ0FBQyxDQUFBO0tBQzVGO0lBQ0QsTUFBTSxNQUFNLEdBQUcsTUFBTUEsY0FBUyxD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
