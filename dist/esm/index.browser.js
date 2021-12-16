import * as b64 from '@juanelas/base64';
import { decode } from '@juanelas/base64';
import { hexToBuf, bufToHex } from 'bigint-conversion';
import { randBytes } from 'bigint-crypto-utils';
import { ec } from 'elliptic';
import { importJWK, CompactEncrypt, compactDecrypt, jwtVerify, generateSecret, exportJWK, GeneralSign, generalVerify, SignJWT } from 'jose';
import { ethers } from 'ethers';
import { hashable } from 'object-sha';
import { SigningKey } from '@ethersproject/signing-key';
import { Wallet } from '@ethersproject/wallet';

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

async function importJwk(jwk, alg) {
    try {
        const key = await importJWK(jwk, alg);
        return key;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

/**
 * Encrypts a block of data to JWE
 *
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
async function jweEncrypt(block, secret, encAlg) {
    // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
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
/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @param encAlg - the algorithm for encryption
 * @returns the plaintext
 */
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

/**
 * Decodes and optionally verifies a JWS, and returns the decoded header, payload.
 * @param jws
 * @param publicJwk - either a public key as a JWK or a function that resolves to a JWK. If not provided, the JWS signature is not verified
 */
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
        const jwk = await importJwk(pubJwk);
        try {
            const verified = await jwtVerify(jws, jwk);
            return {
                header: verified.protectedHeader,
                payload: verified.payload
            };
        }
        catch (error) {
            throw new NrError(error, ['jws verification failed']);
        }
    }
    return { header, payload };
}

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
            throw new NrError(new Error(`Invalid encAlg '${encAlg}'. Supported values are: ${['A128GCM', 'A256GCM'].toString()}`), ['invalid algorithm']);
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
    // const thumbprint: string = await calculateJwkThumbprint(jwk)
    // jwk.kid = thumbprint
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
        await generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
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
        throw new NrError(new Error('current date is before the proof\'s "iat"'), ['invalid iat']);
    }
    if (options.currentTimestamp < options.expectedTimestampInterval.min - options.clockToleranceMs) {
        throw new NrError(new Error('iat < expected minimum reception time'), ['invalid iat']);
    }
    if (options.currentTimestamp > options.expectedTimestampInterval.max + options.clockToleranceMs) {
        throw new NrError(new Error('iat < expected maximum reeption Time'), ['invalid iat']);
    }
}

function isObject(v) {
    return Object.prototype.toString.call(v) === '[object Object]';
}
function jsonSort(obj) {
    if (Array.isArray(obj)) {
        return obj.sort().map(jsonSort); // eslint-disable-line
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

function parseHex(a, prefix0x = false) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/);
    if (hexMatch == null) {
        throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format']);
    }
    const hex = hexMatch[2].toLocaleLowerCase();
    return (prefix0x) ? '0x' + hex : hex;
}

async function parseJwk(jwk, stringify = true) {
    try {
        const key = await importJwk(jwk, jwk.alg);
        const jwk2 = await exportJWK(key);
        jwk2.alg = jwk.alg;
        const sortedJwk = jsonSort(jwk2);
        return (stringify) ? JSON.stringify(sortedJwk) : sortedJwk;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

async function sha(input, algorithm, buffer = false) {
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
        }
        return digest;
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
    }
}

/**
 * Just in case the PoP is not received, the secret can be downloaded from the ledger.
 * The secret should be downloaded before poo.iat + pooToPop max delay.
 * @param contract - an Ethers Contract
 * @param signerAddress - the address (hexadecimal) of the entity publishing the secret.
 * @param exchangeId - the id of the data exchange
 * @param timeout - the timeout in seconds for waiting for the secret to be published on the ledger
 * @returns
 */
async function getSecretFromLedger(contract, signerAddress, exchangeId, timeout = 0) {
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

/**
 * Returns the exchangeId of the data exchange. The id is computed hashing an object with
 * all the properties of the data exchange but the id.
 *   id = BASE64URL(SHA256(hashable(dataExchangeButId)))
 * @param exchange - a complete data exchange without an id
 * @returns the exchange id in hexadecimal
 */
async function exchangeId(exchange) {
    return b64.encode(await sha(hashable(exchange), 'SHA-256'), true, false);
}

const HASH_ALGS = ['SHA-256', 'SHA-384', 'SHA-512'];
const SIGNING_ALGS = ['ES256', 'ES384', 'ES512']; // ECDSA with secp256k1 (ES256K) Edwards Curve DSA are not supported in browsers
const ENC_ALGS = ['A128GCM', 'A256GCM']; // A192GCM is not supported in browsers

function parseTimestamp(timestamp) {
    if ((new Date(timestamp)).getTime() > 0) {
        return Number(timestamp);
    }
    else {
        throw new NrError(new Error('invalid timestamp'), ['invalid iat']);
    }
}
async function checkAgreement(agreement) {
    const parsedAgreement = { ...agreement };
    const agreementClaims = Object.keys(parsedAgreement);
    if (agreementClaims.length < 10 || agreementClaims.length > 11) {
        throw new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format']);
    }
    for (const key of agreementClaims) {
        switch (key) {
            case 'orig':
            case 'dest':
                parsedAgreement[key] = await parseJwk(JSON.parse(agreement[key]));
                break;
            case 'ledgerContractAddress':
            case 'ledgerSignerAddress':
                parsedAgreement[key] = parseHex(parsedAgreement[key], true);
                break;
            case 'pooToPorDelay':
            case 'pooToPopDelay':
            case 'pooToSecretDelay':
                parsedAgreement[key] = parseTimestamp(parsedAgreement[key]);
                break;
            case 'hashAlg':
                if (!HASH_ALGS.includes(parsedAgreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'encAlg':
                if (!ENC_ALGS.includes(parsedAgreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'signingAlg':
                if (!SIGNING_ALGS.includes(parsedAgreement[key])) {
                    throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm']);
                }
                break;
            case 'schema':
                break;
            default:
                throw new NrError(new Error(`Additional key ${key} not allowed in dataAgreement`), ['invalid format']);
        }
    }
    return parsedAgreement;
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
    const privateKey = await importJwk(privateJwk);
    const alg = privateJwk.alg; // if alg were undefined verifyKeyPair would have thrown an error
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

/**
 * Verify a proof
 * @param proof - a non-repudiable proof in Compact JWS formatted JWT string
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
async function verifyProof(proof, expectedPayloadClaims, timestampVerifyOptions) {
    const publicJwk = JSON.parse(expectedPayloadClaims.exchange[expectedPayloadClaims.iss]);
    const verification = await jwsDecode(proof, publicJwk);
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

async function verifyPor(por, dltContract) {
    const { payload: porPayload } = await jwsDecode(por);
    const exchange = porPayload.exchange;
    const dataExchangePreview = { ...exchange };
    // @ts-expect-error
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
        });
    }
    catch (error) {
        throw new NrError(error, ['invalid por']);
    }
    let secretHex, iat;
    try {
        const secret = await getSecretFromLedger(dltContract, exchange.ledgerSignerAddress, exchange.id);
        secretHex = secret.hex;
        iat = secret.iat;
    }
    catch (error) {
        throw new NrError(error, ['cannot verify']);
    }
    try {
        checkIssuedAt(iat, {
            clockToleranceMs: 0,
            expectedTimestampInterval: {
                min: pooPayload.iat * 1000,
                max: pooPayload.iat * 1000 + exchange.pooToSecretDelay
            }
        });
    }
    catch (error) {
        throw new NrError(error, ['secret not published in time']);
    }
    return {
        pooPayload,
        porPayload,
        secretHex,
        destPublicJwk,
        origPublicJwk
    };
}

/**
 * Checks the completeness of a given data exchange by verifying the PoR in the verification request using the secret downloaded from the ledger
 *
 * @param verificationRequest
 * @param dltContract
 * @returns
 */
async function checkCompleteness(verificationRequest, dltContract) {
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
        const verified = await verifyPor(vrPayload.por, dltContract);
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

/**
 * Check if the cipherblock in the disputeRequest is the one agreed for the dataExchange, and if it could be decrypted with the secret published on the ledger for that dataExchange.
 *
 * @param disputeRequest a dispute request as a compact JWS
 * @param dltContract
 * @returns
 */
async function checkDecryption(disputeRequest, dltContract) {
    const { payload: drPayload } = await jwsDecode(disputeRequest);
    const { destPublicJwk, origPublicJwk, secretHex, pooPayload, porPayload } = await verifyPor(drPayload.por, dltContract);
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
    /**
     * TO-DO: check schema!
     */
    return {
        pooPayload,
        porPayload,
        drPayload,
        destPublicJwk,
        origPublicJwk
    };
}

/**
 * The base class that should be instantiated in order to create a Conflict Resolver instance.
 * The Conflict Resolver is an external entity that can:
 *  1. verify the completeness of a data exchange that used the non-repudiation protocol;
 *  2. resolve a dispute when a consumer states that she/he cannot decrypt the data received
 */
class ConflictResolver {
    /**
     *
     * @param jwkPair a pair of public/private keys in JWK format
     * @param dltConfig
     */
    constructor(jwkPair, dltConfig) {
        this.jwkPair = jwkPair;
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        this.dltConfig.contract.address = parseHex(this.dltConfig.contract.address, true); // prefix '0x' to the contract address (just in case it is not there)
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
            this.dltContract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, rpcProvider);
        }
    }
    /**
     * Initialize this instance.
     */
    async init() {
        await verifyKeyPair(this.jwkPair.publicJwk, this.jwkPair.privateJwk);
    }
    /**
     * Checks if a give data exchange has completed succesfully
     *
     * @param verificationRequest
     * @returns a signed resolution
     */
    async resolveCompleteness(verificationRequest) {
        await this.initialized;
        const { payload: vrPayload } = await jwsDecode(verificationRequest);
        const verificationResolution = {
            ...resolution(vrPayload.dataExchangeId, vrPayload.iss),
            resolution: 'not completed',
            type: 'verification'
        };
        try {
            await checkCompleteness(verificationRequest, this.dltContract);
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
    /**
     * Checks if the cipherblock provided in a data exchange can be decrypted
     * with the published secret.
     *
     * @todo Check also data schema
     *
     * @param disputeRequest
     * @returns a signed resolution
     */
    async resolveDispute(disputeRequest) {
        await this.initialized;
        const { payload: drPayload } = await jwsDecode(disputeRequest);
        const disputeResolution = {
            ...resolution(drPayload.dataExchangeId, drPayload.iss),
            resolution: 'denied',
            type: 'dispute'
        };
        try {
            await checkDecryption(disputeRequest, this.dltContract);
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
}
function resolution(dataExchangeId, iss) {
    return {
        dataExchangeId,
        iat: Math.floor(Date.now() / 1000),
        iss
    };
}

async function generateVerificationRequest(iss, dataExchangeId, por, privateJwk) {
    const payload = {
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

var index$2 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    checkCompleteness: checkCompleteness,
    checkDecryption: checkDecryption,
    ConflictResolver: ConflictResolver,
    generateVerificationRequest: generateVerificationRequest,
    verifyPor: verifyPor
});

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
        this.block = {};
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        this.initialized = new Promise((resolve, reject) => {
            this.init(agreement).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    _dltSetup() {
        if (!this.dltConfig.disable) {
            const rpcProvider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
            if (parseHex(this.agreement.ledgerContractAddress) !== parseHex(this.dltConfig.contract.address)) {
                throw new Error(`Contract address ${this.dltConfig.contract.address} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
            }
            this.dltContract = new ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, rpcProvider);
        }
    }
    async init(agreement) {
        this.agreement = await checkAgreement(agreement);
        this._dltSetup();
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
        const proofVerifyOptions = {};
        if (clockToleranceMs !== undefined)
            proofVerifyOptions.clockToleranceMs = clockToleranceMs;
        if (currentDate !== undefined)
            proofVerifyOptions.currentTimestamp = currentDate.valueOf();
        const verified = await verifyProof(poo, expectedPayloadClaims, proofVerifyOptions);
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
        const verified = await verifyProof(pop, expectedPayloadClaims, proofVerifyOptions);
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
     * The secret should be downloaded before poo.iat + pooToPop max delay.
     *
     * @returns the secret
     */
    async getSecretFromLedger() {
        await this.initialized;
        if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
            throw new Error('Cannot get secret if a PoR has not been sent before');
        }
        const currentTimestamp = Date.now();
        const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay;
        const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000);
        const { hex: secretHex, iat } = await getSecretFromLedger(this.dltContract, this.agreement.ledgerSignerAddress, this.exchange.id, timeout);
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
            throw new Error(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`);
        }
        return this.block.secret;
    }
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     */
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
    /**
     * Generates a verification request that can be used to query the
     * Conflict-Resolver Service for completeness of the non-repudiation protocol
     *
     * @returns the verification request as a compact JWS signed with 'dest's private key
     */
    async generateVerificationRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange');
        }
        return await generateVerificationRequest('dest', this.exchange.id, this.block.por.jws, this.jwkPairDest.privateJwk);
    }
    /**
     * Generates a dispute request that can be used to query the
     * Conflict-Resolver Service regarding impossibility to decrypt the cipherblock with the received secret
     *
     * @returns the dispute request as a compact JWS signed with 'dest's private key
     */
    async generateDisputeRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.block.jwe === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange and have received the cipherblock');
        }
        const payload = {
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

/**
 * A ledger signer using an ethers.io Wallet.
 */
class EthersSigner {
    /**
     *
     * @param provider
     * @param privateKey the private key as an hexadecimal string ot Uint8Array
     */
    constructor(provider, privateKey) {
        const privKey = (typeof privateKey === 'string') ? new Uint8Array(hexToBuf(privateKey)) : privateKey;
        const signingKey = new SigningKey(privKey);
        this.signer = new Wallet(signingKey, provider);
    }
    async signTransaction(transaction) {
        return await this.signer.signTransaction(transaction);
    }
}

/**
 * An abstract class that should be implemeneted by any signer for the ledger.
 * A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation
 */
class DltSigner {
    async signTransaction(transaction) {
        throw new Error('not implemented');
    }
}

var index$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EthersSigner: EthersSigner,
    DltSigner: DltSigner
});

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
     * @param privateLedgerKeyHex - the private key (d parameter) as a hexadecimal string used to sign transactions to the ledger. If not provided, it is assumed that a DltSigner is provided in the dltConfig
     */
    constructor(agreement, privateJwk, block, dltConfig, privateLedgerKeyHex) {
        this.jwkPairOrig = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.orig)
        };
        this.publicJwkDest = JSON.parse(agreement.dest);
        // @ts-expect-error I will end assigning the complete Block in the async init()
        this.block = {
            raw: block
        };
        // @ts-expect-error I will end assigning the complete dltConfig in the async init()
        this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig
        };
        this.initialized = new Promise((resolve, reject) => {
            this.init(agreement, privateLedgerKeyHex).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async init(agreement, privateLedgerKeyHex) {
        this.agreement = await checkAgreement(agreement);
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
        await this._dltSetup(privateLedgerKeyHex);
    }
    async _dltSetup(privateLedgerKeyHex) {
        if (!this.dltConfig.disable) {
            const rpcProvider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
            if (this.jwkPairOrig.privateJwk.d === undefined) {
                throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key');
            }
            if (privateLedgerKeyHex !== undefined) {
                this.dltConfig.signer = new EthersSigner(rpcProvider, privateLedgerKeyHex);
            }
            if (this.dltConfig.signer === undefined) {
                throw new Error('Either a dltConfig.signer or a privateLedgerKeyHex MUST be provided.');
            }
            // TO-DO: we need an implementation on DltSigner class:
            // const signerAddress: string = parseHex(await signer.getAddress())
            // if (signerAddress !== this.exchange.ledgerSignerAddress) {
            //   throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address associated to the provided private key ${signerAddress}`)
            // }
            if (parseHex(this.agreement.ledgerContractAddress) !== parseHex(this.dltConfig.contract.address)) {
                throw new Error(`Contract address ${this.dltConfig.contract.address} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
            }
            this.dltContract = new ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, rpcProvider);
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
        this.block.poo = await createProof({
            proofType: 'PoO',
            iss: 'orig',
            exchange: this.exchange
        }, this.jwkPairOrig.privateJwk);
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
        const verified = await verifyProof(por, expectedPayloadClaims, proofVerifyOptions);
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
            const exchangeIdHex = parseHex(bufToHex(b64.decode(this.exchange.id)), true);
            const tx = await this.dltContract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: this.dltConfig.gasLimit });
            // ethers.utils.serializeTransaction(tx)
            tx.nonce = await this.dltContract.provider.getTransactionCount(this.exchange.ledgerSignerAddress);
            tx.gasPrice = await this.dltContract.provider.getGasPrice();
            tx.chainId = (await this.dltContract.provider.getNetwork()).chainId;
            const signedTx = await this.dltConfig.signer.signTransaction(tx);
            const setRegistryTx = await this.dltContract.provider.sendTransaction(signedTx);
            // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
            // const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
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
    /**
     * Generates a verification request that can be used to query the
     * Conflict-Resolver Service for completeness of the non-repudiation protocol
     *
     * @returns the verification request as a compact JWS signed with 'orig's private key
     */
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

export { index$2 as ConflictResolution, ENC_ALGS, HASH_ALGS, index as NonRepudiationProtocol, NrError, SIGNING_ALGS, index$1 as Signers, checkAgreement, checkIssuedAt, createProof, defaultDltConfig, exchangeId, generateKeys, getSecretFromLedger, importJwk, jsonSort, jweDecrypt, jweEncrypt, jwsDecode, oneTimeSecret, parseHex, parseJwk, sha, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2Vycm9ycy9OckVycm9yLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9nZW5lcmF0ZUtleXMudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2ltcG9ydEp3ay50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandlLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9qd3NEZWNvZGUudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2RlZmF1bHREbHRDb25maWcudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvY2hlY2tJc3N1ZWRBdC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9qc29uU29ydC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUp3ay50cyIsIi4uLy4uL3NyYy90cy91dGlscy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2dldFNlY3JldEZyb21MZWRnZXIudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvZXhjaGFuZ2VJZC50cyIsIi4uLy4uL3NyYy90cy9jb25zdGFudHMudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvY2hlY2tBZ3JlZW1lbnQudHMiLCIuLi8uLi9zcmMvdHMvcHJvb2ZzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL3Byb29mcy92ZXJpZnlQcm9vZi50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL3ZlcmlmeVBvci50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL2NoZWNrQ29tcGxldGVuZXNzLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vY2hlY2tEZWNyeXB0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vQ29uZmxpY3RSZXNvbHZlci50cyIsIi4uLy4uL3NyYy90cy9jb25mbGljdC1yZXNvbHV0aW9uL2dlbmVyYXRlVmVyaWZpY2F0aW9uUmVxdWVzdC50cyIsIi4uLy4uL3NyYy90cy9ub24tcmVwdWRpYXRpb24tcHJvdG9jb2wvTm9uUmVwdWRpYXRpb25EZXN0LnRzIiwiLi4vLi4vc3JjL3RzL3NpZ25lcnMvRXRoZXJzU2lnbmVyLnRzIiwiLi4vLi4vc3JjL3RzL3NpZ25lcnMvU2lnbmVyLnRzIiwiLi4vLi4vc3JjL3RzL25vbi1yZXB1ZGlhdGlvbi1wcm90b2NvbC9Ob25SZXB1ZGlhdGlvbk9yaWcudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImVjIiwiRWMiLCJpbXBvcnRKV0tqb3NlIiwiYmFzZTY0ZGVjb2RlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7OztNQUVhLE9BQVEsU0FBUSxLQUFLO0lBR2hDLFlBQWEsS0FBVSxFQUFFLFFBQXVCO1FBQzlDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNaLElBQUksS0FBSyxZQUFZLE9BQU8sRUFBRTtZQUM1QixJQUFJLENBQUMsUUFBUSxHQUFHLEtBQUssQ0FBQyxRQUFRLENBQUE7WUFDOUIsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLFFBQVEsQ0FBQyxDQUFBO1NBQ3RCO2FBQU07WUFDTCxJQUFJLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQTtTQUN6QjtLQUNGO0lBRUQsR0FBRyxDQUFFLEdBQUcsUUFBdUI7UUFDN0IsUUFBUSxDQUFDLE9BQU8sQ0FBQyxPQUFPLElBQUksSUFBSSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQTtLQUN6RDs7O0FDVkg7Ozs7Ozs7O0FBUU8sZUFBZSxZQUFZLENBQUUsR0FBZSxFQUFFLFVBQWdDLEVBQUUsTUFBZ0I7SUFDckcsTUFBTSxJQUFJLEdBQWlCLENBQUMsT0FBTyxFQUFFLE9BQU8sRUFBRSxPQUFPLENBQUMsQ0FBQTtJQUN0RCxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUM7UUFBRSxNQUFNLElBQUksT0FBTyxDQUFDLElBQUksVUFBVSxDQUFDLGdDQUFnQyxHQUFHLDhCQUE4QixJQUFJLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQyxFQUFFLENBQUMsbUJBQW1CLENBQUMsQ0FBQyxDQUFBO0lBRXJLLElBQUksU0FBaUIsQ0FBQTtJQUNyQixJQUFJLFVBQWtCLENBQUE7SUFDdEIsUUFBUSxHQUFHO1FBQ1QsS0FBSyxPQUFPO1lBQ1YsVUFBVSxHQUFHLE9BQU8sQ0FBQTtZQUNwQixTQUFTLEdBQUcsRUFBRSxDQUFBO1lBQ2QsTUFBSztRQUNQLEtBQUssT0FBTztZQUNWLFVBQVUsR0FBRyxPQUFPLENBQUE7WUFDcEIsU0FBUyxHQUFHLEVBQUUsQ0FBQTtZQUNkLE1BQUs7UUFDUDtZQUNFLFVBQVUsR0FBRyxPQUFPLENBQUE7WUFDcEIsU0FBUyxHQUFHLEVBQUUsQ0FBQTtLQUNqQjtJQUVELElBQUksVUFBa0MsQ0FBQTtJQUN0QyxJQUFJLFVBQVUsS0FBSyxTQUFTLEVBQUU7UUFDNUIsSUFBSSxPQUFPLFVBQVUsS0FBSyxRQUFRLEVBQUU7WUFDbEMsSUFBSSxNQUFNLEtBQUssSUFBSSxFQUFFO2dCQUNuQixVQUFVLEdBQUcsR0FBRyxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQWUsQ0FBQTthQUNsRDtpQkFBTTtnQkFDTCxVQUFVLEdBQUcsSUFBSSxVQUFVLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUE7YUFDbEQ7U0FDRjthQUFNO1lBQ0wsVUFBVSxHQUFHLFVBQVUsQ0FBQTtTQUN4QjtLQUNGO1NBQU07UUFDTCxVQUFVLEdBQUcsSUFBSSxVQUFVLENBQUMsTUFBTSxTQUFTLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQTtLQUN4RDtJQUVELE1BQU1BLElBQUUsR0FBRyxJQUFJQyxFQUFFLENBQUMsR0FBRyxHQUFHLFVBQVUsQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO0lBQ3BFLE1BQU0sTUFBTSxHQUFHRCxJQUFFLENBQUMsY0FBYyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0lBQzVDLE1BQU0sS0FBSyxHQUFHLE1BQU0sQ0FBQyxTQUFTLEVBQUUsQ0FBQTtJQUVoQyxNQUFNLElBQUksR0FBRyxLQUFLLENBQUMsSUFBSSxFQUFFLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDLFFBQVEsQ0FBQyxTQUFTLEdBQUcsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0lBQ3RFLE1BQU0sSUFBSSxHQUFHLEtBQUssQ0FBQyxJQUFJLEVBQUUsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7SUFDdEUsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQyxRQUFRLENBQUMsU0FBUyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQTtJQUVsRSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7SUFDakQsTUFBTSxDQUFDLEdBQUcsR0FBRyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFBO0lBQ2pELE1BQU0sQ0FBQyxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLElBQUksRUFBRSxLQUFLLENBQUMsQ0FBQTtJQUVqRCxNQUFNLFVBQVUsR0FBUSxFQUFFLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxHQUFHLEVBQUUsQ0FBQTtJQUVwRSxNQUFNLFNBQVMsR0FBUSxFQUFFLEdBQUcsVUFBVSxFQUFFLENBQUE7SUFDeEMsT0FBTyxTQUFTLENB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
