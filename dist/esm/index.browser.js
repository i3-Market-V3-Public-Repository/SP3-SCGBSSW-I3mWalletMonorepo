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

function parseHex(a, prefix0x = false) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/);
    if (hexMatch == null) {
        throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format']);
    }
    const hex = hexMatch[2].toLocaleLowerCase();
    return (prefix0x) ? '0x' + hex : hex;
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
        this.agreement = {
            ...agreement,
            ledgerContractAddress: parseHex(agreement.ledgerContractAddress),
            ledgerSignerAddress: parseHex(agreement.ledgerSignerAddress)
        };
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
            this.init(privateLedgerKeyHex).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async init(privateLedgerKeyHex) {
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
            if (this.agreement.ledgerContractAddress !== parseHex(this.dltConfig.contract.address)) {
                throw new Error(`Contract address ${parseHex(this.dltConfig.contract.address)} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
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

export { index$2 as ConflictResolution, index as NonRepudiationProtocol, NrError, index$1 as Signers, checkIssuedAt, createProof, defaultDltConfig, generateKeys, getSecretFromLedger, importJwk, jweDecrypt, jweEncrypt, jwsDecode, oneTimeSecret, parseHex, sha, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2Vycm9ycy9OckVycm9yLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9nZW5lcmF0ZUtleXMudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2ltcG9ydEp3ay50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandlLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9qd3NEZWNvZGUudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2RlZmF1bHREbHRDb25maWcudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvY2hlY2tJc3N1ZWRBdC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2dldFNlY3JldEZyb21MZWRnZXIudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvZXhjaGFuZ2VJZC50cyIsIi4uLy4uL3NyYy90cy9wcm9vZnMvY3JlYXRlUHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvcHJvb2ZzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vdmVyaWZ5UG9yLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vY2hlY2tDb21wbGV0ZW5lc3MudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9jaGVja0RlY3J5cHRpb24udHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9Db25mbGljdFJlc29sdmVyLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vZ2VuZXJhdGVWZXJpZmljYXRpb25SZXF1ZXN0LnRzIiwiLi4vLi4vc3JjL3RzL25vbi1yZXB1ZGlhdGlvbi1wcm90b2NvbC9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiLCIuLi8uLi9zcmMvdHMvc2lnbmVycy9FdGhlcnNTaWduZXIudHMiLCIuLi8uLi9zcmMvdHMvc2lnbmVycy9TaWduZXIudHMiLCIuLi8uLi9zcmMvdHMvbm9uLXJlcHVkaWF0aW9uLXByb3RvY29sL05vblJlcHVkaWF0aW9uT3JpZy50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiZWMiLCJFYyIsImltcG9ydEpXS2pvc2UiLCJiYXNlNjRkZWNvZGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O01BRWEsT0FBUSxTQUFRLEtBQUs7SUFHaEMsWUFBYSxLQUFVLEVBQUUsUUFBdUI7UUFDOUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ1osSUFBSSxLQUFLLFlBQVksT0FBTyxFQUFFO1lBQzVCLElBQUksQ0FBQyxRQUFRLEdBQUcsS0FBSyxDQUFDLFFBQVEsQ0FBQTtZQUM5QixJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsUUFBUSxDQUFDLENBQUE7U0FDdEI7YUFBTTtZQUNMLElBQUksQ0FBQyxRQUFRLEdBQUcsUUFBUSxDQUFBO1NBQ3pCO0tBQ0Y7SUFFRCxHQUFHLENBQUUsR0FBRyxRQUF1QjtRQUM3QixRQUFRLENBQUMsT0FBTyxDQUFDLE9BQU8sSUFBSSxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFBO0tBQ3pEOzs7QUNWSDs7Ozs7Ozs7QUFRTyxlQUFlLFlBQVksQ0FBRSxHQUFlLEVBQUUsVUFBZ0MsRUFBRSxNQUFnQjtJQUNyRyxNQUFNLElBQUksR0FBaUIsQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFBO0lBQ3RELElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQztRQUFFLE1BQU0sSUFBSSxPQUFPLENBQUMsSUFBSSxVQUFVLENBQUMsZ0NBQWdDLEdBQUcsOEJBQThCLElBQUksQ0FBQyxRQUFRLEVBQUUsRUFBRSxDQUFDLEVBQUUs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
