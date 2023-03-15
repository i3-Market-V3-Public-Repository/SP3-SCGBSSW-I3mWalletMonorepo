import { ethers, utils } from 'ethers';
import _ from 'lodash';
import * as u8a from 'uint8arrays';
import { v4 } from 'uuid';
import { digest } from 'object-sha';
import { verifyKeyPair, parseJwk, validateDataSharingAgreementSchema, validateDataExchangeAgreement, jwsDecode, validateDataExchange, exchangeId } from '@i3m/non-repudiation-library';
import { verifyJWT } from 'did-jwt';
import crypto, { randomInt, KeyObject, randomBytes, createCipheriv, createDecipheriv, scrypt, createSecretKey } from 'crypto';
import Debug from 'debug';
import { basename, dirname } from 'path';
import { Observable, bufferCount, timeout } from 'rxjs';
import { createAgent } from '@veramo/core';
import { AbstractDIDStore, DIDManager } from '@veramo/did-manager';
import { EthrDIDProvider } from '@veramo/did-provider-ethr';
import { WebDIDProvider } from '@veramo/did-provider-web';
import { AbstractKeyManagementSystem, AbstractKeyStore, KeyManager } from '@veramo/key-manager';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import { Base58 } from '@ethersproject/basex';
import { BigNumber } from '@ethersproject/bignumber';
import { ContractFactory } from '@ethersproject/contracts';
import { InfuraProvider, JsonRpcProvider } from '@ethersproject/providers';
import { getAddress } from '@ethersproject/address';
import { computeAddress } from '@ethersproject/transactions';
import * as qs from 'querystring';
import { getResolver as getResolver$1 } from 'web-did-resolver';
import { SelectiveDisclosure, SdrMessageHandler } from '@veramo/selective-disclosure';
import { MessageHandler } from '@veramo/message-handler';
import { JwtMessageHandler } from '@veramo/did-jwt';
import { CredentialIssuer, W3cMessageHandler } from '@veramo/credential-w3c';
import { mkdir, rm } from 'fs/promises';
import { readFileSync, writeFileSync } from 'fs';

const encode = (buf) => {
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
const decode = (str) => {
    return Buffer.from(str, 'base64');
};
var base64Url = {
    encode,
    decode
};

/**
 * Prepares header and payload, received as standard JS objects, to be signed as needed for a JWS/JWT signature.
 *
 * @param header
 * @param payload
 * @param encoding
 * @returns <base64url(header)>.<base64url(payload)>
 */
function jwsSignInput(header, payload, encoding) {
    const encodedHeader = base64Url.encode(Buffer.from(JSON.stringify(header), 'binary'));
    const encodedPayload = base64Url.encode(Buffer.from(JSON.stringify(payload), encoding));
    return `${encodedHeader}.${encodedPayload}`;
}
/**
 * Returns a decoded JWS
 *
 * @param jws
 * @param encoding
 * @returns
 */
function decodeJWS(jws, encoding) {
    const parts = jws.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/);
    if (parts != null) {
        return {
            header: JSON.parse(base64Url.decode(parts[1]).toString('binary')),
            payload: JSON.parse(base64Url.decode(parts[2]).toString(encoding)),
            signature: parts[3],
            data: `${parts[1]}.${parts[2]}`
        };
    }
    throw new Error('invalid_argument: Incorrect format JWS');
}

class WalletError extends Error {
    constructor(message, httpData) {
        super(message);
        this.code = httpData?.code ?? 1;
        this.status = httpData?.status ?? 500;
    }
}

const keyPairValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const { keyPair } = resource.resource;
        const publicJwk = JSON.parse(keyPair.publicJwk);
        const privateJwk = JSON.parse(keyPair.privateJwk);
        // Verify keyPair
        await verifyKeyPair(publicJwk, privateJwk);
        // Let us rewrite the JWK strings in sorted order
        keyPair.publicJwk = await parseJwk(publicJwk, true);
        keyPair.privateJwk = await parseJwk(privateJwk, true);
        // Let us use a unique id that can be easily found. This way it can be easily linked to contracts added later
        resource.id = await digest(keyPair.publicJwk);
    }
    catch (error) {
        errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'));
    }
    return errors;
};

function getCredentialClaims(vc) {
    return Object.keys(vc.credentialSubject)
        .filter(claim => claim !== 'id');
}

// type Dict<T> = T & {
//   [key: string]: any | undefined
// }
/*
 * Compare two objects by reducing an array of keys in obj1, having the
 * keys in obj2 as the intial value of the result. Key points:
 *
 * - All keys of obj2 are initially in the result.
 *
 * - If the loop finds a key (from obj1, remember) not in obj2, it adds
 *   it to the result.
 *
 * - If the loop finds a key that are both in obj1 and obj2, it compares
 *   the value. If it's the same value, the key is removed from the result.
 */
function getObjectDiff(obj1, obj2) {
    const diff = Object.keys(obj1).reduce((result, key) => {
        if (!Object.prototype.hasOwnProperty.call(obj2, key)) {
            result.push(key);
        }
        else if (_.isEqual(obj1[key], obj2[key])) {
            const resultKeyIndex = result.indexOf(key);
            result.splice(resultKeyIndex, 1);
        }
        return result;
    }, Object.keys(obj2));
    return diff;
}
/**
   * Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.
   *
   * The Wallet only supports the 'ES256K1' algorithm.
   *
   * Useful to verify JWT created by another wallet instance.
   * @param requestBody
   * @returns
   */
async function didJwtVerify(jwt, veramo, expectedPayloadClaims) {
    let decodedJwt;
    try {
        decodedJwt = decodeJWS(jwt);
    }
    catch (error) {
        return {
            verification: 'failed',
            error: 'Invalid JWT format'
        };
    }
    const payload = decodedJwt.payload;
    if (expectedPayloadClaims !== undefined) {
        const expectedPayloadMerged = _.cloneDeep(expectedPayloadClaims);
        _.defaultsDeep(expectedPayloadMerged, payload);
        const diffs = getObjectDiff(payload, expectedPayloadMerged);
        if (diffs.length > 0) {
            return {
                verification: 'failed',
                error: 'The following top-level properties are missing or different: ' + diffs.join(', '),
                decodedJwt
            };
        }
        // const isExpectedPayload = _.isEqual(expectedPayloadMerged, payload)
        // if (!isExpectedPayload) {
        //   return {
        //     verification: 'failed',
        //     error: 'some or all the expected payload claims are not as expected',
        //     decodedJwt
        //   }
        // }
    }
    const resolver = { resolve: async (didUrl) => await veramo.agent.resolveDid({ didUrl }) };
    try {
        const verifiedJWT = await verifyJWT(jwt, { resolver });
        return {
            verification: 'success',
            decodedJwt: verifiedJWT.payload
        };
    }
    catch (error) {
        if (error instanceof Error) {
            return {
                verification: 'failed',
                error: error.message,
                decodedJwt
            };
        }
        else
            throw new Error('unknown error during verification');
    }
}

async function verifyDataSharingAgreementSignature(agreement, veramo, signer) {
    const errors = [];
    const { signatures, ...expectedPayloadClaims } = agreement;
    let verifiedSignature;
    let expectedSigner;
    if (signer === 'provider') {
        expectedSigner = expectedPayloadClaims.parties.providerDid;
        verifiedSignature = await didJwtVerify(signatures.providerSignature, veramo, expectedPayloadClaims);
    }
    else {
        expectedSigner = expectedPayloadClaims.parties.consumerDid;
        verifiedSignature = await didJwtVerify(signatures.consumerSignature, veramo, expectedPayloadClaims);
    }
    if (verifiedSignature.verification === 'success') {
        if (verifiedSignature.decodedJwt?.iss !== expectedSigner) {
            errors.push(new Error(`Signing DID does not match expected signer: ${verifiedSignature.decodedJwt?.iss ?? 'undefined'} != ${expectedSigner}`));
        }
    }
    else {
        errors.push(new Error(verifiedSignature.error));
    }
    return errors;
}

const jwkSecret = (secret = crypto.randomBytes(32)) => {
    const jwk = {
        kid: v4(),
        kty: 'oct',
        k: base64Url.encode(secret)
    };
    return jwk;
};

/**
 * Verifies and returns an ethereum address
 * @param a
 * @returns
 */
function parseAddress(a) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]{40})$/);
    if (hexMatch == null) {
        throw new RangeError('incorrect address format');
    }
    const hex = hexMatch[2];
    return ethers.utils.getAddress('0x' + hex);
}

/**
 * Verifies an hexadecimal string and returns it with (default) or without 0x prefix
 * @param a
 * @param prefix0x
 * @returns
 */
function parseHex(a, prefix0x = true) {
    const hexMatch = a.match(/^(0x)?(([\da-fA-F][\da-fA-F])+)$/);
    if (hexMatch == null) {
        throw new RangeError('wrong hex input');
    }
    const hex = hexMatch[2];
    return (prefix0x) ? '0x' + hex : hex;
}

const debug$9 = Debug('base-wallet' + basename('./dist/esm/index.node.js'));
async function multipleExecutions(options, executors, fnName, ...args) {
    if (executors.length < 1 || executors[0][fnName] === undefined) {
        throw new Error('invalid executors');
    }
    /** By default, if n executors, it is enough with 1 to succeed  */
    const successRate = options.successRate ?? 0;
    if (successRate < 0 || successRate > 1) {
        throw new Error('invalid successRate. It should be a value between 0 and 1 (both included)');
    }
    const minResults = successRate === 0 ? 1 : Math.ceil(successRate * executors.length);
    const _timeout = options.timeout ?? 10000;
    const observable = new Observable((subscriber) => {
        let subscriberSFinished = 0;
        executors.forEach(executor => {
            const fn = executor[fnName];
            let returnPromise = false;
            try {
                const resultOrPromise = fn.call(executor, ...args);
                if (isPromise(resultOrPromise)) {
                    returnPromise = true;
                    resultOrPromise.then((result) => {
                        subscriber.next(result);
                    }).catch((err) => {
                        debug$9(err);
                    }).finally(() => {
                        subscriberSFinished++;
                        if (subscriberSFinished === executors.length) {
                            subscriber.complete();
                        }
                    });
                }
                else {
                    subscriber.next(resultOrPromise);
                }
            }
            catch (err) {
                debug$9(err);
            }
            finally {
                if (!returnPromise) {
                    subscriberSFinished++;
                    if (subscriberSFinished === executors.length) {
                        subscriber.complete();
                    }
                }
            }
        });
    }).pipe(bufferCount(minResults), timeout(_timeout));
    const results = await new Promise((resolve, reject) => {
        const subscription = observable.subscribe({
            next: v => {
                resolve(v);
            }
        });
        setTimeout(() => {
            subscription.unsubscribe();
            reject(new Error('Timeout waiting for results reached'));
        }, _timeout);
    }).catch();
    if (results.length < minResults) {
        throw new Error(`less successful executions (${results.length}) than min requested (${minResults})`);
    }
    return results;
}
function isPromise(promise) {
    return promise !== undefined && typeof promise.then === 'function';
}

/* eslint-disable @typescript-eslint/no-non-null-assertion */
const contractValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const { dataSharingAgreement, keyPair } = resource.resource;
        // Verify schema
        const schemaValidationErrors = await validateDataSharingAgreementSchema(dataSharingAgreement);
        if (schemaValidationErrors.length > 0)
            return schemaValidationErrors;
        if (dataSharingAgreement.parties.consumerDid === dataSharingAgreement.parties.providerDid) {
            throw new Error('the same identity cannot be at the same time the consumer and the provider');
        }
        // Validate dataExchangeAgreemeent
        const deaErrors = await validateDataExchangeAgreement(dataSharingAgreement.dataExchangeAgreement);
        if (deaErrors.length > 0) {
            deaErrors.forEach((error) => {
                errors.push(error);
            });
        }
        // Check role
        let role;
        if (keyPair.publicJwk === dataSharingAgreement.dataExchangeAgreement.orig) {
            role = 'provider';
        }
        else if (keyPair.publicJwk === dataSharingAgreement.dataExchangeAgreement.dest) {
            role = 'consumer';
        }
        else {
            throw new Error(`${keyPair.publicJwk} is not either dataExchangeAgreement.orig or dataExchangeAgreement.dest`);
        }
        // Verify keyPair
        await verifyKeyPair(JSON.parse(keyPair.publicJwk), JSON.parse(keyPair.privateJwk));
        // If an identity is provided, check that is either the provider or the consumer
        if (resource.identity !== undefined) {
            const expectedDid = (role === 'consumer') ? dataSharingAgreement.parties.consumerDid : dataSharingAgreement.parties.providerDid;
            if (expectedDid !== resource.identity) {
                throw new Error(`resource.identity does not match dataSharingAgreement.parties.${role}Did`);
            }
        }
        // Verify the agreement's signatures
        const provSigVerificationErrors = await verifyDataSharingAgreementSignature(dataSharingAgreement, veramo, 'provider');
        provSigVerificationErrors.forEach(err => { errors.push(err); });
        const consSigVerificationErrors = await verifyDataSharingAgreementSignature(dataSharingAgreement, veramo, 'consumer');
        consSigVerificationErrors.forEach(err => { errors.push(err); });
        // Let us use a unique id that can be easily found. This way it can be easily linked to NR proofs
        resource.id = await digest(dataSharingAgreement.dataExchangeAgreement);
    }
    catch (error) {
        errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'));
    }
    return errors;
};

const dataExchangeValidator = async (resource, veramo) => {
    const errors = [];
    errors.push(new Error('NOT IMPLEMENTED. The data exchange will be automatically added when adding a valid nr proof'));
    return errors;
};

const debug$8 = Debug('base-wallet:NrpValidator');
const nrpValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const jws = resource.resource;
        const decodedProof = await jwsDecode(jws, (header, payload) => {
            const key = payload.iss;
            return JSON.parse(payload.exchange[key]);
        });
        const deErrors = await validateDataExchange(decodedProof.payload.exchange);
        if (deErrors.length > 0) {
            deErrors.forEach((error) => {
                errors.push(error);
            });
        }
        else {
            resource.parentResource = decodedProof.payload.exchange.id;
            debug$8(`Received NRP for data exchange ${decodedProof.payload.exchange.id}:\n` + JSON.stringify(decodedProof.payload.exchange, undefined, 2));
            debug$8(`  associated to data exchange agreement ${resource.parentResource}`);
            resource.name = decodedProof.payload.proofType;
        }
    }
    catch (error) {
        errors.push(new Error((typeof error === 'string') ? error : JSON.stringify(error, undefined, 2)));
    }
    return errors;
};

const objectValidator = async (resource, veramo) => {
    const errors = [];
    return errors;
};

const verifiableClaimValidator = async (resource, veramo) => {
    const errors = [];
    const subject = resource.resource.credentialSubject.id;
    resource.identity = subject;
    // Validate verifiable credential
    if (resource.resource === undefined) {
        errors.push(new WalletError(''));
    }
    else {
        try {
            await veramo.agent.handleMessage({
                raw: resource.resource.proof.jwt
            });
        }
        catch (ex) {
            errors.push(ex);
        }
    }
    return errors;
};

class ResourceValidator {
    constructor() {
        this.validators = {};
        this.initValidators();
    }
    initValidators() {
        this.setValidator('VerifiableCredential', verifiableClaimValidator);
        this.setValidator('Object', objectValidator);
        this.setValidator('KeyPair', keyPairValidator);
        this.setValidator('Contract', contractValidator);
        this.setValidator('DataExchange', dataExchangeValidator);
        this.setValidator('NonRepudiationProof', nrpValidator);
    }
    setValidator(name, validator) {
        this.validators[name] = validator;
    }
    async validate(resource, veramo) {
        const validation = {
            validated: false,
            errors: []
        };
        const validator = this.validators[resource.type];
        if (validator !== undefined) {
            validation.errors = await validator(resource, veramo);
            validation.validated = true;
        }
        return validation;
    }
}

const displayDid = (did) => {
    const splittedDid = did.split(':');
    if (splittedDid.length === 1) {
        throw new Error('Wrong did format');
    }
    else if (splittedDid[1] === 'ethr') {
        const address = splittedDid.pop();
        splittedDid.push(`${address.slice(0, 6)}...${address.slice(address.length - 6)}`);
        return splittedDid.join(':');
    }
    else {
        return did;
    }
};

function allEqual(arr) {
    return arr.every(v => _.isEqual(v, arr[0]));
}

var contractName = "EthereumDIDRegistry";
var abi = [
	{
		constant: true,
		inputs: [
			{
				name: "",
				type: "address"
			}
		],
		name: "owners",
		outputs: [
			{
				name: "",
				type: "address"
			}
		],
		payable: false,
		stateMutability: "view",
		type: "function"
	},
	{
		constant: true,
		inputs: [
			{
				name: "",
				type: "address"
			},
			{
				name: "",
				type: "bytes32"
			},
			{
				name: "",
				type: "address"
			}
		],
		name: "delegates",
		outputs: [
			{
				name: "",
				type: "uint256"
			}
		],
		payable: false,
		stateMutability: "view",
		type: "function"
	},
	{
		constant: true,
		inputs: [
			{
				name: "",
				type: "address"
			}
		],
		name: "nonce",
		outputs: [
			{
				name: "",
				type: "uint256"
			}
		],
		payable: false,
		stateMutability: "view",
		type: "function"
	},
	{
		constant: true,
		inputs: [
			{
				name: "",
				type: "address"
			}
		],
		name: "changed",
		outputs: [
			{
				name: "",
				type: "uint256"
			}
		],
		payable: false,
		stateMutability: "view",
		type: "function"
	},
	{
		anonymous: false,
		inputs: [
			{
				indexed: true,
				name: "identity",
				type: "address"
			},
			{
				indexed: false,
				name: "owner",
				type: "address"
			},
			{
				indexed: false,
				name: "previousChange",
				type: "uint256"
			}
		],
		name: "DIDOwnerChanged",
		type: "event"
	},
	{
		anonymous: false,
		inputs: [
			{
				indexed: true,
				name: "identity",
				type: "address"
			},
			{
				indexed: false,
				name: "delegateType",
				type: "bytes32"
			},
			{
				indexed: false,
				name: "delegate",
				type: "address"
			},
			{
				indexed: false,
				name: "validTo",
				type: "uint256"
			},
			{
				indexed: false,
				name: "previousChange",
				type: "uint256"
			}
		],
		name: "DIDDelegateChanged",
		type: "event"
	},
	{
		anonymous: false,
		inputs: [
			{
				indexed: true,
				name: "identity",
				type: "address"
			},
			{
				indexed: false,
				name: "name",
				type: "bytes32"
			},
			{
				indexed: false,
				name: "value",
				type: "bytes"
			},
			{
				indexed: false,
				name: "validTo",
				type: "uint256"
			},
			{
				indexed: false,
				name: "previousChange",
				type: "uint256"
			}
		],
		name: "DIDAttributeChanged",
		type: "event"
	},
	{
		constant: true,
		inputs: [
			{
				name: "identity",
				type: "address"
			}
		],
		name: "identityOwner",
		outputs: [
			{
				name: "",
				type: "address"
			}
		],
		payable: false,
		stateMutability: "view",
		type: "function"
	},
	{
		constant: true,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "delegateType",
				type: "bytes32"
			},
			{
				name: "delegate",
				type: "address"
			}
		],
		name: "validDelegate",
		outputs: [
			{
				name: "",
				type: "bool"
			}
		],
		payable: false,
		stateMutability: "view",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "newOwner",
				type: "address"
			}
		],
		name: "changeOwner",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "sigV",
				type: "uint8"
			},
			{
				name: "sigR",
				type: "bytes32"
			},
			{
				name: "sigS",
				type: "bytes32"
			},
			{
				name: "newOwner",
				type: "address"
			}
		],
		name: "changeOwnerSigned",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "delegateType",
				type: "bytes32"
			},
			{
				name: "delegate",
				type: "address"
			},
			{
				name: "validity",
				type: "uint256"
			}
		],
		name: "addDelegate",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "sigV",
				type: "uint8"
			},
			{
				name: "sigR",
				type: "bytes32"
			},
			{
				name: "sigS",
				type: "bytes32"
			},
			{
				name: "delegateType",
				type: "bytes32"
			},
			{
				name: "delegate",
				type: "address"
			},
			{
				name: "validity",
				type: "uint256"
			}
		],
		name: "addDelegateSigned",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "delegateType",
				type: "bytes32"
			},
			{
				name: "delegate",
				type: "address"
			}
		],
		name: "revokeDelegate",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "sigV",
				type: "uint8"
			},
			{
				name: "sigR",
				type: "bytes32"
			},
			{
				name: "sigS",
				type: "bytes32"
			},
			{
				name: "delegateType",
				type: "bytes32"
			},
			{
				name: "delegate",
				type: "address"
			}
		],
		name: "revokeDelegateSigned",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "name",
				type: "bytes32"
			},
			{
				name: "value",
				type: "bytes"
			},
			{
				name: "validity",
				type: "uint256"
			}
		],
		name: "setAttribute",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "sigV",
				type: "uint8"
			},
			{
				name: "sigR",
				type: "bytes32"
			},
			{
				name: "sigS",
				type: "bytes32"
			},
			{
				name: "name",
				type: "bytes32"
			},
			{
				name: "value",
				type: "bytes"
			},
			{
				name: "validity",
				type: "uint256"
			}
		],
		name: "setAttributeSigned",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "name",
				type: "bytes32"
			},
			{
				name: "value",
				type: "bytes"
			}
		],
		name: "revokeAttribute",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	},
	{
		constant: false,
		inputs: [
			{
				name: "identity",
				type: "address"
			},
			{
				name: "sigV",
				type: "uint8"
			},
			{
				name: "sigR",
				type: "bytes32"
			},
			{
				name: "sigS",
				type: "bytes32"
			},
			{
				name: "name",
				type: "bytes32"
			},
			{
				name: "value",
				type: "bytes"
			}
		],
		name: "revokeAttributeSigned",
		outputs: [
		],
		payable: false,
		stateMutability: "nonpayable",
		type: "function"
	}
];
var bytecode = "0x608060405234801561001057600080fd5b50612273806100206000396000f3006080604052600436106100e5576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168062c023da146100ea578063022914a7146101815780630d44625b14610204578063123b5e9814610289578063240cf1fa14610353578063622b2a3c146103df57806370ae92d2146104685780637ad4b0a4146104bf57806380b29f7c146105605780638733d4e8146105d157806393072684146106545780639c2c1b2b146106ee578063a7068d6614610792578063e476af5c1461080d578063f00d4b5d146108cd578063f96d0f9f14610930575b600080fd5b3480156100f657600080fd5b5061017f600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290505050610987565b005b34801561018d57600080fd5b506101c2600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610998565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561021057600080fd5b50610273600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109cb565b6040518082815260200191505060405180910390f35b34801561029557600080fd5b50610351600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290803590602001909291905050506109fd565b005b34801561035f57600080fd5b506103dd600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff16906020019092919080356000191690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610c72565b005b3480156103eb57600080fd5b5061044e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610ec1565b604051808215151515815260200191505060405180910390f35b34801561047457600080fd5b506104a9600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610f86565b6040518082815260200191505060405180910390f35b3480156104cb57600080fd5b5061055e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919291929080359060200190929190505050610f9e565b005b34801561056c57600080fd5b506105cf600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610fb1565b005b3480156105dd57600080fd5b50610612600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610fc2565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561066057600080fd5b506106ec600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611058565b005b3480156106fa57600080fd5b50610790600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506112b9565b005b34801561079e57600080fd5b5061080b600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611524565b005b34801561081957600080fd5b506108cb600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290505050611537565b005b3480156108d957600080fd5b5061092e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506117a2565b005b34801561093c57600080fd5b50610971600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506117b1565b6040518082815260200191505060405180910390f35b610993833384846117c9565b505050565b60006020528060005260406000206000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600160205282600052604060002060205281600052604060002060205280600052604060002060009250925050505481565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360008c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548b88888860405180897effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018681526020018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f7365744174747269627574650000000000000000000000000000000000000000815250600c01846000191660001916815260200183805190602001908083835b602083101515610c135780518252602082019150602081019050602083039250610bee565b6001836020036101000a0380198251168184511680821785525050505050509050018281526020019850505050505050505060405180910390209050610c6888610c608a8a8a8a8761196c565b868686611a90565b5050505050505050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f0100000000000000000000000000000000000000000000000000000000000000023060036000610cca8b610fc2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054898660405180877effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101867effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018481526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f6368616e67654f776e6572000000000000000000000000000000000000000000815250600b018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401965050505050505060405180910390209050610eb986610eb3888888888761196c565b84611c35565b505050505050565b600080600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008560405180826000191660001916815260200191505060405180910390206000191660001916815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490504281119150509392505050565b60036020528060005260406000206000915090505481565b610fab8433858585611a90565b50505050565b610fbd83338484611e02565b505050565b6000806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905060008173ffffffffffffffffffffffffffffffffffffffff1614151561104e57809150611052565b8291505b50919050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360006110b08c610fc2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548a878760405180887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101877effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018581526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f7265766f6b6544656c6567617465000000000000000000000000000000000000815250600e0183600019166000191681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401975050505050505050604051809103902090506112b0876112a9898989898761196c565b8585611e02565b50505050505050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360006113118d610fc2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548b88888860405180897effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018681526020018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f61646444656c6567617465000000000000000000000000000000000000000000815250600b0184600019166000191681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401828152602001985050505050505050506040518091039020905061151a886115128a8a8a8a8761196c565b868686612022565b5050505050505050565b6115318433858585612022565b50505050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548a878760405180887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101877effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018581526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f7265766f6b654174747269627574650000000000000000000000000000000000815250600f01836000191660001916815260200182805190602001908083835b60208310151561174c5780518252602082019150602081019050602083039250611727565b6001836020036101000a0380198251168184511680821785525050505050509050019750505050505050506040518091039020905061179987611792898989898761196c565b85856117c9565b50505050505050565b6117ad823383611c35565b5050565b60026020528060005260406000206000915090505481565b83836117d482610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614151561180d57600080fd5b8573ffffffffffffffffffffffffffffffffffffffff167f18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e485856000600260008c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205460405180856000191660001916815260200180602001848152602001838152602001828103825285818151815260200191508051906020019080838360005b838110156118e35780820151818401526020810190506118c8565b50505050905090810190601f1680156119105780820380516001836020036101000a031916815260200191505b509550505050505060405180910390a243600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505050505050565b600080600183878787604051600081526020016040526040518085600019166000191681526020018460ff1660ff1681526020018360001916600019168152602001826000191660001916815260200194505050505060206040516020810390808403906000865af11580156119e6573d6000803e3d6000fd5b5050506020604051035190506119fb87610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611a3457600080fd5b600360008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600081548092919060010191905055508091505095945050505050565b8484611a9b82610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611ad457600080fd5b8673ffffffffffffffffffffffffffffffffffffffff167f18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e48686864201600260008d73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205460405180856000191660001916815260200180602001848152602001838152602001828103825285818151815260200191508051906020019080838360005b83811015611bab578082015181840152602081019050611b90565b50505050905090810190601f168015611bd85780820380516001836020036101000a031916815260200191505b509550505050505060405180910390a243600260008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050505050505050565b8282611c4082610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611c7957600080fd5b826000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508473ffffffffffffffffffffffffffffffffffffffff167f38a5a6e68f30ed1ab45860a4afb34bcb2fc00f22ca462d249b8a8d40cda6f7a384600260008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019250505060405180910390a243600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050505050565b8383611e0d82610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611e4657600080fd5b42600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008660405180826000191660001916815260200191505060405180910390206000191660001916815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508573ffffffffffffffffffffffffffffffffffffffff167f5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f7858542600260008c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546040518085600019166000191681526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200183815260200182815260200194505050505060405180910390a243600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505050505050565b848461202d82610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614151561206657600080fd5b824201600160008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008760405180826000191660001916815260200191505060405180910390206000191660001916815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508673ffffffffffffffffffffffffffffffffffffffff167f5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f78686864201600260008d73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546040518085600019166000191681526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200183815260200182815260200194505050505060405180910390a243600260008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505050505050505600a165627a7a72305820ce15794c08edea0fae7ce9c85210f71a312b60c8d5cb2e5fd716c2adcd7403c70029";
var deployedBytecode = "0x6080604052600436106100e5576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168062c023da146100ea578063022914a7146101815780630d44625b14610204578063123b5e9814610289578063240cf1fa14610353578063622b2a3c146103df57806370ae92d2146104685780637ad4b0a4146104bf57806380b29f7c146105605780638733d4e8146105d157806393072684146106545780639c2c1b2b146106ee578063a7068d6614610792578063e476af5c1461080d578063f00d4b5d146108cd578063f96d0f9f14610930575b600080fd5b3480156100f657600080fd5b5061017f600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290505050610987565b005b34801561018d57600080fd5b506101c2600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610998565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561021057600080fd5b50610273600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109cb565b6040518082815260200191505060405180910390f35b34801561029557600080fd5b50610351600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290803590602001909291905050506109fd565b005b34801561035f57600080fd5b506103dd600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff16906020019092919080356000191690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610c72565b005b3480156103eb57600080fd5b5061044e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610ec1565b604051808215151515815260200191505060405180910390f35b34801561047457600080fd5b506104a9600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610f86565b6040518082815260200191505060405180910390f35b3480156104cb57600080fd5b5061055e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919291929080359060200190929190505050610f9e565b005b34801561056c57600080fd5b506105cf600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610fb1565b005b3480156105dd57600080fd5b50610612600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610fc2565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561066057600080fd5b506106ec600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611058565b005b3480156106fa57600080fd5b50610790600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506112b9565b005b34801561079e57600080fd5b5061080b600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611524565b005b34801561081957600080fd5b506108cb600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560ff169060200190929190803560001916906020019092919080356000191690602001909291908035600019169060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290505050611537565b005b3480156108d957600080fd5b5061092e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506117a2565b005b34801561093c57600080fd5b50610971600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506117b1565b6040518082815260200191505060405180910390f35b610993833384846117c9565b505050565b60006020528060005260406000206000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600160205282600052604060002060205281600052604060002060205280600052604060002060009250925050505481565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360008c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548b88888860405180897effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018681526020018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f7365744174747269627574650000000000000000000000000000000000000000815250600c01846000191660001916815260200183805190602001908083835b602083101515610c135780518252602082019150602081019050602083039250610bee565b6001836020036101000a0380198251168184511680821785525050505050509050018281526020019850505050505050505060405180910390209050610c6888610c608a8a8a8a8761196c565b868686611a90565b5050505050505050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f0100000000000000000000000000000000000000000000000000000000000000023060036000610cca8b610fc2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054898660405180877effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101867effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018481526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f6368616e67654f776e6572000000000000000000000000000000000000000000815250600b018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401965050505050505060405180910390209050610eb986610eb3888888888761196c565b84611c35565b505050505050565b600080600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008560405180826000191660001916815260200191505060405180910390206000191660001916815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490504281119150509392505050565b60036020528060005260406000206000915090505481565b610fab8433858585611a90565b50505050565b610fbd83338484611e02565b505050565b6000806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905060008173ffffffffffffffffffffffffffffffffffffffff1614151561104e57809150611052565b8291505b50919050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360006110b08c610fc2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548a878760405180887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101877effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018581526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f7265766f6b6544656c6567617465000000000000000000000000000000000000815250600e0183600019166000191681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401975050505050505050604051809103902090506112b0876112a9898989898761196c565b8585611e02565b50505050505050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360006113118d610fc2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548b88888860405180897effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018681526020018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f61646444656c6567617465000000000000000000000000000000000000000000815250600b0184600019166000191681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401828152602001985050505050505050506040518091039020905061151a886115128a8a8a8a8761196c565b868686612022565b5050505050505050565b6115318433858585612022565b50505050565b600060197f01000000000000000000000000000000000000000000000000000000000000000260007f01000000000000000000000000000000000000000000000000000000000000000230600360008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548a878760405180887effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152600101877effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526001018673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c010000000000000000000000000281526014018581526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401807f7265766f6b654174747269627574650000000000000000000000000000000000815250600f01836000191660001916815260200182805190602001908083835b60208310151561174c5780518252602082019150602081019050602083039250611727565b6001836020036101000a0380198251168184511680821785525050505050509050019750505050505050506040518091039020905061179987611792898989898761196c565b85856117c9565b50505050505050565b6117ad823383611c35565b5050565b60026020528060005260406000206000915090505481565b83836117d482610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614151561180d57600080fd5b8573ffffffffffffffffffffffffffffffffffffffff167f18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e485856000600260008c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205460405180856000191660001916815260200180602001848152602001838152602001828103825285818151815260200191508051906020019080838360005b838110156118e35780820151818401526020810190506118c8565b50505050905090810190601f1680156119105780820380516001836020036101000a031916815260200191505b509550505050505060405180910390a243600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505050505050565b600080600183878787604051600081526020016040526040518085600019166000191681526020018460ff1660ff1681526020018360001916600019168152602001826000191660001916815260200194505050505060206040516020810390808403906000865af11580156119e6573d6000803e3d6000fd5b5050506020604051035190506119fb87610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611a3457600080fd5b600360008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600081548092919060010191905055508091505095945050505050565b8484611a9b82610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611ad457600080fd5b8673ffffffffffffffffffffffffffffffffffffffff167f18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e48686864201600260008d73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205460405180856000191660001916815260200180602001848152602001838152602001828103825285818151815260200191508051906020019080838360005b83811015611bab578082015181840152602081019050611b90565b50505050905090810190601f168015611bd85780820380516001836020036101000a031916815260200191505b509550505050505060405180910390a243600260008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050505050505050565b8282611c4082610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611c7957600080fd5b826000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508473ffffffffffffffffffffffffffffffffffffffff167f38a5a6e68f30ed1ab45860a4afb34bcb2fc00f22ca462d249b8a8d40cda6f7a384600260008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019250505060405180910390a243600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050505050565b8383611e0d82610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611e4657600080fd5b42600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008660405180826000191660001916815260200191505060405180910390206000191660001916815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508573ffffffffffffffffffffffffffffffffffffffff167f5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f7858542600260008c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546040518085600019166000191681526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200183815260200182815260200194505050505060405180910390a243600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505050505050565b848461202d82610fc2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614151561206657600080fd5b824201600160008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008760405180826000191660001916815260200191505060405180910390206000191660001916815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508673ffffffffffffffffffffffffffffffffffffffff167f5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f78686864201600260008d73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546040518085600019166000191681526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200183815260200182815260200194505050505060405180910390a243600260008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505050505050505600a165627a7a72305820ce15794c08edea0fae7ce9c85210f71a312b60c8d5cb2e5fd716c2adcd7403c70029";
var sourceMap = "25:5537:0:-;;;;8:9:-1;5:2;;;30:1;27;20:12;5:2;25:5537:0;;;;;;;";
var deployedSourceMap = "25:5537:0:-;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;5079:138;;8:9:-1;5:2;;;30:1;27;20:12;5:2;5079:138:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;59:41;;8:9:-1;5:2;;;30:1;27;20:12;5:2;59:41:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;104:81;;8:9:-1;5:2;;;30:1;27;20:12;5:2;104:81:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;4467:364;;8:9:-1;5:2;;;30:1;27;20:12;5:2;4467:364:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;1856:326;;8:9:-1;5:2;;;30:1;27;20:12;5:2;1856:326:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;1260:217;;8:9:-1;5:2;;;30:1;27;20:12;5:2;1260:217:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;232:37;;8:9:-1;5:2;;;30:1;27;20:12;5:2;232:37:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;4306:157;;8:9:-1;5:2;;;30:1;27;20:12;5:2;4306:157:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;3484:160;;8:9:-1;5:2;;;30:1;27;20:12;5:2;3484:160:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;790:189;;8:9:-1;5:2;;;30:1;27;20:12;5:2;790:189:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;3648:385;;8:9:-1;5:2;;;30:1;27;20:12;5:2;3648:385:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;2736:411;;8:9:-1;5:2;;;30:1;27;20:12;5:2;2736:411:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;2553:179;;8:9:-1;5:2;;;30:1;27;20:12;5:2;2553:179:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;5220:339;;8:9:-1;5:2;;;30:1;27;20:12;5:2;5220:339:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;1734:118;;8:9:-1;5:2;;;30:1;27;20:12;5:2;1734:118:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;189:39;;8:9:-1;5:2;;;30:1;27;20:12;5:2;189:39:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;5079:138;5162:50;5178:8;5188:10;5200:4;5206:5;5162:15;:50::i;:::-;5079:138;;;:::o;59:41::-;;;;;;;;;;;;;;;;;;;;;;:::o;104:81::-;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::o;4467:364::-;4608:12;4638:4;4633:10;;4650:1;4645:7;;4654:4;4660:5;:15;4666:8;4660:15;;;;;;;;;;;;;;;;4677:8;4703:4;4709:5;4716:8;4623:102;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;36:153:-1;66:2;61:3;58:11;51:19;36:153;;;182:3;176:10;171:3;164:23;98:2;93:3;89:12;82:19;;123:2;118:3;114:12;107:19;;148:2;143:3;139:12;132:19;;36:153;;;274:1;267:3;263:2;259:12;254:3;250:22;246:30;315:4;311:9;305:3;299:10;295:26;356:4;350:3;344:10;340:21;389:7;380;377:20;372:3;365:33;3:399;;;4623:102:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;4608:117;;4731:95;4744:8;4754:48;4769:8;4779:4;4785;4791;4797;4754:14;:48::i;:::-;4804:4;4810:5;4817:8;4731:12;:95::i;:::-;4467:364;;;;;;;;:::o;1856:326::-;1972:12;2002:4;1997:10;;2014:1;2009:7;;2018:4;2024:5;:30;2030:23;2044:8;2030:13;:23::i;:::-;2024:30;;;;;;;;;;;;;;;;2056:8;2081;1987:103;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;1972:118;;2096:81;2108:8;2118:48;2133:8;2143:4;2149;2155;2161;2118:14;:48::i;:::-;2168:8;2096:11;:81::i;:::-;1856:326;;;;;;:::o;1260:217::-;1361:4;1373:13;1389:9;:19;1399:8;1389:19;;;;;;;;;;;;;;;:44;1419:12;1409:23;;;;;;;;;;;;;;;;;;;;;;;;1389:44;;;;;;;;;;;;;;;;;:54;1434:8;1389:54;;;;;;;;;;;;;;;;1373:70;;1468:3;1457:8;:14;1449:23;;1260:217;;;;;;:::o;232:37::-;;;;;;;;;;;;;;;;;:::o;4306:157::-;4401:57;4414:8;4424:10;4436:4;4442:5;4449:8;4401:12;:57::i;:::-;4306:157;;;;:::o;3484:160::-;3579:60;3594:8;3604:10;3616:12;3630:8;3579:14;:60::i;:::-;3484:160;;;:::o;790:189::-;851:7;867:13;883:6;:16;890:8;883:16;;;;;;;;;;;;;;;;;;;;;;;;;867:32;;919:3;910:5;:12;;;;906:47;;;940:5;933:12;;;;906:47;966:8;959:15;;790:189;;;;;:::o;3648:385::-;3789:12;3819:4;3814:10;;3831:1;3826:7;;3835:4;3841:5;:30;3847:23;3861:8;3847:13;:23::i;:::-;3841:30;;;;;;;;;;;;;;;;3873:8;3901:12;3915:8;3804:120;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;3789:135;;3930:98;3945:8;3955:48;3970:8;3980:4;3986;3992;3998;3955:14;:48::i;:::-;4005:12;4019:8;3930:14;:98::i;:::-;3648:385;;;;;;;:::o;2736:411::-;2889:12;2919:4;2914:10;;2931:1;2926:7;;2935:4;2941:5;:30;2947:23;2961:8;2947:13;:23::i;:::-;2941:30;;;;;;;;;;;;;;;;2973:8;2998:12;3012:8;3022;2904:127;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;2889:142;;3037:105;3049:8;3059:48;3074:8;3084:4;3090;3096;3102;3059:14;:48::i;:::-;3109:12;3123:8;3133;3037:11;:105::i;:::-;2736:411;;;;;;;;:::o;2553:179::-;2660:67;2672:8;2682:10;2694:12;2708:8;2718;2660:11;:67::i;:::-;2553:179;;;;:::o;5220:339::-;5349:12;5379:4;5374:10;;5391:1;5386:7;;5395:4;5401:5;:15;5407:8;5401:15;;;;;;;;;;;;;;;;5418:8;5447:4;5453:5;5364:95;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;36:153:-1;66:2;61:3;58:11;51:19;36:153;;;182:3;176:10;171:3;164:23;98:2;93:3;89:12;82:19;;123:2;118:3;114:12;107:19;;148:2;143:3;139:12;132:19;;36:153;;;274:1;267:3;263:2;259:12;254:3;250:22;246:30;315:4;311:9;305:3;299:10;295:26;356:4;350:3;344:10;340:21;389:7;380;377:20;372:3;365:33;3:399;;;5364:95:0;;;;;;;;;;;;;;;;;;;;;;5349:110;;5466:88;5482:8;5492:48;5507:8;5517:4;5523;5529;5535;5492:14;:48::i;:::-;5542:4;5548:5;5466:15;:88::i;:::-;5220:339;;;;;;;:::o;1734:118::-;1804:43;1816:8;1826:10;1838:8;1804:11;:43::i;:::-;1734:118;;:::o;189:39::-;;;;;;;;;;;;;;;;;:::o;4835:240::-;4940:8;4950:5;350:23;364:8;350:13;:23::i;:::-;341:32;;:5;:32;;;332:42;;;;;;;;4988:8;4968:64;;;4998:4;5004:5;5011:1;5014:7;:17;5022:8;5014:17;;;;;;;;;;;;;;;;4968:64;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;23:1:-1;8:100;33:3;30:1;27:10;8:100;;;99:1;94:3;90:11;84:18;80:1;75:3;71:11;64:39;52:2;49:1;45:10;40:15;;8:100;;;12:14;4968:64:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;5058:12;5038:7;:17;5046:8;5038:17;;;;;;;;;;;;;;;:32;;;;4835:240;;;;;;:::o;983:273::-;1096:7;1111:14;1128:33;1138:4;1144;1150;1156;1128:33;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;8:9:-1;5:2;;;45:16;42:1;39;24:38;77:16;74:1;67:27;5:2;1128:33:0;;;;;;;;1111:50;;1185:23;1199:8;1185:13;:23::i;:::-;1175:33;;:6;:33;;;1167:42;;;;;;;;1215:5;:15;1221:8;1215:15;;;;;;;;;;;;;;;;:17;;;;;;;;;;;;;1245:6;1238:13;;983:273;;;;;;;;:::o;4037:265::-;4154:8;4164:5;350:23;364:8;350:13;:23::i;:::-;341:32;;:5;:32;;;332:42;;;;;;;;4202:8;4182:77;;;4212:4;4218:5;4231:8;4225:3;:14;4241:7;:17;4249:8;4241:17;;;;;;;;;;;;;;;;4182:77;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;23:1:-1;8:100;33:3;30:1;27:10;8:100;;;99:1;94:3;90:11;84:18;80:1;75:3;71:11;64:39;52:2;49:1;45:10;40:15;;8:100;;;12:14;4182:77:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;4285:12;4265:7;:17;4273:8;4265:17;;;;;;;;;;;;;;;:32;;;;4037:265;;;;;;;:::o;1481:249::-;1572:8;1582:5;350:23;364:8;350:13;:23::i;:::-;341:32;;:5;:32;;;332:42;;;;;;;;1614:8;1595:6;:16;1602:8;1595:16;;;;;;;;;;;;;;;;:27;;;;;;;;;;;;;;;;;;1649:8;1633:54;;;1659:8;1669:7;:17;1677:8;1669:17;;;;;;;;;;;;;;;;1633:54;;;;;;;;;;;;;;;;;;;;;;;;;;;;1713:12;1693:7;:17;1701:8;1693:17;;;;;;;;;;;;;;;:32;;;;1481:249;;;;;:::o;3151:329::-;3267:8;3277:5;350:23;364:8;350:13;:23::i;:::-;341:32;;:5;:32;;;332:42;;;;;;;;3347:3;3290:9;:19;3300:8;3290:19;;;;;;;;;;;;;;;:44;3320:12;3310:23;;;;;;;;;;;;;;;;;;;;;;;;3290:44;;;;;;;;;;;;;;;;;:54;3335:8;3290:54;;;;;;;;;;;;;;;:60;;;;3380:8;3361:76;;;3390:12;3404:8;3414:3;3419:7;:17;3427:8;3419:17;;;;;;;;;;;;;;;;3361:76;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;3463:12;3443:7;:17;3451:8;3443:17;;;;;;;;;;;;;;;:32;;;;3151:329;;;;;;:::o;2186:363::-;2314:8;2324:5;350:23;364:8;350:13;:23::i;:::-;341:32;;:5;:32;;;332:42;;;;;;;;2400:8;2394:3;:14;2337:9;:19;2347:8;2337:19;;;;;;;;;;;;;;;:44;2367:12;2357:23;;;;;;;;;;;;;;;;;;;;;;;;2337:44;;;;;;;;;;;;;;;;;:54;2382:8;2337:54;;;;;;;;;;;;;;;:71;;;;2438:8;2419:87;;;2448:12;2462:8;2478;2472:3;:14;2488:7;:17;2496:8;2488:17;;;;;;;;;;;;;;;;2419:87;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;2532:12;2512:7;:17;2520:8;2512:17;;;;;;;;;;;;;;;:32;;;;2186:363;;;;;;;:::o";
var source = "pragma solidity ^0.4.4;\n\ncontract EthereumDIDRegistry {\n\n  mapping(address => address) public owners;\n  mapping(address => mapping(bytes32 => mapping(address => uint))) public delegates;\n  mapping(address => uint) public changed;\n  mapping(address => uint) public nonce;\n\n  modifier onlyOwner(address identity, address actor) {\n    require (actor == identityOwner(identity));\n    _;\n  }\n\n  event DIDOwnerChanged(\n    address indexed identity,\n    address owner,\n    uint previousChange\n  );\n\n  event DIDDelegateChanged(\n    address indexed identity,\n    bytes32 delegateType,\n    address delegate,\n    uint validTo,\n    uint previousChange\n  );\n\n  event DIDAttributeChanged(\n    address indexed identity,\n    bytes32 name,\n    bytes value,\n    uint validTo,\n    uint previousChange\n  );\n\n  function identityOwner(address identity) public view returns(address) {\n     address owner = owners[identity];\n     if (owner != 0x0) {\n       return owner;\n     }\n     return identity;\n  }\n\n  function checkSignature(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {\n    address signer = ecrecover(hash, sigV, sigR, sigS);\n    require(signer == identityOwner(identity));\n    nonce[identity]++;\n    return signer;\n  }\n\n  function validDelegate(address identity, bytes32 delegateType, address delegate) public view returns(bool) {\n    uint validity = delegates[identity][keccak256(delegateType)][delegate];\n    return (validity > now);\n  }\n\n  function changeOwner(address identity, address actor, address newOwner) internal onlyOwner(identity, actor) {\n    owners[identity] = newOwner;\n    emit DIDOwnerChanged(identity, newOwner, changed[identity]);\n    changed[identity] = block.number;\n  }\n\n  function changeOwner(address identity, address newOwner) public {\n    changeOwner(identity, msg.sender, newOwner);\n  }\n\n  function changeOwnerSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address newOwner) public {\n    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, \"changeOwner\", newOwner);\n    changeOwner(identity, checkSignature(identity, sigV, sigR, sigS, hash), newOwner);\n  }\n\n  function addDelegate(address identity, address actor, bytes32 delegateType, address delegate, uint validity) internal onlyOwner(identity, actor) {\n    delegates[identity][keccak256(delegateType)][delegate] = now + validity;\n    emit DIDDelegateChanged(identity, delegateType, delegate, now + validity, changed[identity]);\n    changed[identity] = block.number;\n  }\n\n  function addDelegate(address identity, bytes32 delegateType, address delegate, uint validity) public {\n    addDelegate(identity, msg.sender, delegateType, delegate, validity);\n  }\n\n  function addDelegateSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate, uint validity) public {\n    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, \"addDelegate\", delegateType, delegate, validity);\n    addDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hash), delegateType, delegate, validity);\n  }\n\n  function revokeDelegate(address identity, address actor, bytes32 delegateType, address delegate) internal onlyOwner(identity, actor) {\n    delegates[identity][keccak256(delegateType)][delegate] = now;\n    emit DIDDelegateChanged(identity, delegateType, delegate, now, changed[identity]);\n    changed[identity] = block.number;\n  }\n\n  function revokeDelegate(address identity, bytes32 delegateType, address delegate) public {\n    revokeDelegate(identity, msg.sender, delegateType, delegate);\n  }\n\n  function revokeDelegateSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate) public {\n    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, \"revokeDelegate\", delegateType, delegate);\n    revokeDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hash), delegateType, delegate);\n  }\n\n  function setAttribute(address identity, address actor, bytes32 name, bytes value, uint validity ) internal onlyOwner(identity, actor) {\n    emit DIDAttributeChanged(identity, name, value, now + validity, changed[identity]);\n    changed[identity] = block.number;\n  }\n\n  function setAttribute(address identity, bytes32 name, bytes value, uint validity) public {\n    setAttribute(identity, msg.sender, name, value, validity);\n  }\n\n  function setAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes value, uint validity) public {\n    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identity], identity, \"setAttribute\", name, value, validity);\n    setAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value, validity);\n  }\n\n  function revokeAttribute(address identity, address actor, bytes32 name, bytes value ) internal onlyOwner(identity, actor) {\n    emit DIDAttributeChanged(identity, name, value, 0, changed[identity]);\n    changed[identity] = block.number;\n  }\n\n  function revokeAttribute(address identity, bytes32 name, bytes value) public {\n    revokeAttribute(identity, msg.sender, name, value);\n  }\n\n function revokeAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes value) public {\n    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identity], identity, \"revokeAttribute\", name, value); \n    revokeAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value);\n  }\n\n}\n";
var sourcePath = "/Users/pelleb/code/consensys/ethereum-did-registry/contracts/EthereumDIDRegistry.sol";
var ast = {
	absolutePath: "/Users/pelleb/code/consensys/ethereum-did-registry/contracts/EthereumDIDRegistry.sol",
	exportedSymbols: {
		EthereumDIDRegistry: [
			706
		]
	},
	id: 707,
	nodeType: "SourceUnit",
	nodes: [
		{
			id: 1,
			literals: [
				"solidity",
				"^",
				"0.4",
				".4"
			],
			nodeType: "PragmaDirective",
			src: "0:23:0"
		},
		{
			baseContracts: [
			],
			contractDependencies: [
			],
			contractKind: "contract",
			documentation: null,
			fullyImplemented: true,
			id: 706,
			linearizedBaseContracts: [
				706
			],
			name: "EthereumDIDRegistry",
			nodeType: "ContractDefinition",
			nodes: [
				{
					constant: false,
					id: 5,
					name: "owners",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "59:41:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_address_$",
						typeString: "mapping(address => address)"
					},
					typeName: {
						id: 4,
						keyType: {
							id: 2,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "67:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "59:27:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_address_$",
							typeString: "mapping(address => address)"
						},
						valueType: {
							id: 3,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "78:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					constant: false,
					id: 13,
					name: "delegates",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "104:81:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
						typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
					},
					typeName: {
						id: 12,
						keyType: {
							id: 6,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "112:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "104:64:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
							typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
						},
						valueType: {
							id: 11,
							keyType: {
								id: 7,
								name: "bytes32",
								nodeType: "ElementaryTypeName",
								src: "131:7:0",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								}
							},
							nodeType: "Mapping",
							src: "123:44:0",
							typeDescriptions: {
								typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
								typeString: "mapping(bytes32 => mapping(address => uint256))"
							},
							valueType: {
								id: 10,
								keyType: {
									id: 8,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "150:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								nodeType: "Mapping",
								src: "142:24:0",
								typeDescriptions: {
									typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
									typeString: "mapping(address => uint256)"
								},
								valueType: {
									id: 9,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "161:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								}
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					constant: false,
					id: 17,
					name: "changed",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "189:39:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
						typeString: "mapping(address => uint256)"
					},
					typeName: {
						id: 16,
						keyType: {
							id: 14,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "197:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "189:24:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
							typeString: "mapping(address => uint256)"
						},
						valueType: {
							id: 15,
							name: "uint",
							nodeType: "ElementaryTypeName",
							src: "208:4:0",
							typeDescriptions: {
								typeIdentifier: "t_uint256",
								typeString: "uint256"
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					constant: false,
					id: 21,
					name: "nonce",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "232:37:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
						typeString: "mapping(address => uint256)"
					},
					typeName: {
						id: 20,
						keyType: {
							id: 18,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "240:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "232:24:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
							typeString: "mapping(address => uint256)"
						},
						valueType: {
							id: 19,
							name: "uint",
							nodeType: "ElementaryTypeName",
							src: "251:4:0",
							typeDescriptions: {
								typeIdentifier: "t_uint256",
								typeString: "uint256"
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					body: {
						id: 36,
						nodeType: "Block",
						src: "326:60:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_address",
												typeString: "address"
											},
											id: 32,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 28,
												name: "actor",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 25,
												src: "341:5:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											nodeType: "BinaryOperation",
											operator: "==",
											rightExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 30,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 23,
														src: "364:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 29,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "350:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 31,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "350:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											src: "341:32:0",
											typeDescriptions: {
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										],
										id: 27,
										name: "require",
										nodeType: "Identifier",
										overloadedDeclarations: [
											724,
											725
										],
										referencedDeclaration: 724,
										src: "332:7:0",
										typeDescriptions: {
											typeIdentifier: "t_function_require_pure$_t_bool_$returns$__$",
											typeString: "function (bool) pure"
										}
									},
									id: 33,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "332:42:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 34,
								nodeType: "ExpressionStatement",
								src: "332:42:0"
							},
							{
								id: 35,
								nodeType: "PlaceholderStatement",
								src: "380:1:0"
							}
						]
					},
					documentation: null,
					id: 37,
					name: "onlyOwner",
					nodeType: "ModifierDefinition",
					parameters: {
						id: 26,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 23,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 37,
								src: "293:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 22,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "293:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 25,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 37,
								src: "311:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 24,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "311:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "292:33:0"
					},
					src: "274:112:0",
					visibility: "internal"
				},
				{
					anonymous: false,
					documentation: null,
					id: 45,
					name: "DIDOwnerChanged",
					nodeType: "EventDefinition",
					parameters: {
						id: 44,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 39,
								indexed: true,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 45,
								src: "417:24:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 38,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "417:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 41,
								indexed: false,
								name: "owner",
								nodeType: "VariableDeclaration",
								scope: 45,
								src: "447:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 40,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "447:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 43,
								indexed: false,
								name: "previousChange",
								nodeType: "VariableDeclaration",
								scope: 45,
								src: "466:19:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 42,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "466:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "411:78:0"
					},
					src: "390:100:0"
				},
				{
					anonymous: false,
					documentation: null,
					id: 57,
					name: "DIDDelegateChanged",
					nodeType: "EventDefinition",
					parameters: {
						id: 56,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 47,
								indexed: true,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "524:24:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 46,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "524:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 49,
								indexed: false,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "554:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 48,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "554:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 51,
								indexed: false,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "580:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 50,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "580:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 53,
								indexed: false,
								name: "validTo",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "602:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 52,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "602:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 55,
								indexed: false,
								name: "previousChange",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "620:19:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 54,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "620:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "518:125:0"
					},
					src: "494:150:0"
				},
				{
					anonymous: false,
					documentation: null,
					id: 69,
					name: "DIDAttributeChanged",
					nodeType: "EventDefinition",
					parameters: {
						id: 68,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 59,
								indexed: true,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "679:24:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 58,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "679:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 61,
								indexed: false,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "709:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 60,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "709:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 63,
								indexed: false,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "727:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 62,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "727:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 65,
								indexed: false,
								name: "validTo",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "744:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 64,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "744:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 67,
								indexed: false,
								name: "previousChange",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "762:19:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 66,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "762:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "673:112:0"
					},
					src: "648:138:0"
				},
				{
					body: {
						id: 91,
						nodeType: "Block",
						src: "860:119:0",
						statements: [
							{
								assignments: [
									77
								],
								declarations: [
									{
										constant: false,
										id: 77,
										name: "owner",
										nodeType: "VariableDeclaration",
										scope: 92,
										src: "867:13:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										},
										typeName: {
											id: 76,
											name: "address",
											nodeType: "ElementaryTypeName",
											src: "867:7:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 81,
								initialValue: {
									argumentTypes: null,
									baseExpression: {
										argumentTypes: null,
										id: 78,
										name: "owners",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 5,
										src: "883:6:0",
										typeDescriptions: {
											typeIdentifier: "t_mapping$_t_address_$_t_address_$",
											typeString: "mapping(address => address)"
										}
									},
									id: 80,
									indexExpression: {
										argumentTypes: null,
										id: 79,
										name: "identity",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 71,
										src: "890:8:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									isConstant: false,
									isLValue: true,
									isPure: false,
									lValueRequested: false,
									nodeType: "IndexAccess",
									src: "883:16:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "867:32:0"
							},
							{
								condition: {
									argumentTypes: null,
									commonType: {
										typeIdentifier: "t_address",
										typeString: "address"
									},
									id: 84,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftExpression: {
										argumentTypes: null,
										id: 82,
										name: "owner",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 77,
										src: "910:5:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									nodeType: "BinaryOperation",
									operator: "!=",
									rightExpression: {
										argumentTypes: null,
										hexValue: "307830",
										id: 83,
										isConstant: false,
										isLValue: false,
										isPure: true,
										kind: "number",
										lValueRequested: false,
										nodeType: "Literal",
										src: "919:3:0",
										subdenomination: null,
										typeDescriptions: {
											typeIdentifier: "t_rational_0_by_1",
											typeString: "int_const 0"
										},
										value: "0x0"
									},
									src: "910:12:0",
									typeDescriptions: {
										typeIdentifier: "t_bool",
										typeString: "bool"
									}
								},
								falseBody: null,
								id: 88,
								nodeType: "IfStatement",
								src: "906:47:0",
								trueBody: {
									id: 87,
									nodeType: "Block",
									src: "924:29:0",
									statements: [
										{
											expression: {
												argumentTypes: null,
												id: 85,
												name: "owner",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 77,
												src: "940:5:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											functionReturnParameters: 75,
											id: 86,
											nodeType: "Return",
											src: "933:12:0"
										}
									]
								}
							},
							{
								expression: {
									argumentTypes: null,
									id: 89,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 71,
									src: "966:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								functionReturnParameters: 75,
								id: 90,
								nodeType: "Return",
								src: "959:15:0"
							}
						]
					},
					documentation: null,
					id: 92,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: true,
					modifiers: [
					],
					name: "identityOwner",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 72,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 71,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 92,
								src: "813:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 70,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "813:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "812:18:0"
					},
					payable: false,
					returnParameters: {
						id: 75,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 74,
								name: "",
								nodeType: "VariableDeclaration",
								scope: 92,
								src: "851:7:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 73,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "851:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "850:9:0"
					},
					scope: 706,
					src: "790:189:0",
					stateMutability: "view",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 131,
						nodeType: "Block",
						src: "1105:151:0",
						statements: [
							{
								assignments: [
									108
								],
								declarations: [
									{
										constant: false,
										id: 108,
										name: "signer",
										nodeType: "VariableDeclaration",
										scope: 132,
										src: "1111:14:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										},
										typeName: {
											id: 107,
											name: "address",
											nodeType: "ElementaryTypeName",
											src: "1111:7:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 115,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 110,
											name: "hash",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 102,
											src: "1138:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 111,
											name: "sigV",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 96,
											src: "1144:4:0",
											typeDescriptions: {
												typeIdentifier: "t_uint8",
												typeString: "uint8"
											}
										},
										{
											argumentTypes: null,
											id: 112,
											name: "sigR",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 98,
											src: "1150:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 113,
											name: "sigS",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 100,
											src: "1156:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_uint8",
												typeString: "uint8"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										],
										id: 109,
										name: "ecrecover",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 713,
										src: "1128:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_ecrecover_pure$_t_bytes32_$_t_uint8_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
											typeString: "function (bytes32,uint8,bytes32,bytes32) pure returns (address)"
										}
									},
									id: 114,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1128:33:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "1111:50:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_address",
												typeString: "address"
											},
											id: 121,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 117,
												name: "signer",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 108,
												src: "1175:6:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											nodeType: "BinaryOperation",
											operator: "==",
											rightExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 119,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 94,
														src: "1199:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 118,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "1185:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 120,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "1185:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											src: "1175:33:0",
											typeDescriptions: {
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										],
										id: 116,
										name: "require",
										nodeType: "Identifier",
										overloadedDeclarations: [
											724,
											725
										],
										referencedDeclaration: 724,
										src: "1167:7:0",
										typeDescriptions: {
											typeIdentifier: "t_function_require_pure$_t_bool_$returns$__$",
											typeString: "function (bool) pure"
										}
									},
									id: 122,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1167:42:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 123,
								nodeType: "ExpressionStatement",
								src: "1167:42:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 127,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									nodeType: "UnaryOperation",
									operator: "++",
									prefix: false,
									src: "1215:17:0",
									subExpression: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 124,
											name: "nonce",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 21,
											src: "1215:5:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 126,
										indexExpression: {
											argumentTypes: null,
											id: 125,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 94,
											src: "1221:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "1215:15:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 128,
								nodeType: "ExpressionStatement",
								src: "1215:17:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 129,
									name: "signer",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 108,
									src: "1245:6:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								functionReturnParameters: 106,
								id: 130,
								nodeType: "Return",
								src: "1238:13:0"
							}
						]
					},
					documentation: null,
					id: 132,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "checkSignature",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 103,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 94,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1007:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 93,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1007:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 96,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1025:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 95,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "1025:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 98,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1037:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 97,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1037:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 100,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1051:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 99,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1051:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 102,
								name: "hash",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1065:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 101,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1065:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1006:72:0"
					},
					payable: false,
					returnParameters: {
						id: 106,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 105,
								name: "",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1096:7:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 104,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1096:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1095:9:0"
					},
					scope: 706,
					src: "983:273:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 160,
						nodeType: "Block",
						src: "1367:110:0",
						statements: [
							{
								assignments: [
									144
								],
								declarations: [
									{
										constant: false,
										id: 144,
										name: "validity",
										nodeType: "VariableDeclaration",
										scope: 161,
										src: "1373:13:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										},
										typeName: {
											id: 143,
											name: "uint",
											nodeType: "ElementaryTypeName",
											src: "1373:4:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 154,
								initialValue: {
									argumentTypes: null,
									baseExpression: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 145,
												name: "delegates",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 13,
												src: "1389:9:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
													typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
												}
											},
											id: 147,
											indexExpression: {
												argumentTypes: null,
												id: 146,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 134,
												src: "1399:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "1389:19:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
												typeString: "mapping(bytes32 => mapping(address => uint256))"
											}
										},
										id: 151,
										indexExpression: {
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 149,
													name: "delegateType",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 136,
													src: "1419:12:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 148,
												name: "keccak256",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 715,
												src: "1409:9:0",
												typeDescriptions: {
													typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
													typeString: "function () pure returns (bytes32)"
												}
											},
											id: 150,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "1409:23:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: false,
										nodeType: "IndexAccess",
										src: "1389:44:0",
										typeDescriptions: {
											typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
											typeString: "mapping(address => uint256)"
										}
									},
									id: 153,
									indexExpression: {
										argumentTypes: null,
										id: 152,
										name: "delegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 138,
										src: "1434:8:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									isConstant: false,
									isLValue: true,
									isPure: false,
									lValueRequested: false,
									nodeType: "IndexAccess",
									src: "1389:54:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "1373:70:0"
							},
							{
								expression: {
									argumentTypes: null,
									components: [
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											id: 157,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 155,
												name: "validity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 144,
												src: "1457:8:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											nodeType: "BinaryOperation",
											operator: ">",
											rightExpression: {
												argumentTypes: null,
												id: 156,
												name: "now",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 723,
												src: "1468:3:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											src: "1457:14:0",
											typeDescriptions: {
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										}
									],
									id: 158,
									isConstant: false,
									isInlineArray: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									nodeType: "TupleExpression",
									src: "1456:16:0",
									typeDescriptions: {
										typeIdentifier: "t_bool",
										typeString: "bool"
									}
								},
								functionReturnParameters: 142,
								id: 159,
								nodeType: "Return",
								src: "1449:23:0"
							}
						]
					},
					documentation: null,
					id: 161,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: true,
					modifiers: [
					],
					name: "validDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 139,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 134,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1283:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 133,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1283:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 136,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1301:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 135,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1301:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 138,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1323:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 137,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1323:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1282:58:0"
					},
					payable: false,
					returnParameters: {
						id: 142,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 141,
								name: "",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1361:4:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bool",
									typeString: "bool"
								},
								typeName: {
									id: 140,
									name: "bool",
									nodeType: "ElementaryTypeName",
									src: "1361:4:0",
									typeDescriptions: {
										typeIdentifier: "t_bool",
										typeString: "bool"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1360:6:0"
					},
					scope: 706,
					src: "1260:217:0",
					stateMutability: "view",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 195,
						nodeType: "Block",
						src: "1589:141:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									id: 178,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 174,
											name: "owners",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 5,
											src: "1595:6:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_address_$",
												typeString: "mapping(address => address)"
											}
										},
										id: 176,
										indexExpression: {
											argumentTypes: null,
											id: 175,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 163,
											src: "1602:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "1595:16:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										id: 177,
										name: "newOwner",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 167,
										src: "1614:8:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									src: "1595:27:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								id: 179,
								nodeType: "ExpressionStatement",
								src: "1595:27:0"
							},
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 181,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 163,
											src: "1649:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 182,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 167,
											src: "1659:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 183,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "1669:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 185,
											indexExpression: {
												argumentTypes: null,
												id: 184,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 163,
												src: "1677:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "1669:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 180,
										name: "DIDOwnerChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 45,
										src: "1633:15:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_address_$_t_uint256_$returns$__$",
											typeString: "function (address,address,uint256)"
										}
									},
									id: 186,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1633:54:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 187,
								nodeType: "EmitStatement",
								src: "1628:59:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 193,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 188,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "1693:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 190,
										indexExpression: {
											argumentTypes: null,
											id: 189,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 163,
											src: "1701:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "1693:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 191,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "1713:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 192,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "1713:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "1693:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 194,
								nodeType: "ExpressionStatement",
								src: "1693:32:0"
							}
						]
					},
					documentation: null,
					id: 196,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 170,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 163,
									src: "1572:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 171,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 165,
									src: "1582:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 172,
							modifierName: {
								argumentTypes: null,
								id: 169,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "1562:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "1562:26:0"
						}
					],
					name: "changeOwner",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 168,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 163,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 196,
								src: "1502:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 162,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1502:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 165,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 196,
								src: "1520:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 164,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1520:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 167,
								name: "newOwner",
								nodeType: "VariableDeclaration",
								scope: 196,
								src: "1535:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 166,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1535:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1501:51:0"
					},
					payable: false,
					returnParameters: {
						id: 173,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "1589:0:0"
					},
					scope: 706,
					src: "1481:249:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 210,
						nodeType: "Block",
						src: "1798:54:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 204,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 198,
											src: "1816:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 205,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "1826:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 206,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "1826:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 207,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 200,
											src: "1838:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 203,
										name: "changeOwner",
										nodeType: "Identifier",
										overloadedDeclarations: [
											196,
											211
										],
										referencedDeclaration: 196,
										src: "1804:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_address_$returns$__$",
											typeString: "function (address,address,address)"
										}
									},
									id: 208,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1804:43:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 209,
								nodeType: "ExpressionStatement",
								src: "1804:43:0"
							}
						]
					},
					documentation: null,
					id: 211,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "changeOwner",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 201,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 198,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 211,
								src: "1755:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 197,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1755:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 200,
								name: "newOwner",
								nodeType: "VariableDeclaration",
								scope: 211,
								src: "1773:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 199,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1773:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1754:36:0"
					},
					payable: false,
					returnParameters: {
						id: 202,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "1798:0:0"
					},
					scope: 706,
					src: "1734:118:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 256,
						nodeType: "Block",
						src: "1966:216:0",
						statements: [
							{
								assignments: [
									225
								],
								declarations: [
									{
										constant: false,
										id: 225,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 257,
										src: "1972:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 224,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "1972:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 243,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 228,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2002:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 227,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "1997:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 229,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "1997:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 231,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2014:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 230,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "2009:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 232,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2009:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 233,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "2018:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 234,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "2024:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 238,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 236,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 213,
														src: "2044:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 235,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "2030:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 237,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "2030:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2024:30:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 239,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 213,
											src: "2056:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "6368616e67654f776e6572",
											id: 240,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "2066:13:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_497a2d03cc86298e55cb693e1ab1fe854c7b50c0aa5aad6229104986e0bf69c9",
												typeString: "literal_string \"changeOwner\""
											},
											value: "changeOwner"
										},
										{
											argumentTypes: null,
											id: 241,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 221,
											src: "2081:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_497a2d03cc86298e55cb693e1ab1fe854c7b50c0aa5aad6229104986e0bf69c9",
												typeString: "literal_string \"changeOwner\""
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 226,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "1987:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 242,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1987:103:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "1972:118:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 245,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 213,
											src: "2108:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 247,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 213,
													src: "2133:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 248,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 215,
													src: "2143:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 249,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 217,
													src: "2149:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 250,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 219,
													src: "2155:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 251,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 225,
													src: "2161:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 246,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "2118:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 252,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2118:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 253,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 221,
											src: "2168:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 244,
										name: "changeOwner",
										nodeType: "Identifier",
										overloadedDeclarations: [
											196,
											211
										],
										referencedDeclaration: 196,
										src: "2096:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_address_$returns$__$",
											typeString: "function (address,address,address)"
										}
									},
									id: 254,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2096:81:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 255,
								nodeType: "ExpressionStatement",
								src: "2096:81:0"
							}
						]
					},
					documentation: null,
					id: 257,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "changeOwnerSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 222,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 213,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1883:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 212,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1883:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 215,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1901:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 214,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "1901:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 217,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1913:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 216,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1913:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 219,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1927:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 218,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1927:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 221,
								name: "newOwner",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1941:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 220,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1941:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1882:76:0"
					},
					payable: false,
					returnParameters: {
						id: 223,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "1966:0:0"
					},
					scope: 706,
					src: "1856:326:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 307,
						nodeType: "Block",
						src: "2331:218:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									id: 286,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												baseExpression: {
													argumentTypes: null,
													id: 274,
													name: "delegates",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 13,
													src: "2337:9:0",
													typeDescriptions: {
														typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
														typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
													}
												},
												id: 280,
												indexExpression: {
													argumentTypes: null,
													id: 275,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 259,
													src: "2347:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												isConstant: false,
												isLValue: true,
												isPure: false,
												lValueRequested: false,
												nodeType: "IndexAccess",
												src: "2337:19:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
													typeString: "mapping(bytes32 => mapping(address => uint256))"
												}
											},
											id: 281,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 277,
														name: "delegateType",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 263,
														src: "2367:12:0",
														typeDescriptions: {
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													],
													id: 276,
													name: "keccak256",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 715,
													src: "2357:9:0",
													typeDescriptions: {
														typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
														typeString: "function () pure returns (bytes32)"
													}
												},
												id: 278,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "2357:23:0",
												typeDescriptions: {
													typeIdentifier: "t_bytes32",
													typeString: "bytes32"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2337:44:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 282,
										indexExpression: {
											argumentTypes: null,
											id: 279,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 265,
											src: "2382:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "2337:54:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										commonType: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										},
										id: 285,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										leftExpression: {
											argumentTypes: null,
											id: 283,
											name: "now",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 723,
											src: "2394:3:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										nodeType: "BinaryOperation",
										operator: "+",
										rightExpression: {
											argumentTypes: null,
											id: 284,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 267,
											src: "2400:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										src: "2394:14:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "2337:71:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 287,
								nodeType: "ExpressionStatement",
								src: "2337:71:0"
							},
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 289,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 259,
											src: "2438:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 290,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 263,
											src: "2448:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 291,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 265,
											src: "2462:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											id: 294,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 292,
												name: "now",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 723,
												src: "2472:3:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											nodeType: "BinaryOperation",
											operator: "+",
											rightExpression: {
												argumentTypes: null,
												id: 293,
												name: "validity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 267,
												src: "2478:8:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											src: "2472:14:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 295,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "2488:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 297,
											indexExpression: {
												argumentTypes: null,
												id: 296,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 259,
												src: "2496:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2488:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 288,
										name: "DIDDelegateChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 57,
										src: "2419:18:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,address,uint256,uint256)"
										}
									},
									id: 298,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2419:87:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 299,
								nodeType: "EmitStatement",
								src: "2414:92:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 305,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 300,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "2512:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 302,
										indexExpression: {
											argumentTypes: null,
											id: 301,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 259,
											src: "2520:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "2512:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 303,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "2532:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 304,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "2532:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "2512:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 306,
								nodeType: "ExpressionStatement",
								src: "2512:32:0"
							}
						]
					},
					documentation: null,
					id: 308,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 270,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 259,
									src: "2314:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 271,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 261,
									src: "2324:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 272,
							modifierName: {
								argumentTypes: null,
								id: 269,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "2304:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "2304:26:0"
						}
					],
					name: "addDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 268,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 259,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2207:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 258,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2207:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 261,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2225:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 260,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2225:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 263,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2240:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 262,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2240:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 265,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2262:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 264,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2262:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 267,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2280:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 266,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "2280:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "2206:88:0"
					},
					payable: false,
					returnParameters: {
						id: 273,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "2331:0:0"
					},
					scope: 706,
					src: "2186:363:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 328,
						nodeType: "Block",
						src: "2654:78:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 320,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 310,
											src: "2672:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 321,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "2682:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 322,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "2682:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 323,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 312,
											src: "2694:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 324,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 314,
											src: "2708:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 325,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 316,
											src: "2718:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 319,
										name: "addDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											308,
											329
										],
										referencedDeclaration: 308,
										src: "2660:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,address,uint256)"
										}
									},
									id: 326,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2660:67:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 327,
								nodeType: "ExpressionStatement",
								src: "2660:67:0"
							}
						]
					},
					documentation: null,
					id: 329,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "addDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 317,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 310,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2574:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 309,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2574:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 312,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2592:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 311,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2592:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 314,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2614:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 313,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2614:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 316,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2632:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 315,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "2632:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "2573:73:0"
					},
					payable: false,
					returnParameters: {
						id: 318,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "2654:0:0"
					},
					scope: 706,
					src: "2553:179:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 382,
						nodeType: "Block",
						src: "2883:264:0",
						statements: [
							{
								assignments: [
									347
								],
								declarations: [
									{
										constant: false,
										id: 347,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 383,
										src: "2889:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 346,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "2889:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 367,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 350,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2919:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 349,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "2914:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 351,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2914:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 353,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2931:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 352,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "2926:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 354,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2926:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 355,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "2935:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 356,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "2941:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 360,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 358,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 331,
														src: "2961:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 357,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "2947:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 359,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "2947:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2941:30:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 361,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 331,
											src: "2973:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "61646444656c6567617465",
											id: 362,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "2983:13:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_debebbcfc53a895bddcfa7790235910fa4c752e6acb9c798d39f50a51a8429a2",
												typeString: "literal_string \"addDelegate\""
											},
											value: "addDelegate"
										},
										{
											argumentTypes: null,
											id: 363,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 339,
											src: "2998:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 364,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 341,
											src: "3012:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 365,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 343,
											src: "3022:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_debebbcfc53a895bddcfa7790235910fa4c752e6acb9c798d39f50a51a8429a2",
												typeString: "literal_string \"addDelegate\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 348,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "2904:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 366,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2904:127:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "2889:142:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 369,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 331,
											src: "3049:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 371,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 331,
													src: "3074:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 372,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 333,
													src: "3084:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 373,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 335,
													src: "3090:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 374,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 337,
													src: "3096:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 375,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 347,
													src: "3102:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 370,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "3059:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 376,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3059:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 377,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 339,
											src: "3109:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 378,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 341,
											src: "3123:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 379,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 343,
											src: "3133:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 368,
										name: "addDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											308,
											329
										],
										referencedDeclaration: 308,
										src: "3037:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,address,uint256)"
										}
									},
									id: 380,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3037:105:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 381,
								nodeType: "ExpressionStatement",
								src: "3037:105:0"
							}
						]
					},
					documentation: null,
					id: 383,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "addDelegateSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 344,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 331,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2763:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 330,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2763:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 333,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2781:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 332,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "2781:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 335,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2793:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 334,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2793:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 337,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2807:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 336,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2807:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 339,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2821:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 338,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2821:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 341,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2843:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 340,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2843:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 343,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2861:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 342,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "2861:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "2762:113:0"
					},
					payable: false,
					returnParameters: {
						id: 345,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "2883:0:0"
					},
					scope: 706,
					src: "2736:411:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 427,
						nodeType: "Block",
						src: "3284:196:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									id: 408,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												baseExpression: {
													argumentTypes: null,
													id: 398,
													name: "delegates",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 13,
													src: "3290:9:0",
													typeDescriptions: {
														typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
														typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
													}
												},
												id: 404,
												indexExpression: {
													argumentTypes: null,
													id: 399,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 385,
													src: "3300:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												isConstant: false,
												isLValue: true,
												isPure: false,
												lValueRequested: false,
												nodeType: "IndexAccess",
												src: "3290:19:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
													typeString: "mapping(bytes32 => mapping(address => uint256))"
												}
											},
											id: 405,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 401,
														name: "delegateType",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 389,
														src: "3320:12:0",
														typeDescriptions: {
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													],
													id: 400,
													name: "keccak256",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 715,
													src: "3310:9:0",
													typeDescriptions: {
														typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
														typeString: "function () pure returns (bytes32)"
													}
												},
												id: 402,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "3310:23:0",
												typeDescriptions: {
													typeIdentifier: "t_bytes32",
													typeString: "bytes32"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "3290:44:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 406,
										indexExpression: {
											argumentTypes: null,
											id: 403,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 391,
											src: "3335:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "3290:54:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										id: 407,
										name: "now",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 723,
										src: "3347:3:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "3290:60:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 409,
								nodeType: "ExpressionStatement",
								src: "3290:60:0"
							},
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 411,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 385,
											src: "3380:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 412,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 389,
											src: "3390:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 413,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 391,
											src: "3404:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 414,
											name: "now",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 723,
											src: "3414:3:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 415,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "3419:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 417,
											indexExpression: {
												argumentTypes: null,
												id: 416,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 385,
												src: "3427:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "3419:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 410,
										name: "DIDDelegateChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 57,
										src: "3361:18:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,address,uint256,uint256)"
										}
									},
									id: 418,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3361:76:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 419,
								nodeType: "EmitStatement",
								src: "3356:81:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 425,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 420,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "3443:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 422,
										indexExpression: {
											argumentTypes: null,
											id: 421,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 385,
											src: "3451:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "3443:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 423,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "3463:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 424,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "3463:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "3443:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 426,
								nodeType: "ExpressionStatement",
								src: "3443:32:0"
							}
						]
					},
					documentation: null,
					id: 428,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 394,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 385,
									src: "3267:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 395,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 387,
									src: "3277:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 396,
							modifierName: {
								argumentTypes: null,
								id: 393,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "3257:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "3257:26:0"
						}
					],
					name: "revokeDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 392,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 385,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3175:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 384,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3175:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 387,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3193:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 386,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3193:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 389,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3208:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 388,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3208:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 391,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3230:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 390,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3230:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "3174:73:0"
					},
					payable: false,
					returnParameters: {
						id: 397,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "3284:0:0"
					},
					scope: 706,
					src: "3151:329:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 445,
						nodeType: "Block",
						src: "3573:71:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 438,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 430,
											src: "3594:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 439,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "3604:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 440,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "3604:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 441,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 432,
											src: "3616:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 442,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 434,
											src: "3630:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 437,
										name: "revokeDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											428,
											446
										],
										referencedDeclaration: 428,
										src: "3579:14:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$returns$__$",
											typeString: "function (address,address,bytes32,address)"
										}
									},
									id: 443,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3579:60:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 444,
								nodeType: "ExpressionStatement",
								src: "3579:60:0"
							}
						]
					},
					documentation: null,
					id: 446,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 435,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 430,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 446,
								src: "3508:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 429,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3508:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 432,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 446,
								src: "3526:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 431,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3526:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 434,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 446,
								src: "3548:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 433,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3548:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "3507:58:0"
					},
					payable: false,
					returnParameters: {
						id: 436,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "3573:0:0"
					},
					scope: 706,
					src: "3484:160:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 495,
						nodeType: "Block",
						src: "3783:250:0",
						statements: [
							{
								assignments: [
									462
								],
								declarations: [
									{
										constant: false,
										id: 462,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 496,
										src: "3789:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 461,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "3789:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 481,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 465,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "3819:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 464,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "3814:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 466,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3814:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 468,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "3831:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 467,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "3826:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 469,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3826:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 470,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "3835:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 471,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "3841:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 475,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 473,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 448,
														src: "3861:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 472,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "3847:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 474,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "3847:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "3841:30:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 476,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 448,
											src: "3873:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "7265766f6b6544656c6567617465",
											id: 477,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "3883:16:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_f63fea8fc7bd9fe254f7933b81fa1716b5a073ddd1aa14e432aa87d81784f86c",
												typeString: "literal_string \"revokeDelegate\""
											},
											value: "revokeDelegate"
										},
										{
											argumentTypes: null,
											id: 478,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 456,
											src: "3901:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 479,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 458,
											src: "3915:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_f63fea8fc7bd9fe254f7933b81fa1716b5a073ddd1aa14e432aa87d81784f86c",
												typeString: "literal_string \"revokeDelegate\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 463,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "3804:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 480,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3804:120:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "3789:135:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 483,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 448,
											src: "3945:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 485,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 448,
													src: "3970:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 486,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 450,
													src: "3980:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 487,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 452,
													src: "3986:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 488,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 454,
													src: "3992:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 489,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 462,
													src: "3998:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 484,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "3955:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 490,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3955:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 491,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 456,
											src: "4005:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 492,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 458,
											src: "4019:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 482,
										name: "revokeDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											428,
											446
										],
										referencedDeclaration: 428,
										src: "3930:14:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$returns$__$",
											typeString: "function (address,address,bytes32,address)"
										}
									},
									id: 493,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3930:98:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 494,
								nodeType: "ExpressionStatement",
								src: "3930:98:0"
							}
						]
					},
					documentation: null,
					id: 496,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeDelegateSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 459,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 448,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3678:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 447,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3678:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 450,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3696:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 449,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "3696:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 452,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3708:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 451,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3708:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 454,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3722:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 453,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3722:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 456,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3736:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 455,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3736:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 458,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3758:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 457,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3758:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "3677:98:0"
					},
					payable: false,
					returnParameters: {
						id: 460,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "3783:0:0"
					},
					scope: 706,
					src: "3648:385:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 532,
						nodeType: "Block",
						src: "4171:131:0",
						statements: [
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 514,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 498,
											src: "4202:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 515,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 502,
											src: "4212:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 516,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 504,
											src: "4218:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											id: 519,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 517,
												name: "now",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 723,
												src: "4225:3:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											nodeType: "BinaryOperation",
											operator: "+",
											rightExpression: {
												argumentTypes: null,
												id: 518,
												name: "validity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 506,
												src: "4231:8:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											src: "4225:14:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 520,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "4241:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 522,
											indexExpression: {
												argumentTypes: null,
												id: 521,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 498,
												src: "4249:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "4241:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 513,
										name: "DIDAttributeChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 69,
										src: "4182:19:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,bytes memory,uint256,uint256)"
										}
									},
									id: 523,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4182:77:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 524,
								nodeType: "EmitStatement",
								src: "4177:82:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 530,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 525,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "4265:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 527,
										indexExpression: {
											argumentTypes: null,
											id: 526,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 498,
											src: "4273:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "4265:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 528,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "4285:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 529,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "4285:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "4265:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 531,
								nodeType: "ExpressionStatement",
								src: "4265:32:0"
							}
						]
					},
					documentation: null,
					id: 533,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 509,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 498,
									src: "4154:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 510,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 500,
									src: "4164:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 511,
							modifierName: {
								argumentTypes: null,
								id: 508,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "4144:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "4144:26:0"
						}
					],
					name: "setAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 507,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 498,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4059:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 497,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4059:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 500,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4077:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 499,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4077:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 502,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4092:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 501,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4092:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 504,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4106:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 503,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4106:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 506,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4119:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 505,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "4119:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4058:76:0"
					},
					payable: false,
					returnParameters: {
						id: 512,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4171:0:0"
					},
					scope: 706,
					src: "4037:265:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 553,
						nodeType: "Block",
						src: "4395:68:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 545,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 535,
											src: "4414:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 546,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "4424:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 547,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "4424:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 548,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 537,
											src: "4436:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 549,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 539,
											src: "4442:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											id: 550,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 541,
											src: "4449:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 544,
										name: "setAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											533,
											554
										],
										referencedDeclaration: 533,
										src: "4401:12:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory,uint256)"
										}
									},
									id: 551,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4401:57:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 552,
								nodeType: "ExpressionStatement",
								src: "4401:57:0"
							}
						]
					},
					documentation: null,
					id: 554,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "setAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 542,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 535,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4328:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 534,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4328:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 537,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4346:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 536,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4346:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 539,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4360:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 538,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4360:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 541,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4373:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 540,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "4373:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4327:60:0"
					},
					payable: false,
					returnParameters: {
						id: 543,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4395:0:0"
					},
					scope: 706,
					src: "4306:157:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 605,
						nodeType: "Block",
						src: "4602:229:0",
						statements: [
							{
								assignments: [
									572
								],
								declarations: [
									{
										constant: false,
										id: 572,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 606,
										src: "4608:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 571,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "4608:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 590,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 575,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "4638:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 574,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "4633:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 576,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "4633:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 578,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "4650:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 577,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "4645:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 579,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "4645:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 580,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "4654:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 581,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "4660:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 583,
											indexExpression: {
												argumentTypes: null,
												id: 582,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 556,
												src: "4666:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "4660:15:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 584,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 556,
											src: "4677:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "736574417474726962757465",
											id: 585,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "4687:14:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_e5bbb0cf2a185ea034bc61efc4cb764352403a5c06c1da63a3fd765abbac4ea6",
												typeString: "literal_string \"setAttribute\""
											},
											value: "setAttribute"
										},
										{
											argumentTypes: null,
											id: 586,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 564,
											src: "4703:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 587,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 566,
											src: "4709:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											id: 588,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 568,
											src: "4716:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_e5bbb0cf2a185ea034bc61efc4cb764352403a5c06c1da63a3fd765abbac4ea6",
												typeString: "literal_string \"setAttribute\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 573,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "4623:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 589,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4623:102:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "4608:117:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 592,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 556,
											src: "4744:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 594,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 556,
													src: "4769:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 595,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 558,
													src: "4779:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 596,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 560,
													src: "4785:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 597,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 562,
													src: "4791:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 598,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 572,
													src: "4797:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 593,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "4754:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 599,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "4754:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 600,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 564,
											src: "4804:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 601,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 566,
											src: "4810:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											id: 602,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 568,
											src: "4817:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 591,
										name: "setAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											533,
											554
										],
										referencedDeclaration: 533,
										src: "4731:12:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory,uint256)"
										}
									},
									id: 603,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4731:95:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 604,
								nodeType: "ExpressionStatement",
								src: "4731:95:0"
							}
						]
					},
					documentation: null,
					id: 606,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "setAttributeSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 569,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 556,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4495:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 555,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4495:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 558,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4513:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 557,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "4513:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 560,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4525:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 559,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4525:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 562,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4539:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 561,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4539:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 564,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4553:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 563,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4553:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 566,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4567:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 565,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4567:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 568,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4580:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 567,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "4580:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4494:100:0"
					},
					payable: false,
					returnParameters: {
						id: 570,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4602:0:0"
					},
					scope: 706,
					src: "4467:364:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 638,
						nodeType: "Block",
						src: "4957:118:0",
						statements: [
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 622,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 608,
											src: "4988:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 623,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 612,
											src: "4998:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 624,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 614,
											src: "5004:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											hexValue: "30",
											id: 625,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "number",
											lValueRequested: false,
											nodeType: "Literal",
											src: "5011:1:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_rational_0_by_1",
												typeString: "int_const 0"
											},
											value: "0"
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 626,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "5014:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 628,
											indexExpression: {
												argumentTypes: null,
												id: 627,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 608,
												src: "5022:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "5014:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_rational_0_by_1",
												typeString: "int_const 0"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 621,
										name: "DIDAttributeChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 69,
										src: "4968:19:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,bytes memory,uint256,uint256)"
										}
									},
									id: 629,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4968:64:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 630,
								nodeType: "EmitStatement",
								src: "4963:69:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 636,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 631,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "5038:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 633,
										indexExpression: {
											argumentTypes: null,
											id: 632,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 608,
											src: "5046:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "5038:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 634,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "5058:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 635,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "5058:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "5038:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 637,
								nodeType: "ExpressionStatement",
								src: "5038:32:0"
							}
						]
					},
					documentation: null,
					id: 639,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 617,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 608,
									src: "4940:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 618,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 610,
									src: "4950:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 619,
							modifierName: {
								argumentTypes: null,
								id: 616,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "4930:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "4930:26:0"
						}
					],
					name: "revokeAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 615,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 608,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4860:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 607,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4860:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 610,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4878:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 609,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4878:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 612,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4893:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 611,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4893:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 614,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4907:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 613,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4907:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4859:61:0"
					},
					payable: false,
					returnParameters: {
						id: 620,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4957:0:0"
					},
					scope: 706,
					src: "4835:240:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 656,
						nodeType: "Block",
						src: "5156:61:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 649,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 641,
											src: "5178:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 650,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "5188:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 651,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "5188:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 652,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 643,
											src: "5200:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 653,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 645,
											src: "5206:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										],
										id: 648,
										name: "revokeAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											639,
											657
										],
										referencedDeclaration: 639,
										src: "5162:15:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory)"
										}
									},
									id: 654,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "5162:50:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 655,
								nodeType: "ExpressionStatement",
								src: "5162:50:0"
							}
						]
					},
					documentation: null,
					id: 657,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 646,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 641,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 657,
								src: "5104:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 640,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "5104:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 643,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 657,
								src: "5122:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 642,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5122:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 645,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 657,
								src: "5136:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 644,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "5136:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "5103:45:0"
					},
					payable: false,
					returnParameters: {
						id: 647,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "5156:0:0"
					},
					scope: 706,
					src: "5079:138:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 704,
						nodeType: "Block",
						src: "5343:216:0",
						statements: [
							{
								assignments: [
									673
								],
								declarations: [
									{
										constant: false,
										id: 673,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 705,
										src: "5349:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 672,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "5349:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 690,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 676,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "5379:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 675,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "5374:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 677,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "5374:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 679,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "5391:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 678,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "5386:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 680,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "5386:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 681,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "5395:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 682,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "5401:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 684,
											indexExpression: {
												argumentTypes: null,
												id: 683,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 659,
												src: "5407:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "5401:15:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 685,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 659,
											src: "5418:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "7265766f6b65417474726962757465",
											id: 686,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "5428:17:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_168e4cc0ad03cc4b6896d89f8a470b9997cd8bbe87ac639c5474674fa958f860",
												typeString: "literal_string \"revokeAttribute\""
											},
											value: "revokeAttribute"
										},
										{
											argumentTypes: null,
											id: 687,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 667,
											src: "5447:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 688,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 669,
											src: "5453:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_168e4cc0ad03cc4b6896d89f8a470b9997cd8bbe87ac639c5474674fa958f860",
												typeString: "literal_string \"revokeAttribute\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										],
										id: 674,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "5364:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 689,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "5364:95:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "5349:110:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 692,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 659,
											src: "5482:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 694,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 659,
													src: "5507:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 695,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 661,
													src: "5517:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 696,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 663,
													src: "5523:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 697,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 665,
													src: "5529:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 698,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 673,
													src: "5535:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 693,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "5492:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 699,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "5492:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 700,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 667,
											src: "5542:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 701,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 669,
											src: "5548:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										],
										id: 691,
										name: "revokeAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											639,
											657
										],
										referencedDeclaration: 639,
										src: "5466:15:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory)"
										}
									},
									id: 702,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "5466:88:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 703,
								nodeType: "ExpressionStatement",
								src: "5466:88:0"
							}
						]
					},
					documentation: null,
					id: 705,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeAttributeSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 670,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 659,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5251:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 658,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "5251:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 661,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5269:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 660,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "5269:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 663,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5281:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 662,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5281:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 665,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5295:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 664,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5295:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 667,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5309:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 666,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5309:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 669,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5323:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 668,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "5323:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "5250:85:0"
					},
					payable: false,
					returnParameters: {
						id: 671,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "5343:0:0"
					},
					scope: 706,
					src: "5220:339:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				}
			],
			scope: 707,
			src: "25:5537:0"
		}
	],
	src: "0:5563:0"
};
var legacyAST = {
	absolutePath: "/Users/pelleb/code/consensys/ethereum-did-registry/contracts/EthereumDIDRegistry.sol",
	exportedSymbols: {
		EthereumDIDRegistry: [
			706
		]
	},
	id: 707,
	nodeType: "SourceUnit",
	nodes: [
		{
			id: 1,
			literals: [
				"solidity",
				"^",
				"0.4",
				".4"
			],
			nodeType: "PragmaDirective",
			src: "0:23:0"
		},
		{
			baseContracts: [
			],
			contractDependencies: [
			],
			contractKind: "contract",
			documentation: null,
			fullyImplemented: true,
			id: 706,
			linearizedBaseContracts: [
				706
			],
			name: "EthereumDIDRegistry",
			nodeType: "ContractDefinition",
			nodes: [
				{
					constant: false,
					id: 5,
					name: "owners",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "59:41:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_address_$",
						typeString: "mapping(address => address)"
					},
					typeName: {
						id: 4,
						keyType: {
							id: 2,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "67:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "59:27:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_address_$",
							typeString: "mapping(address => address)"
						},
						valueType: {
							id: 3,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "78:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					constant: false,
					id: 13,
					name: "delegates",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "104:81:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
						typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
					},
					typeName: {
						id: 12,
						keyType: {
							id: 6,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "112:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "104:64:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
							typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
						},
						valueType: {
							id: 11,
							keyType: {
								id: 7,
								name: "bytes32",
								nodeType: "ElementaryTypeName",
								src: "131:7:0",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								}
							},
							nodeType: "Mapping",
							src: "123:44:0",
							typeDescriptions: {
								typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
								typeString: "mapping(bytes32 => mapping(address => uint256))"
							},
							valueType: {
								id: 10,
								keyType: {
									id: 8,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "150:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								nodeType: "Mapping",
								src: "142:24:0",
								typeDescriptions: {
									typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
									typeString: "mapping(address => uint256)"
								},
								valueType: {
									id: 9,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "161:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								}
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					constant: false,
					id: 17,
					name: "changed",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "189:39:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
						typeString: "mapping(address => uint256)"
					},
					typeName: {
						id: 16,
						keyType: {
							id: 14,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "197:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "189:24:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
							typeString: "mapping(address => uint256)"
						},
						valueType: {
							id: 15,
							name: "uint",
							nodeType: "ElementaryTypeName",
							src: "208:4:0",
							typeDescriptions: {
								typeIdentifier: "t_uint256",
								typeString: "uint256"
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					constant: false,
					id: 21,
					name: "nonce",
					nodeType: "VariableDeclaration",
					scope: 706,
					src: "232:37:0",
					stateVariable: true,
					storageLocation: "default",
					typeDescriptions: {
						typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
						typeString: "mapping(address => uint256)"
					},
					typeName: {
						id: 20,
						keyType: {
							id: 18,
							name: "address",
							nodeType: "ElementaryTypeName",
							src: "240:7:0",
							typeDescriptions: {
								typeIdentifier: "t_address",
								typeString: "address"
							}
						},
						nodeType: "Mapping",
						src: "232:24:0",
						typeDescriptions: {
							typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
							typeString: "mapping(address => uint256)"
						},
						valueType: {
							id: 19,
							name: "uint",
							nodeType: "ElementaryTypeName",
							src: "251:4:0",
							typeDescriptions: {
								typeIdentifier: "t_uint256",
								typeString: "uint256"
							}
						}
					},
					value: null,
					visibility: "public"
				},
				{
					body: {
						id: 36,
						nodeType: "Block",
						src: "326:60:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_address",
												typeString: "address"
											},
											id: 32,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 28,
												name: "actor",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 25,
												src: "341:5:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											nodeType: "BinaryOperation",
											operator: "==",
											rightExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 30,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 23,
														src: "364:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 29,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "350:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 31,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "350:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											src: "341:32:0",
											typeDescriptions: {
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										],
										id: 27,
										name: "require",
										nodeType: "Identifier",
										overloadedDeclarations: [
											724,
											725
										],
										referencedDeclaration: 724,
										src: "332:7:0",
										typeDescriptions: {
											typeIdentifier: "t_function_require_pure$_t_bool_$returns$__$",
											typeString: "function (bool) pure"
										}
									},
									id: 33,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "332:42:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 34,
								nodeType: "ExpressionStatement",
								src: "332:42:0"
							},
							{
								id: 35,
								nodeType: "PlaceholderStatement",
								src: "380:1:0"
							}
						]
					},
					documentation: null,
					id: 37,
					name: "onlyOwner",
					nodeType: "ModifierDefinition",
					parameters: {
						id: 26,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 23,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 37,
								src: "293:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 22,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "293:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 25,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 37,
								src: "311:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 24,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "311:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "292:33:0"
					},
					src: "274:112:0",
					visibility: "internal"
				},
				{
					anonymous: false,
					documentation: null,
					id: 45,
					name: "DIDOwnerChanged",
					nodeType: "EventDefinition",
					parameters: {
						id: 44,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 39,
								indexed: true,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 45,
								src: "417:24:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 38,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "417:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 41,
								indexed: false,
								name: "owner",
								nodeType: "VariableDeclaration",
								scope: 45,
								src: "447:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 40,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "447:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 43,
								indexed: false,
								name: "previousChange",
								nodeType: "VariableDeclaration",
								scope: 45,
								src: "466:19:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 42,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "466:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "411:78:0"
					},
					src: "390:100:0"
				},
				{
					anonymous: false,
					documentation: null,
					id: 57,
					name: "DIDDelegateChanged",
					nodeType: "EventDefinition",
					parameters: {
						id: 56,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 47,
								indexed: true,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "524:24:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 46,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "524:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 49,
								indexed: false,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "554:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 48,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "554:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 51,
								indexed: false,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "580:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 50,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "580:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 53,
								indexed: false,
								name: "validTo",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "602:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 52,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "602:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 55,
								indexed: false,
								name: "previousChange",
								nodeType: "VariableDeclaration",
								scope: 57,
								src: "620:19:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 54,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "620:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "518:125:0"
					},
					src: "494:150:0"
				},
				{
					anonymous: false,
					documentation: null,
					id: 69,
					name: "DIDAttributeChanged",
					nodeType: "EventDefinition",
					parameters: {
						id: 68,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 59,
								indexed: true,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "679:24:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 58,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "679:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 61,
								indexed: false,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "709:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 60,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "709:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 63,
								indexed: false,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "727:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 62,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "727:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 65,
								indexed: false,
								name: "validTo",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "744:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 64,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "744:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 67,
								indexed: false,
								name: "previousChange",
								nodeType: "VariableDeclaration",
								scope: 69,
								src: "762:19:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 66,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "762:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "673:112:0"
					},
					src: "648:138:0"
				},
				{
					body: {
						id: 91,
						nodeType: "Block",
						src: "860:119:0",
						statements: [
							{
								assignments: [
									77
								],
								declarations: [
									{
										constant: false,
										id: 77,
										name: "owner",
										nodeType: "VariableDeclaration",
										scope: 92,
										src: "867:13:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										},
										typeName: {
											id: 76,
											name: "address",
											nodeType: "ElementaryTypeName",
											src: "867:7:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 81,
								initialValue: {
									argumentTypes: null,
									baseExpression: {
										argumentTypes: null,
										id: 78,
										name: "owners",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 5,
										src: "883:6:0",
										typeDescriptions: {
											typeIdentifier: "t_mapping$_t_address_$_t_address_$",
											typeString: "mapping(address => address)"
										}
									},
									id: 80,
									indexExpression: {
										argumentTypes: null,
										id: 79,
										name: "identity",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 71,
										src: "890:8:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									isConstant: false,
									isLValue: true,
									isPure: false,
									lValueRequested: false,
									nodeType: "IndexAccess",
									src: "883:16:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "867:32:0"
							},
							{
								condition: {
									argumentTypes: null,
									commonType: {
										typeIdentifier: "t_address",
										typeString: "address"
									},
									id: 84,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftExpression: {
										argumentTypes: null,
										id: 82,
										name: "owner",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 77,
										src: "910:5:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									nodeType: "BinaryOperation",
									operator: "!=",
									rightExpression: {
										argumentTypes: null,
										hexValue: "307830",
										id: 83,
										isConstant: false,
										isLValue: false,
										isPure: true,
										kind: "number",
										lValueRequested: false,
										nodeType: "Literal",
										src: "919:3:0",
										subdenomination: null,
										typeDescriptions: {
											typeIdentifier: "t_rational_0_by_1",
											typeString: "int_const 0"
										},
										value: "0x0"
									},
									src: "910:12:0",
									typeDescriptions: {
										typeIdentifier: "t_bool",
										typeString: "bool"
									}
								},
								falseBody: null,
								id: 88,
								nodeType: "IfStatement",
								src: "906:47:0",
								trueBody: {
									id: 87,
									nodeType: "Block",
									src: "924:29:0",
									statements: [
										{
											expression: {
												argumentTypes: null,
												id: 85,
												name: "owner",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 77,
												src: "940:5:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											functionReturnParameters: 75,
											id: 86,
											nodeType: "Return",
											src: "933:12:0"
										}
									]
								}
							},
							{
								expression: {
									argumentTypes: null,
									id: 89,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 71,
									src: "966:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								functionReturnParameters: 75,
								id: 90,
								nodeType: "Return",
								src: "959:15:0"
							}
						]
					},
					documentation: null,
					id: 92,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: true,
					modifiers: [
					],
					name: "identityOwner",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 72,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 71,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 92,
								src: "813:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 70,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "813:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "812:18:0"
					},
					payable: false,
					returnParameters: {
						id: 75,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 74,
								name: "",
								nodeType: "VariableDeclaration",
								scope: 92,
								src: "851:7:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 73,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "851:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "850:9:0"
					},
					scope: 706,
					src: "790:189:0",
					stateMutability: "view",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 131,
						nodeType: "Block",
						src: "1105:151:0",
						statements: [
							{
								assignments: [
									108
								],
								declarations: [
									{
										constant: false,
										id: 108,
										name: "signer",
										nodeType: "VariableDeclaration",
										scope: 132,
										src: "1111:14:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										},
										typeName: {
											id: 107,
											name: "address",
											nodeType: "ElementaryTypeName",
											src: "1111:7:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 115,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 110,
											name: "hash",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 102,
											src: "1138:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 111,
											name: "sigV",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 96,
											src: "1144:4:0",
											typeDescriptions: {
												typeIdentifier: "t_uint8",
												typeString: "uint8"
											}
										},
										{
											argumentTypes: null,
											id: 112,
											name: "sigR",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 98,
											src: "1150:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 113,
											name: "sigS",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 100,
											src: "1156:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_uint8",
												typeString: "uint8"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										],
										id: 109,
										name: "ecrecover",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 713,
										src: "1128:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_ecrecover_pure$_t_bytes32_$_t_uint8_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
											typeString: "function (bytes32,uint8,bytes32,bytes32) pure returns (address)"
										}
									},
									id: 114,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1128:33:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "1111:50:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_address",
												typeString: "address"
											},
											id: 121,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 117,
												name: "signer",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 108,
												src: "1175:6:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											nodeType: "BinaryOperation",
											operator: "==",
											rightExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 119,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 94,
														src: "1199:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 118,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "1185:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 120,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "1185:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											src: "1175:33:0",
											typeDescriptions: {
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										],
										id: 116,
										name: "require",
										nodeType: "Identifier",
										overloadedDeclarations: [
											724,
											725
										],
										referencedDeclaration: 724,
										src: "1167:7:0",
										typeDescriptions: {
											typeIdentifier: "t_function_require_pure$_t_bool_$returns$__$",
											typeString: "function (bool) pure"
										}
									},
									id: 122,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1167:42:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 123,
								nodeType: "ExpressionStatement",
								src: "1167:42:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 127,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									nodeType: "UnaryOperation",
									operator: "++",
									prefix: false,
									src: "1215:17:0",
									subExpression: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 124,
											name: "nonce",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 21,
											src: "1215:5:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 126,
										indexExpression: {
											argumentTypes: null,
											id: 125,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 94,
											src: "1221:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "1215:15:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 128,
								nodeType: "ExpressionStatement",
								src: "1215:17:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 129,
									name: "signer",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 108,
									src: "1245:6:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								functionReturnParameters: 106,
								id: 130,
								nodeType: "Return",
								src: "1238:13:0"
							}
						]
					},
					documentation: null,
					id: 132,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "checkSignature",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 103,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 94,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1007:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 93,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1007:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 96,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1025:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 95,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "1025:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 98,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1037:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 97,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1037:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 100,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1051:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 99,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1051:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 102,
								name: "hash",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1065:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 101,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1065:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1006:72:0"
					},
					payable: false,
					returnParameters: {
						id: 106,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 105,
								name: "",
								nodeType: "VariableDeclaration",
								scope: 132,
								src: "1096:7:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 104,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1096:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1095:9:0"
					},
					scope: 706,
					src: "983:273:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 160,
						nodeType: "Block",
						src: "1367:110:0",
						statements: [
							{
								assignments: [
									144
								],
								declarations: [
									{
										constant: false,
										id: 144,
										name: "validity",
										nodeType: "VariableDeclaration",
										scope: 161,
										src: "1373:13:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										},
										typeName: {
											id: 143,
											name: "uint",
											nodeType: "ElementaryTypeName",
											src: "1373:4:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 154,
								initialValue: {
									argumentTypes: null,
									baseExpression: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 145,
												name: "delegates",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 13,
												src: "1389:9:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
													typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
												}
											},
											id: 147,
											indexExpression: {
												argumentTypes: null,
												id: 146,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 134,
												src: "1399:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "1389:19:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
												typeString: "mapping(bytes32 => mapping(address => uint256))"
											}
										},
										id: 151,
										indexExpression: {
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 149,
													name: "delegateType",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 136,
													src: "1419:12:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 148,
												name: "keccak256",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 715,
												src: "1409:9:0",
												typeDescriptions: {
													typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
													typeString: "function () pure returns (bytes32)"
												}
											},
											id: 150,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "1409:23:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: false,
										nodeType: "IndexAccess",
										src: "1389:44:0",
										typeDescriptions: {
											typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
											typeString: "mapping(address => uint256)"
										}
									},
									id: 153,
									indexExpression: {
										argumentTypes: null,
										id: 152,
										name: "delegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 138,
										src: "1434:8:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									isConstant: false,
									isLValue: true,
									isPure: false,
									lValueRequested: false,
									nodeType: "IndexAccess",
									src: "1389:54:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "1373:70:0"
							},
							{
								expression: {
									argumentTypes: null,
									components: [
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											id: 157,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 155,
												name: "validity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 144,
												src: "1457:8:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											nodeType: "BinaryOperation",
											operator: ">",
											rightExpression: {
												argumentTypes: null,
												id: 156,
												name: "now",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 723,
												src: "1468:3:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											src: "1457:14:0",
											typeDescriptions: {
												typeIdentifier: "t_bool",
												typeString: "bool"
											}
										}
									],
									id: 158,
									isConstant: false,
									isInlineArray: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									nodeType: "TupleExpression",
									src: "1456:16:0",
									typeDescriptions: {
										typeIdentifier: "t_bool",
										typeString: "bool"
									}
								},
								functionReturnParameters: 142,
								id: 159,
								nodeType: "Return",
								src: "1449:23:0"
							}
						]
					},
					documentation: null,
					id: 161,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: true,
					modifiers: [
					],
					name: "validDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 139,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 134,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1283:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 133,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1283:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 136,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1301:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 135,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1301:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 138,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1323:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 137,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1323:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1282:58:0"
					},
					payable: false,
					returnParameters: {
						id: 142,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 141,
								name: "",
								nodeType: "VariableDeclaration",
								scope: 161,
								src: "1361:4:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bool",
									typeString: "bool"
								},
								typeName: {
									id: 140,
									name: "bool",
									nodeType: "ElementaryTypeName",
									src: "1361:4:0",
									typeDescriptions: {
										typeIdentifier: "t_bool",
										typeString: "bool"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1360:6:0"
					},
					scope: 706,
					src: "1260:217:0",
					stateMutability: "view",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 195,
						nodeType: "Block",
						src: "1589:141:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									id: 178,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 174,
											name: "owners",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 5,
											src: "1595:6:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_address_$",
												typeString: "mapping(address => address)"
											}
										},
										id: 176,
										indexExpression: {
											argumentTypes: null,
											id: 175,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 163,
											src: "1602:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "1595:16:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										id: 177,
										name: "newOwner",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 167,
										src: "1614:8:0",
										typeDescriptions: {
											typeIdentifier: "t_address",
											typeString: "address"
										}
									},
									src: "1595:27:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								id: 179,
								nodeType: "ExpressionStatement",
								src: "1595:27:0"
							},
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 181,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 163,
											src: "1649:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 182,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 167,
											src: "1659:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 183,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "1669:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 185,
											indexExpression: {
												argumentTypes: null,
												id: 184,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 163,
												src: "1677:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "1669:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 180,
										name: "DIDOwnerChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 45,
										src: "1633:15:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_address_$_t_uint256_$returns$__$",
											typeString: "function (address,address,uint256)"
										}
									},
									id: 186,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1633:54:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 187,
								nodeType: "EmitStatement",
								src: "1628:59:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 193,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 188,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "1693:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 190,
										indexExpression: {
											argumentTypes: null,
											id: 189,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 163,
											src: "1701:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "1693:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 191,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "1713:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 192,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "1713:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "1693:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 194,
								nodeType: "ExpressionStatement",
								src: "1693:32:0"
							}
						]
					},
					documentation: null,
					id: 196,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 170,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 163,
									src: "1572:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 171,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 165,
									src: "1582:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 172,
							modifierName: {
								argumentTypes: null,
								id: 169,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "1562:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "1562:26:0"
						}
					],
					name: "changeOwner",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 168,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 163,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 196,
								src: "1502:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 162,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1502:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 165,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 196,
								src: "1520:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 164,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1520:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 167,
								name: "newOwner",
								nodeType: "VariableDeclaration",
								scope: 196,
								src: "1535:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 166,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1535:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1501:51:0"
					},
					payable: false,
					returnParameters: {
						id: 173,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "1589:0:0"
					},
					scope: 706,
					src: "1481:249:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 210,
						nodeType: "Block",
						src: "1798:54:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 204,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 198,
											src: "1816:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 205,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "1826:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 206,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "1826:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 207,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 200,
											src: "1838:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 203,
										name: "changeOwner",
										nodeType: "Identifier",
										overloadedDeclarations: [
											196,
											211
										],
										referencedDeclaration: 196,
										src: "1804:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_address_$returns$__$",
											typeString: "function (address,address,address)"
										}
									},
									id: 208,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1804:43:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 209,
								nodeType: "ExpressionStatement",
								src: "1804:43:0"
							}
						]
					},
					documentation: null,
					id: 211,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "changeOwner",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 201,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 198,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 211,
								src: "1755:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 197,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1755:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 200,
								name: "newOwner",
								nodeType: "VariableDeclaration",
								scope: 211,
								src: "1773:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 199,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1773:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1754:36:0"
					},
					payable: false,
					returnParameters: {
						id: 202,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "1798:0:0"
					},
					scope: 706,
					src: "1734:118:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 256,
						nodeType: "Block",
						src: "1966:216:0",
						statements: [
							{
								assignments: [
									225
								],
								declarations: [
									{
										constant: false,
										id: 225,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 257,
										src: "1972:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 224,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "1972:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 243,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 228,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2002:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 227,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "1997:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 229,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "1997:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 231,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2014:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 230,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "2009:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 232,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2009:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 233,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "2018:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 234,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "2024:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 238,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 236,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 213,
														src: "2044:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 235,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "2030:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 237,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "2030:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2024:30:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 239,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 213,
											src: "2056:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "6368616e67654f776e6572",
											id: 240,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "2066:13:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_497a2d03cc86298e55cb693e1ab1fe854c7b50c0aa5aad6229104986e0bf69c9",
												typeString: "literal_string \"changeOwner\""
											},
											value: "changeOwner"
										},
										{
											argumentTypes: null,
											id: 241,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 221,
											src: "2081:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_497a2d03cc86298e55cb693e1ab1fe854c7b50c0aa5aad6229104986e0bf69c9",
												typeString: "literal_string \"changeOwner\""
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 226,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "1987:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 242,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "1987:103:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "1972:118:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 245,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 213,
											src: "2108:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 247,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 213,
													src: "2133:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 248,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 215,
													src: "2143:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 249,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 217,
													src: "2149:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 250,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 219,
													src: "2155:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 251,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 225,
													src: "2161:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 246,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "2118:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 252,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2118:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 253,
											name: "newOwner",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 221,
											src: "2168:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 244,
										name: "changeOwner",
										nodeType: "Identifier",
										overloadedDeclarations: [
											196,
											211
										],
										referencedDeclaration: 196,
										src: "2096:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_address_$returns$__$",
											typeString: "function (address,address,address)"
										}
									},
									id: 254,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2096:81:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 255,
								nodeType: "ExpressionStatement",
								src: "2096:81:0"
							}
						]
					},
					documentation: null,
					id: 257,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "changeOwnerSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 222,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 213,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1883:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 212,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1883:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 215,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1901:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 214,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "1901:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 217,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1913:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 216,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1913:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 219,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1927:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 218,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "1927:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 221,
								name: "newOwner",
								nodeType: "VariableDeclaration",
								scope: 257,
								src: "1941:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 220,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "1941:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "1882:76:0"
					},
					payable: false,
					returnParameters: {
						id: 223,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "1966:0:0"
					},
					scope: 706,
					src: "1856:326:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 307,
						nodeType: "Block",
						src: "2331:218:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									id: 286,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												baseExpression: {
													argumentTypes: null,
													id: 274,
													name: "delegates",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 13,
													src: "2337:9:0",
													typeDescriptions: {
														typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
														typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
													}
												},
												id: 280,
												indexExpression: {
													argumentTypes: null,
													id: 275,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 259,
													src: "2347:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												isConstant: false,
												isLValue: true,
												isPure: false,
												lValueRequested: false,
												nodeType: "IndexAccess",
												src: "2337:19:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
													typeString: "mapping(bytes32 => mapping(address => uint256))"
												}
											},
											id: 281,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 277,
														name: "delegateType",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 263,
														src: "2367:12:0",
														typeDescriptions: {
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													],
													id: 276,
													name: "keccak256",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 715,
													src: "2357:9:0",
													typeDescriptions: {
														typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
														typeString: "function () pure returns (bytes32)"
													}
												},
												id: 278,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "2357:23:0",
												typeDescriptions: {
													typeIdentifier: "t_bytes32",
													typeString: "bytes32"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2337:44:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 282,
										indexExpression: {
											argumentTypes: null,
											id: 279,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 265,
											src: "2382:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "2337:54:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										commonType: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										},
										id: 285,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										leftExpression: {
											argumentTypes: null,
											id: 283,
											name: "now",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 723,
											src: "2394:3:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										nodeType: "BinaryOperation",
										operator: "+",
										rightExpression: {
											argumentTypes: null,
											id: 284,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 267,
											src: "2400:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										src: "2394:14:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "2337:71:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 287,
								nodeType: "ExpressionStatement",
								src: "2337:71:0"
							},
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 289,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 259,
											src: "2438:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 290,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 263,
											src: "2448:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 291,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 265,
											src: "2462:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											id: 294,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 292,
												name: "now",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 723,
												src: "2472:3:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											nodeType: "BinaryOperation",
											operator: "+",
											rightExpression: {
												argumentTypes: null,
												id: 293,
												name: "validity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 267,
												src: "2478:8:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											src: "2472:14:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 295,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "2488:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 297,
											indexExpression: {
												argumentTypes: null,
												id: 296,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 259,
												src: "2496:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2488:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 288,
										name: "DIDDelegateChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 57,
										src: "2419:18:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,address,uint256,uint256)"
										}
									},
									id: 298,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2419:87:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 299,
								nodeType: "EmitStatement",
								src: "2414:92:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 305,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 300,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "2512:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 302,
										indexExpression: {
											argumentTypes: null,
											id: 301,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 259,
											src: "2520:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "2512:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 303,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "2532:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 304,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "2532:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "2512:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 306,
								nodeType: "ExpressionStatement",
								src: "2512:32:0"
							}
						]
					},
					documentation: null,
					id: 308,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 270,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 259,
									src: "2314:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 271,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 261,
									src: "2324:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 272,
							modifierName: {
								argumentTypes: null,
								id: 269,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "2304:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "2304:26:0"
						}
					],
					name: "addDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 268,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 259,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2207:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 258,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2207:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 261,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2225:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 260,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2225:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 263,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2240:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 262,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2240:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 265,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2262:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 264,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2262:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 267,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 308,
								src: "2280:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 266,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "2280:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "2206:88:0"
					},
					payable: false,
					returnParameters: {
						id: 273,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "2331:0:0"
					},
					scope: 706,
					src: "2186:363:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 328,
						nodeType: "Block",
						src: "2654:78:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 320,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 310,
											src: "2672:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 321,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "2682:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 322,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "2682:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 323,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 312,
											src: "2694:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 324,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 314,
											src: "2708:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 325,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 316,
											src: "2718:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 319,
										name: "addDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											308,
											329
										],
										referencedDeclaration: 308,
										src: "2660:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,address,uint256)"
										}
									},
									id: 326,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2660:67:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 327,
								nodeType: "ExpressionStatement",
								src: "2660:67:0"
							}
						]
					},
					documentation: null,
					id: 329,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "addDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 317,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 310,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2574:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 309,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2574:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 312,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2592:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 311,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2592:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 314,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2614:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 313,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2614:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 316,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 329,
								src: "2632:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 315,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "2632:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "2573:73:0"
					},
					payable: false,
					returnParameters: {
						id: 318,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "2654:0:0"
					},
					scope: 706,
					src: "2553:179:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 382,
						nodeType: "Block",
						src: "2883:264:0",
						statements: [
							{
								assignments: [
									347
								],
								declarations: [
									{
										constant: false,
										id: 347,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 383,
										src: "2889:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 346,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "2889:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 367,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 350,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2919:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 349,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "2914:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 351,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2914:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 353,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "2931:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 352,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "2926:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 354,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "2926:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 355,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "2935:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 356,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "2941:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 360,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 358,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 331,
														src: "2961:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 357,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "2947:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 359,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "2947:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "2941:30:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 361,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 331,
											src: "2973:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "61646444656c6567617465",
											id: 362,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "2983:13:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_debebbcfc53a895bddcfa7790235910fa4c752e6acb9c798d39f50a51a8429a2",
												typeString: "literal_string \"addDelegate\""
											},
											value: "addDelegate"
										},
										{
											argumentTypes: null,
											id: 363,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 339,
											src: "2998:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 364,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 341,
											src: "3012:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 365,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 343,
											src: "3022:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_debebbcfc53a895bddcfa7790235910fa4c752e6acb9c798d39f50a51a8429a2",
												typeString: "literal_string \"addDelegate\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 348,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "2904:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 366,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "2904:127:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "2889:142:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 369,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 331,
											src: "3049:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 371,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 331,
													src: "3074:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 372,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 333,
													src: "3084:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 373,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 335,
													src: "3090:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 374,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 337,
													src: "3096:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 375,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 347,
													src: "3102:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 370,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "3059:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 376,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3059:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 377,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 339,
											src: "3109:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 378,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 341,
											src: "3123:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 379,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 343,
											src: "3133:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 368,
										name: "addDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											308,
											329
										],
										referencedDeclaration: 308,
										src: "3037:11:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,address,uint256)"
										}
									},
									id: 380,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3037:105:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 381,
								nodeType: "ExpressionStatement",
								src: "3037:105:0"
							}
						]
					},
					documentation: null,
					id: 383,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "addDelegateSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 344,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 331,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2763:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 330,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2763:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 333,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2781:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 332,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "2781:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 335,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2793:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 334,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2793:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 337,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2807:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 336,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2807:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 339,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2821:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 338,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "2821:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 341,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2843:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 340,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "2843:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 343,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 383,
								src: "2861:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 342,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "2861:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "2762:113:0"
					},
					payable: false,
					returnParameters: {
						id: 345,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "2883:0:0"
					},
					scope: 706,
					src: "2736:411:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 427,
						nodeType: "Block",
						src: "3284:196:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									id: 408,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												baseExpression: {
													argumentTypes: null,
													id: 398,
													name: "delegates",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 13,
													src: "3290:9:0",
													typeDescriptions: {
														typeIdentifier: "t_mapping$_t_address_$_t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$_$",
														typeString: "mapping(address => mapping(bytes32 => mapping(address => uint256)))"
													}
												},
												id: 404,
												indexExpression: {
													argumentTypes: null,
													id: 399,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 385,
													src: "3300:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												isConstant: false,
												isLValue: true,
												isPure: false,
												lValueRequested: false,
												nodeType: "IndexAccess",
												src: "3290:19:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_bytes32_$_t_mapping$_t_address_$_t_uint256_$_$",
													typeString: "mapping(bytes32 => mapping(address => uint256))"
												}
											},
											id: 405,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 401,
														name: "delegateType",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 389,
														src: "3320:12:0",
														typeDescriptions: {
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_bytes32",
															typeString: "bytes32"
														}
													],
													id: 400,
													name: "keccak256",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 715,
													src: "3310:9:0",
													typeDescriptions: {
														typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
														typeString: "function () pure returns (bytes32)"
													}
												},
												id: 402,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "3310:23:0",
												typeDescriptions: {
													typeIdentifier: "t_bytes32",
													typeString: "bytes32"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "3290:44:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 406,
										indexExpression: {
											argumentTypes: null,
											id: 403,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 391,
											src: "3335:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "3290:54:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										id: 407,
										name: "now",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 723,
										src: "3347:3:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "3290:60:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 409,
								nodeType: "ExpressionStatement",
								src: "3290:60:0"
							},
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 411,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 385,
											src: "3380:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 412,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 389,
											src: "3390:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 413,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 391,
											src: "3404:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 414,
											name: "now",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 723,
											src: "3414:3:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 415,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "3419:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 417,
											indexExpression: {
												argumentTypes: null,
												id: 416,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 385,
												src: "3427:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "3419:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 410,
										name: "DIDDelegateChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 57,
										src: "3361:18:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_address_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,address,uint256,uint256)"
										}
									},
									id: 418,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3361:76:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 419,
								nodeType: "EmitStatement",
								src: "3356:81:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 425,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 420,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "3443:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 422,
										indexExpression: {
											argumentTypes: null,
											id: 421,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 385,
											src: "3451:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "3443:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 423,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "3463:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 424,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "3463:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "3443:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 426,
								nodeType: "ExpressionStatement",
								src: "3443:32:0"
							}
						]
					},
					documentation: null,
					id: 428,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 394,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 385,
									src: "3267:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 395,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 387,
									src: "3277:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 396,
							modifierName: {
								argumentTypes: null,
								id: 393,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "3257:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "3257:26:0"
						}
					],
					name: "revokeDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 392,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 385,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3175:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 384,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3175:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 387,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3193:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 386,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3193:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 389,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3208:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 388,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3208:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 391,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 428,
								src: "3230:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 390,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3230:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "3174:73:0"
					},
					payable: false,
					returnParameters: {
						id: 397,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "3284:0:0"
					},
					scope: 706,
					src: "3151:329:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 445,
						nodeType: "Block",
						src: "3573:71:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 438,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 430,
											src: "3594:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 439,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "3604:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 440,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "3604:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 441,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 432,
											src: "3616:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 442,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 434,
											src: "3630:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 437,
										name: "revokeDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											428,
											446
										],
										referencedDeclaration: 428,
										src: "3579:14:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$returns$__$",
											typeString: "function (address,address,bytes32,address)"
										}
									},
									id: 443,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3579:60:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 444,
								nodeType: "ExpressionStatement",
								src: "3579:60:0"
							}
						]
					},
					documentation: null,
					id: 446,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeDelegate",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 435,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 430,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 446,
								src: "3508:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 429,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3508:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 432,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 446,
								src: "3526:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 431,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3526:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 434,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 446,
								src: "3548:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 433,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3548:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "3507:58:0"
					},
					payable: false,
					returnParameters: {
						id: 436,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "3573:0:0"
					},
					scope: 706,
					src: "3484:160:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 495,
						nodeType: "Block",
						src: "3783:250:0",
						statements: [
							{
								assignments: [
									462
								],
								declarations: [
									{
										constant: false,
										id: 462,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 496,
										src: "3789:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 461,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "3789:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 481,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 465,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "3819:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 464,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "3814:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 466,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3814:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 468,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "3831:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 467,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "3826:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 469,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3826:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 470,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "3835:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 471,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "3841:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 475,
											indexExpression: {
												argumentTypes: null,
												"arguments": [
													{
														argumentTypes: null,
														id: 473,
														name: "identity",
														nodeType: "Identifier",
														overloadedDeclarations: [
														],
														referencedDeclaration: 448,
														src: "3861:8:0",
														typeDescriptions: {
															typeIdentifier: "t_address",
															typeString: "address"
														}
													}
												],
												expression: {
													argumentTypes: [
														{
															typeIdentifier: "t_address",
															typeString: "address"
														}
													],
													id: 472,
													name: "identityOwner",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 92,
													src: "3847:13:0",
													typeDescriptions: {
														typeIdentifier: "t_function_internal_view$_t_address_$returns$_t_address_$",
														typeString: "function (address) view returns (address)"
													}
												},
												id: 474,
												isConstant: false,
												isLValue: false,
												isPure: false,
												kind: "functionCall",
												lValueRequested: false,
												names: [
												],
												nodeType: "FunctionCall",
												src: "3847:23:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "3841:30:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 476,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 448,
											src: "3873:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "7265766f6b6544656c6567617465",
											id: 477,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "3883:16:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_f63fea8fc7bd9fe254f7933b81fa1716b5a073ddd1aa14e432aa87d81784f86c",
												typeString: "literal_string \"revokeDelegate\""
											},
											value: "revokeDelegate"
										},
										{
											argumentTypes: null,
											id: 478,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 456,
											src: "3901:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 479,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 458,
											src: "3915:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_f63fea8fc7bd9fe254f7933b81fa1716b5a073ddd1aa14e432aa87d81784f86c",
												typeString: "literal_string \"revokeDelegate\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 463,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "3804:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 480,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3804:120:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "3789:135:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 483,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 448,
											src: "3945:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 485,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 448,
													src: "3970:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 486,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 450,
													src: "3980:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 487,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 452,
													src: "3986:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 488,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 454,
													src: "3992:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 489,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 462,
													src: "3998:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 484,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "3955:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 490,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "3955:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 491,
											name: "delegateType",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 456,
											src: "4005:12:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 492,
											name: "delegate",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 458,
											src: "4019:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											}
										],
										id: 482,
										name: "revokeDelegate",
										nodeType: "Identifier",
										overloadedDeclarations: [
											428,
											446
										],
										referencedDeclaration: 428,
										src: "3930:14:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_address_$returns$__$",
											typeString: "function (address,address,bytes32,address)"
										}
									},
									id: 493,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "3930:98:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 494,
								nodeType: "ExpressionStatement",
								src: "3930:98:0"
							}
						]
					},
					documentation: null,
					id: 496,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeDelegateSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 459,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 448,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3678:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 447,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3678:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 450,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3696:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 449,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "3696:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 452,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3708:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 451,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3708:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 454,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3722:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 453,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3722:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 456,
								name: "delegateType",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3736:20:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 455,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "3736:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 458,
								name: "delegate",
								nodeType: "VariableDeclaration",
								scope: 496,
								src: "3758:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 457,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "3758:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "3677:98:0"
					},
					payable: false,
					returnParameters: {
						id: 460,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "3783:0:0"
					},
					scope: 706,
					src: "3648:385:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 532,
						nodeType: "Block",
						src: "4171:131:0",
						statements: [
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 514,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 498,
											src: "4202:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 515,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 502,
											src: "4212:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 516,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 504,
											src: "4218:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											commonType: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											id: 519,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											leftExpression: {
												argumentTypes: null,
												id: 517,
												name: "now",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 723,
												src: "4225:3:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											nodeType: "BinaryOperation",
											operator: "+",
											rightExpression: {
												argumentTypes: null,
												id: 518,
												name: "validity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 506,
												src: "4231:8:0",
												typeDescriptions: {
													typeIdentifier: "t_uint256",
													typeString: "uint256"
												}
											},
											src: "4225:14:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 520,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "4241:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 522,
											indexExpression: {
												argumentTypes: null,
												id: 521,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 498,
												src: "4249:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "4241:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 513,
										name: "DIDAttributeChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 69,
										src: "4182:19:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,bytes memory,uint256,uint256)"
										}
									},
									id: 523,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4182:77:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 524,
								nodeType: "EmitStatement",
								src: "4177:82:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 530,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 525,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "4265:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 527,
										indexExpression: {
											argumentTypes: null,
											id: 526,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 498,
											src: "4273:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "4265:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 528,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "4285:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 529,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "4285:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "4265:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 531,
								nodeType: "ExpressionStatement",
								src: "4265:32:0"
							}
						]
					},
					documentation: null,
					id: 533,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 509,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 498,
									src: "4154:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 510,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 500,
									src: "4164:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 511,
							modifierName: {
								argumentTypes: null,
								id: 508,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "4144:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "4144:26:0"
						}
					],
					name: "setAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 507,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 498,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4059:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 497,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4059:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 500,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4077:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 499,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4077:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 502,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4092:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 501,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4092:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 504,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4106:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 503,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4106:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 506,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 533,
								src: "4119:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 505,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "4119:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4058:76:0"
					},
					payable: false,
					returnParameters: {
						id: 512,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4171:0:0"
					},
					scope: 706,
					src: "4037:265:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 553,
						nodeType: "Block",
						src: "4395:68:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 545,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 535,
											src: "4414:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 546,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "4424:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 547,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "4424:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 548,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 537,
											src: "4436:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 549,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 539,
											src: "4442:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											id: 550,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 541,
											src: "4449:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 544,
										name: "setAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											533,
											554
										],
										referencedDeclaration: 533,
										src: "4401:12:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory,uint256)"
										}
									},
									id: 551,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4401:57:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 552,
								nodeType: "ExpressionStatement",
								src: "4401:57:0"
							}
						]
					},
					documentation: null,
					id: 554,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "setAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 542,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 535,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4328:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 534,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4328:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 537,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4346:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 536,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4346:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 539,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4360:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 538,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4360:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 541,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 554,
								src: "4373:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 540,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "4373:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4327:60:0"
					},
					payable: false,
					returnParameters: {
						id: 543,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4395:0:0"
					},
					scope: 706,
					src: "4306:157:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 605,
						nodeType: "Block",
						src: "4602:229:0",
						statements: [
							{
								assignments: [
									572
								],
								declarations: [
									{
										constant: false,
										id: 572,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 606,
										src: "4608:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 571,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "4608:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 590,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 575,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "4638:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 574,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "4633:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 576,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "4633:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 578,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "4650:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 577,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "4645:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 579,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "4645:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 580,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "4654:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 581,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "4660:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 583,
											indexExpression: {
												argumentTypes: null,
												id: 582,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 556,
												src: "4666:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "4660:15:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 584,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 556,
											src: "4677:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "736574417474726962757465",
											id: 585,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "4687:14:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_e5bbb0cf2a185ea034bc61efc4cb764352403a5c06c1da63a3fd765abbac4ea6",
												typeString: "literal_string \"setAttribute\""
											},
											value: "setAttribute"
										},
										{
											argumentTypes: null,
											id: 586,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 564,
											src: "4703:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 587,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 566,
											src: "4709:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											id: 588,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 568,
											src: "4716:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_e5bbb0cf2a185ea034bc61efc4cb764352403a5c06c1da63a3fd765abbac4ea6",
												typeString: "literal_string \"setAttribute\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 573,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "4623:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 589,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4623:102:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "4608:117:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 592,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 556,
											src: "4744:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 594,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 556,
													src: "4769:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 595,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 558,
													src: "4779:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 596,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 560,
													src: "4785:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 597,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 562,
													src: "4791:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 598,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 572,
													src: "4797:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 593,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "4754:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 599,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "4754:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 600,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 564,
											src: "4804:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 601,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 566,
											src: "4810:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											id: 602,
											name: "validity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 568,
											src: "4817:8:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 591,
										name: "setAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											533,
											554
										],
										referencedDeclaration: 533,
										src: "4731:12:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory,uint256)"
										}
									},
									id: 603,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4731:95:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 604,
								nodeType: "ExpressionStatement",
								src: "4731:95:0"
							}
						]
					},
					documentation: null,
					id: 606,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "setAttributeSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 569,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 556,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4495:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 555,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4495:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 558,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4513:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 557,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "4513:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 560,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4525:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 559,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4525:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 562,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4539:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 561,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4539:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 564,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4553:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 563,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4553:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 566,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4567:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 565,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4567:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 568,
								name: "validity",
								nodeType: "VariableDeclaration",
								scope: 606,
								src: "4580:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint256",
									typeString: "uint256"
								},
								typeName: {
									id: 567,
									name: "uint",
									nodeType: "ElementaryTypeName",
									src: "4580:4:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4494:100:0"
					},
					payable: false,
					returnParameters: {
						id: 570,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4602:0:0"
					},
					scope: 706,
					src: "4467:364:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 638,
						nodeType: "Block",
						src: "4957:118:0",
						statements: [
							{
								eventCall: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 622,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 608,
											src: "4988:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 623,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 612,
											src: "4998:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 624,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 614,
											src: "5004:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										},
										{
											argumentTypes: null,
											hexValue: "30",
											id: 625,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "number",
											lValueRequested: false,
											nodeType: "Literal",
											src: "5011:1:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_rational_0_by_1",
												typeString: "int_const 0"
											},
											value: "0"
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 626,
												name: "changed",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 17,
												src: "5014:7:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 628,
											indexExpression: {
												argumentTypes: null,
												id: 627,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 608,
												src: "5022:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "5014:17:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											},
											{
												typeIdentifier: "t_rational_0_by_1",
												typeString: "int_const 0"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										],
										id: 621,
										name: "DIDAttributeChanged",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 69,
										src: "4968:19:0",
										typeDescriptions: {
											typeIdentifier: "t_function_event_nonpayable$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$_t_uint256_$_t_uint256_$returns$__$",
											typeString: "function (address,bytes32,bytes memory,uint256,uint256)"
										}
									},
									id: 629,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "4968:64:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 630,
								nodeType: "EmitStatement",
								src: "4963:69:0"
							},
							{
								expression: {
									argumentTypes: null,
									id: 636,
									isConstant: false,
									isLValue: false,
									isPure: false,
									lValueRequested: false,
									leftHandSide: {
										argumentTypes: null,
										baseExpression: {
											argumentTypes: null,
											id: 631,
											name: "changed",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 17,
											src: "5038:7:0",
											typeDescriptions: {
												typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
												typeString: "mapping(address => uint256)"
											}
										},
										id: 633,
										indexExpression: {
											argumentTypes: null,
											id: 632,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 608,
											src: "5046:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										isConstant: false,
										isLValue: true,
										isPure: false,
										lValueRequested: true,
										nodeType: "IndexAccess",
										src: "5038:17:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									nodeType: "Assignment",
									operator: "=",
									rightHandSide: {
										argumentTypes: null,
										expression: {
											argumentTypes: null,
											id: 634,
											name: "block",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 711,
											src: "5058:5:0",
											typeDescriptions: {
												typeIdentifier: "t_magic_block",
												typeString: "block"
											}
										},
										id: 635,
										isConstant: false,
										isLValue: false,
										isPure: false,
										lValueRequested: false,
										memberName: "number",
										nodeType: "MemberAccess",
										referencedDeclaration: null,
										src: "5058:12:0",
										typeDescriptions: {
											typeIdentifier: "t_uint256",
											typeString: "uint256"
										}
									},
									src: "5038:32:0",
									typeDescriptions: {
										typeIdentifier: "t_uint256",
										typeString: "uint256"
									}
								},
								id: 637,
								nodeType: "ExpressionStatement",
								src: "5038:32:0"
							}
						]
					},
					documentation: null,
					id: 639,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
						{
							"arguments": [
								{
									argumentTypes: null,
									id: 617,
									name: "identity",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 608,
									src: "4940:8:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								{
									argumentTypes: null,
									id: 618,
									name: "actor",
									nodeType: "Identifier",
									overloadedDeclarations: [
									],
									referencedDeclaration: 610,
									src: "4950:5:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								}
							],
							id: 619,
							modifierName: {
								argumentTypes: null,
								id: 616,
								name: "onlyOwner",
								nodeType: "Identifier",
								overloadedDeclarations: [
								],
								referencedDeclaration: 37,
								src: "4930:9:0",
								typeDescriptions: {
									typeIdentifier: "t_modifier$_t_address_$_t_address_$",
									typeString: "modifier (address,address)"
								}
							},
							nodeType: "ModifierInvocation",
							src: "4930:26:0"
						}
					],
					name: "revokeAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 615,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 608,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4860:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 607,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4860:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 610,
								name: "actor",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4878:13:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 609,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "4878:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 612,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4893:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 611,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "4893:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 614,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 639,
								src: "4907:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 613,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "4907:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "4859:61:0"
					},
					payable: false,
					returnParameters: {
						id: 620,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "4957:0:0"
					},
					scope: 706,
					src: "4835:240:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "internal"
				},
				{
					body: {
						id: 656,
						nodeType: "Block",
						src: "5156:61:0",
						statements: [
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 649,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 641,
											src: "5178:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											expression: {
												argumentTypes: null,
												id: 650,
												name: "msg",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 721,
												src: "5188:3:0",
												typeDescriptions: {
													typeIdentifier: "t_magic_message",
													typeString: "msg"
												}
											},
											id: 651,
											isConstant: false,
											isLValue: false,
											isPure: false,
											lValueRequested: false,
											memberName: "sender",
											nodeType: "MemberAccess",
											referencedDeclaration: null,
											src: "5188:10:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 652,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 643,
											src: "5200:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 653,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 645,
											src: "5206:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										],
										id: 648,
										name: "revokeAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											639,
											657
										],
										referencedDeclaration: 639,
										src: "5162:15:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory)"
										}
									},
									id: 654,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "5162:50:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 655,
								nodeType: "ExpressionStatement",
								src: "5162:50:0"
							}
						]
					},
					documentation: null,
					id: 657,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeAttribute",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 646,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 641,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 657,
								src: "5104:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 640,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "5104:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 643,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 657,
								src: "5122:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 642,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5122:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 645,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 657,
								src: "5136:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 644,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "5136:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "5103:45:0"
					},
					payable: false,
					returnParameters: {
						id: 647,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "5156:0:0"
					},
					scope: 706,
					src: "5079:138:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				},
				{
					body: {
						id: 704,
						nodeType: "Block",
						src: "5343:216:0",
						statements: [
							{
								assignments: [
									673
								],
								declarations: [
									{
										constant: false,
										id: 673,
										name: "hash",
										nodeType: "VariableDeclaration",
										scope: 705,
										src: "5349:12:0",
										stateVariable: false,
										storageLocation: "default",
										typeDescriptions: {
											typeIdentifier: "t_bytes32",
											typeString: "bytes32"
										},
										typeName: {
											id: 672,
											name: "bytes32",
											nodeType: "ElementaryTypeName",
											src: "5349:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										value: null,
										visibility: "internal"
									}
								],
								id: 690,
								initialValue: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30783139",
													id: 676,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "5379:4:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													},
													value: "0x19"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_25_by_1",
														typeString: "int_const 25"
													}
												],
												id: 675,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "5374:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 677,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "5374:10:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													hexValue: "30",
													id: 679,
													isConstant: false,
													isLValue: false,
													isPure: true,
													kind: "number",
													lValueRequested: false,
													nodeType: "Literal",
													src: "5391:1:0",
													subdenomination: null,
													typeDescriptions: {
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													},
													value: "0"
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_rational_0_by_1",
														typeString: "int_const 0"
													}
												],
												id: 678,
												isConstant: false,
												isLValue: false,
												isPure: true,
												lValueRequested: false,
												nodeType: "ElementaryTypeNameExpression",
												src: "5386:4:0",
												typeDescriptions: {
													typeIdentifier: "t_type$_t_bytes1_$",
													typeString: "type(bytes1)"
												},
												typeName: "byte"
											},
											id: 680,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "typeConversion",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "5386:7:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											}
										},
										{
											argumentTypes: null,
											id: 681,
											name: "this",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 734,
											src: "5395:4:0",
											typeDescriptions: {
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											}
										},
										{
											argumentTypes: null,
											baseExpression: {
												argumentTypes: null,
												id: 682,
												name: "nonce",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 21,
												src: "5401:5:0",
												typeDescriptions: {
													typeIdentifier: "t_mapping$_t_address_$_t_uint256_$",
													typeString: "mapping(address => uint256)"
												}
											},
											id: 684,
											indexExpression: {
												argumentTypes: null,
												id: 683,
												name: "identity",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 659,
												src: "5407:8:0",
												typeDescriptions: {
													typeIdentifier: "t_address",
													typeString: "address"
												}
											},
											isConstant: false,
											isLValue: true,
											isPure: false,
											lValueRequested: false,
											nodeType: "IndexAccess",
											src: "5401:15:0",
											typeDescriptions: {
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											}
										},
										{
											argumentTypes: null,
											id: 685,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 659,
											src: "5418:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											hexValue: "7265766f6b65417474726962757465",
											id: 686,
											isConstant: false,
											isLValue: false,
											isPure: true,
											kind: "string",
											lValueRequested: false,
											nodeType: "Literal",
											src: "5428:17:0",
											subdenomination: null,
											typeDescriptions: {
												typeIdentifier: "t_stringliteral_168e4cc0ad03cc4b6896d89f8a470b9997cd8bbe87ac639c5474674fa958f860",
												typeString: "literal_string \"revokeAttribute\""
											},
											value: "revokeAttribute"
										},
										{
											argumentTypes: null,
											id: 687,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 667,
											src: "5447:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 688,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 669,
											src: "5453:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_bytes1",
												typeString: "bytes1"
											},
											{
												typeIdentifier: "t_contract$_EthereumDIDRegistry_$706",
												typeString: "contract EthereumDIDRegistry"
											},
											{
												typeIdentifier: "t_uint256",
												typeString: "uint256"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_stringliteral_168e4cc0ad03cc4b6896d89f8a470b9997cd8bbe87ac639c5474674fa958f860",
												typeString: "literal_string \"revokeAttribute\""
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										],
										id: 674,
										name: "keccak256",
										nodeType: "Identifier",
										overloadedDeclarations: [
										],
										referencedDeclaration: 715,
										src: "5364:9:0",
										typeDescriptions: {
											typeIdentifier: "t_function_sha3_pure$__$returns$_t_bytes32_$",
											typeString: "function () pure returns (bytes32)"
										}
									},
									id: 689,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "5364:95:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								nodeType: "VariableDeclarationStatement",
								src: "5349:110:0"
							},
							{
								expression: {
									argumentTypes: null,
									"arguments": [
										{
											argumentTypes: null,
											id: 692,
											name: "identity",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 659,
											src: "5482:8:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											"arguments": [
												{
													argumentTypes: null,
													id: 694,
													name: "identity",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 659,
													src: "5507:8:0",
													typeDescriptions: {
														typeIdentifier: "t_address",
														typeString: "address"
													}
												},
												{
													argumentTypes: null,
													id: 695,
													name: "sigV",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 661,
													src: "5517:4:0",
													typeDescriptions: {
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													}
												},
												{
													argumentTypes: null,
													id: 696,
													name: "sigR",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 663,
													src: "5523:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 697,
													name: "sigS",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 665,
													src: "5529:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												},
												{
													argumentTypes: null,
													id: 698,
													name: "hash",
													nodeType: "Identifier",
													overloadedDeclarations: [
													],
													referencedDeclaration: 673,
													src: "5535:4:0",
													typeDescriptions: {
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												}
											],
											expression: {
												argumentTypes: [
													{
														typeIdentifier: "t_address",
														typeString: "address"
													},
													{
														typeIdentifier: "t_uint8",
														typeString: "uint8"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													},
													{
														typeIdentifier: "t_bytes32",
														typeString: "bytes32"
													}
												],
												id: 693,
												name: "checkSignature",
												nodeType: "Identifier",
												overloadedDeclarations: [
												],
												referencedDeclaration: 132,
												src: "5492:14:0",
												typeDescriptions: {
													typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_uint8_$_t_bytes32_$_t_bytes32_$_t_bytes32_$returns$_t_address_$",
													typeString: "function (address,uint8,bytes32,bytes32,bytes32) returns (address)"
												}
											},
											id: 699,
											isConstant: false,
											isLValue: false,
											isPure: false,
											kind: "functionCall",
											lValueRequested: false,
											names: [
											],
											nodeType: "FunctionCall",
											src: "5492:48:0",
											typeDescriptions: {
												typeIdentifier: "t_address",
												typeString: "address"
											}
										},
										{
											argumentTypes: null,
											id: 700,
											name: "name",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 667,
											src: "5542:4:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											}
										},
										{
											argumentTypes: null,
											id: 701,
											name: "value",
											nodeType: "Identifier",
											overloadedDeclarations: [
											],
											referencedDeclaration: 669,
											src: "5548:5:0",
											typeDescriptions: {
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										}
									],
									expression: {
										argumentTypes: [
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_address",
												typeString: "address"
											},
											{
												typeIdentifier: "t_bytes32",
												typeString: "bytes32"
											},
											{
												typeIdentifier: "t_bytes_memory_ptr",
												typeString: "bytes memory"
											}
										],
										id: 691,
										name: "revokeAttribute",
										nodeType: "Identifier",
										overloadedDeclarations: [
											639,
											657
										],
										referencedDeclaration: 639,
										src: "5466:15:0",
										typeDescriptions: {
											typeIdentifier: "t_function_internal_nonpayable$_t_address_$_t_address_$_t_bytes32_$_t_bytes_memory_ptr_$returns$__$",
											typeString: "function (address,address,bytes32,bytes memory)"
										}
									},
									id: 702,
									isConstant: false,
									isLValue: false,
									isPure: false,
									kind: "functionCall",
									lValueRequested: false,
									names: [
									],
									nodeType: "FunctionCall",
									src: "5466:88:0",
									typeDescriptions: {
										typeIdentifier: "t_tuple$__$",
										typeString: "tuple()"
									}
								},
								id: 703,
								nodeType: "ExpressionStatement",
								src: "5466:88:0"
							}
						]
					},
					documentation: null,
					id: 705,
					implemented: true,
					isConstructor: false,
					isDeclaredConst: false,
					modifiers: [
					],
					name: "revokeAttributeSigned",
					nodeType: "FunctionDefinition",
					parameters: {
						id: 670,
						nodeType: "ParameterList",
						parameters: [
							{
								constant: false,
								id: 659,
								name: "identity",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5251:16:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_address",
									typeString: "address"
								},
								typeName: {
									id: 658,
									name: "address",
									nodeType: "ElementaryTypeName",
									src: "5251:7:0",
									typeDescriptions: {
										typeIdentifier: "t_address",
										typeString: "address"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 661,
								name: "sigV",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5269:10:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_uint8",
									typeString: "uint8"
								},
								typeName: {
									id: 660,
									name: "uint8",
									nodeType: "ElementaryTypeName",
									src: "5269:5:0",
									typeDescriptions: {
										typeIdentifier: "t_uint8",
										typeString: "uint8"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 663,
								name: "sigR",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5281:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 662,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5281:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 665,
								name: "sigS",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5295:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 664,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5295:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 667,
								name: "name",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5309:12:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes32",
									typeString: "bytes32"
								},
								typeName: {
									id: 666,
									name: "bytes32",
									nodeType: "ElementaryTypeName",
									src: "5309:7:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes32",
										typeString: "bytes32"
									}
								},
								value: null,
								visibility: "internal"
							},
							{
								constant: false,
								id: 669,
								name: "value",
								nodeType: "VariableDeclaration",
								scope: 705,
								src: "5323:11:0",
								stateVariable: false,
								storageLocation: "default",
								typeDescriptions: {
									typeIdentifier: "t_bytes_memory_ptr",
									typeString: "bytes"
								},
								typeName: {
									id: 668,
									name: "bytes",
									nodeType: "ElementaryTypeName",
									src: "5323:5:0",
									typeDescriptions: {
										typeIdentifier: "t_bytes_storage_ptr",
										typeString: "bytes"
									}
								},
								value: null,
								visibility: "internal"
							}
						],
						src: "5250:85:0"
					},
					payable: false,
					returnParameters: {
						id: 671,
						nodeType: "ParameterList",
						parameters: [
						],
						src: "5343:0:0"
					},
					scope: 706,
					src: "5220:339:0",
					stateMutability: "nonpayable",
					superFunction: null,
					visibility: "public"
				}
			],
			scope: 707,
			src: "25:5537:0"
		}
	],
	src: "0:5563:0"
};
var compiler = {
	name: "solc",
	version: "0.4.24+commit.e67f0147.Emscripten.clang"
};
var networks = {
	"1": {
		events: {
		},
		links: {
		},
		address: "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b"
	},
	"3": {
		events: {
		},
		links: {
		},
		address: "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b"
	},
	"4": {
		events: {
		},
		links: {
		},
		address: "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b"
	},
	"42": {
		events: {
		},
		links: {
		},
		address: "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b"
	}
};
var schemaVersion = "2.0.0";
var updatedAt = "2018-06-15T00:50:05.725Z";
var DidRegistryContract = {
	contractName: contractName,
	abi: abi,
	bytecode: bytecode,
	deployedBytecode: deployedBytecode,
	sourceMap: sourceMap,
	deployedSourceMap: deployedSourceMap,
	source: source,
	sourcePath: sourcePath,
	ast: ast,
	legacyAST: legacyAST,
	compiler: compiler,
	networks: networks,
	schemaVersion: schemaVersion,
	updatedAt: updatedAt
};

const identifierMatcher = /^(.*)?(0x[0-9a-fA-F]{40}|0x[0-9a-fA-F]{66})$/;
const nullAddress = '0x0000000000000000000000000000000000000000';
const DEFAULT_REGISTRY_ADDRESS = '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b';
var verificationMethodTypes;
(function (verificationMethodTypes) {
    verificationMethodTypes["EcdsaSecp256k1VerificationKey2019"] = "EcdsaSecp256k1VerificationKey2019";
    verificationMethodTypes["EcdsaSecp256k1RecoveryMethod2020"] = "EcdsaSecp256k1RecoveryMethod2020";
    verificationMethodTypes["Ed25519VerificationKey2018"] = "Ed25519VerificationKey2018";
    verificationMethodTypes["RSAVerificationKey2018"] = "RSAVerificationKey2018";
    verificationMethodTypes["X25519KeyAgreementKey2019"] = "X25519KeyAgreementKey2019";
})(verificationMethodTypes || (verificationMethodTypes = {}));
var eventNames;
(function (eventNames) {
    eventNames["DIDOwnerChanged"] = "DIDOwnerChanged";
    eventNames["DIDAttributeChanged"] = "DIDAttributeChanged";
    eventNames["DIDDelegateChanged"] = "DIDDelegateChanged";
})(eventNames || (eventNames = {}));
const legacyAttrTypes = {
    sigAuth: 'SignatureAuthentication2018',
    veriKey: 'VerificationKey2018',
    enc: 'KeyAgreementKey2019',
};
const legacyAlgoMap = {
    /**@deprecated */
    Secp256k1VerificationKey2018: verificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
    /**@deprecated */
    Ed25519SignatureAuthentication2018: verificationMethodTypes.Ed25519VerificationKey2018,
    /**@deprecated */
    Secp256k1SignatureAuthentication2018: verificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
    //keep legacy mapping
    RSAVerificationKey2018: verificationMethodTypes.RSAVerificationKey2018,
    Ed25519VerificationKey2018: verificationMethodTypes.Ed25519VerificationKey2018,
    X25519KeyAgreementKey2019: verificationMethodTypes.X25519KeyAgreementKey2019,
};
function bytes32toString(input) {
    const buff = typeof input === 'string' ? Buffer.from(input.slice(2), 'hex') : Buffer.from(input);
    return buff.toString('utf8').replace(/\0+$/, '');
}
function stringToBytes32(str) {
    const buffStr = '0x' + Buffer.from(str).slice(0, 32).toString('hex');
    return buffStr + '0'.repeat(66 - buffStr.length);
}
function interpretIdentifier(identifier) {
    let id = identifier;
    let network = undefined;
    if (id.startsWith('did:ethr')) {
        id = id.split('?')[0];
        const components = id.split(':');
        id = components[components.length - 1];
        if (components.length >= 4) {
            network = components.splice(2, components.length - 3).join(':');
        }
    }
    if (id.length > 42) {
        return { address: computeAddress(id), publicKey: id, network };
    }
    else {
        return { address: getAddress(id), network }; // checksum address
    }
}
const knownInfuraNetworks = {
    mainnet: '0x1',
    ropsten: '0x3',
    rinkeby: '0x4',
    goerli: '0x5',
    kovan: '0x2a',
};
const knownNetworks = {
    ...knownInfuraNetworks,
    rsk: '0x1e',
    'rsk:testnet': '0x1f',
    artis_t1: '0x03c401',
    artis_s1: '0x03c301',
    matic: '0x89',
    maticmum: '0x13881',
};
var Errors;
(function (Errors) {
    /**
     * The resolver has failed to construct the DID document.
     * This can be caused by a network issue, a wrong registry address or malformed logs while parsing the registry history.
     * Please inspect the `DIDResolutionMetadata.message` to debug further.
     */
    Errors["notFound"] = "notFound";
    /**
     * The resolver does not know how to resolve the given DID. Most likely it is not a `did:ethr`.
     */
    Errors["invalidDid"] = "invalidDid";
    /**
     * The resolver is misconfigured or is being asked to resolve a DID anchored on an unknown network
     */
    Errors["unknownNetwork"] = "unknownNetwork";
})(Errors || (Errors = {}));

function configureNetworksWithInfura(projectId) {
    if (!projectId) {
        return {};
    }
    const networks = [
        { name: 'mainnet', chainId: '0x1', provider: new InfuraProvider('homestead', projectId) },
        { name: 'ropsten', chainId: '0x3', provider: new InfuraProvider('ropsten', projectId) },
        { name: 'rinkeby', chainId: '0x4', provider: new InfuraProvider('rinkeby', projectId) },
        { name: 'goerli', chainId: '0x5', provider: new InfuraProvider('goerli', projectId) },
        { name: 'kovan', chainId: '0x2a', provider: new InfuraProvider('kovan', projectId) },
    ];
    return configureNetworks({ networks });
}
function getContractForNetwork(conf) {
    let provider = conf.provider || conf.web3?.currentProvider;
    if (!provider) {
        if (conf.rpcUrl) {
            const chainIdRaw = conf.chainId ? conf.chainId : knownNetworks[conf.name || ''];
            const chainId = chainIdRaw ? BigNumber.from(chainIdRaw).toNumber() : chainIdRaw;
            const networkName = knownInfuraNetworks[conf.name || ''] ? conf.name?.replace('mainnet', 'homestead') : 'any';
            provider = new JsonRpcProvider(conf.rpcUrl, chainId || networkName);
        }
        else {
            throw new Error(`invalid_config: No web3 provider could be determined for network ${conf.name || conf.chainId}`);
        }
    }
    const contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach(conf.registry || DEFAULT_REGISTRY_ADDRESS)
        .connect(provider);
    return contract;
}
function configureNetwork(net) {
    const networks = {};
    const chainId = net.chainId || knownNetworks[net.name || ''];
    if (chainId) {
        if (net.name) {
            networks[net.name] = getContractForNetwork(net);
        }
        const id = typeof chainId === 'number' ? `0x${chainId.toString(16)}` : chainId;
        networks[id] = getContractForNetwork(net);
    }
    else if (net.provider || net.web3 || net.rpcUrl) {
        networks[net.name || ''] = getContractForNetwork(net);
    }
    return networks;
}
function configureNetworks(conf) {
    return {
        ...configureNetwork(conf),
        ...conf.networks?.reduce((networks, net) => {
            return { ...networks, ...configureNetwork(net) };
        }, {}),
    };
}
/**
 * Generates a configuration that maps ethereum network names and chainIDs to the respective ERC1056 contracts deployed on them.
 * @returns a record of ERC1056 `Contract` instances
 * @param conf configuration options for the resolver. An array of network details.
 * Each network entry should contain at least one of `name` or `chainId` AND one of `provider`, `web3`, or `rpcUrl`
 * For convenience, you can also specify an `infuraProjectId` which will create a mapping for all the networks supported by https://infura.io.
 * @example ```js
 * [
 *   { name: 'development', registry: '0x9af37603e98e0dc2b855be647c39abe984fc2445', rpcUrl: 'http://127.0.0.1:8545/' },
 *   { name: 'goerli', chainId: 5, provider: new InfuraProvider('goerli') },
 *   { name: 'rinkeby', provider: new AlchemyProvider('rinkeby') },
 *   { name: 'rsk:testnet', chainId: '0x1f', rpcUrl: 'https://public-node.testnet.rsk.co' },
 * ]
 * ```
 */
function configureResolverWithNetworks(conf = {}) {
    const networks = {
        ...configureNetworksWithInfura(conf.infuraProjectId),
        ...configureNetworks(conf),
    };
    if (Object.keys(networks).length === 0) {
        throw new Error('invalid_config: Please make sure to have at least one network');
    }
    return networks;
}

/**
 * A class that can be used to interact with the ERC1056 contract on behalf of a local controller key-pair
 */
class EthrDidController {
    /**
     * Creates an EthrDidController instance.
     *
     * @param identifier - required - a `did:ethr` string or a publicKeyHex or an ethereum address
     * @param signer - optional - a Signer that represents the current controller key (owner) of the identifier. If a 'signer' is not provided, then a 'contract' with an attached signer can be used.
     * @param contract - optional - a Contract instance representing a ERC1056 contract. At least one of `contract`, `provider`, or `rpcUrl` is required
     * @param chainNameOrId - optional - the network name or chainID, defaults to 'mainnet'
     * @param provider - optional - a web3 Provider. At least one of `contract`, `provider`, or `rpcUrl` is required
     * @param rpcUrl - optional - a JSON-RPC URL that can be used to connect to an ethereum network. At least one of `contract`, `provider`, or `rpcUrl` is required
     * @param registry - optional - The ERC1056 registry address. Defaults to '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'. Only used with 'provider' or 'rpcUrl'
     */
    constructor(identifier, contract, signer, chainNameOrId = 'mainnet', provider, rpcUrl, registry = DEFAULT_REGISTRY_ADDRESS) {
        // initialize identifier
        const { address, publicKey, network } = interpretIdentifier(identifier);
        const net = network || chainNameOrId;
        // initialize contract connection
        if (contract) {
            this.contract = contract;
        }
        else if (provider || signer?.provider || rpcUrl) {
            const prov = provider || signer?.provider;
            this.contract = getContractForNetwork({ name: net, provider: prov, registry, rpcUrl });
        }
        else {
            throw new Error(' either a contract instance or a provider or rpcUrl is required to initialize');
        }
        this.signer = signer;
        this.address = address;
        let networkString = net ? `${net}:` : '';
        if (networkString in ['mainnet:', '0x1:']) {
            networkString = '';
        }
        this.did = publicKey ? `did:ethr:${networkString}${publicKey}` : `did:ethr:${networkString}${address}`;
    }
    async getOwner(address, blockTag) {
        const result = await this.contract.functions.identityOwner(address, { blockTag });
        return result[0];
    }
    async attachContract(controller) {
        const currentOwner = controller ? await controller : await this.getOwner(this.address, 'latest');
        const signer = this.signer
            ? this.signer
            : this.contract.provider.getSigner(currentOwner) || this.contract.signer;
        return this.contract.connect(signer);
    }
    async changeOwner(newOwner, options = {}) {
        // console.log(`changing owner for ${oldOwner} on registry at ${registryContract.address}`)
        const overrides = {
            gasLimit: 123456,
            gasPrice: 1000000000,
            ...options,
        };
        const contract = await this.attachContract(overrides.from);
        delete overrides.from;
        const ownerChange = await contract.functions.changeOwner(this.address, newOwner, overrides);
        return await ownerChange.wait();
    }
    async addDelegate(delegateType, delegateAddress, exp, options = {}) {
        const overrides = {
            gasLimit: 123456,
            gasPrice: 1000000000,
            ...options,
        };
        const contract = await this.attachContract(overrides.from);
        delete overrides.from;
        const delegateTypeBytes = stringToBytes32(delegateType);
        const addDelegateTx = await contract.functions.addDelegate(this.address, delegateTypeBytes, delegateAddress, exp, overrides);
        return await addDelegateTx.wait();
    }
    async revokeDelegate(delegateType, delegateAddress, options = {}) {
        const overrides = {
            gasLimit: 123456,
            gasPrice: 1000000000,
            ...options,
        };
        delegateType = delegateType.startsWith('0x') ? delegateType : stringToBytes32(delegateType);
        const contract = await this.attachContract(overrides.from);
        delete overrides.from;
        const addDelegateTx = await contract.functions.revokeDelegate(this.address, delegateType, delegateAddress, overrides);
        return await addDelegateTx.wait();
    }
    async setAttribute(attrName, attrValue, exp, options = {}) {
        const overrides = {
            gasLimit: 123456,
            gasPrice: 1000000000,
            controller: undefined,
            ...options,
        };
        attrName = attrName.startsWith('0x') ? attrName : stringToBytes32(attrName);
        attrValue = attrValue.startsWith('0x') ? attrValue : '0x' + Buffer.from(attrValue, 'utf-8').toString('hex');
        const contract = await this.attachContract(overrides.from);
        delete overrides.from;
        const setAttrTx = await contract.functions.setAttribute(this.address, attrName, attrValue, exp, overrides);
        return await setAttrTx.wait();
    }
    async revokeAttribute(attrName, attrValue, options = {}) {
        // console.log(`revoking attribute ${attrName}(${attrValue}) for ${identity}`)
        const overrides = {
            gasLimit: 123456,
            gasPrice: 1000000000,
            ...options,
        };
        attrName = attrName.startsWith('0x') ? attrName : stringToBytes32(attrName);
        attrValue = attrValue.startsWith('0x') ? attrValue : '0x' + Buffer.from(attrValue, 'utf-8').toString('hex');
        const contract = await this.attachContract(overrides.from);
        delete overrides.from;
        const revokeAttributeTX = await contract.functions.revokeAttribute(this.address, attrName, attrValue, overrides);
        return await revokeAttributeTX.wait();
    }
}

function populateEventMetaClass(logResult, blockNumber) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = {};
    if (logResult.eventFragment.inputs.length !== logResult.args.length) {
        throw new TypeError('malformed event input. wrong number of arguments');
    }
    logResult.eventFragment.inputs.forEach((input, index) => {
        let val = logResult.args[index];
        if (typeof val === 'object') {
            val = BigNumber.from(val);
        }
        if (input.type === 'bytes32') {
            val = bytes32toString(val);
        }
        result[input.name] = val;
    });
    result._eventName = logResult.name;
    result.blockNumber = blockNumber;
    return result;
}
function logDecoder(contract, logs) {
    const results = logs.map((log) => {
        const res = contract.interface.parseLog(log);
        const event = populateEventMetaClass(res, log.blockNumber);
        return event;
    });
    return results;
}

class EthrDidResolver {
    constructor(options) {
        this.contracts = configureResolverWithNetworks(options);
    }
    /**
     * returns the current owner of a DID (represented by an address or public key)
     *
     * @param address
     */
    async getOwner(address, networkId, blockTag) {
        //TODO: check if address or public key
        return new EthrDidController(address, this.contracts[networkId]).getOwner(address, blockTag);
    }
    /**
     * returns the previous change
     *
     * @param address
     */
    async previousChange(address, networkId, blockTag) {
        const result = await this.contracts[networkId].functions.changed(address, { blockTag });
        // console.log(`last change result: '${BigNumber.from(result['0'])}'`)
        return BigNumber.from(result['0']);
    }
    async getBlockMetadata(blockHeight, networkId) {
        const block = await this.contracts[networkId].provider.getBlock(blockHeight);
        return {
            height: block.number.toString(),
            isoDate: new Date(block.timestamp * 1000).toISOString().replace('.000', ''),
        };
    }
    async changeLog(identity, networkId, blockTag = 'latest') {
        const contract = this.contracts[networkId];
        const provider = contract.provider;
        const hexChainId = networkId.startsWith('0x') ? networkId : knownNetworks[networkId];
        //TODO: this can be used to check if the configuration is ok
        const chainId = hexChainId ? BigNumber.from(hexChainId).toNumber() : (await provider.getNetwork()).chainId;
        const history = [];
        const { address, publicKey } = interpretIdentifier(identity);
        const controllerKey = publicKey;
        let previousChange = await this.previousChange(address, networkId, blockTag);
        while (previousChange) {
            const blockNumber = previousChange;
            // console.log(`gigel ${previousChange}`)
            const logs = await provider.getLogs({
                address: contract.address,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                topics: [null, `0x000000000000000000000000${address.slice(2)}`],
                fromBlock: previousChange.toHexString(),
                toBlock: previousChange.toHexString(),
            });
            const events = logDecoder(contract, logs);
            events.reverse();
            previousChange = null;
            for (const event of events) {
                history.unshift(event);
                if (event.previousChange.lt(blockNumber)) {
                    previousChange = event.previousChange;
                }
            }
        }
        return { address, history, controllerKey, chainId };
    }
    wrapDidDocument(did, address, controllerKey, history, chainId, blockHeight, now) {
        const baseDIDDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld',
            ],
            id: did,
            verificationMethod: [],
            authentication: [],
            assertionMethod: [],
        };
        let controller = address;
        const authentication = [`${did}#controller`];
        const keyAgreement = [];
        let versionId = 0;
        let nextVersionId = Number.POSITIVE_INFINITY;
        let deactivated = false;
        let delegateCount = 0;
        let serviceCount = 0;
        const auth = {};
        const keyAgreementRefs = {};
        const pks = {};
        const services = {};
        for (const event of history) {
            if (blockHeight !== -1 && event.blockNumber > blockHeight) {
                if (nextVersionId > event.blockNumber) {
                    nextVersionId = event.blockNumber;
                }
                continue;
            }
            else {
                if (versionId < event.blockNumber) {
                    versionId = event.blockNumber;
                }
            }
            const validTo = event.validTo || BigNumber.from(0);
            const eventIndex = `${event._eventName}-${event.delegateType || event.name}-${event.delegate || event.value}`;
            if (validTo && validTo.gte(now)) {
                if (event._eventName === eventNames.DIDDelegateChanged) {
                    const currentEvent = event;
                    delegateCount++;
                    const delegateType = currentEvent.delegateType; //conversion from bytes32 is done in logParser
                    switch (delegateType) {
                        case 'sigAuth':
                            auth[eventIndex] = `${did}#delegate-${delegateCount}`;
                        // eslint-disable-line no-fallthrough
                        case 'veriKey':
                            pks[eventIndex] = {
                                id: `${did}#delegate-${delegateCount}`,
                                type: verificationMethodTypes.EcdsaSecp256k1RecoveryMethod2020,
                                controller: did,
                                blockchainAccountId: `${currentEvent.delegate}@eip155:${chainId}`,
                            };
                            break;
                    }
                }
                else if (event._eventName === eventNames.DIDAttributeChanged) {
                    const currentEvent = event;
                    const name = currentEvent.name; //conversion from bytes32 is done in logParser
                    const match = name.match(/^did\/(pub|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/);
                    if (match) {
                        const section = match[1];
                        const algorithm = match[2];
                        const type = legacyAttrTypes[match[4]] || match[4];
                        const encoding = match[6];
                        switch (section) {
                            case 'pub': {
                                delegateCount++;
                                const pk = {
                                    id: `${did}#delegate-${delegateCount}`,
                                    type: `${algorithm}${type}`,
                                    controller: did,
                                };
                                pk.type = legacyAlgoMap[pk.type] || algorithm;
                                switch (encoding) {
                                    case null:
                                    case undefined:
                                    case 'hex':
                                        pk.publicKeyHex = currentEvent.value.slice(2);
                                        break;
                                    case 'base64':
                                        pk.publicKeyBase64 = Buffer.from(currentEvent.value.slice(2), 'hex').toString('base64');
                                        break;
                                    case 'base58':
                                        pk.publicKeyBase58 = Base58.encode(Buffer.from(currentEvent.value.slice(2), 'hex'));
                                        break;
                                    case 'pem':
                                        pk.publicKeyPem = Buffer.from(currentEvent.value.slice(2), 'hex').toString();
                                        break;
                                    default:
                                        pk.value = currentEvent.value;
                                }
                                pks[eventIndex] = pk;
                                if (match[4] === 'sigAuth') {
                                    auth[eventIndex] = pk.id;
                                }
                                else if (match[4] === 'enc') {
                                    keyAgreementRefs[eventIndex] = pk.id;
                                }
                                break;
                            }
                            case 'svc':
                                serviceCount++;
                                services[eventIndex] = {
                                    id: `${did}#service-${serviceCount}`,
                                    type: algorithm,
                                    serviceEndpoint: Buffer.from(currentEvent.value.slice(2), 'hex').toString(),
                                };
                                break;
                        }
                    }
                }
            }
            else if (event._eventName === eventNames.DIDOwnerChanged) {
                const currentEvent = event;
                controller = currentEvent.owner;
                if (currentEvent.owner === nullAddress) {
                    deactivated = true;
                    break;
                }
            }
            else {
                if (event._eventName === eventNames.DIDDelegateChanged ||
                    (event._eventName === eventNames.DIDAttributeChanged &&
                        event.name.match(/^did\/pub\//))) {
                    delegateCount++;
                }
                else if (event._eventName === eventNames.DIDAttributeChanged &&
                    event.name.match(/^did\/svc\//)) {
                    serviceCount++;
                }
                delete auth[eventIndex];
                delete pks[eventIndex];
                delete services[eventIndex];
            }
        }
        const publicKeys = [
            {
                id: `${did}#controller`,
                type: verificationMethodTypes.EcdsaSecp256k1RecoveryMethod2020,
                controller: did,
                blockchainAccountId: `${controller}@eip155:${chainId}`,
            },
        ];
        if (controllerKey && controller == address) {
            publicKeys.push({
                id: `${did}#controllerKey`,
                type: verificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
                controller: did,
                publicKeyHex: controllerKey,
            });
            authentication.push(`${did}#controllerKey`);
        }
        const didDocument = {
            ...baseDIDDocument,
            verificationMethod: publicKeys.concat(Object.values(pks)),
            authentication: authentication.concat(Object.values(auth)),
        };
        if (Object.values(services).length > 0) {
            didDocument.service = Object.values(services);
        }
        if (Object.values(keyAgreementRefs).length > 0) {
            didDocument.keyAgreement = keyAgreement.concat(Object.values(keyAgreementRefs));
        }
        didDocument.assertionMethod = [...(didDocument.verificationMethod?.map((pk) => pk.id) || [])];
        return deactivated
            ? {
                didDocument: { ...baseDIDDocument, '@context': 'https://www.w3.org/ns/did/v1' },
                deactivated,
                versionId,
                nextVersionId,
            }
            : { didDocument, deactivated, versionId, nextVersionId };
    }
    async resolve(did, parsed, 
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _unused, options) {
        const fullId = parsed.id.match(identifierMatcher);
        if (!fullId) {
            return {
                didResolutionMetadata: {
                    error: Errors.invalidDid,
                    message: `Not a valid did:ethr: ${parsed.id}`,
                },
                didDocumentMetadata: {},
                didDocument: null,
            };
        }
        const id = fullId[2];
        const networkId = !fullId[1] ? 'mainnet' : fullId[1].slice(0, -1);
        let blockTag = options.blockTag || 'latest';
        if (typeof parsed.query === 'string') {
            const qParams = qs.decode(parsed.query);
            blockTag = typeof qParams['versionId'] === 'string' ? qParams['versionId'] : blockTag;
            try {
                blockTag = Number.parseInt(blockTag);
            }
            catch (e) {
                blockTag = 'latest';
                // invalid versionId parameters are ignored
            }
        }
        if (!this.contracts[networkId]) {
            return {
                didResolutionMetadata: {
                    error: Errors.unknownNetwork,
                    message: `The DID resolver does not have a configuration for network: ${networkId}`,
                },
                didDocumentMetadata: {},
                didDocument: null,
            };
        }
        let now = BigNumber.from(Math.floor(new Date().getTime() / 1000));
        if (typeof blockTag === 'number') {
            const block = await this.getBlockMetadata(blockTag, networkId);
            now = BigNumber.from(Date.parse(block.isoDate) / 1000);
        }
        const { address, history, controllerKey, chainId } = await this.changeLog(id, networkId, 'latest');
        try {
            const { didDocument, deactivated, versionId, nextVersionId } = this.wrapDidDocument(did, address, controllerKey, history, chainId, blockTag, now);
            const status = deactivated ? { deactivated: true } : {};
            let versionMeta = {};
            let versionMetaNext = {};
            if (versionId !== 0) {
                const block = await this.getBlockMetadata(versionId, networkId);
                versionMeta = {
                    versionId: block.height,
                    updated: block.isoDate,
                };
            }
            if (nextVersionId !== Number.POSITIVE_INFINITY) {
                const block = await this.getBlockMetadata(nextVersionId, networkId);
                versionMetaNext = {
                    nextVersionId: block.height,
                    nextUpdate: block.isoDate,
                };
            }
            return {
                didDocumentMetadata: { ...status, ...versionMeta, ...versionMetaNext },
                didResolutionMetadata: { contentType: 'application/did+ld+json' },
                didDocument,
            };
        }
        catch (e) {
            return {
                didResolutionMetadata: {
                    error: Errors.notFound,
                    message: e.toString(), // This is not in spec, nut may be helpful
                },
                didDocumentMetadata: {},
                didDocument: null,
            };
        }
    }
    build() {
        return { ethr: this.resolve.bind(this) };
    }
}

function getResolver(options) {
    return new EthrDidMultipleRpcResolver(options).build();
}
class EthrDidMultipleRpcResolver {
    constructor(options) {
        this.options = options;
        this.resolvers = [];
        const providerConfs = [];
        options.networks.forEach(conf => {
            if (conf.rpcUrl instanceof Array) {
                conf.rpcUrl.forEach((rpcUrl, index) => {
                    if (providerConfs[index] === undefined)
                        providerConfs[index] = [];
                    providerConfs[index].push({
                        name: conf.network,
                        rpcUrl: rpcUrl
                    });
                });
            }
            else {
                if (providerConfs[0] === undefined)
                    providerConfs[0] = [];
                providerConfs[0].push({
                    name: conf.network,
                    rpcUrl: conf.rpcUrl
                });
            }
        });
        providerConfs.forEach(conf => {
            const resolver = new EthrDidResolver({
                networks: conf
            });
            this.resolvers.push(resolver);
        });
        if (this.resolvers.length === 0) {
            throw new Error('no networks');
        }
        this.networks = options.networks;
        this.multiRpcOptions = options.multiRpcOptions ?? {};
    }
    async getOwner(address, networkId, blockTag) {
        // return await this.resolvers[0].getOwner(address, networkId, blockTag)
        return await this.multiproviderFnExec('getOwner', address, networkId, blockTag);
    }
    async previousChange(address, networkId, blockTag) {
        return await this.multiproviderFnExec('previousChange', address, networkId, blockTag);
    }
    async getBlockMetadata(blockHeight, networkId) {
        return await this.multiproviderFnExec('getBlockMetadata', blockHeight, networkId);
    }
    async changeLog(identity, networkId, blockTag) {
        return await this.multiproviderFnExec('changeLog', identity, networkId, blockTag);
    }
    wrapDidDocument(did, address, controllerKey, history, chainId, blockHeight, now) {
        return this.resolvers[0].wrapDidDocument(did, address, controllerKey, history, chainId, blockHeight, now);
    }
    async resolve(did, parsed, _unused, options) {
        return await this.multiproviderFnExec('resolve', did, parsed, _unused, options);
    }
    build() {
        return { ethr: this.resolve.bind(this) };
    }
    async multiproviderFnExec(fnName, ...args) {
        const results = await multipleExecutions(this.multiRpcOptions, this.resolvers, fnName, ...args);
        if (allEqual(results))
            return results[0];
        throw new Error('not all responses are equal, please consider removing the missbehaving/malicious RPC endpoint.');
    }
}

const debug$7 = Debug('base-wallet:DidWalletStore');
class DIDWalletStore extends AbstractDIDStore {
    constructor(store) {
        super();
        this.store = store;
    }
    async import(args) {
        await this.store.set(`identities.${args.did}`, args);
        return true;
    }
    async get(args) {
        debug$7('Get ddo');
        const ddos = await this.store.get('identities', {});
        if (args.did !== undefined) {
            if (ddos[args.did] === undefined) {
                throw new WalletError('DID not found', { status: 404 });
            }
            return ddos[args.did];
        }
        else if (args.alias !== undefined) {
            throw new WalletError('Get by alias not implemented.', { status: 500 });
        }
        else {
            const dids = Object.keys(ddos);
            if (dids.length === 0) {
                throw new WalletError('DID not found', { status: 404 });
            }
            return ddos[dids[0]]; // Return a random ddo
        }
    }
    async delete(args) {
        await this.store.delete(`identities.${args.did}`);
        return true;
    }
    async list(args) {
        const dids = await this.store.get('identities');
        if (dids === undefined) {
            return [];
        }
        const { alias, provider } = args;
        return Object.keys(dids).filter((did) => {
            if (alias !== undefined && dids[did].alias !== alias) {
                return false;
            }
            if (provider !== undefined && dids[did].provider !== provider) {
                return false;
            }
            return true;
        }).map(did => dids[did]);
    }
}

const debug$6 = Debug('base-wallet:KMS');
class KeyWalletManagementSystem extends AbstractKeyManagementSystem {
    constructor(keyWallet) {
        super();
        this.keyWallet = keyWallet;
    }
    async createKey(args) {
        const type = args.type;
        // TODO: Add type to createAccountKeyPair function
        const kid = await this.keyWallet.createAccountKeyPair();
        debug$6('Import', args, kid);
        const publicKey = await this.keyWallet.getPublicKey(kid);
        if (!(publicKey instanceof Uint8Array)) {
            // TODO: convert from string
            throw Error('Only Uint8Array supported yet');
        }
        return {
            kid,
            type,
            publicKeyHex: ethers.utils.hexlify(publicKey).substr(2) // TODO: Remove 0x from the string
        };
    }
    async deleteKey(args) {
        await this.keyWallet.delete(args.kid);
        debug$6('Delete', args);
        return true;
    }
    async encryptJWE(args) {
        throw new Error('[encryptJWE] Method not implemented.');
    }
    async decryptJWE(args) {
        throw new Error('[decryptJWE] Method not implemented.');
    }
    async signJWT(args) {
        let message;
        const { key, data } = args;
        if (typeof data === 'string') {
            message = u8a.fromString(data, 'utf-8');
        }
        else {
            message = data;
        }
        const messageDigest = ethers.utils.sha256(message);
        const messageDigestBytes = ethers.utils.arrayify(messageDigest);
        const signature = await this.keyWallet.signDigest(key.kid, messageDigestBytes);
        // Remove recovery parameter
        // (ethers adds a 2 byte recovery parameter at the end )
        const signatureBase64url = u8a.toString(signature.subarray(0, signature.length - 1), 'base64url');
        return signatureBase64url;
    }
    async signEthTX(args) {
        const { key, transaction } = args;
        const { v, r, s, from, ...tx } = transaction;
        const address = ethers.utils.computeAddress(`0x${key.publicKeyHex}`);
        if (address.toLowerCase() !== from.toLowerCase()) {
            throw new WalletError('Transaction from parammeter does not match the chosen key.');
        }
        const data = ethers.utils.serializeTransaction(tx);
        const messageDigest = ethers.utils.keccak256(data);
        const messageDigestBytes = ethers.utils.arrayify(messageDigest);
        const signature = await this.keyWallet.signDigest(args.key.kid, messageDigestBytes);
        const signedTransaction = ethers.utils.serializeTransaction(tx, signature);
        return signedTransaction;
    }
}

const debug$5 = Debug('base-wallet:KeyWalletStore');
class KeyWalletStore extends AbstractKeyStore {
    constructor(keyWallet) {
        super();
        this.keyWallet = keyWallet;
    }
    async import(args) {
        debug$5('Import key. Doing nothing');
        return true;
    }
    async get(args) {
        // TODO: Add type to createAccountKeyPair function
        const kid = args.kid;
        debug$5('Get key', args, kid);
        const publicKey = await this.keyWallet.getPublicKey(kid);
        if (!(publicKey instanceof Uint8Array)) {
            throw Error('Only Uint8Array supported yet');
        }
        // TODO: Set type properly
        return {
            kid,
            type: 'Secp256k1',
            kms: 'keyWallet',
            publicKeyHex: utils.hexlify(publicKey).substr(2)
        };
    }
    async delete(args) {
        return true;
    }
}

// Core interfaces
const DEFAULT_PROVIDER = 'did:ethr:i3m';
const DEFAULT_PROVIDERS_DATA = {
    'did:ethr:i3m': {
        network: 'i3m',
        rpcUrl: [
            'http://95.211.3.244:8545',
            'http://95.211.3.249:8545',
            'http://95.211.3.250:8545',
            'http://95.211.3.251:8545'
        ]
    }
};
class Veramo {
    constructor(store, keyWallet, providersData) {
        this.defaultKms = 'keyWallet';
        this.providersData = providersData;
        const ethrDidResolver = getResolver({
            networks: Object.values(this.providersData),
            multiRpcOptions: {
                successRate: 0.5
            }
        });
        const webDidResolver = getResolver$1();
        const resolver = new Resolver({ ...ethrDidResolver, ...webDidResolver });
        this.providers = {
            'did:web': new WebDIDProvider({ defaultKms: this.defaultKms })
        };
        for (const [key, provider] of Object.entries(this.providersData)) {
            this.providers[key] = new EthrDIDProvider({
                defaultKms: this.defaultKms,
                ...{
                    ...provider,
                    rpcUrl: (provider.rpcUrl !== undefined) ? ((typeof provider.rpcUrl === 'string') ? provider.rpcUrl : provider.rpcUrl[0]) : undefined
                }
            });
        }
        this.agent = createAgent({
            plugins: [
                new KeyManager({
                    store: new KeyWalletStore(keyWallet),
                    kms: {
                        keyWallet: new KeyWalletManagementSystem(keyWallet)
                    }
                }),
                new DIDManager({
                    store: new DIDWalletStore(store),
                    defaultProvider: DEFAULT_PROVIDER,
                    providers: this.providers
                }),
                new CredentialIssuer(),
                new SelectiveDisclosure(),
                // new DataStore(dbConnection),
                // new DataStoreORM(dbConnection),
                new MessageHandler({
                    messageHandlers: [
                        new JwtMessageHandler(),
                        new SdrMessageHandler(),
                        new W3cMessageHandler()
                    ]
                }),
                new DIDResolverPlugin({
                    resolver
                })
            ]
        });
    }
    getProvider(name) {
        const provider = this.providers[name];
        if (provider === undefined)
            throw new WalletError('Identifier provider does not exist: ' + name);
        return provider;
    }
}

function shuffleArray(arr) {
    const arr2 = [...arr];
    const ret = [];
    for (let i = 0; i < arr.length; i++) {
        const randomIndex = randomInt(arr.length - i);
        ret.push(arr2[randomIndex]);
        arr2.splice(randomIndex, 1);
    }
    return ret;
}

/* eslint-disable @typescript-eslint/no-non-null-assertion */
const debug$4 = Debug('base-wallet:base-wallet.ts');
class BaseWallet {
    constructor(opts) {
        this.dialog = opts.dialog;
        this.store = opts.store;
        this.toast = opts.toast;
        this.keyWallet = opts.keyWallet;
        this.resourceValidator = new ResourceValidator();
        this.provider = opts.provider ?? DEFAULT_PROVIDER;
        this.providersData = opts.providersData ?? DEFAULT_PROVIDERS_DATA;
        // Init veramo framework
        this.veramo = new Veramo(this.store, this.keyWallet, this.providersData);
    }
    async executeTransaction(options = {}) {
        const providerData = this.veramo.providersData[this.provider];
        if (providerData?.rpcUrl === undefined) {
            throw new WalletError('This provider has incomplete information, cannot execute transaction');
        }
        let transaction = options.transaction;
        const notifyUser = options.notifyUser ?? true;
        if (transaction === undefined) {
            transaction = await this.dialog.text({
                title: 'Execute transaction',
                message: 'Put the transaction. Should start with 0x'
            });
        }
        if (transaction === undefined || !transaction.startsWith('0x')) {
            throw new WalletError(`Invalid transaction ${transaction ?? '<undefined>'}`);
        }
        const notifyUserFn = async (response) => {
            response.wait().then(receipt => {
                this.toast.show({
                    message: 'Transaction properly executed',
                    type: 'success'
                });
                debug$4(receipt);
            }).catch(err => {
                const reason = err.reason ?? '';
                this.toast.show({
                    message: 'Error sending transaction to the ledger' + reason,
                    type: 'error'
                });
                debug$4(reason);
            });
        };
        const sendTransaction = async (provider, transaction) => {
            const response = await provider.sendTransaction(transaction);
            if (notifyUser) {
                notifyUserFn(response).catch((reason) => {
                    debug$4(reason);
                });
            }
            else {
                debug$4(response);
            }
        };
        // Let us shuffle the array of rpcUrls
        const rpcUrls = shuffleArray((providerData.rpcUrl instanceof Array) ? providerData.rpcUrl : [providerData.rpcUrl]);
        const providers = rpcUrls.map(rpcUrl => new ethers.providers.JsonRpcProvider(rpcUrl));
        let success = false;
        for (const provider of providers) {
            try {
                await sendTransaction(provider, transaction);
                success = true;
                break;
            }
            catch (error) {
                debug$4(error);
            }
        }
        if (!success) {
            throw new WalletError('Error sending transaction to the blockchain');
        }
    }
    async queryBalance() {
        const providerData = this.veramo.providersData[this.provider];
        if (providerData?.rpcUrl === undefined) {
            throw new WalletError(`The provider '${this.provider}' has incomplete information: cannot execute transaction`);
        }
        const identities = await this.veramo.agent.didManagerFind();
        const identity = await this.dialog.select({
            message: 'Select an account to get its balance.',
            values: identities,
            getText(identity) {
                return identity.alias ?? identity.did;
            }
        });
        if (identity === undefined) {
            throw new WalletError('Query balance cancelled');
        }
        // Let us shuffle the array of rpcUrls
        const rpcUrls = shuffleArray((providerData.rpcUrl instanceof Array) ? providerData.rpcUrl : [providerData.rpcUrl]);
        const providers = rpcUrls.map(rpcUrl => new ethers.providers.StaticJsonRpcProvider(rpcUrl));
        const address = ethers.utils.computeAddress(`0x${identity.keys[0].publicKeyHex}`);
        const balance = await providers[0].getBalance(address);
        console.log(balance);
        const balances = await multipleExecutions({ successRate: 0 }, providers, 'getBalance', address);
        const ether = ethers.utils.formatEther(balances[0]);
        this.toast.show({
            message: 'Balance',
            details: `The account '${address}' current balance is ${ether} ETH.`,
            type: 'success'
        });
    }
    async createTransaction() {
        const providerData = this.veramo.providersData[this.provider];
        if (providerData?.rpcUrl === undefined) {
            throw new WalletError('This provider has incomplete information, cannot execute transaction');
        }
        const identities = await this.veramo.agent.didManagerFind();
        const transactionData = await this.dialog.form({
            title: 'Create Transaction',
            descriptors: {
                from: {
                    type: 'select',
                    message: 'Select the origin account',
                    values: identities,
                    getText(identity) {
                        return identity.alias ?? '<UNKNOWN>';
                    }
                },
                to: { type: 'text', message: 'Type the destination account' },
                value: { type: 'text', message: 'Put the ether value' },
                sign: { type: 'confirmation', message: 'Sign the transaction?', acceptMsg: 'Sign', rejectMsg: 'Cancel' }
            },
            order: ['from', 'to', 'value', 'sign']
        });
        if (transactionData === undefined) {
            throw new WalletError('Create transaction cancelled');
        }
        // We ask to the fastest RPC endpoint
        const rpcUrls = shuffleArray((providerData.rpcUrl instanceof Array) ? providerData.rpcUrl : [providerData.rpcUrl]);
        const providers = rpcUrls.map(rpcUrl => new ethers.providers.JsonRpcProvider(rpcUrl));
        const from = ethers.utils.computeAddress(`0x${transactionData.from.keys[0].publicKeyHex}`);
        const nonce = (await multipleExecutions({ successRate: 0 }, providers, 'getTransactionCount', from, 'latest'))[0];
        const gasPrice = (await multipleExecutions({ successRate: 0 }, providers, 'getGasPrice'))[0];
        const tx = {
            to: transactionData.to,
            value: ethers.utils.parseEther(transactionData.value),
            nonce: Number(nonce),
            gasLimit: ethers.utils.hexlify(100000),
            gasPrice
        };
        let transaction = '';
        if (transactionData.sign) {
            const response = await this.identitySign({ did: transactionData.from.did }, { type: 'Transaction', data: { ...tx, from } });
            transaction = response.signature;
        }
        else {
            transaction = ethers.utils.serializeTransaction(tx);
        }
        await this.dialog.confirmation({
            message: `Transaction created, click the input to copy its value.\n<input value="${transaction}" disabled></input>`,
            acceptMsg: 'Continue',
            rejectMsg: ''
        });
    }
    async wipe() {
        const confirmation = await this.dialog.confirmation({
            title: 'Delete Wallet?',
            message: 'Are you sure you want to delete this wallet?',
            acceptMsg: 'Delete',
            rejectMsg: 'Cancel'
        });
        if (confirmation !== true) {
            throw new WalletError('Operation rejected by user');
        }
        await Promise.all([
            this.store.clear(),
            this.keyWallet.wipe()
        ]);
    }
    // UTILITIES
    async selectIdentity(options) {
        const identities = await this.veramo.agent.didManagerFind();
        const message = `${options?.reason ?? 'Authentication required. Please, select an identity to proceed.'}`;
        const identity = await this.dialog.select({
            message,
            values: identities,
            getText: (ddo) => ddo.alias !== undefined ? ddo.alias : ddo.did
        });
        if (identity === undefined) {
            throw new WalletError('No did selected');
        }
        return identity;
    }
    async selectCredentialsForSdr(sdrMessage) {
        if (sdrMessage.data === null || sdrMessage.data === undefined || sdrMessage.from === undefined) {
            return;
        }
        const sdrData = sdrMessage.data;
        // ** Step 1: Organize the data in an easy to work data structure **
        // Map from DID to its credentials related with this SDR
        const candidateIdentities = {};
        const resources = await this.store.get('resources', {});
        for (const resource of Object.values(resources)) {
            if (resource.type !== 'VerifiableCredential' || resource.identity === undefined)
                continue;
            for (const claim of Object.keys(resource.resource.credentialSubject)) {
                if (claim === 'id')
                    continue;
                const requiredClaim = sdrData.claims.find((v) => v.claimType === claim);
                if (requiredClaim !== undefined) {
                    let candidateIdentity = candidateIdentities[resource.identity];
                    if (candidateIdentity === undefined) {
                        candidateIdentity = {};
                        candidateIdentities[resource.identity] = candidateIdentity;
                    }
                    let candidateClaim = candidateIdentity[requiredClaim.claimType];
                    if (candidateClaim === undefined) {
                        candidateClaim = {
                            ...requiredClaim,
                            credentials: []
                        };
                        candidateIdentity[requiredClaim.claimType] = candidateClaim;
                    }
                    candidateClaim.credentials.push(resource.resource);
                }
            }
        }
        // ** Step 2: Select the identities that have all the essential claims **
        const validIdentities = {};
        const essentialClaims = sdrData.claims.filter((claim) => claim.essential === true);
        for (const did of Object.keys(candidateIdentities)) {
            const candidateIdentity = candidateIdentities[did];
            // If an identity do no has an essential claim, this identity is marked as invalid
            let valid = true;
            for (const essentialClaim of essentialClaims) {
                if (candidateIdentity[essentialClaim.claimType] === undefined) {
                    valid = false;
                    break;
                }
            }
            if (valid) {
                validIdentities[did] = candidateIdentity;
            }
        }
        // ** Step 3: Select one of the valid identities **
        let selectedDid;
        const validDids = Object.keys(validIdentities);
        if (validDids.length === 0) ;
        else if (validDids.length === 1) {
            // There is only one identity fulfilling the requirement. Use this identity
            selectedDid = Object.keys(validIdentities)[0];
        }
        else {
            // Select one of the valid identities
            const identities = (await this.veramo.agent.didManagerFind()).filter(identity => validDids.includes(identity.did));
            const message = `Requested claims ${sdrData.claims.map(claim => claim.claimType).join(',')} are available in the following identities. Please select one to continue...`;
            const identity = await this.dialog.select({
                message,
                values: identities,
                getText: (identity) => {
                    return identity.alias !== undefined ? `${identity.alias} (${displayDid(identity.did)})` : displayDid(identity.did);
                }
            });
            if (identity !== undefined) {
                selectedDid = identity.did;
            }
        }
        if (selectedDid === undefined) {
            throw new WalletError('Selective disclousure cancelled by the user');
        }
        const selectedIdentity = validIdentities[selectedDid];
        // ** Step 4: Execute the selective disclosure **
        const credentials = [];
        do {
            const disclosure = await this.dialog.form({
                title: 'Selective disclosure',
                descriptors: Object.values(selectedIdentity).reduce((prev, claim) => {
                    const descriptors = {
                        ...prev,
                        [claim.claimType]: {
                            type: 'select',
                            message: `${sdrMessage.from ?? 'UNKNOWN'} has requested the claim <b>${claim.claimType}</b>.You have the following claim/s that meet the request. \nSelect the claim to disclouse or leave empty for not disclousing it.${claim.essential === true ? '\n<b>This claim is compulsory. Not disclosing it will cancel the disclosure.</b>' : ''}`,
                            values: [undefined, ...claim.credentials],
                            getText(credential) {
                                if (credential === undefined) {
                                    return 'Don\'t disclose';
                                }
                                const value = credential.credentialSubject[claim.claimType];
                                return `${claim.claimType}=${value} (by ${displayDid(credential.issuer.id)})`;
                            },
                            getContext(credential) {
                                return credential !== undefined ? 'success' : 'danger';
                            }
                        }
                    };
                    return descriptors;
                }, {}),
                order: Object.keys(selectedIdentity)
            });
            if (disclosure === undefined) {
                const cancel = await this.dialog.confirmation({
                    message: 'You cancelled the selective disclosure. Are you sure?',
                    acceptMsg: 'Yes',
                    rejectMsg: 'No',
                    allowCancel: false
                });
                if (cancel === true) {
                    throw new WalletError('Selective disclosure denied');
                }
            }
            else {
                const missingEssentials = [];
                for (const [claimType, credential] of Object.entries(disclosure)) {
                    if (credential === undefined) {
                        // Check essential credential skipped
                        const claim = essentialClaims.find((claim) => claim.claimType === claimType);
                        if (claim !== undefined) {
                            missingEssentials.push(claimType);
                        }
                        continue;
                    }
                    credentials.push(credential);
                }
                let continueSelectiveDisclosure;
                if (missingEssentials.length > 0) {
                    continueSelectiveDisclosure = await this.dialog.confirmation({
                        message: `You skipped the mandatory claims: ${missingEssentials.join(', ')}. <b>The selective disclosure will be canceled</b>. \nContinue?`,
                        acceptMsg: 'No',
                        rejectMsg: 'Yes',
                        allowCancel: false
                    });
                }
                else if (credentials.length === 0) {
                    continueSelectiveDisclosure = await this.dialog.confirmation({
                        message: 'You did not select any claim.<b>The selective disclosure will be canceled</b>. \nContinue?',
                        acceptMsg: 'No',
                        rejectMsg: 'Yes',
                        allowCancel: false
                    });
                }
                else {
                    break;
                }
                if (continueSelectiveDisclosure === false) {
                    throw new WalletError('Selective disclosure denied');
                }
            }
        } while (true);
        // ** Step 5: Generate Verifiable Presentation **
        const vp = await this.veramo.agent.createVerifiablePresentation({
            presentation: {
                holder: selectedDid,
                verifier: [sdrMessage.from],
                verifiableCredential: credentials,
                request: sdrMessage.raw
            },
            proofFormat: 'jwt',
            save: false
        });
        return vp;
    }
    getKeyWallet() {
        return this.keyWallet;
    }
    async call(functionMetadata) {
        await this[functionMetadata.call]();
    }
    // API METHODS
    /**
     * Gets a list of identities managed by this wallet
     * @returns
     */
    async getIdentities() {
        return await this.store.get('identities', {});
    }
    /**
     * Returns a list of DIDs managed by this wallet
     *
     * @param queryParameters. You can filter by alias.
     * @returns
     */
    async identityList(queryParameters) {
        const { alias } = queryParameters;
        const identities = await this.veramo.agent.didManagerFind({ alias });
        return identities.map(ddo => ({ did: ddo.did }));
    }
    /**
     * Creates an identity
     * @param requestBody
     * @returns the DID of the created identity
     */
    async identityCreate(requestBody) {
        const { alias } = requestBody;
        const { did } = await this.veramo.agent.didManagerCreate({
            alias,
            provider: this.provider
        });
        return { did };
    }
    async identitySelect(queryParameters) {
        const { did } = await this.selectIdentity(queryParameters);
        return { did };
    }
    /**
     * Signs using the identity set in pathParameters. Currently suporting RAW signatures of base64url-encoded data, arbritrary JSON objects (it returns a JWT); and transactions for the DLT.
     * @param pathParameters
     * @param requestBody
     * @returns
     */
    async identitySign(pathParameters, requestBody) {
        let response;
        switch (requestBody.type) {
            case 'Transaction': {
                const { data: transaction } = requestBody;
                if (transaction === undefined) {
                    throw new WalletError('No transaction present on the request', { code: 400 });
                }
                const identity = await this.veramo.agent.didManagerGet(pathParameters);
                const signature = await this.veramo.agent.keyManagerSignEthTX({
                    kid: identity.keys[0].kid,
                    transaction
                });
                response = { signature };
                break;
            }
            case 'Raw': {
                const { data } = requestBody;
                if (data === undefined) {
                    throw new WalletError('No data present on the request', { code: 400 });
                }
                const identity = await this.veramo.agent.didManagerGet(pathParameters);
                const signature = await this.veramo.agent.keyManagerSignJWT({
                    kid: identity.keys[0].kid,
                    data: u8a.fromString(data.payload, 'base64url')
                });
                response = { signature };
                break;
            }
            case 'JWT': {
                const { data } = requestBody;
                if (data === undefined) {
                    throw new WalletError('No data present on the request', { code: 400 });
                }
                const identity = await this.veramo.agent.didManagerGet(pathParameters);
                const header = {
                    ...data.header ?? undefined,
                    alg: 'ES256K',
                    typ: 'JWT'
                };
                const payload = {
                    ...data.payload,
                    iss: pathParameters.did,
                    iat: Math.floor(Date.now() / 1000)
                };
                const jwsDataToSign = jwsSignInput(header, payload);
                const signature = await this.veramo.agent.keyManagerSignJWT({
                    kid: identity.keys[0].kid,
                    data: jwsDataToSign
                });
                response = { signature: `${jwsDataToSign}.${signature}` };
                break;
            }
            default:
                throw new WalletError('Unknown sign data type');
        }
        return response;
    }
    /**
     * Returns info regarding an identity. It includes DLT addresses bounded to the identity
     *
     * @param pathParameters
     * @returns
     */
    async identityInfo(pathParameters) {
        const ddo = await this.veramo.agent.didManagerGet({
            did: pathParameters.did
        });
        const result = _.pick(ddo, ['did', 'alias', 'provider']);
        let addresses = [];
        if (ddo.provider.startsWith('did:ethr')) {
            addresses = ddo.keys.map((key) => ethers.utils.computeAddress(`0x${key.publicKeyHex}`));
        }
        return { ...result, addresses };
    }
    async identityDeployTransaction(pathParameters, requestBody) {
        throw new Error('Method not implemented.');
    }
    /**
     * Get resources stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.
     * @returns
     */
    async getResources() {
        return await this.store.get('resources', {});
    }
    async getResource(id) {
        const resourcesMap = await this.getResources();
        const resources = Object
            .keys(resourcesMap)
            .map(key => resourcesMap[key])
            .filter((resource) => resource.id === id);
        if (resources.length !== 1) {
            throw Error('resource not found');
        }
        return resources[0];
    }
    async setResource(resource) {
        // If a parentResource is provided, do not allow to store the resource if it does not exist
        let parentResource;
        if (resource.parentResource !== undefined) {
            try {
                parentResource = await this.getResource(resource.parentResource);
            }
            catch (error) {
                debug$4('Failed to add resource since parent resource does not exist:\n' + JSON.stringify(resource, undefined, 2));
                throw new Error('Parent resource for provided resource does not exist');
            }
        }
        // If an identity is provided, do not allow to store the resource if it does not exist.
        if (resource.identity !== undefined) {
            if (!await this.store.has(`identities.${resource.identity}`)) {
                debug$4('Failed to add resource since the identity is associated to does not exist:\n' + JSON.stringify(resource, undefined, 2));
                throw new Error('Identity for this resource does not exist');
            }
        }
        if (parentResource !== undefined) {
            // Do not allow as well a children resource with a different identity than its father
            if (resource.identity !== undefined && parentResource.identity !== resource.identity) {
                debug$4('Failed to add resource since it has a different identity than its parent resource');
                throw new Error('Identity mismatch between parent and child resources');
            }
            // If child identity is not provided, it inherits its parent's
            if (resource.identity === undefined) {
                resource.identity = parentResource.identity;
            }
        }
        await this.store.set(`resources.${resource.id}`, resource);
    }
    /**
     * Gets a list of resources stored in the wallet's vault.
     * @returns
     */
    async resourceList(query) {
        const queries = Object.keys(query);
        const extraConsent = [];
        const filters = [];
        if (queries.includes('type')) {
            extraConsent.push(`type '<code>${query.type ?? 'unknown'}</code>'`);
            filters.push((resource) => resource.type === query.type);
        }
        if (queries.includes('identity')) {
            if (query.identity !== '' && query.identity !== undefined) {
                extraConsent.push(`identity '<code>${query.identity}</code>'`);
                filters.push((resource) => resource.identity === query.identity);
            }
            else {
                extraConsent.push('not liked to any identity');
                filters.push((resource) => resource.identity === undefined);
            }
        }
        if (queries.includes('parentResource')) {
            let parentResource;
            try {
                parentResource = await this.getResource(query.parentResource);
            }
            catch (error) {
                throw new WalletError('Invalid parentResource id', { status: 400 });
            }
            if (query.parentResource !== '' && query.parentResource !== undefined) {
                extraConsent.push(`parent-resource:\n\tid '<code>${query.parentResource}</code>\n\t<code>${parentResource.type}</code>'`);
                filters.push((resource) => resource.parentResource === query.parentResource);
            }
            else {
                filters.push((resource) => resource.parentResource === undefined);
            }
        }
        // TODO: Use wallet-protocol token to get the application name
        const consentText = `One application wants to retrieve all your stored resources${extraConsent.length > 0 ? ' with:\n' + extraConsent.join('\n\t') : ''}.\nDo you agree?`;
        const confirmation = await this.dialog.confirmation({
            message: consentText,
            acceptMsg: 'Yes',
            rejectMsg: 'No'
        });
        if (confirmation === false) {
            throw new WalletError('User cannceled the operation', { status: 403 });
        }
        const resourcesMap = await this.getResources();
        const resources = Object
            .keys(resourcesMap)
            .map(key => resourcesMap[key])
            .filter((resource) => filters.reduce((success, filter) => success && filter(resource), true));
        return resources;
    }
    /**
     * Deletes a given resource and all its children
     * @param id
     */
    async deleteResource(id, requestConfirmation = true) {
        let confirmation = true;
        if (requestConfirmation) {
            confirmation = await this.dialog.confirmation({
                message: 'Are you sure you want to delete this resource and all its children resources (if any)? This action cannot be undone',
                acceptMsg: 'Delete',
                rejectMsg: 'Cancel'
            });
        }
        if (confirmation === true) {
            await this.store.delete(`resources.${id}`);
            const resourcesMap = await this.getResources();
            const resources = Object
                .keys(resourcesMap)
                .map(key => resourcesMap[key])
                .filter((resource) => resource.parentResource === id);
            for (const resource of resources) {
                await this.deleteResource(resource.id, false);
            }
        }
    }
    /**
     * Deletes a given identity (DID) and all its associated resources
     * @param did
     */
    async deleteIdentity(did) {
        const confirmation = await this.dialog.confirmation({
            message: 'Are you sure you want to delete this identity and all its associated resources (if any)?\n' + did + '\nThis action cannot be undone',
            acceptMsg: 'Delete',
            rejectMsg: 'Cancel'
        });
        if (confirmation === true) {
            await this.veramo.agent.didManagerDelete({ did });
            const resourcesMap = await this.getResources();
            const resources = Object
                .keys(resourcesMap)
                .map(key => resourcesMap[key])
                .filter((resource) => resource.identity === did);
            for (const resource of resources) {
                await this.deleteResource(resource.id, false);
            }
        }
    }
    /**
     * Securely stores in the wallet a new resource.
     *
     * @param requestBody
     * @returns and identifier of the created resource
     */
    async resourceCreate(requestBody) {
        const resource = { ...requestBody, id: v4() };
        // Very hacky but it is the only place. If the resource is a contract without a keypair, we look for an existing one and we add it
        if (resource.type === 'Contract' && resource.resource.keyPair === undefined) {
            // A contract parent resource is a keyPair
            let parentId;
            let keyPairResource;
            try {
                parentId = await digest(resource.resource.dataSharingAgreement.dataExchangeAgreement.orig);
                keyPairResource = (await this.getResource(parentId));
            }
            catch (error) {
                try {
                    parentId = await digest(resource.resource.dataSharingAgreement.dataExchangeAgreement.dest);
                    keyPairResource = (await this.getResource(parentId));
                }
                catch (error2) {
                    throw new WalletError('No associated keyPair found for this contract, please provide one', { status: 400 });
                }
            }
            resource.resource.keyPair = keyPairResource.resource.keyPair;
            resource.parentResource = parentId;
        }
        // Validate resource
        const validation = await this.resourceValidator.validate(resource, this.veramo);
        if (!validation.validated) {
            throw new WalletError(`Resource validation failed: type ${resource.type} not supported`, { status: 400 });
        }
        if (validation.errors.length > 0) {
            const errorMsg = [];
            validation.errors.forEach((error) => {
                errorMsg.push(error.message);
            });
            throw new WalletError('Resource validation failed:\n' + errorMsg.join('\n'), { status: 400 });
        }
        switch (resource.type) {
            case 'VerifiableCredential': {
                const credentialSubject = getCredentialClaims(resource.resource)
                    .map(claim => `  - ${claim}: ${JSON.stringify(resource.resource.credentialSubject[claim])}`)
                    .join('\n');
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add the following verifiable credential: \n${credentialSubject}`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                break;
            }
            case 'Object': {
                const confirmation = await this.dialog.confirmation({
                    message: 'Do you want to add an object into your wallet?'
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                break;
            }
            case 'KeyPair': {
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add the following keys to your wallet?\n\t${JSON.stringify(resource.resource.keyPair, undefined, 2)}`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                break;
            }
            case 'Contract': {
                const { dataSharingAgreement, keyPair } = resource.resource; // They keyPair is assigned before validation, so it cannot be undefined
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add the a data sharing agreement to your wallet?\n\tofferingId: ${dataSharingAgreement.dataOfferingDescription.dataOfferingId}\n\tproviderDID: ${dataSharingAgreement.parties.providerDid}\n\tconsumerDID: ${dataSharingAgreement.parties.consumerDid}`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                const parentId = await digest(keyPair.publicJwk);
                // If the keyPair was already created, we overwrite it
                const keyPairResource = {
                    id: parentId,
                    identity: resource.identity,
                    type: 'KeyPair',
                    resource: { keyPair: keyPair }
                };
                // A contract parent resource is a keyPair
                resource.parentResource = parentId;
                try {
                    await this.setResource(keyPairResource);
                }
                catch (error) {
                    throw new WalletError('Failed to add resource', { status: 500 });
                }
                break;
            }
            case 'NonRepudiationProof': {
                const decodedProof = decodeJWS(resource.resource).payload;
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add a non repudiation proof into your wallet?\nType: ${decodedProof.proofType}\nExchangeId: ${await exchangeId(decodedProof.exchange)}`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                // If the data exchange has not been yet created, add it to the resources
                if (!await this.store.has(`resources.${resource.parentResource}`)) {
                    const dataExchange = decodedProof.exchange;
                    const { id, cipherblockDgst, blockCommitment, secretCommitment, ...dataExchangeAgreement } = dataExchange;
                    const dataExchangeResource = {
                        id,
                        parentResource: await digest(dataExchangeAgreement),
                        type: 'DataExchange',
                        resource: dataExchange
                    };
                    try {
                        await this.setResource(dataExchangeResource);
                    }
                    catch (error) {
                        throw new WalletError('Failed to add resource', { status: 500 });
                    }
                }
                break;
            }
            default:
                throw new WalletError('Resource type not supported', { status: 501 });
        }
        await this.setResource(resource);
        return resource;
    }
    /**
     * Initiates the flow of choosing which credentials to present after a selective disclosure request.
     * @param pathParameters
     * @returns
     */
    async selectiveDisclosure(pathParameters) {
        const sdrRaw = pathParameters.jwt;
        let sdrMessage;
        try {
            sdrMessage = await this.veramo.agent.handleMessage({
                raw: sdrRaw,
                save: false
            });
        }
        catch (err) {
            if (err instanceof Error) {
                throw new WalletError(`Cannot verify selective disclousure request: ${err.message}`);
            }
            throw err;
        }
        if (sdrMessage.from === undefined) {
            throw new WalletError('Selective disclosure request origin not defined');
        }
        const vp = await this.selectCredentialsForSdr(sdrMessage);
        if (vp === undefined) {
            throw new WalletError('No verifiable credentials selected');
        }
        return {
            jwt: vp.proof.jwt
        };
    }
    /**
     * Deploys a transaction to the connected DLT
     * @param requestBody
     * @returns
     */
    async transactionDeploy(requestBody) {
        await this.executeTransaction({
            transaction: requestBody.transaction
        });
        return {};
    }
    /**
     * Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.
     *
     * The Wallet only supports the 'ES256K1' algorithm.
     *
     * Useful to verify JWT created by another wallet instance.
     * @param requestBody
     * @returns
     */
    async didJwtVerify(requestBody) {
        try {
            return await didJwtVerify(requestBody.jwt, this.veramo, requestBody.expectedPayloadClaims);
        }
        catch (error) {
            if (typeof error === 'string') {
                throw new WalletError(error);
            }
            throw new Error(typeof error === 'string' ? error : 'unknown error');
        }
    }
    /**
     * Retrieves information regarding the current connection to the DLT.
     * @returns
     */
    async providerinfoGet() {
        const providerData = this.veramo.providersData[this.provider];
        return {
            provider: this.provider,
            ...providerData
        };
    }
}

const debug$3 = Debug('base-wallet:TestDialog');
class TestDialog {
    constructor() {
        // Value management
        this.valuesStack = [{
                text: 'With love for my caller',
                confirmation: true,
                selectMap(values) {
                    if (values.length > 0) {
                        return values[0];
                    }
                    return undefined;
                }
            }];
    }
    get values() {
        return this.valuesStack[this.valuesStack.length - 1];
    }
    async setValues(values, cb) {
        this.valuesStack.push(Object.assign({}, this.values, values));
        await cb();
        this.valuesStack.pop();
    }
    // Dialog methods
    async text(options) {
        debug$3('Returning a dummy text:', this.values.text);
        return this.values.text;
    }
    async confirmation(options) {
        debug$3('Ask for user confirmation:', this.values.confirmation);
        return this.values.confirmation;
    }
    async select(options) {
        const value = this.values.selectMap(options.values);
        debug$3('Pick item ', value, ' from ', options.values);
        return value;
    }
    async authenticate() {
        throw new Error('Method not implemented.');
    }
    async form(options) {
        const formValue = {};
        const keys = Object.keys(options.descriptors);
        for (const key of keys) {
            let response;
            const descriptor = options.descriptors[key];
            switch (descriptor.type) {
                case 'confirmation':
                    response = this.confirmation(descriptor);
                    break;
                case 'select':
                    response = this.select(descriptor);
                    break;
                case 'text':
                    response = this.text(descriptor);
                    break;
            }
            if (response !== undefined) {
                formValue[key] = await response;
            }
        }
        return formValue;
    }
}

var events = {exports: {}};

var R = typeof Reflect === 'object' ? Reflect : null;
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  };

var ReflectOwnKeys;
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys;
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
};

function EventEmitter() {
  EventEmitter.init.call(this);
}
events.exports = EventEmitter;
events.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(name, resolver);
      reject(err);
    }

    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    }
    eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
    if (name !== 'error') {
      addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
    }
  });
}

function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
  if (typeof emitter.on === 'function') {
    eventTargetAgnosticAddListener(emitter, 'error', handler, flags);
  }
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    // EventTarget does not have `error` event semantics like Node
    // EventEmitters, we do not listen for `error` events here.
    emitter.addEventListener(name, function wrapListener(arg) {
      // IE does not have builtin `{ once: true }` support so we
      // have to do it manually.
      if (flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  } else {
    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
  }
}

/**
 * A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.
 *
 * `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)
 *
 * The wallet's storage-file can be encrypted for added security.
 */
class FileStore extends events.exports.EventEmitter {
    constructor(filepath, keyObjectOrPassword, defaultModel) {
        super();
        const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
        if (!isNode) {
            throw new Error('FileStore can only be instantiated from Node.js');
        }
        this.filepath = filepath;
        if (keyObjectOrPassword instanceof KeyObject) {
            this.key = keyObjectOrPassword;
        }
        else if (typeof keyObjectOrPassword === 'string') {
            this._password = keyObjectOrPassword;
        }
        this.defaultModel = defaultModel ?? {};
        this.initialized = this.init();
    }
    on(eventName, listener) {
        return super.on(eventName, listener);
    }
    emit(eventName, ...args) {
        return super.emit(eventName, ...args);
    }
    async init() {
        await mkdir(dirname(this.filepath), { recursive: true }).catch();
        if (this._password !== undefined) {
            await this.deriveKey(this._password);
        }
        const model = await this.getModel();
        await this.setModel(model);
    }
    async deriveKey(password, salt) {
        this._passwordSalt = salt ?? randomBytes(64);
        // derive encryption key
        this.key = await deriveKey(password, {
            alg: 'scrypt',
            derivedKeyLength: 32,
            salt: this._passwordSalt
        });
    }
    async getModel() {
        let model = _.cloneDeep(this.defaultModel);
        try {
            const fileBuf = readFileSync(this.filepath);
            if (this.key === undefined) {
                model = JSON.parse(fileBuf.toString('utf8'));
            }
            else {
                model = await this.decryptModel(fileBuf);
            }
        }
        catch (error) {
            if (error?.code !== 'ENOENT') {
                throw error;
            }
        }
        return model;
    }
    async setModel(model) {
        if (this.key === undefined) {
            writeFileSync(this.filepath, JSON.stringify(model), { encoding: 'utf8' });
        }
        else {
            writeFileSync(this.filepath, await this.encryptModel(model));
        }
    }
    async encryptModel(model) {
        if (this._password === undefined && this.key === undefined) {
            throw new Error('For the store to be encrypted you must provide a key/password');
        }
        // random initialization vector
        const iv = randomBytes(16);
        // AES 256 GCM Mode
        const cipher = createCipheriv('aes-256-gcm', this.key, iv);
        // encrypt the given text
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(model), 'utf8'), cipher.final()]);
        // extract the auth tag
        const tag = cipher.getAuthTag();
        // generate output
        if (this._passwordSalt !== undefined) {
            return Buffer.concat([this._passwordSalt, iv, tag, encrypted]);
        }
        return Buffer.concat([iv, tag, encrypted]);
    }
    async decryptModel(encryptedModel) {
        if (this._password === undefined && this.key === undefined) {
            throw new Error('For the store to be encrypted you must provide a key/password');
        }
        // extract all parts.
        const buf = Buffer.from(encryptedModel);
        let iv;
        let tag;
        let ciphertext;
        if (this._password !== undefined) {
            const salt = buf.subarray(0, 64);
            if (salt.compare(this._passwordSalt) !== 0) { // eslint-disable-line @typescript-eslint/no-non-null-assertion
                await this.deriveKey(this._password, salt);
            }
            iv = buf.subarray(64, 80);
            tag = buf.subarray(80, 96);
            ciphertext = buf.subarray(96);
        }
        else {
            iv = buf.subarray(0, 16);
            tag = buf.subarray(16, 32);
            ciphertext = buf.subarray(32);
        }
        // AES 256 GCM Mode
        const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
        decipher.setAuthTag(tag);
        // decrypt, pass to JSON string, parse
        return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
    }
    async get(key, defaultValue) {
        await this.initialized;
        const model = await this.getModel();
        return _.get(model, key, defaultValue);
    }
    async set(keyOrStore, value) {
        await this.initialized;
        const model = await this.getModel();
        if (value === undefined) {
            Object.assign(model, keyOrStore);
        }
        else {
            _.set(model, keyOrStore, value);
        }
        await this.setModel(model);
        this.emit('changed', Date.now());
    }
    async has(key) {
        await this.initialized;
        const model = await this.getModel();
        return _.has(model, key);
    }
    async delete(key) {
        await this.initialized;
        let model = await this.getModel();
        model = _.omit(model, key);
        await this.setModel(model);
        this.emit('changed', Date.now());
    }
    async clear() {
        await this.initialized;
        this.emit('cleared', Date.now());
        await rm(this.filepath);
    }
    async getStore() {
        await this.initialized;
        return await this.getModel();
    }
    getPath() {
        return this.filepath;
    }
}
async function deriveKey(password, opts, returnBuffer = false) {
    let scryptOptions = {};
    if (opts.algOptions !== undefined) {
        scryptOptions = {
            N: 16384,
            r: 8,
            p: 1,
            ...opts.algOptions
        };
        scryptOptions.maxmem = 256 * scryptOptions.N * scryptOptions.r; // eslint-disable-line @typescript-eslint/no-non-null-assertion
    }
    const keyPromise = new Promise((resolve, reject) => {
        scrypt(password, opts.salt, opts.derivedKeyLength, scryptOptions, (err, key) => {
            if (err !== null)
                reject(err);
            resolve(returnBuffer ? key : createSecretKey(key));
        });
    });
    return await keyPromise;
}

/**
 * A class that implements a storage in RAM to be used by a wallet
 */
class RamStore extends events.exports.EventEmitter {
    constructor(defaultModel) {
        super();
        this.defaultModel = defaultModel;
        this.model = _.cloneDeep(defaultModel);
    }
    on(eventName, listener) {
        return super.on(eventName, listener);
    }
    emit(eventName, ...args) {
        return super.emit(eventName, ...args);
    }
    get(key, defaultValue) {
        return _.get(this.model, key, defaultValue);
    }
    set(keyOrStore, value) {
        if (value === undefined) {
            Object.assign({}, this.model, keyOrStore);
            return;
        }
        _.set(this.model, keyOrStore, value);
        this.emit('changed', Date.now());
    }
    has(key) {
        return _.has(this.model, key);
    }
    delete(key) {
        this.model = _.omit(this.model, key);
        this.emit('changed', Date.now());
    }
    clear() {
        this.model = _.cloneDeep(this.defaultModel);
        this.emit('cleared', Date.now());
    }
    getStore() {
        return this.model;
    }
    getPath() {
        return 'RAM';
    }
}

const debug$2 = Debug('base-wallet:TestDialog');
class TestToast {
    show(toast) {
        debug$2('Show message:', toast.message);
    }
    close(toastId) {
        debug$2('Close toast', toastId);
    }
}

const debug$1 = Debug('base-wallet:NullDialog');
class NullDialog {
    constructor() {
        // Value management
        this.valuesStack = [{
                text: 'With love for my caller',
                confirmation: true,
                selectMap(values) {
                    if (values.length > 0) {
                        return values[0];
                    }
                    return undefined;
                }
            }];
    }
    get values() {
        return this.valuesStack[this.valuesStack.length - 1];
    }
    async setValues(values, cb) {
        this.valuesStack.push(Object.assign({}, this.values, values));
        await cb();
        this.valuesStack.pop();
    }
    // Dialog methods
    async text(options) {
        debug$1('Returning a dummy text:', this.values.text);
        return this.values.text;
    }
    async confirmation(options) {
        debug$1('Ask for user confirmation:', this.values.confirmation);
        return this.values.confirmation;
    }
    async select(options) {
        const value = this.values.selectMap(options.values);
        debug$1('Pick item ', value, ' from ', options.values);
        return value;
    }
    async authenticate() {
        throw new Error('Method not implemented.');
    }
    async form(options) {
        const formValue = {};
        const keys = Object.keys(options.descriptors);
        for (const key of keys) {
            let response;
            const descriptor = options.descriptors[key];
            switch (descriptor.type) {
                case 'confirmation':
                    response = this.confirmation(descriptor);
                    break;
                case 'select':
                    response = this.select(descriptor);
                    break;
                case 'text':
                    response = this.text(descriptor);
                    break;
            }
            if (response !== undefined) {
                formValue[key] = await response;
            }
        }
        return formValue;
    }
}

const debug = Debug('base-wallet:ConsoleToast');
class ConsoleToast {
    show(toast) {
        debug('Show message:', toast.message);
    }
    close(toastId) {
        debug('Close toast', toastId);
    }
}

export { BaseWallet, ConsoleToast, DEFAULT_PROVIDER, DEFAULT_PROVIDERS_DATA, FileStore, NullDialog, RamStore, TestDialog, RamStore as TestStore, TestToast, Veramo, WalletError, base64Url as base64url, deriveKey, didJwtVerify, getCredentialClaims, jwkSecret, multipleExecutions, parseAddress, parseHex, verifyDataSharingAgreementSignature };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3V0aWxzL2Jhc2U2NHVybC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9qd3MudHMiLCIuLi8uLi9zcmMvdHMvZXJyb3JzLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL2tleVBhaXItdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2NyZWRlbnRpYWwtY2xhaW1zLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2RpZC1qd3QtdmVyaWZ5LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2RhdGEtc2hhcmluZy1hZ3JlZW1lbnQtdmFsaWRhdGlvbi50cyIsIi4uLy4uL3NyYy90cy91dGlscy9nZW5lcmF0ZS1zZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VBZGRyZXNzLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3BhcnNlSGV4LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL211bHRpcGxlLWV4ZWN1dGlvbnMudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvY29udHJhY3QtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL2RhdGFFeGNoYW5nZS12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvbnJwLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9vYmplY3QtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL3ZjLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9yZXNvdXJjZS12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZGlzcGxheS1kaWQudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvYWxsLWVxdWFsLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9ldGhyLWRpZC1yZXNvbHZlcl9ETy1OT1QtRURJVC9oZWxwZXJzLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9ldGhyLWRpZC1yZXNvbHZlcl9ETy1OT1QtRURJVC9jb25maWd1cmF0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9ldGhyLWRpZC1yZXNvbHZlcl9ETy1OT1QtRURJVC9jb250cm9sbGVyLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9ldGhyLWRpZC1yZXNvbHZlcl9ETy1OT1QtRURJVC9sb2dQYXJzZXIudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2V0aHItZGlkLXJlc29sdmVyX0RPLU5PVC1FRElUL3Jlc29sdmVyLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9ldGhyLWRpZC1tdWx0aXBsZS1ycGMtcHJvdmlkZXIudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2RpZC13YWxsZXQtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2tleS13YWxsZXQtbWFuYWdlbWVudC1zeXN0ZW0udHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2tleS13YWxsZXQtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL3ZlcmFtby50cyIsIi4uLy4uL3NyYy90cy91dGlscy9zaHVmZmxlLWFycmF5LnRzIiwiLi4vLi4vc3JjL3RzL3dhbGxldC9iYXNlLXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy90ZXN0L2RpYWxvZy50cyIsIi4uLy4uL25vZGVfbW9kdWxlcy9ldmVudHMvZXZlbnRzLmpzIiwiLi4vLi4vc3JjL3RzL2ltcGwvc3RvcmVzL2ZpbGUtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9zdG9yZXMvcmFtLXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3QvdG9hc3QudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9kaWFsb2dzL251bGwtZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvdG9hc3QvY29uc29sZS10b2FzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiYmFzZTY0dXJsIiwidXVpZHY0IiwiZGVidWciLCJldGhyRGlkTXVsdGlwbGVScGNHZXRSZXNvbHZlciIsIndlYkRpZEdldFJlc29sdmVyIiwidXVpZCIsImRpZEp3dFZlcmlmeUZuIiwiZXZlbnRzTW9kdWxlIiwiZXZlbnRzIiwiRXZlbnRFbWl0dGVyIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxNQUFNLE1BQU0sR0FBRyxDQUFDLEdBQVcsS0FBWTtJQUNyQyxPQUFPLEdBQUcsQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDekYsQ0FBQyxDQUFBO0FBRUQsTUFBTSxNQUFNLEdBQUcsQ0FBQyxHQUFXLEtBQVk7SUFDckMsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxRQUFRLENBQUMsQ0FBQTtBQUNuQyxDQUFDLENBQUE7QUFFRCxnQkFBZTtJQUNiLE1BQU07SUFDTixNQUFNO0NBQ1A7O0FDRkQ7Ozs7Ozs7QUFPRztTQUNhLFlBQVksQ0FBRSxNQUFjLEVBQUUsT0FBZSxFQUFFLFFBQXlCLEVBQUE7SUFDdEYsTUFBTSxhQUFhLEdBQUdBLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUE7SUFDckYsTUFBTSxjQUFjLEdBQUdBLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUE7QUFFdkYsSUFBQSxPQUFPLENBQUcsRUFBQSxhQUFhLENBQUksQ0FBQSxFQUFBLGNBQWMsRUFBRSxDQUFBO0FBQzdDLENBQUM7QUFFRDs7Ozs7O0FBTUc7QUFDYSxTQUFBLFNBQVMsQ0FBRSxHQUFXLEVBQUUsUUFBeUIsRUFBQTtJQUMvRCxN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RyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUM3Qzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7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
