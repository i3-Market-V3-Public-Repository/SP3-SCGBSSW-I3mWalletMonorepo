import * as b64 from '@juanelas/base64';
import { decode } from '@juanelas/base64';
import { hexToBuf, parseHex as parseHex$1, bufToHex } from 'bigint-conversion';
import { randBytes, randBytesSync } from 'bigint-crypto-utils';
import elliptic from 'elliptic';
import { importJWK, CompactEncrypt, decodeProtectedHeader, compactDecrypt, jwtVerify, generateSecret, exportJWK, GeneralSign, generalVerify, SignJWT } from 'jose';
import { hashable } from 'object-sha';
import { ethers, Wallet } from 'ethers';
import Ajv from 'ajv-draft-04';
import addFormats from 'ajv-formats';
import _ from 'lodash';
import { SigningKey } from 'ethers/lib/utils';

const HASH_ALGS = ['SHA-256', 'SHA-384', 'SHA-512'];
const SIGNING_ALGS = ['ES256', 'ES384', 'ES512'];
const ENC_ALGS = ['A128GCM', 'A256GCM'];
const KEY_AGREEMENT_ALGS = ['ECDH-ES'];

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
        const errors = this.nrErrors.concat(nrErrors);
        this.nrErrors = [...(new Set(errors))];
    }
}

const { ec: Ec } = elliptic;
async function generateKeys(alg, privateKey, base64) {
    if (!SIGNING_ALGS.includes(alg))
        throw new NrError(new RangeError(`Invalid signature algorithm '${alg}''. Allowed algorithms are ${SIGNING_ALGS.toString()}`), ['invalid algorithm']);
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
    const ec = new Ec('p' + namedCurve.substring(namedCurve.length - 3));
    const ecPriv = ec.keyFromPrivate(privKeyBuf);
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
    const jwkAlg = alg === undefined ? jwk.alg : alg;
    const algs = ENC_ALGS.concat(SIGNING_ALGS).concat(KEY_AGREEMENT_ALGS);
    if (!algs.includes(jwkAlg)) {
        throw new NrError('invalid alg. Must be one of: ' + algs.join(','), ['invalid algorithm']);
    }
    try {
        const key = await importJWK(jwk, alg);
        return key;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

async function jweEncrypt(block, secretOrPublicKey, encAlg) {
    let alg;
    let enc;
    const jwk = { ...secretOrPublicKey };
    if (ENC_ALGS.includes(secretOrPublicKey.alg)) {
        alg = 'dir';
        enc = encAlg !== undefined ? encAlg : secretOrPublicKey.alg;
    }
    else if (SIGNING_ALGS.concat(KEY_AGREEMENT_ALGS).includes(secretOrPublicKey.alg)) {
        if (encAlg === undefined) {
            throw new NrError('An encryption algorith encAlg for content encryption should be provided. Allowed values are: ' + ENC_ALGS.join(','), ['encryption failed']);
        }
        enc = encAlg;
        alg = 'ECDH-ES';
        jwk.alg = alg;
    }
    else {
        throw new NrError(`Not a valid symmetric or assymetric alg: ${secretOrPublicKey.alg}`, ['encryption failed', 'invalid key', 'invalid algorithm']);
    }
    const key = await importJwk(jwk);
    let jwe;
    try {
        jwe = await new CompactEncrypt(block)
            .setProtectedHeader({ alg, enc, kid: secretOrPublicKey.kid })
            .encrypt(key);
        return jwe;
    }
    catch (error) {
        throw new NrError(error, ['encryption failed']);
    }
}
async function jweDecrypt(jwe, secretOrPrivateKey) {
    try {
        const jwk = { ...secretOrPrivateKey };
        const { alg, enc } = decodeProtectedHeader(jwe);
        if (alg === undefined || enc === undefined) {
            throw new NrError('missing enc or alg in jwe header', ['invalid format']);
        }
        if (alg === 'ECDH-ES') {
            jwk.alg = alg;
        }
        const key = await importJwk(jwk);
        return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [enc] });
    }
    catch (error) {
        const nrError = new NrError(error, ['decryption failed']);
        throw nrError;
    }
}

async function jwsDecode(jws, publicJwk) {
    const regex = /^([a-zA-Z0-9_-]+)\.{1,2}([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/;
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
        const pubKey = await importJwk(pubJwk);
        try {
            const verified = await jwtVerify(jws, pubKey);
            return {
                header: verified.protectedHeader,
                payload: verified.payload,
                signer: pubJwk
            };
        }
        catch (error) {
            throw new NrError(error, ['jws verification failed']);
        }
    }
    return { header, payload };
}

function algByteLength(alg) {
    const algs = ENC_ALGS.concat(HASH_ALGS).concat(SIGNING_ALGS);
    if (algs.includes(alg)) {
        return Number(alg.match(/\d{3}/)[0]) / 8;
    }
    throw new NrError('unsupported algorithm', ['invalid algorithm']);
}

async function oneTimeSecret(encAlg, secret, base64) {
    let key;
    if (!ENC_ALGS.includes(encAlg)) {
        throw new NrError(new Error(`Invalid encAlg '${encAlg}'. Supported values are: ${ENC_ALGS.toString()}`), ['invalid algorithm']);
    }
    const secretLength = algByteLength(encAlg);
    if (secret !== undefined) {
        if (typeof secret === 'string') {
            if (base64 === true) {
                key = b64.decode(secret);
            }
            else {
                const parsedSecret = parseHex$1(secret, false);
                if (parsedSecret !== parseHex$1(secret, false, secretLength)) {
                    throw new NrError(new RangeError(`Expected hex length ${secretLength * 2} does not meet provided one ${parsedSecret.length / 2}`), ['invalid key']);
                }
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
    jwk.alg = encAlg;
    return { jwk: jwk, hex: bufToHex(decode(jwk.k), false, secretLength) };
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
        await generalVerify(jws, pubKey);
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
    }
}

function checkTimestamp(timestamp, notBefore, notAfter, tolerance = 2000) {
    if (timestamp < notBefore - tolerance) {
        throw new NrError(new Error(`timestamp ${(new Date(timestamp).toTimeString())} before 'notBefore' ${(new Date(notBefore).toTimeString())} with tolerance of ${tolerance / 1000}s`), ['invalid timestamp']);
    }
    else if (timestamp > notAfter + tolerance) {
        throw new NrError(new Error(`timestamp ${(new Date(timestamp).toTimeString())} after 'notAfter' ${(new Date(notAfter).toTimeString())} with tolerance of ${tolerance / 1000}s`), ['invalid timestamp']);
    }
}

function isObject(v) {
    return Object.prototype.toString.call(v) === '[object Object]';
}
function jsonSort(obj) {
    if (Array.isArray(obj)) {
        return obj.sort().map(jsonSort);
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

function parseHex(a, prefix0x = false, byteLength) {
    try {
        return parseHex$1(a, prefix0x, byteLength);
    }
    catch (error) {
        throw new NrError(error, ['invalid format']);
    }
}

async function parseJwk(jwk, stringify) {
    try {
        await importJwk(jwk, jwk.alg);
        const sortedJwk = jsonSort(jwk);
        return (stringify) ? JSON.stringify(sortedJwk) : sortedJwk;
    }
    catch (error) {
        throw new NrError(error, ['invalid key']);
    }
}

async function sha(input, algorithm) {
    const algorithms = HASH_ALGS;
    if (!algorithms.includes(algorithm)) {
        throw new NrError(new RangeError(`Valid hash algorith values are any of ${JSON.stringify(algorithms)}`), ['invalid algorithm']);
    }
    const encoder = new TextEncoder();
    const hashInput = (typeof input === 'string') ? encoder.encode(input).buffer : input;
    try {
        let digest;
        if (true) {
            digest = new Uint8Array(await crypto.subtle.digest(algorithm, hashInput));
        }'crypto'
        return digest;
    }
    catch (error) {
        throw new NrError(error, ['unexpected error']);
    }
}

function parseAddress(a) {
    const hexMatch = a.match(/^(0x)?([\da-fA-F]{40})$/);
    if (hexMatch == null) {
        throw new RangeError('incorrect address format');
    }
    try {
        const hex = parseHex(a, true, 20);
        return ethers.utils.getAddress(hex);
    }
    catch (error) {
        throw new NrError(error, ['invalid EIP-55 address']);
    }
}

function getDltAddress(didOrKeyInHex) {
    const didRegEx = /^did:ethr:(\w+:)?(0x[0-9a-fA-F]{40}[0-9a-fA-F]{26}?)$/;
    const match = didOrKeyInHex.match(didRegEx);
    const key = (match !== null) ? match[match.length - 1] : didOrKeyInHex;
    try {
        return ethers.utils.computeAddress(key);
    }
    catch (error) {
        throw new NrError('no a DID or a valid public or private key', ['invalid format']);
    }
}

async function exchangeId(exchange) {
    return b64.encode(await sha(hashable(exchange), 'SHA-256'), true, false);
}

var openapi = "3.0.3";
var info = {
	version: "2.1.6",
	title: "i3M Wallet API",
	contact: {
		name: "Juan Hernández Serrano",
		email: "j.hernandez@upc.edu"
	},
	license: {
		name: "MIT"
	},
	description: "i3M-Wallet API that can be used to interact with the i3M-Wallet. Most of the functionalities will also require end-user interaction with the wallet app.\n"
};
var tags = [
	{
		name: "identities",
		description: "Endpoints to manage identities (DIDs).\n"
	},
	{
		name: "resources",
		description: "Besides identities, the wallet MAY securely store arbitrary resources in a secure vault, which may be selectively disclosed upon request. Currently storing verifiable credentials\n"
	},
	{
		name: "selectiveDisclosure",
		description: "Ednpoints for the selective disclosure process (used to present verifiable credentials)\n"
	},
	{
		name: "transaction",
		description: "Endpoints for deploying signed transactions to the DLT the wallet is connected to.\n"
	},
	{
		name: "utils",
		description: "Additional helpler functions\n"
	}
];
var paths = {
	"/identities": {
		get: {
			summary: "List all DIDs",
			operationId: "identityList",
			"x-eov-operation-handler": "identities",
			tags: [
				"identities"
			],
			parameters: [
				{
					"in": "query",
					name: "alias",
					schema: {
						type: "string",
						description: "An alias for the identity"
					}
				}
			],
			responses: {
				"200": {
					description: "An array of identities",
					content: {
						"application/json": {
							schema: {
								title: "IdentityListInput",
								description: "A list of DIDs",
								type: "array",
								items: {
									type: "object",
									properties: {
										did: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										}
									},
									required: [
										"did"
									]
								}
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		},
		post: {
			summary: "Create an account",
			operationId: "identityCreate",
			"x-eov-operation-handler": "identities",
			tags: [
				"identities"
			],
			requestBody: {
				description: "Create a DID.",
				required: false,
				content: {
					"application/json": {
						schema: {
							title: "IdentityCreateInput",
							description: "Besides the here defined options, provider specific properties should be added here if necessary, e.g. \"path\" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).\n",
							type: "object",
							properties: {
								alias: {
									type: "string"
								}
							},
							additionalProperties: true
						}
					}
				}
			},
			responses: {
				"201": {
					description: "the ID and type of the created account",
					content: {
						"application/json": {
							schema: {
								title: "IdentityCreateOutput",
								description: "It returns the account id and type\n",
								type: "object",
								properties: {
									did: {
										description: "a DID using the ethr resolver",
										type: "string",
										pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
										example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
									}
								},
								additionalProperties: true,
								required: [
									"did"
								]
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	},
	"/identities/select": {
		get: {
			summary: "Gets an identity selected by the user.",
			operationId: "identitySelect",
			"x-eov-operation-handler": "identities",
			tags: [
				"identities"
			],
			parameters: [
				{
					"in": "query",
					name: "reason",
					schema: {
						type: "string",
						description: "Message to show to the user with the reason to pick an identity"
					}
				}
			],
			responses: {
				"200": {
					description: "Selected identity",
					content: {
						"application/json": {
							schema: {
								title: "IdentitySelectOutput",
								type: "object",
								properties: {
									did: {
										description: "a DID using the ethr resolver",
										type: "string",
										pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
										example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
									}
								},
								required: [
									"did"
								]
							}
						}
					}
				}
			}
		}
	},
	"/identities/{did}/sign": {
		post: {
			summary: "Signs a message",
			operationId: "identitySign",
			"x-eov-operation-handler": "identities",
			tags: [
				"identities"
			],
			parameters: [
				{
					"in": "path",
					name: "did",
					schema: {
						description: "a DID using the ethr resolver",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
						example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
					},
					required: true
				}
			],
			requestBody: {
				description: "Data to sign.",
				required: true,
				content: {
					"application/json": {
						schema: {
							title: "SignInput",
							oneOf: [
								{
									title: "SignTransaction",
									type: "object",
									properties: {
										type: {
											"enum": [
												"Transaction"
											]
										},
										data: {
											title: "Transaction",
											type: "object",
											additionalProperties: true,
											properties: {
												from: {
													type: "string"
												},
												to: {
													type: "string"
												},
												nonce: {
													type: "number"
												}
											}
										}
									},
									required: [
										"type",
										"data"
									]
								},
								{
									title: "SignRaw",
									type: "object",
									properties: {
										type: {
											"enum": [
												"Raw"
											]
										},
										data: {
											type: "object",
											properties: {
												payload: {
													description: "Base64Url encoded data to sign",
													type: "string",
													pattern: "^[A-Za-z0-9_-]+$"
												}
											},
											required: [
												"payload"
											]
										}
									},
									required: [
										"type",
										"data"
									]
								},
								{
									title: "SignJWT",
									type: "object",
									properties: {
										type: {
											"enum": [
												"JWT"
											]
										},
										data: {
											type: "object",
											properties: {
												header: {
													description: "header fields to be added to the JWS header. \"alg\" and \"kid\" will be ignored since they are automatically added by the wallet.",
													type: "object",
													additionalProperties: true
												},
												payload: {
													description: "A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.",
													type: "object",
													additionalProperties: true
												}
											},
											required: [
												"payload"
											]
										}
									},
									required: [
										"type",
										"data"
									]
								}
							]
						}
					}
				}
			},
			responses: {
				"200": {
					description: "Signed data",
					content: {
						"application/json": {
							schema: {
								title: "SignOutput",
								type: "object",
								properties: {
									signature: {
										type: "string"
									}
								},
								required: [
									"signature"
								]
							}
						}
					}
				}
			}
		}
	},
	"/identities/{did}/info": {
		get: {
			summary: "Gets extra information of an identity.",
			operationId: "identityInfo",
			"x-eov-operation-handler": "identities",
			tags: [
				"identities"
			],
			parameters: [
				{
					"in": "path",
					name: "did",
					schema: {
						description: "a DID using the ethr resolver",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
						example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
					},
					required: true
				}
			],
			responses: {
				"200": {
					description: "Identity data",
					content: {
						"application/json": {
							schema: {
								title: "Identity Data",
								type: "object",
								properties: {
									did: {
										type: "string",
										example: "did:ethr:i3m:0x03142f480f831e835822fc0cd35726844a7069d28df58fb82037f1598812e1ade8"
									},
									alias: {
										type: "string",
										example: "identity1"
									},
									provider: {
										type: "string",
										example: "did:ethr:i3m"
									},
									addresses: {
										type: "array",
										items: {
											description: "Ethereum Address in EIP-55 format (with checksum)",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										example: [
											"0x8646cAcF516de1292be1D30AB68E7Ea51e9B1BE7"
										]
									}
								},
								required: [
									"did"
								]
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	},
	"/identities/{did}/deploy-tx": {
		post: {
			summary: "Signs and deploys a transaction",
			operationId: "identityDeployTransaction",
			"x-eov-operation-handler": "identities",
			tags: [
				"identities"
			],
			parameters: [
				{
					"in": "path",
					name: "did",
					schema: {
						description: "a DID using the ethr resolver",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
						example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
					},
					required: true
				}
			],
			requestBody: {
				description: "Transaction to sign and deploy",
				required: true,
				content: {
					"application/json": {
						schema: {
							title: "Transaction",
							type: "object",
							additionalProperties: true,
							properties: {
								from: {
									type: "string"
								},
								to: {
									type: "string"
								},
								nonce: {
									type: "number"
								}
							}
						}
					}
				}
			},
			responses: {
				"200": {
					description: "Selected identity",
					content: {
						"application/json": {
							schema: {
								title: "Receipt",
								type: "object",
								properties: {
									receipt: {
										type: "string"
									}
								},
								required: [
									"receipt"
								]
							}
						}
					}
				}
			}
		}
	},
	"/resources": {
		get: {
			summary: "Lists the resources that match the filter specified in the query parameters.",
			operationId: "resourceList",
			"x-eov-operation-handler": "resources",
			tags: [
				"resources"
			],
			parameters: [
				{
					"in": "query",
					name: "type",
					example: "Contract",
					required: false,
					schema: {
						type: "string",
						"enum": [
							"VerifiableCredential",
							"Object",
							"Contract",
							"DataExchange",
							"NonRepudiationProof"
						]
					},
					description: "Filter the resources by resource type."
				},
				{
					"in": "query",
					name: "identity",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863",
					allowEmptyValue: true,
					required: false,
					schema: {
						description: "a DID using the ethr resolver",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
						example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
					},
					description: "Filter the resource associated to an identity DID. Send empty value to get all the resources that are not associated to any identity."
				},
				{
					"in": "query",
					name: "parentResource",
					required: false,
					schema: {
						type: "string"
					},
					description: "Get only resources with the given parent resource id."
				}
			],
			responses: {
				"200": {
					description: "A paged array of resources. Only the props requested will be returned. Security policies may prevent some props from being returned.",
					content: {
						"application/json": {
							schema: {
								title: "ResourceListOutput",
								description: "A list of resources",
								type: "array",
								items: {
									title: "Resource",
									anyOf: [
										{
											title: "VerifiableCredential",
											type: "object",
											properties: {
												type: {
													example: "VerifiableCredential",
													"enum": [
														"VerifiableCredential"
													]
												},
												name: {
													type: "string",
													example: "Resource name"
												},
												resource: {
													type: "object",
													properties: {
														"@context": {
															type: "array",
															items: {
																type: "string"
															},
															example: [
																"https://www.w3.org/2018/credentials/v1"
															]
														},
														id: {
															type: "string",
															example: "http://example.edu/credentials/1872"
														},
														type: {
															type: "array",
															items: {
																type: "string"
															},
															example: [
																"VerifiableCredential"
															]
														},
														issuer: {
															type: "object",
															properties: {
																id: {
																	description: "a DID using the ethr resolver",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																}
															},
															additionalProperties: true,
															required: [
																"id"
															]
														},
														issuanceDate: {
															type: "string",
															format: "date-time",
															example: "2021-06-10T19:07:28.000Z"
														},
														credentialSubject: {
															type: "object",
															properties: {
																id: {
																	description: "a DID using the ethr resolver",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																}
															},
															required: [
																"id"
															],
															additionalProperties: true
														},
														proof: {
															type: "object",
															properties: {
																type: {
																	type: "string",
																	"enum": [
																		"JwtProof2020"
																	]
																}
															},
															required: [
																"type"
															],
															additionalProperties: true
														}
													},
													additionalProperties: true,
													required: [
														"@context",
														"type",
														"issuer",
														"issuanceDate",
														"credentialSubject",
														"proof"
													]
												}
											},
											required: [
												"type",
												"resource"
											]
										},
										{
											title: "ObjectResource",
											type: "object",
											properties: {
												type: {
													example: "Object",
													"enum": [
														"Object"
													]
												},
												name: {
													type: "string",
													example: "Resource name"
												},
												parentResource: {
													type: "string"
												},
												identity: {
													description: "a DID using the ethr resolver",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
													example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
												},
												resource: {
													type: "object",
													additionalProperties: true
												}
											},
											required: [
												"type",
												"resource"
											]
										},
										{
											title: "Contract",
											type: "object",
											properties: {
												type: {
													example: "Contract",
													"enum": [
														"Contract"
													]
												},
												name: {
													type: "string",
													example: "Resource name"
												},
												identity: {
													description: "a DID using the ethr resolver",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
													example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
												},
												resource: {
													type: "object",
													properties: {
														dataSharingAgreement: {
															type: "object",
															required: [
																"dataOfferingDescription",
																"parties",
																"purpose",
																"duration",
																"intendedUse",
																"licenseGrant",
																"dataStream",
																"personalData",
																"pricingModel",
																"dataExchangeAgreement",
																"signatures"
															],
															properties: {
																dataOfferingDescription: {
																	type: "object",
																	required: [
																		"dataOfferingId",
																		"version",
																		"active"
																	],
																	properties: {
																		dataOfferingId: {
																			type: "string"
																		},
																		version: {
																			type: "integer"
																		},
																		category: {
																			type: "string"
																		},
																		active: {
																			type: "boolean"
																		},
																		title: {
																			type: "string"
																		}
																	}
																},
																parties: {
																	type: "object",
																	required: [
																		"providerDid",
																		"consumerDid"
																	],
																	properties: {
																		providerDid: {
																			description: "a DID using the ethr resolver",
																			type: "string",
																			pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
																			example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																		},
																		consumerDid: {
																			description: "a DID using the ethr resolver",
																			type: "string",
																			pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
																			example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																		}
																	}
																},
																purpose: {
																	type: "string"
																},
																duration: {
																	type: "object",
																	required: [
																		"creationDate",
																		"startDate",
																		"endDate"
																	],
																	properties: {
																		creationDate: {
																			type: "integer"
																		},
																		startDate: {
																			type: "integer"
																		},
																		endDate: {
																			type: "integer"
																		}
																	}
																},
																intendedUse: {
																	type: "object",
																	required: [
																		"processData",
																		"shareDataWithThirdParty",
																		"editData"
																	],
																	properties: {
																		processData: {
																			type: "boolean"
																		},
																		shareDataWithThirdParty: {
																			type: "boolean"
																		},
																		editData: {
																			type: "boolean"
																		}
																	}
																},
																licenseGrant: {
																	type: "object",
																	required: [
																		"transferable",
																		"exclusiveness",
																		"paidUp",
																		"revocable",
																		"processing",
																		"modifying",
																		"analyzing",
																		"storingData",
																		"storingCopy",
																		"reproducing",
																		"distributing",
																		"loaning",
																		"selling",
																		"renting",
																		"furtherLicensing",
																		"leasing"
																	],
																	properties: {
																		transferable: {
																			type: "boolean"
																		},
																		exclusiveness: {
																			type: "boolean"
																		},
																		paidUp: {
																			type: "boolean"
																		},
																		revocable: {
																			type: "boolean"
																		},
																		processing: {
																			type: "boolean"
																		},
																		modifying: {
																			type: "boolean"
																		},
																		analyzing: {
																			type: "boolean"
																		},
																		storingData: {
																			type: "boolean"
																		},
																		storingCopy: {
																			type: "boolean"
																		},
																		reproducing: {
																			type: "boolean"
																		},
																		distributing: {
																			type: "boolean"
																		},
																		loaning: {
																			type: "boolean"
																		},
																		selling: {
																			type: "boolean"
																		},
																		renting: {
																			type: "boolean"
																		},
																		furtherLicensing: {
																			type: "boolean"
																		},
																		leasing: {
																			type: "boolean"
																		}
																	}
																},
																dataStream: {
																	type: "boolean"
																},
																personalData: {
																	type: "boolean"
																},
																pricingModel: {
																	type: "object",
																	required: [
																		"basicPrice",
																		"currency",
																		"hasFreePrice"
																	],
																	properties: {
																		paymentType: {
																			type: "string"
																		},
																		pricingModelName: {
																			type: "string"
																		},
																		basicPrice: {
																			type: "number",
																			format: "float"
																		},
																		currency: {
																			type: "string"
																		},
																		fee: {
																			type: "number",
																			format: "float"
																		},
																		hasPaymentOnSubscription: {
																			type: "object",
																			properties: {
																				paymentOnSubscriptionName: {
																					type: "string"
																				},
																				paymentType: {
																					type: "string"
																				},
																				timeDuration: {
																					type: "string"
																				},
																				description: {
																					type: "string"
																				},
																				repeat: {
																					type: "string"
																				},
																				hasSubscriptionPrice: {
																					type: "integer"
																				}
																			}
																		},
																		hasFreePrice: {
																			type: "object",
																			properties: {
																				hasPriceFree: {
																					type: "boolean"
																				}
																			}
																		}
																	}
																},
																dataExchangeAgreement: {
																	type: "object",
																	required: [
																		"orig",
																		"dest",
																		"encAlg",
																		"signingAlg",
																		"hashAlg",
																		"ledgerContractAddress",
																		"ledgerSignerAddress",
																		"pooToPorDelay",
																		"pooToPopDelay",
																		"pooToSecretDelay"
																	],
																	properties: {
																		orig: {
																			type: "string",
																			description: "A stringified JWK with alphabetically sorted claims",
																			example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
																		},
																		dest: {
																			type: "string",
																			description: "A stringified JWK with alphabetically sorted claims",
																			example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
																		},
																		encAlg: {
																			type: "string",
																			"enum": [
																				"A128GCM",
																				"A256GCM"
																			],
																			example: "A256GCM"
																		},
																		signingAlg: {
																			type: "string",
																			"enum": [
																				"ES256",
																				"ES384",
																				"ES512"
																			],
																			example: "ES256"
																		},
																		hashAlg: {
																			type: "string",
																			"enum": [
																				"SHA-256",
																				"SHA-384",
																				"SHA-512"
																			],
																			example: "SHA-256"
																		},
																		ledgerContractAddress: {
																			description: "Ethereum Address in EIP-55 format (with checksum)",
																			type: "string",
																			pattern: "^0x([0-9A-Fa-f]){40}$",
																			example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																		},
																		ledgerSignerAddress: {
																			description: "Ethereum Address in EIP-55 format (with checksum)",
																			type: "string",
																			pattern: "^0x([0-9A-Fa-f]){40}$",
																			example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																		},
																		pooToPorDelay: {
																			description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
																			type: "integer",
																			minimum: 1,
																			example: 10000
																		},
																		pooToPopDelay: {
																			description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
																			type: "integer",
																			minimum: 1,
																			example: 20000
																		},
																		pooToSecretDelay: {
																			description: "Maximum acceptable time between issued PoO and secret published on the ledger",
																			type: "integer",
																			minimum: 1,
																			example: 180000
																		},
																		schema: {
																			description: "A stringified JSON-LD schema describing the data format",
																			type: "string"
																		}
																	}
																},
																signatures: {
																	type: "object",
																	required: [
																		"providerSignature",
																		"consumerSignature"
																	],
																	properties: {
																		providerSignature: {
																			title: "CompactJWS",
																			type: "string",
																			pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
																		},
																		consumerSignature: {
																			title: "CompactJWS",
																			type: "string",
																			pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
																		}
																	}
																}
															}
														},
														keyPair: {
															type: "object",
															properties: {
																privateJwk: {
																	type: "string",
																	description: "A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",
																	example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
																},
																publicJwk: {
																	type: "string",
																	description: "A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`). It MUST match either `dataSharingAgreement.dataExchangeAgreement.orig` or `dataSharingAgreement.dataExchangeAgreement.dest`\n",
																	example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
																}
															},
															required: [
																"privateJwk",
																"publicJwk"
															]
														}
													},
													required: [
														"dataSharingAgreement",
														"keyPair"
													]
												}
											},
											required: [
												"type",
												"resource"
											]
										},
										{
											title: "NonRepudiationProof",
											type: "object",
											properties: {
												type: {
													example: "NonRepudiationProof",
													"enum": [
														"NonRepudiationProof"
													]
												},
												name: {
													type: "string",
													example: "Resource name"
												},
												resource: {
													description: "a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"
												}
											},
											required: [
												"type",
												"resource"
											]
										},
										{
											title: "DataExchangeResource",
											type: "object",
											properties: {
												type: {
													example: "DataExchange",
													"enum": [
														"DataExchange"
													]
												},
												name: {
													type: "string",
													example: "Resource name"
												},
												resource: {
													allOf: [
														{
															type: "object",
															required: [
																"orig",
																"dest",
																"encAlg",
																"signingAlg",
																"hashAlg",
																"ledgerContractAddress",
																"ledgerSignerAddress",
																"pooToPorDelay",
																"pooToPopDelay",
																"pooToSecretDelay"
															],
															properties: {
																orig: {
																	type: "string",
																	description: "A stringified JWK with alphabetically sorted claims",
																	example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
																},
																dest: {
																	type: "string",
																	description: "A stringified JWK with alphabetically sorted claims",
																	example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
																},
																encAlg: {
																	type: "string",
																	"enum": [
																		"A128GCM",
																		"A256GCM"
																	],
																	example: "A256GCM"
																},
																signingAlg: {
																	type: "string",
																	"enum": [
																		"ES256",
																		"ES384",
																		"ES512"
																	],
																	example: "ES256"
																},
																hashAlg: {
																	type: "string",
																	"enum": [
																		"SHA-256",
																		"SHA-384",
																		"SHA-512"
																	],
																	example: "SHA-256"
																},
																ledgerContractAddress: {
																	description: "Ethereum Address in EIP-55 format (with checksum)",
																	type: "string",
																	pattern: "^0x([0-9A-Fa-f]){40}$",
																	example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																},
																ledgerSignerAddress: {
																	description: "Ethereum Address in EIP-55 format (with checksum)",
																	type: "string",
																	pattern: "^0x([0-9A-Fa-f]){40}$",
																	example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																},
																pooToPorDelay: {
																	description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
																	type: "integer",
																	minimum: 1,
																	example: 10000
																},
																pooToPopDelay: {
																	description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
																	type: "integer",
																	minimum: 1,
																	example: 20000
																},
																pooToSecretDelay: {
																	description: "Maximum acceptable time between issued PoO and secret published on the ledger",
																	type: "integer",
																	minimum: 1,
																	example: 180000
																},
																schema: {
																	description: "A stringified JSON-LD schema describing the data format",
																	type: "string"
																}
															}
														},
														{
															type: "object",
															properties: {
																cipherblockDgst: {
																	type: "string",
																	description: "hash of the cipherblock in base64url with no padding",
																	pattern: "^[a-zA-Z0-9_-]+$"
																},
																blockCommitment: {
																	type: "string",
																	description: "hash of the plaintext block in base64url with no padding",
																	pattern: "^[a-zA-Z0-9_-]+$"
																},
																secretCommitment: {
																	type: "string",
																	description: "ash of the secret that can be used to decrypt the block in base64url with no padding",
																	pattern: "^[a-zA-Z0-9_-]+$"
																}
															},
															required: [
																"cipherblockDgst",
																"blockCommitment",
																"secretCommitment"
															]
														}
													]
												}
											},
											required: [
												"type",
												"resource"
											]
										}
									]
								}
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		},
		post: {
			summary: "Create a resource",
			operationId: "resourceCreate",
			"x-eov-operation-handler": "resources",
			tags: [
				"resources"
			],
			requestBody: {
				description: "Create a resource. Nowadays it only supports storage of verifiable credentials.",
				content: {
					"application/json": {
						schema: {
							title: "Resource",
							anyOf: [
								{
									title: "VerifiableCredential",
									type: "object",
									properties: {
										type: {
											example: "VerifiableCredential",
											"enum": [
												"VerifiableCredential"
											]
										},
										name: {
											type: "string",
											example: "Resource name"
										},
										resource: {
											type: "object",
											properties: {
												"@context": {
													type: "array",
													items: {
														type: "string"
													},
													example: [
														"https://www.w3.org/2018/credentials/v1"
													]
												},
												id: {
													type: "string",
													example: "http://example.edu/credentials/1872"
												},
												type: {
													type: "array",
													items: {
														type: "string"
													},
													example: [
														"VerifiableCredential"
													]
												},
												issuer: {
													type: "object",
													properties: {
														id: {
															description: "a DID using the ethr resolver",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
															example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
														}
													},
													additionalProperties: true,
													required: [
														"id"
													]
												},
												issuanceDate: {
													type: "string",
													format: "date-time",
													example: "2021-06-10T19:07:28.000Z"
												},
												credentialSubject: {
													type: "object",
													properties: {
														id: {
															description: "a DID using the ethr resolver",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
															example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
														}
													},
													required: [
														"id"
													],
													additionalProperties: true
												},
												proof: {
													type: "object",
													properties: {
														type: {
															type: "string",
															"enum": [
																"JwtProof2020"
															]
														}
													},
													required: [
														"type"
													],
													additionalProperties: true
												}
											},
											additionalProperties: true,
											required: [
												"@context",
												"type",
												"issuer",
												"issuanceDate",
												"credentialSubject",
												"proof"
											]
										}
									},
									required: [
										"type",
										"resource"
									]
								},
								{
									title: "ObjectResource",
									type: "object",
									properties: {
										type: {
											example: "Object",
											"enum": [
												"Object"
											]
										},
										name: {
											type: "string",
											example: "Resource name"
										},
										parentResource: {
											type: "string"
										},
										identity: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										resource: {
											type: "object",
											additionalProperties: true
										}
									},
									required: [
										"type",
										"resource"
									]
								},
								{
									title: "Contract",
									type: "object",
									properties: {
										type: {
											example: "Contract",
											"enum": [
												"Contract"
											]
										},
										name: {
											type: "string",
											example: "Resource name"
										},
										identity: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										resource: {
											type: "object",
											properties: {
												dataSharingAgreement: {
													type: "object",
													required: [
														"dataOfferingDescription",
														"parties",
														"purpose",
														"duration",
														"intendedUse",
														"licenseGrant",
														"dataStream",
														"personalData",
														"pricingModel",
														"dataExchangeAgreement",
														"signatures"
													],
													properties: {
														dataOfferingDescription: {
															type: "object",
															required: [
																"dataOfferingId",
																"version",
																"active"
															],
															properties: {
																dataOfferingId: {
																	type: "string"
																},
																version: {
																	type: "integer"
																},
																category: {
																	type: "string"
																},
																active: {
																	type: "boolean"
																},
																title: {
																	type: "string"
																}
															}
														},
														parties: {
															type: "object",
															required: [
																"providerDid",
																"consumerDid"
															],
															properties: {
																providerDid: {
																	description: "a DID using the ethr resolver",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																},
																consumerDid: {
																	description: "a DID using the ethr resolver",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																}
															}
														},
														purpose: {
															type: "string"
														},
														duration: {
															type: "object",
															required: [
																"creationDate",
																"startDate",
																"endDate"
															],
															properties: {
																creationDate: {
																	type: "integer"
																},
																startDate: {
																	type: "integer"
																},
																endDate: {
																	type: "integer"
																}
															}
														},
														intendedUse: {
															type: "object",
															required: [
																"processData",
																"shareDataWithThirdParty",
																"editData"
															],
															properties: {
																processData: {
																	type: "boolean"
																},
																shareDataWithThirdParty: {
																	type: "boolean"
																},
																editData: {
																	type: "boolean"
																}
															}
														},
														licenseGrant: {
															type: "object",
															required: [
																"transferable",
																"exclusiveness",
																"paidUp",
																"revocable",
																"processing",
																"modifying",
																"analyzing",
																"storingData",
																"storingCopy",
																"reproducing",
																"distributing",
																"loaning",
																"selling",
																"renting",
																"furtherLicensing",
																"leasing"
															],
															properties: {
																transferable: {
																	type: "boolean"
																},
																exclusiveness: {
																	type: "boolean"
																},
																paidUp: {
																	type: "boolean"
																},
																revocable: {
																	type: "boolean"
																},
																processing: {
																	type: "boolean"
																},
																modifying: {
																	type: "boolean"
																},
																analyzing: {
																	type: "boolean"
																},
																storingData: {
																	type: "boolean"
																},
																storingCopy: {
																	type: "boolean"
																},
																reproducing: {
																	type: "boolean"
																},
																distributing: {
																	type: "boolean"
																},
																loaning: {
																	type: "boolean"
																},
																selling: {
																	type: "boolean"
																},
																renting: {
																	type: "boolean"
																},
																furtherLicensing: {
																	type: "boolean"
																},
																leasing: {
																	type: "boolean"
																}
															}
														},
														dataStream: {
															type: "boolean"
														},
														personalData: {
															type: "boolean"
														},
														pricingModel: {
															type: "object",
															required: [
																"basicPrice",
																"currency",
																"hasFreePrice"
															],
															properties: {
																paymentType: {
																	type: "string"
																},
																pricingModelName: {
																	type: "string"
																},
																basicPrice: {
																	type: "number",
																	format: "float"
																},
																currency: {
																	type: "string"
																},
																fee: {
																	type: "number",
																	format: "float"
																},
																hasPaymentOnSubscription: {
																	type: "object",
																	properties: {
																		paymentOnSubscriptionName: {
																			type: "string"
																		},
																		paymentType: {
																			type: "string"
																		},
																		timeDuration: {
																			type: "string"
																		},
																		description: {
																			type: "string"
																		},
																		repeat: {
																			type: "string"
																		},
																		hasSubscriptionPrice: {
																			type: "integer"
																		}
																	}
																},
																hasFreePrice: {
																	type: "object",
																	properties: {
																		hasPriceFree: {
																			type: "boolean"
																		}
																	}
																}
															}
														},
														dataExchangeAgreement: {
															type: "object",
															required: [
																"orig",
																"dest",
																"encAlg",
																"signingAlg",
																"hashAlg",
																"ledgerContractAddress",
																"ledgerSignerAddress",
																"pooToPorDelay",
																"pooToPopDelay",
																"pooToSecretDelay"
															],
															properties: {
																orig: {
																	type: "string",
																	description: "A stringified JWK with alphabetically sorted claims",
																	example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
																},
																dest: {
																	type: "string",
																	description: "A stringified JWK with alphabetically sorted claims",
																	example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
																},
																encAlg: {
																	type: "string",
																	"enum": [
																		"A128GCM",
																		"A256GCM"
																	],
																	example: "A256GCM"
																},
																signingAlg: {
																	type: "string",
																	"enum": [
																		"ES256",
																		"ES384",
																		"ES512"
																	],
																	example: "ES256"
																},
																hashAlg: {
																	type: "string",
																	"enum": [
																		"SHA-256",
																		"SHA-384",
																		"SHA-512"
																	],
																	example: "SHA-256"
																},
																ledgerContractAddress: {
																	description: "Ethereum Address in EIP-55 format (with checksum)",
																	type: "string",
																	pattern: "^0x([0-9A-Fa-f]){40}$",
																	example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																},
																ledgerSignerAddress: {
																	description: "Ethereum Address in EIP-55 format (with checksum)",
																	type: "string",
																	pattern: "^0x([0-9A-Fa-f]){40}$",
																	example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																},
																pooToPorDelay: {
																	description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
																	type: "integer",
																	minimum: 1,
																	example: 10000
																},
																pooToPopDelay: {
																	description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
																	type: "integer",
																	minimum: 1,
																	example: 20000
																},
																pooToSecretDelay: {
																	description: "Maximum acceptable time between issued PoO and secret published on the ledger",
																	type: "integer",
																	minimum: 1,
																	example: 180000
																},
																schema: {
																	description: "A stringified JSON-LD schema describing the data format",
																	type: "string"
																}
															}
														},
														signatures: {
															type: "object",
															required: [
																"providerSignature",
																"consumerSignature"
															],
															properties: {
																providerSignature: {
																	title: "CompactJWS",
																	type: "string",
																	pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
																},
																consumerSignature: {
																	title: "CompactJWS",
																	type: "string",
																	pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
																}
															}
														}
													}
												},
												keyPair: {
													type: "object",
													properties: {
														privateJwk: {
															type: "string",
															description: "A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",
															example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
														},
														publicJwk: {
															type: "string",
															description: "A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`). It MUST match either `dataSharingAgreement.dataExchangeAgreement.orig` or `dataSharingAgreement.dataExchangeAgreement.dest`\n",
															example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
														}
													},
													required: [
														"privateJwk",
														"publicJwk"
													]
												}
											},
											required: [
												"dataSharingAgreement",
												"keyPair"
											]
										}
									},
									required: [
										"type",
										"resource"
									]
								},
								{
									title: "NonRepudiationProof",
									type: "object",
									properties: {
										type: {
											example: "NonRepudiationProof",
											"enum": [
												"NonRepudiationProof"
											]
										},
										name: {
											type: "string",
											example: "Resource name"
										},
										resource: {
											description: "a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"
										}
									},
									required: [
										"type",
										"resource"
									]
								},
								{
									title: "DataExchangeResource",
									type: "object",
									properties: {
										type: {
											example: "DataExchange",
											"enum": [
												"DataExchange"
											]
										},
										name: {
											type: "string",
											example: "Resource name"
										},
										resource: {
											allOf: [
												{
													type: "object",
													required: [
														"orig",
														"dest",
														"encAlg",
														"signingAlg",
														"hashAlg",
														"ledgerContractAddress",
														"ledgerSignerAddress",
														"pooToPorDelay",
														"pooToPopDelay",
														"pooToSecretDelay"
													],
													properties: {
														orig: {
															type: "string",
															description: "A stringified JWK with alphabetically sorted claims",
															example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
														},
														dest: {
															type: "string",
															description: "A stringified JWK with alphabetically sorted claims",
															example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
														},
														encAlg: {
															type: "string",
															"enum": [
																"A128GCM",
																"A256GCM"
															],
															example: "A256GCM"
														},
														signingAlg: {
															type: "string",
															"enum": [
																"ES256",
																"ES384",
																"ES512"
															],
															example: "ES256"
														},
														hashAlg: {
															type: "string",
															"enum": [
																"SHA-256",
																"SHA-384",
																"SHA-512"
															],
															example: "SHA-256"
														},
														ledgerContractAddress: {
															description: "Ethereum Address in EIP-55 format (with checksum)",
															type: "string",
															pattern: "^0x([0-9A-Fa-f]){40}$",
															example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
														},
														ledgerSignerAddress: {
															description: "Ethereum Address in EIP-55 format (with checksum)",
															type: "string",
															pattern: "^0x([0-9A-Fa-f]){40}$",
															example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
														},
														pooToPorDelay: {
															description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
															type: "integer",
															minimum: 1,
															example: 10000
														},
														pooToPopDelay: {
															description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
															type: "integer",
															minimum: 1,
															example: 20000
														},
														pooToSecretDelay: {
															description: "Maximum acceptable time between issued PoO and secret published on the ledger",
															type: "integer",
															minimum: 1,
															example: 180000
														},
														schema: {
															description: "A stringified JSON-LD schema describing the data format",
															type: "string"
														}
													}
												},
												{
													type: "object",
													properties: {
														cipherblockDgst: {
															type: "string",
															description: "hash of the cipherblock in base64url with no padding",
															pattern: "^[a-zA-Z0-9_-]+$"
														},
														blockCommitment: {
															type: "string",
															description: "hash of the plaintext block in base64url with no padding",
															pattern: "^[a-zA-Z0-9_-]+$"
														},
														secretCommitment: {
															type: "string",
															description: "ash of the secret that can be used to decrypt the block in base64url with no padding",
															pattern: "^[a-zA-Z0-9_-]+$"
														}
													},
													required: [
														"cipherblockDgst",
														"blockCommitment",
														"secretCommitment"
													]
												}
											]
										}
									},
									required: [
										"type",
										"resource"
									]
								}
							]
						}
					}
				}
			},
			responses: {
				"201": {
					description: "the ID and type of the created resource",
					content: {
						"application/json": {
							schema: {
								type: "object",
								properties: {
									id: {
										type: "string"
									}
								},
								required: [
									"id"
								]
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	},
	"/disclosure/{jwt}": {
		get: {
			summary: "Request selective disclosure of resources",
			operationId: "selectiveDisclosure",
			"x-eov-operation-handler": "disclosure",
			tags: [
				"selectiveDisclosure"
			],
			parameters: [
				{
					"in": "path",
					name: "jwt",
					schema: {
						type: "string",
						pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
					},
					required: true,
					description: "A JWT containing a selective disclosure object. The payload MUST contain:\n\n```json\n{\n  \"type\": \"selectiveDisclosureReq\", // MUST be selectiveDisclosureReq\n  \"iss\": \"did:\", // the DID of the OIDC Provider\n  \"aud\": \"\", // DID of the OIDC RP\n  \"iat\": 4354535,\t// The time of issuance\n  \"exp\": 3452345, // [OPTIONAL] Expiration time of JWT\n  callback: \"https://...\", // Callback URL for returning the response to a request\n  resources: [\n    { \"id\": \"id\", \"mandatory\": true, \"iss\": [ { did: or url:} ], \"reason\": \"\" }\n  ]\n}\n```\n"
				}
			],
			responses: {
				"200": {
					description: "Disclosure ok (mandatory claims provided)",
					content: {
						"application/json": {
							schema: {
								type: "object",
								properties: {
									jwt: {
										type: "string"
									}
								}
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	},
	"/transaction/deploy": {
		post: {
			summary: "Deploy a signed transaction",
			operationId: "transactionDeploy",
			"x-eov-operation-handler": "transaction",
			tags: [
				"transaction"
			],
			requestBody: {
				description: "Create a resource.",
				content: {
					"application/json": {
						schema: {
							title: "SignedTransaction",
							description: "A list of resources",
							type: "object",
							properties: {
								transaction: {
									type: "string",
									pattern: "^0x(?:[A-Fa-f0-9])+$"
								}
							}
						}
					}
				}
			},
			responses: {
				"200": {
					description: "Deployment OK"
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	},
	"/did-jwt/verify": {
		post: {
			summary: "Use the wallet to verify a JWT. The Wallet only supports DID issuers and the 'ES256K1' algorithm. Useful to verify JWT created by another wallet instance.\n",
			operationId: "didJwtVerify",
			"x-eov-operation-handler": "did-jwt",
			tags: [
				"utils"
			],
			requestBody: {
				description: "Verify a JWT resolving the public key from the signer DID and optionally check values for expected payload claims",
				required: true,
				content: {
					"application/json": {
						schema: {
							type: "object",
							properties: {
								jwt: {
									type: "string",
									pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",
									example: "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJmaWVsZDEiOiJzYWRzYWQ3NSIsImZpZWxkMiI6ImFmZnNhczlmODdzIiwiaXNzIjoiZGlkOmV0aHI6aTNtOjB4MDNmOTcwNjRhMzUzZmFmNWRkNTQwYWE2N2I2OTE2YmY1NmMwOWM1MGNjODAzN2E0NTNlNzg1ODdmMjdmYjg4ZTk0IiwiaWF0IjoxNjY1NDAwMzYzfQ.IpQ7WprvDMk6QWcJXuPBazat-2657dWIK-iGvOOB5oAhAmMqDBm8OEtKordqeqcEWwhWw_C7_ziMMZkPz1JIkw"
								},
								expectedPayloadClaims: {
									type: "object",
									additionalProperties: true,
									description: "The expected values of the proof's payload claims. An expected value of '' can be used to just check that the claim is in the payload. An example could be:\n\n```json\n{\n  iss: 'orig',\n  exchange: {\n    id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',\n    orig: '{\"kty\":\"EC\",\"x\":\"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY\",\"y\":\"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0\",\"crv\":\"P-256\"}', // Public key in JSON.stringify(JWK) of the block origin (sender)\n    dest: '{\"kty\":\"EC\",\"x\":\"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA\",\"y\":\"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY\",\"crv\":\"P-256\"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)\n    hash_alg: 'SHA-256',\n    cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding\n    block_commitment: '', // hash of the plaintext block in base64url with no padding\n    secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding\n  }\n}\n```\n"
								}
							},
							required: [
								"jwt"
							]
						}
					}
				}
			},
			responses: {
				"200": {
					description: "A verification object. If `verification` equals `success` all checkings have passed; if it is `failed`, you can access the error message in `error`. Unless the JWT decoding fails (invalid format), the decoded JWT payload can be accessed in `payload`.\n\nExample of success:\n\n```json\n{\n  \"verification\": \"success\",\n  \"payload\": {\n    \"iss\": \"did:ethr:i3m:0x02d846307c9fd53106eb20db5a774c4b71f25c59c7bc423990f942e3fdb02c5898\",\n    \"iat\": 1665138018,\n    \"action\": \"buy 1457adf6\"\n  }\n}\n```\n\nExample of failure:\n\n```json\n{\n  \"verification\": \"failed\",\n  \"error\": \"invalid_jwt: JWT iss is required\"\n  \"payload\": {\n    \"iat\": 1665138018,\n    \"action\": \"buy 1457adf6\"\n  }\n}\n```\n",
					content: {
						"application/json": {
							schema: {
								title: "VerificationOutput",
								type: "object",
								properties: {
									verification: {
										type: "string",
										"enum": [
											"success",
											"failed"
										],
										description: "whether verification has been successful or has failed"
									},
									error: {
										type: "string",
										description: "error message if verification failed"
									},
									decodedJwt: {
										description: "the decoded JWT"
									}
								},
								required: [
									"verification"
								]
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	},
	"/providerinfo": {
		get: {
			summary: "Gets info of the DLT provider the wallet is using",
			operationId: "providerinfoGet",
			"x-eov-operation-handler": "providerinfo",
			tags: [
				"utils"
			],
			responses: {
				"200": {
					description: "A JSON object with information of the DLT provider currently in use.",
					content: {
						"application/json": {
							schema: {
								title: "ProviderData",
								description: "A JSON object with information of the DLT provider currently in use.",
								type: "object",
								properties: {
									provider: {
										type: "string",
										example: "did:ethr:i3m"
									},
									network: {
										type: "string",
										example: "i3m"
									},
									rpcUrl: {
										type: "string",
										example: "http://95.211.3.250:8545"
									}
								},
								additionalProperties: true
							}
						}
					}
				},
				"default": {
					description: "unexpected error",
					content: {
						"application/json": {
							schema: {
								type: "object",
								title: "Error",
								required: [
									"code",
									"message"
								],
								properties: {
									code: {
										type: "integer",
										format: "int32"
									},
									message: {
										type: "string"
									}
								}
							}
						}
					}
				}
			}
		}
	}
};
var components = {
	schemas: {
		IdentitySelectOutput: {
			title: "IdentitySelectOutput",
			type: "object",
			properties: {
				did: {
					description: "a DID using the ethr resolver",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				}
			},
			required: [
				"did"
			]
		},
		SignInput: {
			title: "SignInput",
			oneOf: [
				{
					title: "SignTransaction",
					type: "object",
					properties: {
						type: {
							"enum": [
								"Transaction"
							]
						},
						data: {
							title: "Transaction",
							type: "object",
							additionalProperties: true,
							properties: {
								from: {
									type: "string"
								},
								to: {
									type: "string"
								},
								nonce: {
									type: "number"
								}
							}
						}
					},
					required: [
						"type",
						"data"
					]
				},
				{
					title: "SignRaw",
					type: "object",
					properties: {
						type: {
							"enum": [
								"Raw"
							]
						},
						data: {
							type: "object",
							properties: {
								payload: {
									description: "Base64Url encoded data to sign",
									type: "string",
									pattern: "^[A-Za-z0-9_-]+$"
								}
							},
							required: [
								"payload"
							]
						}
					},
					required: [
						"type",
						"data"
					]
				},
				{
					title: "SignJWT",
					type: "object",
					properties: {
						type: {
							"enum": [
								"JWT"
							]
						},
						data: {
							type: "object",
							properties: {
								header: {
									description: "header fields to be added to the JWS header. \"alg\" and \"kid\" will be ignored since they are automatically added by the wallet.",
									type: "object",
									additionalProperties: true
								},
								payload: {
									description: "A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.",
									type: "object",
									additionalProperties: true
								}
							},
							required: [
								"payload"
							]
						}
					},
					required: [
						"type",
						"data"
					]
				}
			]
		},
		SignRaw: {
			title: "SignRaw",
			type: "object",
			properties: {
				type: {
					"enum": [
						"Raw"
					]
				},
				data: {
					type: "object",
					properties: {
						payload: {
							description: "Base64Url encoded data to sign",
							type: "string",
							pattern: "^[A-Za-z0-9_-]+$"
						}
					},
					required: [
						"payload"
					]
				}
			},
			required: [
				"type",
				"data"
			]
		},
		SignTransaction: {
			title: "SignTransaction",
			type: "object",
			properties: {
				type: {
					"enum": [
						"Transaction"
					]
				},
				data: {
					title: "Transaction",
					type: "object",
					additionalProperties: true,
					properties: {
						from: {
							type: "string"
						},
						to: {
							type: "string"
						},
						nonce: {
							type: "number"
						}
					}
				}
			},
			required: [
				"type",
				"data"
			]
		},
		SignJWT: {
			title: "SignJWT",
			type: "object",
			properties: {
				type: {
					"enum": [
						"JWT"
					]
				},
				data: {
					type: "object",
					properties: {
						header: {
							description: "header fields to be added to the JWS header. \"alg\" and \"kid\" will be ignored since they are automatically added by the wallet.",
							type: "object",
							additionalProperties: true
						},
						payload: {
							description: "A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.",
							type: "object",
							additionalProperties: true
						}
					},
					required: [
						"payload"
					]
				}
			},
			required: [
				"type",
				"data"
			]
		},
		Transaction: {
			title: "Transaction",
			type: "object",
			additionalProperties: true,
			properties: {
				from: {
					type: "string"
				},
				to: {
					type: "string"
				},
				nonce: {
					type: "number"
				}
			}
		},
		SignOutput: {
			title: "SignOutput",
			type: "object",
			properties: {
				signature: {
					type: "string"
				}
			},
			required: [
				"signature"
			]
		},
		Receipt: {
			title: "Receipt",
			type: "object",
			properties: {
				receipt: {
					type: "string"
				}
			},
			required: [
				"receipt"
			]
		},
		SignTypes: {
			title: "SignTypes",
			type: "string",
			"enum": [
				"Transaction",
				"Raw",
				"JWT"
			]
		},
		IdentityListInput: {
			title: "IdentityListInput",
			description: "A list of DIDs",
			type: "array",
			items: {
				type: "object",
				properties: {
					did: {
						description: "a DID using the ethr resolver",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
						example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
					}
				},
				required: [
					"did"
				]
			}
		},
		IdentityCreateInput: {
			title: "IdentityCreateInput",
			description: "Besides the here defined options, provider specific properties should be added here if necessary, e.g. \"path\" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).\n",
			type: "object",
			properties: {
				alias: {
					type: "string"
				}
			},
			additionalProperties: true
		},
		IdentityCreateOutput: {
			title: "IdentityCreateOutput",
			description: "It returns the account id and type\n",
			type: "object",
			properties: {
				did: {
					description: "a DID using the ethr resolver",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				}
			},
			additionalProperties: true,
			required: [
				"did"
			]
		},
		ResourceListOutput: {
			title: "ResourceListOutput",
			description: "A list of resources",
			type: "array",
			items: {
				title: "Resource",
				anyOf: [
					{
						title: "VerifiableCredential",
						type: "object",
						properties: {
							type: {
								example: "VerifiableCredential",
								"enum": [
									"VerifiableCredential"
								]
							},
							name: {
								type: "string",
								example: "Resource name"
							},
							resource: {
								type: "object",
								properties: {
									"@context": {
										type: "array",
										items: {
											type: "string"
										},
										example: [
											"https://www.w3.org/2018/credentials/v1"
										]
									},
									id: {
										type: "string",
										example: "http://example.edu/credentials/1872"
									},
									type: {
										type: "array",
										items: {
											type: "string"
										},
										example: [
											"VerifiableCredential"
										]
									},
									issuer: {
										type: "object",
										properties: {
											id: {
												description: "a DID using the ethr resolver",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
												example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
											}
										},
										additionalProperties: true,
										required: [
											"id"
										]
									},
									issuanceDate: {
										type: "string",
										format: "date-time",
										example: "2021-06-10T19:07:28.000Z"
									},
									credentialSubject: {
										type: "object",
										properties: {
											id: {
												description: "a DID using the ethr resolver",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
												example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
											}
										},
										required: [
											"id"
										],
										additionalProperties: true
									},
									proof: {
										type: "object",
										properties: {
											type: {
												type: "string",
												"enum": [
													"JwtProof2020"
												]
											}
										},
										required: [
											"type"
										],
										additionalProperties: true
									}
								},
								additionalProperties: true,
								required: [
									"@context",
									"type",
									"issuer",
									"issuanceDate",
									"credentialSubject",
									"proof"
								]
							}
						},
						required: [
							"type",
							"resource"
						]
					},
					{
						title: "ObjectResource",
						type: "object",
						properties: {
							type: {
								example: "Object",
								"enum": [
									"Object"
								]
							},
							name: {
								type: "string",
								example: "Resource name"
							},
							parentResource: {
								type: "string"
							},
							identity: {
								description: "a DID using the ethr resolver",
								type: "string",
								pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
								example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
							},
							resource: {
								type: "object",
								additionalProperties: true
							}
						},
						required: [
							"type",
							"resource"
						]
					},
					{
						title: "Contract",
						type: "object",
						properties: {
							type: {
								example: "Contract",
								"enum": [
									"Contract"
								]
							},
							name: {
								type: "string",
								example: "Resource name"
							},
							identity: {
								description: "a DID using the ethr resolver",
								type: "string",
								pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
								example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
							},
							resource: {
								type: "object",
								properties: {
									dataSharingAgreement: {
										type: "object",
										required: [
											"dataOfferingDescription",
											"parties",
											"purpose",
											"duration",
											"intendedUse",
											"licenseGrant",
											"dataStream",
											"personalData",
											"pricingModel",
											"dataExchangeAgreement",
											"signatures"
										],
										properties: {
											dataOfferingDescription: {
												type: "object",
												required: [
													"dataOfferingId",
													"version",
													"active"
												],
												properties: {
													dataOfferingId: {
														type: "string"
													},
													version: {
														type: "integer"
													},
													category: {
														type: "string"
													},
													active: {
														type: "boolean"
													},
													title: {
														type: "string"
													}
												}
											},
											parties: {
												type: "object",
												required: [
													"providerDid",
													"consumerDid"
												],
												properties: {
													providerDid: {
														description: "a DID using the ethr resolver",
														type: "string",
														pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
														example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
													},
													consumerDid: {
														description: "a DID using the ethr resolver",
														type: "string",
														pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
														example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
													}
												}
											},
											purpose: {
												type: "string"
											},
											duration: {
												type: "object",
												required: [
													"creationDate",
													"startDate",
													"endDate"
												],
												properties: {
													creationDate: {
														type: "integer"
													},
													startDate: {
														type: "integer"
													},
													endDate: {
														type: "integer"
													}
												}
											},
											intendedUse: {
												type: "object",
												required: [
													"processData",
													"shareDataWithThirdParty",
													"editData"
												],
												properties: {
													processData: {
														type: "boolean"
													},
													shareDataWithThirdParty: {
														type: "boolean"
													},
													editData: {
														type: "boolean"
													}
												}
											},
											licenseGrant: {
												type: "object",
												required: [
													"transferable",
													"exclusiveness",
													"paidUp",
													"revocable",
													"processing",
													"modifying",
													"analyzing",
													"storingData",
													"storingCopy",
													"reproducing",
													"distributing",
													"loaning",
													"selling",
													"renting",
													"furtherLicensing",
													"leasing"
												],
												properties: {
													transferable: {
														type: "boolean"
													},
													exclusiveness: {
														type: "boolean"
													},
													paidUp: {
														type: "boolean"
													},
													revocable: {
														type: "boolean"
													},
													processing: {
														type: "boolean"
													},
													modifying: {
														type: "boolean"
													},
													analyzing: {
														type: "boolean"
													},
													storingData: {
														type: "boolean"
													},
													storingCopy: {
														type: "boolean"
													},
													reproducing: {
														type: "boolean"
													},
													distributing: {
														type: "boolean"
													},
													loaning: {
														type: "boolean"
													},
													selling: {
														type: "boolean"
													},
													renting: {
														type: "boolean"
													},
													furtherLicensing: {
														type: "boolean"
													},
													leasing: {
														type: "boolean"
													}
												}
											},
											dataStream: {
												type: "boolean"
											},
											personalData: {
												type: "boolean"
											},
											pricingModel: {
												type: "object",
												required: [
													"basicPrice",
													"currency",
													"hasFreePrice"
												],
												properties: {
													paymentType: {
														type: "string"
													},
													pricingModelName: {
														type: "string"
													},
													basicPrice: {
														type: "number",
														format: "float"
													},
													currency: {
														type: "string"
													},
													fee: {
														type: "number",
														format: "float"
													},
													hasPaymentOnSubscription: {
														type: "object",
														properties: {
															paymentOnSubscriptionName: {
																type: "string"
															},
															paymentType: {
																type: "string"
															},
															timeDuration: {
																type: "string"
															},
															description: {
																type: "string"
															},
															repeat: {
																type: "string"
															},
															hasSubscriptionPrice: {
																type: "integer"
															}
														}
													},
													hasFreePrice: {
														type: "object",
														properties: {
															hasPriceFree: {
																type: "boolean"
															}
														}
													}
												}
											},
											dataExchangeAgreement: {
												type: "object",
												required: [
													"orig",
													"dest",
													"encAlg",
													"signingAlg",
													"hashAlg",
													"ledgerContractAddress",
													"ledgerSignerAddress",
													"pooToPorDelay",
													"pooToPopDelay",
													"pooToSecretDelay"
												],
												properties: {
													orig: {
														type: "string",
														description: "A stringified JWK with alphabetically sorted claims",
														example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
													},
													dest: {
														type: "string",
														description: "A stringified JWK with alphabetically sorted claims",
														example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
													},
													encAlg: {
														type: "string",
														"enum": [
															"A128GCM",
															"A256GCM"
														],
														example: "A256GCM"
													},
													signingAlg: {
														type: "string",
														"enum": [
															"ES256",
															"ES384",
															"ES512"
														],
														example: "ES256"
													},
													hashAlg: {
														type: "string",
														"enum": [
															"SHA-256",
															"SHA-384",
															"SHA-512"
														],
														example: "SHA-256"
													},
													ledgerContractAddress: {
														description: "Ethereum Address in EIP-55 format (with checksum)",
														type: "string",
														pattern: "^0x([0-9A-Fa-f]){40}$",
														example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
													},
													ledgerSignerAddress: {
														description: "Ethereum Address in EIP-55 format (with checksum)",
														type: "string",
														pattern: "^0x([0-9A-Fa-f]){40}$",
														example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
													},
													pooToPorDelay: {
														description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
														type: "integer",
														minimum: 1,
														example: 10000
													},
													pooToPopDelay: {
														description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
														type: "integer",
														minimum: 1,
														example: 20000
													},
													pooToSecretDelay: {
														description: "Maximum acceptable time between issued PoO and secret published on the ledger",
														type: "integer",
														minimum: 1,
														example: 180000
													},
													schema: {
														description: "A stringified JSON-LD schema describing the data format",
														type: "string"
													}
												}
											},
											signatures: {
												type: "object",
												required: [
													"providerSignature",
													"consumerSignature"
												],
												properties: {
													providerSignature: {
														title: "CompactJWS",
														type: "string",
														pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
													},
													consumerSignature: {
														title: "CompactJWS",
														type: "string",
														pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
													}
												}
											}
										}
									},
									keyPair: {
										type: "object",
										properties: {
											privateJwk: {
												type: "string",
												description: "A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",
												example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
											},
											publicJwk: {
												type: "string",
												description: "A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`). It MUST match either `dataSharingAgreement.dataExchangeAgreement.orig` or `dataSharingAgreement.dataExchangeAgreement.dest`\n",
												example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
											}
										},
										required: [
											"privateJwk",
											"publicJwk"
										]
									}
								},
								required: [
									"dataSharingAgreement",
									"keyPair"
								]
							}
						},
						required: [
							"type",
							"resource"
						]
					},
					{
						title: "NonRepudiationProof",
						type: "object",
						properties: {
							type: {
								example: "NonRepudiationProof",
								"enum": [
									"NonRepudiationProof"
								]
							},
							name: {
								type: "string",
								example: "Resource name"
							},
							resource: {
								description: "a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"
							}
						},
						required: [
							"type",
							"resource"
						]
					},
					{
						title: "DataExchangeResource",
						type: "object",
						properties: {
							type: {
								example: "DataExchange",
								"enum": [
									"DataExchange"
								]
							},
							name: {
								type: "string",
								example: "Resource name"
							},
							resource: {
								allOf: [
									{
										type: "object",
										required: [
											"orig",
											"dest",
											"encAlg",
											"signingAlg",
											"hashAlg",
											"ledgerContractAddress",
											"ledgerSignerAddress",
											"pooToPorDelay",
											"pooToPopDelay",
											"pooToSecretDelay"
										],
										properties: {
											orig: {
												type: "string",
												description: "A stringified JWK with alphabetically sorted claims",
												example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
											},
											dest: {
												type: "string",
												description: "A stringified JWK with alphabetically sorted claims",
												example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
											},
											encAlg: {
												type: "string",
												"enum": [
													"A128GCM",
													"A256GCM"
												],
												example: "A256GCM"
											},
											signingAlg: {
												type: "string",
												"enum": [
													"ES256",
													"ES384",
													"ES512"
												],
												example: "ES256"
											},
											hashAlg: {
												type: "string",
												"enum": [
													"SHA-256",
													"SHA-384",
													"SHA-512"
												],
												example: "SHA-256"
											},
											ledgerContractAddress: {
												description: "Ethereum Address in EIP-55 format (with checksum)",
												type: "string",
												pattern: "^0x([0-9A-Fa-f]){40}$",
												example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
											},
											ledgerSignerAddress: {
												description: "Ethereum Address in EIP-55 format (with checksum)",
												type: "string",
												pattern: "^0x([0-9A-Fa-f]){40}$",
												example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
											},
											pooToPorDelay: {
												description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
												type: "integer",
												minimum: 1,
												example: 10000
											},
											pooToPopDelay: {
												description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
												type: "integer",
												minimum: 1,
												example: 20000
											},
											pooToSecretDelay: {
												description: "Maximum acceptable time between issued PoO and secret published on the ledger",
												type: "integer",
												minimum: 1,
												example: 180000
											},
											schema: {
												description: "A stringified JSON-LD schema describing the data format",
												type: "string"
											}
										}
									},
									{
										type: "object",
										properties: {
											cipherblockDgst: {
												type: "string",
												description: "hash of the cipherblock in base64url with no padding",
												pattern: "^[a-zA-Z0-9_-]+$"
											},
											blockCommitment: {
												type: "string",
												description: "hash of the plaintext block in base64url with no padding",
												pattern: "^[a-zA-Z0-9_-]+$"
											},
											secretCommitment: {
												type: "string",
												description: "ash of the secret that can be used to decrypt the block in base64url with no padding",
												pattern: "^[a-zA-Z0-9_-]+$"
											}
										},
										required: [
											"cipherblockDgst",
											"blockCommitment",
											"secretCommitment"
										]
									}
								]
							}
						},
						required: [
							"type",
							"resource"
						]
					}
				]
			}
		},
		Resource: {
			title: "Resource",
			anyOf: [
				{
					title: "VerifiableCredential",
					type: "object",
					properties: {
						type: {
							example: "VerifiableCredential",
							"enum": [
								"VerifiableCredential"
							]
						},
						name: {
							type: "string",
							example: "Resource name"
						},
						resource: {
							type: "object",
							properties: {
								"@context": {
									type: "array",
									items: {
										type: "string"
									},
									example: [
										"https://www.w3.org/2018/credentials/v1"
									]
								},
								id: {
									type: "string",
									example: "http://example.edu/credentials/1872"
								},
								type: {
									type: "array",
									items: {
										type: "string"
									},
									example: [
										"VerifiableCredential"
									]
								},
								issuer: {
									type: "object",
									properties: {
										id: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										}
									},
									additionalProperties: true,
									required: [
										"id"
									]
								},
								issuanceDate: {
									type: "string",
									format: "date-time",
									example: "2021-06-10T19:07:28.000Z"
								},
								credentialSubject: {
									type: "object",
									properties: {
										id: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										}
									},
									required: [
										"id"
									],
									additionalProperties: true
								},
								proof: {
									type: "object",
									properties: {
										type: {
											type: "string",
											"enum": [
												"JwtProof2020"
											]
										}
									},
									required: [
										"type"
									],
									additionalProperties: true
								}
							},
							additionalProperties: true,
							required: [
								"@context",
								"type",
								"issuer",
								"issuanceDate",
								"credentialSubject",
								"proof"
							]
						}
					},
					required: [
						"type",
						"resource"
					]
				},
				{
					title: "ObjectResource",
					type: "object",
					properties: {
						type: {
							example: "Object",
							"enum": [
								"Object"
							]
						},
						name: {
							type: "string",
							example: "Resource name"
						},
						parentResource: {
							type: "string"
						},
						identity: {
							description: "a DID using the ethr resolver",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						resource: {
							type: "object",
							additionalProperties: true
						}
					},
					required: [
						"type",
						"resource"
					]
				},
				{
					title: "Contract",
					type: "object",
					properties: {
						type: {
							example: "Contract",
							"enum": [
								"Contract"
							]
						},
						name: {
							type: "string",
							example: "Resource name"
						},
						identity: {
							description: "a DID using the ethr resolver",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						resource: {
							type: "object",
							properties: {
								dataSharingAgreement: {
									type: "object",
									required: [
										"dataOfferingDescription",
										"parties",
										"purpose",
										"duration",
										"intendedUse",
										"licenseGrant",
										"dataStream",
										"personalData",
										"pricingModel",
										"dataExchangeAgreement",
										"signatures"
									],
									properties: {
										dataOfferingDescription: {
											type: "object",
											required: [
												"dataOfferingId",
												"version",
												"active"
											],
											properties: {
												dataOfferingId: {
													type: "string"
												},
												version: {
													type: "integer"
												},
												category: {
													type: "string"
												},
												active: {
													type: "boolean"
												},
												title: {
													type: "string"
												}
											}
										},
										parties: {
											type: "object",
											required: [
												"providerDid",
												"consumerDid"
											],
											properties: {
												providerDid: {
													description: "a DID using the ethr resolver",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
													example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
												},
												consumerDid: {
													description: "a DID using the ethr resolver",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
													example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
												}
											}
										},
										purpose: {
											type: "string"
										},
										duration: {
											type: "object",
											required: [
												"creationDate",
												"startDate",
												"endDate"
											],
											properties: {
												creationDate: {
													type: "integer"
												},
												startDate: {
													type: "integer"
												},
												endDate: {
													type: "integer"
												}
											}
										},
										intendedUse: {
											type: "object",
											required: [
												"processData",
												"shareDataWithThirdParty",
												"editData"
											],
											properties: {
												processData: {
													type: "boolean"
												},
												shareDataWithThirdParty: {
													type: "boolean"
												},
												editData: {
													type: "boolean"
												}
											}
										},
										licenseGrant: {
											type: "object",
											required: [
												"transferable",
												"exclusiveness",
												"paidUp",
												"revocable",
												"processing",
												"modifying",
												"analyzing",
												"storingData",
												"storingCopy",
												"reproducing",
												"distributing",
												"loaning",
												"selling",
												"renting",
												"furtherLicensing",
												"leasing"
											],
											properties: {
												transferable: {
													type: "boolean"
												},
												exclusiveness: {
													type: "boolean"
												},
												paidUp: {
													type: "boolean"
												},
												revocable: {
													type: "boolean"
												},
												processing: {
													type: "boolean"
												},
												modifying: {
													type: "boolean"
												},
												analyzing: {
													type: "boolean"
												},
												storingData: {
													type: "boolean"
												},
												storingCopy: {
													type: "boolean"
												},
												reproducing: {
													type: "boolean"
												},
												distributing: {
													type: "boolean"
												},
												loaning: {
													type: "boolean"
												},
												selling: {
													type: "boolean"
												},
												renting: {
													type: "boolean"
												},
												furtherLicensing: {
													type: "boolean"
												},
												leasing: {
													type: "boolean"
												}
											}
										},
										dataStream: {
											type: "boolean"
										},
										personalData: {
											type: "boolean"
										},
										pricingModel: {
											type: "object",
											required: [
												"basicPrice",
												"currency",
												"hasFreePrice"
											],
											properties: {
												paymentType: {
													type: "string"
												},
												pricingModelName: {
													type: "string"
												},
												basicPrice: {
													type: "number",
													format: "float"
												},
												currency: {
													type: "string"
												},
												fee: {
													type: "number",
													format: "float"
												},
												hasPaymentOnSubscription: {
													type: "object",
													properties: {
														paymentOnSubscriptionName: {
															type: "string"
														},
														paymentType: {
															type: "string"
														},
														timeDuration: {
															type: "string"
														},
														description: {
															type: "string"
														},
														repeat: {
															type: "string"
														},
														hasSubscriptionPrice: {
															type: "integer"
														}
													}
												},
												hasFreePrice: {
													type: "object",
													properties: {
														hasPriceFree: {
															type: "boolean"
														}
													}
												}
											}
										},
										dataExchangeAgreement: {
											type: "object",
											required: [
												"orig",
												"dest",
												"encAlg",
												"signingAlg",
												"hashAlg",
												"ledgerContractAddress",
												"ledgerSignerAddress",
												"pooToPorDelay",
												"pooToPopDelay",
												"pooToSecretDelay"
											],
											properties: {
												orig: {
													type: "string",
													description: "A stringified JWK with alphabetically sorted claims",
													example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
												},
												dest: {
													type: "string",
													description: "A stringified JWK with alphabetically sorted claims",
													example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
												},
												encAlg: {
													type: "string",
													"enum": [
														"A128GCM",
														"A256GCM"
													],
													example: "A256GCM"
												},
												signingAlg: {
													type: "string",
													"enum": [
														"ES256",
														"ES384",
														"ES512"
													],
													example: "ES256"
												},
												hashAlg: {
													type: "string",
													"enum": [
														"SHA-256",
														"SHA-384",
														"SHA-512"
													],
													example: "SHA-256"
												},
												ledgerContractAddress: {
													description: "Ethereum Address in EIP-55 format (with checksum)",
													type: "string",
													pattern: "^0x([0-9A-Fa-f]){40}$",
													example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
												},
												ledgerSignerAddress: {
													description: "Ethereum Address in EIP-55 format (with checksum)",
													type: "string",
													pattern: "^0x([0-9A-Fa-f]){40}$",
													example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
												},
												pooToPorDelay: {
													description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
													type: "integer",
													minimum: 1,
													example: 10000
												},
												pooToPopDelay: {
													description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
													type: "integer",
													minimum: 1,
													example: 20000
												},
												pooToSecretDelay: {
													description: "Maximum acceptable time between issued PoO and secret published on the ledger",
													type: "integer",
													minimum: 1,
													example: 180000
												},
												schema: {
													description: "A stringified JSON-LD schema describing the data format",
													type: "string"
												}
											}
										},
										signatures: {
											type: "object",
											required: [
												"providerSignature",
												"consumerSignature"
											],
											properties: {
												providerSignature: {
													title: "CompactJWS",
													type: "string",
													pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
												},
												consumerSignature: {
													title: "CompactJWS",
													type: "string",
													pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
												}
											}
										}
									}
								},
								keyPair: {
									type: "object",
									properties: {
										privateJwk: {
											type: "string",
											description: "A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",
											example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
										},
										publicJwk: {
											type: "string",
											description: "A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`). It MUST match either `dataSharingAgreement.dataExchangeAgreement.orig` or `dataSharingAgreement.dataExchangeAgreement.dest`\n",
											example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
										}
									},
									required: [
										"privateJwk",
										"publicJwk"
									]
								}
							},
							required: [
								"dataSharingAgreement",
								"keyPair"
							]
						}
					},
					required: [
						"type",
						"resource"
					]
				},
				{
					title: "NonRepudiationProof",
					type: "object",
					properties: {
						type: {
							example: "NonRepudiationProof",
							"enum": [
								"NonRepudiationProof"
							]
						},
						name: {
							type: "string",
							example: "Resource name"
						},
						resource: {
							description: "a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"
						}
					},
					required: [
						"type",
						"resource"
					]
				},
				{
					title: "DataExchangeResource",
					type: "object",
					properties: {
						type: {
							example: "DataExchange",
							"enum": [
								"DataExchange"
							]
						},
						name: {
							type: "string",
							example: "Resource name"
						},
						resource: {
							allOf: [
								{
									type: "object",
									required: [
										"orig",
										"dest",
										"encAlg",
										"signingAlg",
										"hashAlg",
										"ledgerContractAddress",
										"ledgerSignerAddress",
										"pooToPorDelay",
										"pooToPopDelay",
										"pooToSecretDelay"
									],
									properties: {
										orig: {
											type: "string",
											description: "A stringified JWK with alphabetically sorted claims",
											example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
										},
										dest: {
											type: "string",
											description: "A stringified JWK with alphabetically sorted claims",
											example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
										},
										encAlg: {
											type: "string",
											"enum": [
												"A128GCM",
												"A256GCM"
											],
											example: "A256GCM"
										},
										signingAlg: {
											type: "string",
											"enum": [
												"ES256",
												"ES384",
												"ES512"
											],
											example: "ES256"
										},
										hashAlg: {
											type: "string",
											"enum": [
												"SHA-256",
												"SHA-384",
												"SHA-512"
											],
											example: "SHA-256"
										},
										ledgerContractAddress: {
											description: "Ethereum Address in EIP-55 format (with checksum)",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										ledgerSignerAddress: {
											description: "Ethereum Address in EIP-55 format (with checksum)",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										pooToPorDelay: {
											description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
											type: "integer",
											minimum: 1,
											example: 10000
										},
										pooToPopDelay: {
											description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
											type: "integer",
											minimum: 1,
											example: 20000
										},
										pooToSecretDelay: {
											description: "Maximum acceptable time between issued PoO and secret published on the ledger",
											type: "integer",
											minimum: 1,
											example: 180000
										},
										schema: {
											description: "A stringified JSON-LD schema describing the data format",
											type: "string"
										}
									}
								},
								{
									type: "object",
									properties: {
										cipherblockDgst: {
											type: "string",
											description: "hash of the cipherblock in base64url with no padding",
											pattern: "^[a-zA-Z0-9_-]+$"
										},
										blockCommitment: {
											type: "string",
											description: "hash of the plaintext block in base64url with no padding",
											pattern: "^[a-zA-Z0-9_-]+$"
										},
										secretCommitment: {
											type: "string",
											description: "ash of the secret that can be used to decrypt the block in base64url with no padding",
											pattern: "^[a-zA-Z0-9_-]+$"
										}
									},
									required: [
										"cipherblockDgst",
										"blockCommitment",
										"secretCommitment"
									]
								}
							]
						}
					},
					required: [
						"type",
						"resource"
					]
				}
			]
		},
		VerifiableCredential: {
			title: "VerifiableCredential",
			type: "object",
			properties: {
				type: {
					example: "VerifiableCredential",
					"enum": [
						"VerifiableCredential"
					]
				},
				name: {
					type: "string",
					example: "Resource name"
				},
				resource: {
					type: "object",
					properties: {
						"@context": {
							type: "array",
							items: {
								type: "string"
							},
							example: [
								"https://www.w3.org/2018/credentials/v1"
							]
						},
						id: {
							type: "string",
							example: "http://example.edu/credentials/1872"
						},
						type: {
							type: "array",
							items: {
								type: "string"
							},
							example: [
								"VerifiableCredential"
							]
						},
						issuer: {
							type: "object",
							properties: {
								id: {
									description: "a DID using the ethr resolver",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
									example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
								}
							},
							additionalProperties: true,
							required: [
								"id"
							]
						},
						issuanceDate: {
							type: "string",
							format: "date-time",
							example: "2021-06-10T19:07:28.000Z"
						},
						credentialSubject: {
							type: "object",
							properties: {
								id: {
									description: "a DID using the ethr resolver",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
									example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
								}
							},
							required: [
								"id"
							],
							additionalProperties: true
						},
						proof: {
							type: "object",
							properties: {
								type: {
									type: "string",
									"enum": [
										"JwtProof2020"
									]
								}
							},
							required: [
								"type"
							],
							additionalProperties: true
						}
					},
					additionalProperties: true,
					required: [
						"@context",
						"type",
						"issuer",
						"issuanceDate",
						"credentialSubject",
						"proof"
					]
				}
			},
			required: [
				"type",
				"resource"
			]
		},
		ObjectResource: {
			title: "ObjectResource",
			type: "object",
			properties: {
				type: {
					example: "Object",
					"enum": [
						"Object"
					]
				},
				name: {
					type: "string",
					example: "Resource name"
				},
				parentResource: {
					type: "string"
				},
				identity: {
					description: "a DID using the ethr resolver",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				},
				resource: {
					type: "object",
					additionalProperties: true
				}
			},
			required: [
				"type",
				"resource"
			]
		},
		Contract: {
			title: "Contract",
			type: "object",
			properties: {
				type: {
					example: "Contract",
					"enum": [
						"Contract"
					]
				},
				name: {
					type: "string",
					example: "Resource name"
				},
				identity: {
					description: "a DID using the ethr resolver",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				},
				resource: {
					type: "object",
					properties: {
						dataSharingAgreement: {
							type: "object",
							required: [
								"dataOfferingDescription",
								"parties",
								"purpose",
								"duration",
								"intendedUse",
								"licenseGrant",
								"dataStream",
								"personalData",
								"pricingModel",
								"dataExchangeAgreement",
								"signatures"
							],
							properties: {
								dataOfferingDescription: {
									type: "object",
									required: [
										"dataOfferingId",
										"version",
										"active"
									],
									properties: {
										dataOfferingId: {
											type: "string"
										},
										version: {
											type: "integer"
										},
										category: {
											type: "string"
										},
										active: {
											type: "boolean"
										},
										title: {
											type: "string"
										}
									}
								},
								parties: {
									type: "object",
									required: [
										"providerDid",
										"consumerDid"
									],
									properties: {
										providerDid: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										consumerDid: {
											description: "a DID using the ethr resolver",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										}
									}
								},
								purpose: {
									type: "string"
								},
								duration: {
									type: "object",
									required: [
										"creationDate",
										"startDate",
										"endDate"
									],
									properties: {
										creationDate: {
											type: "integer"
										},
										startDate: {
											type: "integer"
										},
										endDate: {
											type: "integer"
										}
									}
								},
								intendedUse: {
									type: "object",
									required: [
										"processData",
										"shareDataWithThirdParty",
										"editData"
									],
									properties: {
										processData: {
											type: "boolean"
										},
										shareDataWithThirdParty: {
											type: "boolean"
										},
										editData: {
											type: "boolean"
										}
									}
								},
								licenseGrant: {
									type: "object",
									required: [
										"transferable",
										"exclusiveness",
										"paidUp",
										"revocable",
										"processing",
										"modifying",
										"analyzing",
										"storingData",
										"storingCopy",
										"reproducing",
										"distributing",
										"loaning",
										"selling",
										"renting",
										"furtherLicensing",
										"leasing"
									],
									properties: {
										transferable: {
											type: "boolean"
										},
										exclusiveness: {
											type: "boolean"
										},
										paidUp: {
											type: "boolean"
										},
										revocable: {
											type: "boolean"
										},
										processing: {
											type: "boolean"
										},
										modifying: {
											type: "boolean"
										},
										analyzing: {
											type: "boolean"
										},
										storingData: {
											type: "boolean"
										},
										storingCopy: {
											type: "boolean"
										},
										reproducing: {
											type: "boolean"
										},
										distributing: {
											type: "boolean"
										},
										loaning: {
											type: "boolean"
										},
										selling: {
											type: "boolean"
										},
										renting: {
											type: "boolean"
										},
										furtherLicensing: {
											type: "boolean"
										},
										leasing: {
											type: "boolean"
										}
									}
								},
								dataStream: {
									type: "boolean"
								},
								personalData: {
									type: "boolean"
								},
								pricingModel: {
									type: "object",
									required: [
										"basicPrice",
										"currency",
										"hasFreePrice"
									],
									properties: {
										paymentType: {
											type: "string"
										},
										pricingModelName: {
											type: "string"
										},
										basicPrice: {
											type: "number",
											format: "float"
										},
										currency: {
											type: "string"
										},
										fee: {
											type: "number",
											format: "float"
										},
										hasPaymentOnSubscription: {
											type: "object",
											properties: {
												paymentOnSubscriptionName: {
													type: "string"
												},
												paymentType: {
													type: "string"
												},
												timeDuration: {
													type: "string"
												},
												description: {
													type: "string"
												},
												repeat: {
													type: "string"
												},
												hasSubscriptionPrice: {
													type: "integer"
												}
											}
										},
										hasFreePrice: {
											type: "object",
											properties: {
												hasPriceFree: {
													type: "boolean"
												}
											}
										}
									}
								},
								dataExchangeAgreement: {
									type: "object",
									required: [
										"orig",
										"dest",
										"encAlg",
										"signingAlg",
										"hashAlg",
										"ledgerContractAddress",
										"ledgerSignerAddress",
										"pooToPorDelay",
										"pooToPopDelay",
										"pooToSecretDelay"
									],
									properties: {
										orig: {
											type: "string",
											description: "A stringified JWK with alphabetically sorted claims",
											example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
										},
										dest: {
											type: "string",
											description: "A stringified JWK with alphabetically sorted claims",
											example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
										},
										encAlg: {
											type: "string",
											"enum": [
												"A128GCM",
												"A256GCM"
											],
											example: "A256GCM"
										},
										signingAlg: {
											type: "string",
											"enum": [
												"ES256",
												"ES384",
												"ES512"
											],
											example: "ES256"
										},
										hashAlg: {
											type: "string",
											"enum": [
												"SHA-256",
												"SHA-384",
												"SHA-512"
											],
											example: "SHA-256"
										},
										ledgerContractAddress: {
											description: "Ethereum Address in EIP-55 format (with checksum)",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										ledgerSignerAddress: {
											description: "Ethereum Address in EIP-55 format (with checksum)",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										pooToPorDelay: {
											description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
											type: "integer",
											minimum: 1,
											example: 10000
										},
										pooToPopDelay: {
											description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
											type: "integer",
											minimum: 1,
											example: 20000
										},
										pooToSecretDelay: {
											description: "Maximum acceptable time between issued PoO and secret published on the ledger",
											type: "integer",
											minimum: 1,
											example: 180000
										},
										schema: {
											description: "A stringified JSON-LD schema describing the data format",
											type: "string"
										}
									}
								},
								signatures: {
									type: "object",
									required: [
										"providerSignature",
										"consumerSignature"
									],
									properties: {
										providerSignature: {
											title: "CompactJWS",
											type: "string",
											pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
										},
										consumerSignature: {
											title: "CompactJWS",
											type: "string",
											pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
										}
									}
								}
							}
						},
						keyPair: {
							type: "object",
							properties: {
								privateJwk: {
									type: "string",
									description: "A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)\n",
									example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
								},
								publicJwk: {
									type: "string",
									description: "A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`). It MUST match either `dataSharingAgreement.dataExchangeAgreement.orig` or `dataSharingAgreement.dataExchangeAgreement.dest`\n",
									example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8\",\"y\":\"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE\"}"
								}
							},
							required: [
								"privateJwk",
								"publicJwk"
							]
						}
					},
					required: [
						"dataSharingAgreement",
						"keyPair"
					]
				}
			},
			required: [
				"type",
				"resource"
			]
		},
		DataExchangeResource: {
			title: "DataExchangeResource",
			type: "object",
			properties: {
				type: {
					example: "DataExchange",
					"enum": [
						"DataExchange"
					]
				},
				name: {
					type: "string",
					example: "Resource name"
				},
				resource: {
					allOf: [
						{
							type: "object",
							required: [
								"orig",
								"dest",
								"encAlg",
								"signingAlg",
								"hashAlg",
								"ledgerContractAddress",
								"ledgerSignerAddress",
								"pooToPorDelay",
								"pooToPopDelay",
								"pooToSecretDelay"
							],
							properties: {
								orig: {
									type: "string",
									description: "A stringified JWK with alphabetically sorted claims",
									example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
								},
								dest: {
									type: "string",
									description: "A stringified JWK with alphabetically sorted claims",
									example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
								},
								encAlg: {
									type: "string",
									"enum": [
										"A128GCM",
										"A256GCM"
									],
									example: "A256GCM"
								},
								signingAlg: {
									type: "string",
									"enum": [
										"ES256",
										"ES384",
										"ES512"
									],
									example: "ES256"
								},
								hashAlg: {
									type: "string",
									"enum": [
										"SHA-256",
										"SHA-384",
										"SHA-512"
									],
									example: "SHA-256"
								},
								ledgerContractAddress: {
									description: "Ethereum Address in EIP-55 format (with checksum)",
									type: "string",
									pattern: "^0x([0-9A-Fa-f]){40}$",
									example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
								},
								ledgerSignerAddress: {
									description: "Ethereum Address in EIP-55 format (with checksum)",
									type: "string",
									pattern: "^0x([0-9A-Fa-f]){40}$",
									example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
								},
								pooToPorDelay: {
									description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
									type: "integer",
									minimum: 1,
									example: 10000
								},
								pooToPopDelay: {
									description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
									type: "integer",
									minimum: 1,
									example: 20000
								},
								pooToSecretDelay: {
									description: "Maximum acceptable time between issued PoO and secret published on the ledger",
									type: "integer",
									minimum: 1,
									example: 180000
								},
								schema: {
									description: "A stringified JSON-LD schema describing the data format",
									type: "string"
								}
							}
						},
						{
							type: "object",
							properties: {
								cipherblockDgst: {
									type: "string",
									description: "hash of the cipherblock in base64url with no padding",
									pattern: "^[a-zA-Z0-9_-]+$"
								},
								blockCommitment: {
									type: "string",
									description: "hash of the plaintext block in base64url with no padding",
									pattern: "^[a-zA-Z0-9_-]+$"
								},
								secretCommitment: {
									type: "string",
									description: "ash of the secret that can be used to decrypt the block in base64url with no padding",
									pattern: "^[a-zA-Z0-9_-]+$"
								}
							},
							required: [
								"cipherblockDgst",
								"blockCommitment",
								"secretCommitment"
							]
						}
					]
				}
			},
			required: [
				"type",
				"resource"
			]
		},
		NonRepudiationProof: {
			title: "NonRepudiationProof",
			type: "object",
			properties: {
				type: {
					example: "NonRepudiationProof",
					"enum": [
						"NonRepudiationProof"
					]
				},
				name: {
					type: "string",
					example: "Resource name"
				},
				resource: {
					description: "a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS"
				}
			},
			required: [
				"type",
				"resource"
			]
		},
		ResourceId: {
			type: "object",
			properties: {
				id: {
					type: "string"
				}
			},
			required: [
				"id"
			]
		},
		ResourceType: {
			type: "string",
			"enum": [
				"VerifiableCredential",
				"Object",
				"Contract",
				"DataExchange",
				"NonRepudiationProof"
			]
		},
		SignedTransaction: {
			title: "SignedTransaction",
			description: "A list of resources",
			type: "object",
			properties: {
				transaction: {
					type: "string",
					pattern: "^0x(?:[A-Fa-f0-9])+$"
				}
			}
		},
		DecodedJwt: {
			title: "JwtPayload",
			type: "object",
			properties: {
				header: {
					type: "object",
					properties: {
						typ: {
							type: "string",
							"enum": [
								"JWT"
							]
						},
						alg: {
							type: "string",
							"enum": [
								"ES256K"
							]
						}
					},
					required: [
						"typ",
						"alg"
					],
					additionalProperties: true
				},
				payload: {
					type: "object",
					properties: {
						iss: {
							description: "a DID using the ethr resolver",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						}
					},
					required: [
						"iss"
					],
					additionalProperties: true
				},
				signature: {
					type: "string",
					format: "^[A-Za-z0-9_-]+$"
				},
				data: {
					type: "string",
					format: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",
					description: "<base64url(header)>.<base64url(payload)>"
				}
			},
			required: [
				"signature",
				"data"
			]
		},
		VerificationOutput: {
			title: "VerificationOutput",
			type: "object",
			properties: {
				verification: {
					type: "string",
					"enum": [
						"success",
						"failed"
					],
					description: "whether verification has been successful or has failed"
				},
				error: {
					type: "string",
					description: "error message if verification failed"
				},
				decodedJwt: {
					description: "the decoded JWT"
				}
			},
			required: [
				"verification"
			]
		},
		ProviderData: {
			title: "ProviderData",
			description: "A JSON object with information of the DLT provider currently in use.",
			type: "object",
			properties: {
				provider: {
					type: "string",
					example: "did:ethr:i3m"
				},
				network: {
					type: "string",
					example: "i3m"
				},
				rpcUrl: {
					type: "string",
					example: "http://95.211.3.250:8545"
				}
			},
			additionalProperties: true
		},
		EthereumAddress: {
			description: "Ethereum Address in EIP-55 format (with checksum)",
			type: "string",
			pattern: "^0x([0-9A-Fa-f]){40}$",
			example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
		},
		did: {
			description: "a DID using the ethr resolver",
			type: "string",
			pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
			example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
		},
		IdentityData: {
			title: "Identity Data",
			type: "object",
			properties: {
				did: {
					type: "string",
					example: "did:ethr:i3m:0x03142f480f831e835822fc0cd35726844a7069d28df58fb82037f1598812e1ade8"
				},
				alias: {
					type: "string",
					example: "identity1"
				},
				provider: {
					type: "string",
					example: "did:ethr:i3m"
				},
				addresses: {
					type: "array",
					items: {
						description: "Ethereum Address in EIP-55 format (with checksum)",
						type: "string",
						pattern: "^0x([0-9A-Fa-f]){40}$",
						example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
					},
					example: [
						"0x8646cAcF516de1292be1D30AB68E7Ea51e9B1BE7"
					]
				}
			},
			required: [
				"did"
			]
		},
		ApiError: {
			type: "object",
			title: "Error",
			required: [
				"code",
				"message"
			],
			properties: {
				code: {
					type: "integer",
					format: "int32"
				},
				message: {
					type: "string"
				}
			}
		},
		CompactJWS: {
			title: "CompactJWS",
			type: "string",
			pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
		},
		DataExchangeAgreement: {
			type: "object",
			required: [
				"orig",
				"dest",
				"encAlg",
				"signingAlg",
				"hashAlg",
				"ledgerContractAddress",
				"ledgerSignerAddress",
				"pooToPorDelay",
				"pooToPopDelay",
				"pooToSecretDelay"
			],
			properties: {
				orig: {
					type: "string",
					description: "A stringified JWK with alphabetically sorted claims",
					example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
				},
				dest: {
					type: "string",
					description: "A stringified JWK with alphabetically sorted claims",
					example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
				},
				encAlg: {
					type: "string",
					"enum": [
						"A128GCM",
						"A256GCM"
					],
					example: "A256GCM"
				},
				signingAlg: {
					type: "string",
					"enum": [
						"ES256",
						"ES384",
						"ES512"
					],
					example: "ES256"
				},
				hashAlg: {
					type: "string",
					"enum": [
						"SHA-256",
						"SHA-384",
						"SHA-512"
					],
					example: "SHA-256"
				},
				ledgerContractAddress: {
					description: "Ethereum Address in EIP-55 format (with checksum)",
					type: "string",
					pattern: "^0x([0-9A-Fa-f]){40}$",
					example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
				},
				ledgerSignerAddress: {
					description: "Ethereum Address in EIP-55 format (with checksum)",
					type: "string",
					pattern: "^0x([0-9A-Fa-f]){40}$",
					example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
				},
				pooToPorDelay: {
					description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
					type: "integer",
					minimum: 1,
					example: 10000
				},
				pooToPopDelay: {
					description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
					type: "integer",
					minimum: 1,
					example: 20000
				},
				pooToSecretDelay: {
					description: "Maximum acceptable time between issued PoO and secret published on the ledger",
					type: "integer",
					minimum: 1,
					example: 180000
				},
				schema: {
					description: "A stringified JSON-LD schema describing the data format",
					type: "string"
				}
			}
		},
		DataSharingAgreement: {
			type: "object",
			required: [
				"dataOfferingDescription",
				"parties",
				"purpose",
				"duration",
				"intendedUse",
				"licenseGrant",
				"dataStream",
				"personalData",
				"pricingModel",
				"dataExchangeAgreement",
				"signatures"
			],
			properties: {
				dataOfferingDescription: {
					type: "object",
					required: [
						"dataOfferingId",
						"version",
						"active"
					],
					properties: {
						dataOfferingId: {
							type: "string"
						},
						version: {
							type: "integer"
						},
						category: {
							type: "string"
						},
						active: {
							type: "boolean"
						},
						title: {
							type: "string"
						}
					}
				},
				parties: {
					type: "object",
					required: [
						"providerDid",
						"consumerDid"
					],
					properties: {
						providerDid: {
							description: "a DID using the ethr resolver",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						consumerDid: {
							description: "a DID using the ethr resolver",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						}
					}
				},
				purpose: {
					type: "string"
				},
				duration: {
					type: "object",
					required: [
						"creationDate",
						"startDate",
						"endDate"
					],
					properties: {
						creationDate: {
							type: "integer"
						},
						startDate: {
							type: "integer"
						},
						endDate: {
							type: "integer"
						}
					}
				},
				intendedUse: {
					type: "object",
					required: [
						"processData",
						"shareDataWithThirdParty",
						"editData"
					],
					properties: {
						processData: {
							type: "boolean"
						},
						shareDataWithThirdParty: {
							type: "boolean"
						},
						editData: {
							type: "boolean"
						}
					}
				},
				licenseGrant: {
					type: "object",
					required: [
						"transferable",
						"exclusiveness",
						"paidUp",
						"revocable",
						"processing",
						"modifying",
						"analyzing",
						"storingData",
						"storingCopy",
						"reproducing",
						"distributing",
						"loaning",
						"selling",
						"renting",
						"furtherLicensing",
						"leasing"
					],
					properties: {
						transferable: {
							type: "boolean"
						},
						exclusiveness: {
							type: "boolean"
						},
						paidUp: {
							type: "boolean"
						},
						revocable: {
							type: "boolean"
						},
						processing: {
							type: "boolean"
						},
						modifying: {
							type: "boolean"
						},
						analyzing: {
							type: "boolean"
						},
						storingData: {
							type: "boolean"
						},
						storingCopy: {
							type: "boolean"
						},
						reproducing: {
							type: "boolean"
						},
						distributing: {
							type: "boolean"
						},
						loaning: {
							type: "boolean"
						},
						selling: {
							type: "boolean"
						},
						renting: {
							type: "boolean"
						},
						furtherLicensing: {
							type: "boolean"
						},
						leasing: {
							type: "boolean"
						}
					}
				},
				dataStream: {
					type: "boolean"
				},
				personalData: {
					type: "boolean"
				},
				pricingModel: {
					type: "object",
					required: [
						"basicPrice",
						"currency",
						"hasFreePrice"
					],
					properties: {
						paymentType: {
							type: "string"
						},
						pricingModelName: {
							type: "string"
						},
						basicPrice: {
							type: "number",
							format: "float"
						},
						currency: {
							type: "string"
						},
						fee: {
							type: "number",
							format: "float"
						},
						hasPaymentOnSubscription: {
							type: "object",
							properties: {
								paymentOnSubscriptionName: {
									type: "string"
								},
								paymentType: {
									type: "string"
								},
								timeDuration: {
									type: "string"
								},
								description: {
									type: "string"
								},
								repeat: {
									type: "string"
								},
								hasSubscriptionPrice: {
									type: "integer"
								}
							}
						},
						hasFreePrice: {
							type: "object",
							properties: {
								hasPriceFree: {
									type: "boolean"
								}
							}
						}
					}
				},
				dataExchangeAgreement: {
					type: "object",
					required: [
						"orig",
						"dest",
						"encAlg",
						"signingAlg",
						"hashAlg",
						"ledgerContractAddress",
						"ledgerSignerAddress",
						"pooToPorDelay",
						"pooToPopDelay",
						"pooToSecretDelay"
					],
					properties: {
						orig: {
							type: "string",
							description: "A stringified JWK with alphabetically sorted claims",
							example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
						},
						dest: {
							type: "string",
							description: "A stringified JWK with alphabetically sorted claims",
							example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
						},
						encAlg: {
							type: "string",
							"enum": [
								"A128GCM",
								"A256GCM"
							],
							example: "A256GCM"
						},
						signingAlg: {
							type: "string",
							"enum": [
								"ES256",
								"ES384",
								"ES512"
							],
							example: "ES256"
						},
						hashAlg: {
							type: "string",
							"enum": [
								"SHA-256",
								"SHA-384",
								"SHA-512"
							],
							example: "SHA-256"
						},
						ledgerContractAddress: {
							description: "Ethereum Address in EIP-55 format (with checksum)",
							type: "string",
							pattern: "^0x([0-9A-Fa-f]){40}$",
							example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
						},
						ledgerSignerAddress: {
							description: "Ethereum Address in EIP-55 format (with checksum)",
							type: "string",
							pattern: "^0x([0-9A-Fa-f]){40}$",
							example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
						},
						pooToPorDelay: {
							description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
							type: "integer",
							minimum: 1,
							example: 10000
						},
						pooToPopDelay: {
							description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
							type: "integer",
							minimum: 1,
							example: 20000
						},
						pooToSecretDelay: {
							description: "Maximum acceptable time between issued PoO and secret published on the ledger",
							type: "integer",
							minimum: 1,
							example: 180000
						},
						schema: {
							description: "A stringified JSON-LD schema describing the data format",
							type: "string"
						}
					}
				},
				signatures: {
					type: "object",
					required: [
						"providerSignature",
						"consumerSignature"
					],
					properties: {
						providerSignature: {
							title: "CompactJWS",
							type: "string",
							pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
						},
						consumerSignature: {
							title: "CompactJWS",
							type: "string",
							pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"
						}
					}
				}
			}
		},
		DataExchange: {
			allOf: [
				{
					type: "object",
					required: [
						"orig",
						"dest",
						"encAlg",
						"signingAlg",
						"hashAlg",
						"ledgerContractAddress",
						"ledgerSignerAddress",
						"pooToPorDelay",
						"pooToPopDelay",
						"pooToSecretDelay"
					],
					properties: {
						orig: {
							type: "string",
							description: "A stringified JWK with alphabetically sorted claims",
							example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo\",\"y\":\"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0\"}"
						},
						dest: {
							type: "string",
							description: "A stringified JWK with alphabetically sorted claims",
							example: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k\",\"y\":\"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4\"}"
						},
						encAlg: {
							type: "string",
							"enum": [
								"A128GCM",
								"A256GCM"
							],
							example: "A256GCM"
						},
						signingAlg: {
							type: "string",
							"enum": [
								"ES256",
								"ES384",
								"ES512"
							],
							example: "ES256"
						},
						hashAlg: {
							type: "string",
							"enum": [
								"SHA-256",
								"SHA-384",
								"SHA-512"
							],
							example: "SHA-256"
						},
						ledgerContractAddress: {
							description: "Ethereum Address in EIP-55 format (with checksum)",
							type: "string",
							pattern: "^0x([0-9A-Fa-f]){40}$",
							example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
						},
						ledgerSignerAddress: {
							description: "Ethereum Address in EIP-55 format (with checksum)",
							type: "string",
							pattern: "^0x([0-9A-Fa-f]){40}$",
							example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
						},
						pooToPorDelay: {
							description: "Maximum acceptable time in milliseconds between issued PoO and verified PoR",
							type: "integer",
							minimum: 1,
							example: 10000
						},
						pooToPopDelay: {
							description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
							type: "integer",
							minimum: 1,
							example: 20000
						},
						pooToSecretDelay: {
							description: "Maximum acceptable time between issued PoO and secret published on the ledger",
							type: "integer",
							minimum: 1,
							example: 180000
						},
						schema: {
							description: "A stringified JSON-LD schema describing the data format",
							type: "string"
						}
					}
				},
				{
					type: "object",
					properties: {
						cipherblockDgst: {
							type: "string",
							description: "hash of the cipherblock in base64url with no padding",
							pattern: "^[a-zA-Z0-9_-]+$"
						},
						blockCommitment: {
							type: "string",
							description: "hash of the plaintext block in base64url with no padding",
							pattern: "^[a-zA-Z0-9_-]+$"
						},
						secretCommitment: {
							type: "string",
							description: "ash of the secret that can be used to decrypt the block in base64url with no padding",
							pattern: "^[a-zA-Z0-9_-]+$"
						}
					},
					required: [
						"cipherblockDgst",
						"blockCommitment",
						"secretCommitment"
					]
				}
			]
		}
	}
};
var spec = {
	openapi: openapi,
	info: info,
	tags: tags,
	paths: paths,
	components: components
};

var id = "https://spec.openapis.org/oas/3.0/schema/2021-09-28";
var $schema = "http://json-schema.org/draft-04/schema#";
var description = "The description of OpenAPI v3.0.x documents, as defined by https://spec.openapis.org/oas/v3.0.3";
var type = "object";
var required = [
	"openapi",
	"info",
	"paths"
];
var properties = {
	openapi: {
		type: "string",
		pattern: "^3\\.0\\.\\d(-.+)?$"
	},
	info: {
		$ref: "#/definitions/Info"
	},
	externalDocs: {
		$ref: "#/definitions/ExternalDocumentation"
	},
	servers: {
		type: "array",
		items: {
			$ref: "#/definitions/Server"
		}
	},
	security: {
		type: "array",
		items: {
			$ref: "#/definitions/SecurityRequirement"
		}
	},
	tags: {
		type: "array",
		items: {
			$ref: "#/definitions/Tag"
		},
		uniqueItems: true
	},
	paths: {
		$ref: "#/definitions/Paths"
	},
	components: {
		$ref: "#/definitions/Components"
	}
};
var patternProperties = {
	"^x-": {
	}
};
var additionalProperties = false;
var definitions = {
	Reference: {
		type: "object",
		required: [
			"$ref"
		],
		patternProperties: {
			"^\\$ref$": {
				type: "string",
				format: "uri-reference"
			}
		}
	},
	Info: {
		type: "object",
		required: [
			"title",
			"version"
		],
		properties: {
			title: {
				type: "string"
			},
			description: {
				type: "string"
			},
			termsOfService: {
				type: "string",
				format: "uri-reference"
			},
			contact: {
				$ref: "#/definitions/Contact"
			},
			license: {
				$ref: "#/definitions/License"
			},
			version: {
				type: "string"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Contact: {
		type: "object",
		properties: {
			name: {
				type: "string"
			},
			url: {
				type: "string",
				format: "uri-reference"
			},
			email: {
				type: "string",
				format: "email"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	License: {
		type: "object",
		required: [
			"name"
		],
		properties: {
			name: {
				type: "string"
			},
			url: {
				type: "string",
				format: "uri-reference"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Server: {
		type: "object",
		required: [
			"url"
		],
		properties: {
			url: {
				type: "string"
			},
			description: {
				type: "string"
			},
			variables: {
				type: "object",
				additionalProperties: {
					$ref: "#/definitions/ServerVariable"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	ServerVariable: {
		type: "object",
		required: [
			"default"
		],
		properties: {
			"enum": {
				type: "array",
				items: {
					type: "string"
				}
			},
			"default": {
				type: "string"
			},
			description: {
				type: "string"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Components: {
		type: "object",
		properties: {
			schemas: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Schema"
							},
							{
								$ref: "#/definitions/Reference"
							}
						]
					}
				}
			},
			responses: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/Response"
							}
						]
					}
				}
			},
			parameters: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/Parameter"
							}
						]
					}
				}
			},
			examples: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/Example"
							}
						]
					}
				}
			},
			requestBodies: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/RequestBody"
							}
						]
					}
				}
			},
			headers: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/Header"
							}
						]
					}
				}
			},
			securitySchemes: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/SecurityScheme"
							}
						]
					}
				}
			},
			links: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/Link"
							}
						]
					}
				}
			},
			callbacks: {
				type: "object",
				patternProperties: {
					"^[a-zA-Z0-9\\.\\-_]+$": {
						oneOf: [
							{
								$ref: "#/definitions/Reference"
							},
							{
								$ref: "#/definitions/Callback"
							}
						]
					}
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Schema: {
		type: "object",
		properties: {
			title: {
				type: "string"
			},
			multipleOf: {
				type: "number",
				minimum: 0,
				exclusiveMinimum: true
			},
			maximum: {
				type: "number"
			},
			exclusiveMaximum: {
				type: "boolean",
				"default": false
			},
			minimum: {
				type: "number"
			},
			exclusiveMinimum: {
				type: "boolean",
				"default": false
			},
			maxLength: {
				type: "integer",
				minimum: 0
			},
			minLength: {
				type: "integer",
				minimum: 0,
				"default": 0
			},
			pattern: {
				type: "string",
				format: "regex"
			},
			maxItems: {
				type: "integer",
				minimum: 0
			},
			minItems: {
				type: "integer",
				minimum: 0,
				"default": 0
			},
			uniqueItems: {
				type: "boolean",
				"default": false
			},
			maxProperties: {
				type: "integer",
				minimum: 0
			},
			minProperties: {
				type: "integer",
				minimum: 0,
				"default": 0
			},
			required: {
				type: "array",
				items: {
					type: "string"
				},
				minItems: 1,
				uniqueItems: true
			},
			"enum": {
				type: "array",
				items: {
				},
				minItems: 1,
				uniqueItems: false
			},
			type: {
				type: "string",
				"enum": [
					"array",
					"boolean",
					"integer",
					"number",
					"object",
					"string"
				]
			},
			not: {
				oneOf: [
					{
						$ref: "#/definitions/Schema"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			allOf: {
				type: "array",
				items: {
					oneOf: [
						{
							$ref: "#/definitions/Schema"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			oneOf: {
				type: "array",
				items: {
					oneOf: [
						{
							$ref: "#/definitions/Schema"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			anyOf: {
				type: "array",
				items: {
					oneOf: [
						{
							$ref: "#/definitions/Schema"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			items: {
				oneOf: [
					{
						$ref: "#/definitions/Schema"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			properties: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Schema"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			additionalProperties: {
				oneOf: [
					{
						$ref: "#/definitions/Schema"
					},
					{
						$ref: "#/definitions/Reference"
					},
					{
						type: "boolean"
					}
				],
				"default": true
			},
			description: {
				type: "string"
			},
			format: {
				type: "string"
			},
			"default": {
			},
			nullable: {
				type: "boolean",
				"default": false
			},
			discriminator: {
				$ref: "#/definitions/Discriminator"
			},
			readOnly: {
				type: "boolean",
				"default": false
			},
			writeOnly: {
				type: "boolean",
				"default": false
			},
			example: {
			},
			externalDocs: {
				$ref: "#/definitions/ExternalDocumentation"
			},
			deprecated: {
				type: "boolean",
				"default": false
			},
			xml: {
				$ref: "#/definitions/XML"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Discriminator: {
		type: "object",
		required: [
			"propertyName"
		],
		properties: {
			propertyName: {
				type: "string"
			},
			mapping: {
				type: "object",
				additionalProperties: {
					type: "string"
				}
			}
		}
	},
	XML: {
		type: "object",
		properties: {
			name: {
				type: "string"
			},
			namespace: {
				type: "string",
				format: "uri"
			},
			prefix: {
				type: "string"
			},
			attribute: {
				type: "boolean",
				"default": false
			},
			wrapped: {
				type: "boolean",
				"default": false
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Response: {
		type: "object",
		required: [
			"description"
		],
		properties: {
			description: {
				type: "string"
			},
			headers: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Header"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			content: {
				type: "object",
				additionalProperties: {
					$ref: "#/definitions/MediaType"
				}
			},
			links: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Link"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	MediaType: {
		type: "object",
		properties: {
			schema: {
				oneOf: [
					{
						$ref: "#/definitions/Schema"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			example: {
			},
			examples: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Example"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			encoding: {
				type: "object",
				additionalProperties: {
					$ref: "#/definitions/Encoding"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false,
		allOf: [
			{
				$ref: "#/definitions/ExampleXORExamples"
			}
		]
	},
	Example: {
		type: "object",
		properties: {
			summary: {
				type: "string"
			},
			description: {
				type: "string"
			},
			value: {
			},
			externalValue: {
				type: "string",
				format: "uri-reference"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Header: {
		type: "object",
		properties: {
			description: {
				type: "string"
			},
			required: {
				type: "boolean",
				"default": false
			},
			deprecated: {
				type: "boolean",
				"default": false
			},
			allowEmptyValue: {
				type: "boolean",
				"default": false
			},
			style: {
				type: "string",
				"enum": [
					"simple"
				],
				"default": "simple"
			},
			explode: {
				type: "boolean"
			},
			allowReserved: {
				type: "boolean",
				"default": false
			},
			schema: {
				oneOf: [
					{
						$ref: "#/definitions/Schema"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			content: {
				type: "object",
				additionalProperties: {
					$ref: "#/definitions/MediaType"
				},
				minProperties: 1,
				maxProperties: 1
			},
			example: {
			},
			examples: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Example"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false,
		allOf: [
			{
				$ref: "#/definitions/ExampleXORExamples"
			},
			{
				$ref: "#/definitions/SchemaXORContent"
			}
		]
	},
	Paths: {
		type: "object",
		patternProperties: {
			"^\\/": {
				$ref: "#/definitions/PathItem"
			},
			"^x-": {
			}
		},
		additionalProperties: false
	},
	PathItem: {
		type: "object",
		properties: {
			$ref: {
				type: "string"
			},
			summary: {
				type: "string"
			},
			description: {
				type: "string"
			},
			servers: {
				type: "array",
				items: {
					$ref: "#/definitions/Server"
				}
			},
			parameters: {
				type: "array",
				items: {
					oneOf: [
						{
							$ref: "#/definitions/Parameter"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				},
				uniqueItems: true
			}
		},
		patternProperties: {
			"^(get|put|post|delete|options|head|patch|trace)$": {
				$ref: "#/definitions/Operation"
			},
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Operation: {
		type: "object",
		required: [
			"responses"
		],
		properties: {
			tags: {
				type: "array",
				items: {
					type: "string"
				}
			},
			summary: {
				type: "string"
			},
			description: {
				type: "string"
			},
			externalDocs: {
				$ref: "#/definitions/ExternalDocumentation"
			},
			operationId: {
				type: "string"
			},
			parameters: {
				type: "array",
				items: {
					oneOf: [
						{
							$ref: "#/definitions/Parameter"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				},
				uniqueItems: true
			},
			requestBody: {
				oneOf: [
					{
						$ref: "#/definitions/RequestBody"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			responses: {
				$ref: "#/definitions/Responses"
			},
			callbacks: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Callback"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			deprecated: {
				type: "boolean",
				"default": false
			},
			security: {
				type: "array",
				items: {
					$ref: "#/definitions/SecurityRequirement"
				}
			},
			servers: {
				type: "array",
				items: {
					$ref: "#/definitions/Server"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Responses: {
		type: "object",
		properties: {
			"default": {
				oneOf: [
					{
						$ref: "#/definitions/Response"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			}
		},
		patternProperties: {
			"^[1-5](?:\\d{2}|XX)$": {
				oneOf: [
					{
						$ref: "#/definitions/Response"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			"^x-": {
			}
		},
		minProperties: 1,
		additionalProperties: false
	},
	SecurityRequirement: {
		type: "object",
		additionalProperties: {
			type: "array",
			items: {
				type: "string"
			}
		}
	},
	Tag: {
		type: "object",
		required: [
			"name"
		],
		properties: {
			name: {
				type: "string"
			},
			description: {
				type: "string"
			},
			externalDocs: {
				$ref: "#/definitions/ExternalDocumentation"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	ExternalDocumentation: {
		type: "object",
		required: [
			"url"
		],
		properties: {
			description: {
				type: "string"
			},
			url: {
				type: "string",
				format: "uri-reference"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	ExampleXORExamples: {
		description: "Example and examples are mutually exclusive",
		not: {
			required: [
				"example",
				"examples"
			]
		}
	},
	SchemaXORContent: {
		description: "Schema and content are mutually exclusive, at least one is required",
		not: {
			required: [
				"schema",
				"content"
			]
		},
		oneOf: [
			{
				required: [
					"schema"
				]
			},
			{
				required: [
					"content"
				],
				description: "Some properties are not allowed if content is present",
				allOf: [
					{
						not: {
							required: [
								"style"
							]
						}
					},
					{
						not: {
							required: [
								"explode"
							]
						}
					},
					{
						not: {
							required: [
								"allowReserved"
							]
						}
					},
					{
						not: {
							required: [
								"example"
							]
						}
					},
					{
						not: {
							required: [
								"examples"
							]
						}
					}
				]
			}
		]
	},
	Parameter: {
		type: "object",
		properties: {
			name: {
				type: "string"
			},
			"in": {
				type: "string"
			},
			description: {
				type: "string"
			},
			required: {
				type: "boolean",
				"default": false
			},
			deprecated: {
				type: "boolean",
				"default": false
			},
			allowEmptyValue: {
				type: "boolean",
				"default": false
			},
			style: {
				type: "string"
			},
			explode: {
				type: "boolean"
			},
			allowReserved: {
				type: "boolean",
				"default": false
			},
			schema: {
				oneOf: [
					{
						$ref: "#/definitions/Schema"
					},
					{
						$ref: "#/definitions/Reference"
					}
				]
			},
			content: {
				type: "object",
				additionalProperties: {
					$ref: "#/definitions/MediaType"
				},
				minProperties: 1,
				maxProperties: 1
			},
			example: {
			},
			examples: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Example"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false,
		required: [
			"name",
			"in"
		],
		allOf: [
			{
				$ref: "#/definitions/ExampleXORExamples"
			},
			{
				$ref: "#/definitions/SchemaXORContent"
			},
			{
				$ref: "#/definitions/ParameterLocation"
			}
		]
	},
	ParameterLocation: {
		description: "Parameter location",
		oneOf: [
			{
				description: "Parameter in path",
				required: [
					"required"
				],
				properties: {
					"in": {
						"enum": [
							"path"
						]
					},
					style: {
						"enum": [
							"matrix",
							"label",
							"simple"
						],
						"default": "simple"
					},
					required: {
						"enum": [
							true
						]
					}
				}
			},
			{
				description: "Parameter in query",
				properties: {
					"in": {
						"enum": [
							"query"
						]
					},
					style: {
						"enum": [
							"form",
							"spaceDelimited",
							"pipeDelimited",
							"deepObject"
						],
						"default": "form"
					}
				}
			},
			{
				description: "Parameter in header",
				properties: {
					"in": {
						"enum": [
							"header"
						]
					},
					style: {
						"enum": [
							"simple"
						],
						"default": "simple"
					}
				}
			},
			{
				description: "Parameter in cookie",
				properties: {
					"in": {
						"enum": [
							"cookie"
						]
					},
					style: {
						"enum": [
							"form"
						],
						"default": "form"
					}
				}
			}
		]
	},
	RequestBody: {
		type: "object",
		required: [
			"content"
		],
		properties: {
			description: {
				type: "string"
			},
			content: {
				type: "object",
				additionalProperties: {
					$ref: "#/definitions/MediaType"
				}
			},
			required: {
				type: "boolean",
				"default": false
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	SecurityScheme: {
		oneOf: [
			{
				$ref: "#/definitions/APIKeySecurityScheme"
			},
			{
				$ref: "#/definitions/HTTPSecurityScheme"
			},
			{
				$ref: "#/definitions/OAuth2SecurityScheme"
			},
			{
				$ref: "#/definitions/OpenIdConnectSecurityScheme"
			}
		]
	},
	APIKeySecurityScheme: {
		type: "object",
		required: [
			"type",
			"name",
			"in"
		],
		properties: {
			type: {
				type: "string",
				"enum": [
					"apiKey"
				]
			},
			name: {
				type: "string"
			},
			"in": {
				type: "string",
				"enum": [
					"header",
					"query",
					"cookie"
				]
			},
			description: {
				type: "string"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	HTTPSecurityScheme: {
		type: "object",
		required: [
			"scheme",
			"type"
		],
		properties: {
			scheme: {
				type: "string"
			},
			bearerFormat: {
				type: "string"
			},
			description: {
				type: "string"
			},
			type: {
				type: "string",
				"enum": [
					"http"
				]
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false,
		oneOf: [
			{
				description: "Bearer",
				properties: {
					scheme: {
						type: "string",
						pattern: "^[Bb][Ee][Aa][Rr][Ee][Rr]$"
					}
				}
			},
			{
				description: "Non Bearer",
				not: {
					required: [
						"bearerFormat"
					]
				},
				properties: {
					scheme: {
						not: {
							type: "string",
							pattern: "^[Bb][Ee][Aa][Rr][Ee][Rr]$"
						}
					}
				}
			}
		]
	},
	OAuth2SecurityScheme: {
		type: "object",
		required: [
			"type",
			"flows"
		],
		properties: {
			type: {
				type: "string",
				"enum": [
					"oauth2"
				]
			},
			flows: {
				$ref: "#/definitions/OAuthFlows"
			},
			description: {
				type: "string"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	OpenIdConnectSecurityScheme: {
		type: "object",
		required: [
			"type",
			"openIdConnectUrl"
		],
		properties: {
			type: {
				type: "string",
				"enum": [
					"openIdConnect"
				]
			},
			openIdConnectUrl: {
				type: "string",
				format: "uri-reference"
			},
			description: {
				type: "string"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	OAuthFlows: {
		type: "object",
		properties: {
			implicit: {
				$ref: "#/definitions/ImplicitOAuthFlow"
			},
			password: {
				$ref: "#/definitions/PasswordOAuthFlow"
			},
			clientCredentials: {
				$ref: "#/definitions/ClientCredentialsFlow"
			},
			authorizationCode: {
				$ref: "#/definitions/AuthorizationCodeOAuthFlow"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	ImplicitOAuthFlow: {
		type: "object",
		required: [
			"authorizationUrl",
			"scopes"
		],
		properties: {
			authorizationUrl: {
				type: "string",
				format: "uri-reference"
			},
			refreshUrl: {
				type: "string",
				format: "uri-reference"
			},
			scopes: {
				type: "object",
				additionalProperties: {
					type: "string"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	PasswordOAuthFlow: {
		type: "object",
		required: [
			"tokenUrl",
			"scopes"
		],
		properties: {
			tokenUrl: {
				type: "string",
				format: "uri-reference"
			},
			refreshUrl: {
				type: "string",
				format: "uri-reference"
			},
			scopes: {
				type: "object",
				additionalProperties: {
					type: "string"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	ClientCredentialsFlow: {
		type: "object",
		required: [
			"tokenUrl",
			"scopes"
		],
		properties: {
			tokenUrl: {
				type: "string",
				format: "uri-reference"
			},
			refreshUrl: {
				type: "string",
				format: "uri-reference"
			},
			scopes: {
				type: "object",
				additionalProperties: {
					type: "string"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	AuthorizationCodeOAuthFlow: {
		type: "object",
		required: [
			"authorizationUrl",
			"tokenUrl",
			"scopes"
		],
		properties: {
			authorizationUrl: {
				type: "string",
				format: "uri-reference"
			},
			tokenUrl: {
				type: "string",
				format: "uri-reference"
			},
			refreshUrl: {
				type: "string",
				format: "uri-reference"
			},
			scopes: {
				type: "object",
				additionalProperties: {
					type: "string"
				}
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false
	},
	Link: {
		type: "object",
		properties: {
			operationId: {
				type: "string"
			},
			operationRef: {
				type: "string",
				format: "uri-reference"
			},
			parameters: {
				type: "object",
				additionalProperties: {
				}
			},
			requestBody: {
			},
			description: {
				type: "string"
			},
			server: {
				$ref: "#/definitions/Server"
			}
		},
		patternProperties: {
			"^x-": {
			}
		},
		additionalProperties: false,
		not: {
			description: "Operation Id and Operation Ref are mutually exclusive",
			required: [
				"operationId",
				"operationRef"
			]
		}
	},
	Callback: {
		type: "object",
		additionalProperties: {
			$ref: "#/definitions/PathItem"
		},
		patternProperties: {
			"^x-": {
			}
		}
	},
	Encoding: {
		type: "object",
		properties: {
			contentType: {
				type: "string"
			},
			headers: {
				type: "object",
				additionalProperties: {
					oneOf: [
						{
							$ref: "#/definitions/Header"
						},
						{
							$ref: "#/definitions/Reference"
						}
					]
				}
			},
			style: {
				type: "string",
				"enum": [
					"form",
					"spaceDelimited",
					"pipeDelimited",
					"deepObject"
				]
			},
			explode: {
				type: "boolean"
			},
			allowReserved: {
				type: "boolean",
				"default": false
			}
		},
		additionalProperties: false
	}
};
var jsonSchema = {
	id: id,
	$schema: $schema,
	description: description,
	type: type,
	required: required,
	properties: properties,
	patternProperties: patternProperties,
	additionalProperties: additionalProperties,
	definitions: definitions
};

function parseTimestamp(timestamp) {
    if ((new Date(timestamp)).getTime() > 0) {
        return Number(timestamp);
    }
    else {
        throw new NrError(new Error('invalid timestamp'), ['invalid timestamp']);
    }
}
async function validateDataSharingAgreementSchema(agreement) {
    const errors = [];
    const ajv = new Ajv({ strictSchema: false, removeAdditional: 'all' });
    ajv.addMetaSchema(jsonSchema);
    addFormats(ajv);
    const schema = spec.components.schemas.DataSharingAgreement;
    try {
        const validate = ajv.compile(schema);
        const clonedAgreement = _.cloneDeep(agreement);
        const valid = validate(agreement);
        if (!valid) {
            if (validate.errors !== null && validate.errors !== undefined && validate.errors.length > 0) {
                validate.errors.forEach(error => {
                    errors.push(new NrError(`[${error.instancePath}] ${error.message ?? 'unknown'}`, ['invalid format']));
                });
            }
        }
        if (hashable(clonedAgreement) !== hashable(agreement)) {
            errors.push(new NrError('Additional claims beyond the schema are not supported', ['invalid format']));
        }
    }
    catch (error) {
        errors.push(new NrError(error, ['invalid format']));
    }
    return errors;
}
async function validateDataExchange(dataExchange) {
    const errors = [];
    try {
        const { id, ...dataExchangeButId } = dataExchange;
        if (id !== await exchangeId(dataExchangeButId)) {
            errors.push(new NrError('Invalid dataExchange id', ['cannot verify', 'invalid format']));
        }
        const { blockCommitment, secretCommitment, cipherblockDgst, ...dataExchangeAgreement } = dataExchangeButId;
        const deaErrors = await validateDataExchangeAgreement(dataExchangeAgreement);
        if (deaErrors.length > 0) {
            deaErrors.forEach((error) => {
                errors.push(error);
            });
        }
    }
    catch (error) {
        errors.push(new NrError('Invalid dataExchange', ['cannot verify', 'invalid format']));
    }
    return errors;
}
async function validateDataExchangeAgreement(agreement) {
    const errors = [];
    const agreementClaims = Object.keys(agreement);
    if (agreementClaims.length < 10 || agreementClaims.length > 11) {
        errors.push(new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format']));
    }
    for (const key of agreementClaims) {
        let parsedAddress;
        switch (key) {
            case 'orig':
            case 'dest':
                try {
                    if (agreement[key] !== await parseJwk(JSON.parse(agreement[key]), true)) {
                        errors.push(new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be alphabetically sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose.\n${agreement[key]}`, ['invalid key', 'invalid format']));
                    }
                }
                catch (error) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be alphabetically sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose.`, ['invalid key', 'invalid format']));
                }
                break;
            case 'ledgerContractAddress':
            case 'ledgerSignerAddress':
                try {
                    parsedAddress = parseAddress(agreement[key]);
                    if (agreement[key] !== parsedAddress) {
                        errors.push(new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}. Did you mean ${parsedAddress} instead?`, ['invalid EIP-55 address', 'invalid format']));
                    }
                }
                catch (error) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}.`, ['invalid EIP-55 address', 'invalid format']));
                }
                break;
            case 'pooToPorDelay':
            case 'pooToPopDelay':
            case 'pooToSecretDelay':
                try {
                    if (agreement[key] !== parseTimestamp(agreement[key])) {
                        errors.push(new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid timestamp', 'invalid format']));
                    }
                }
                catch (error) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid timestamp', 'invalid format']));
                }
                break;
            case 'hashAlg':
                if (!HASH_ALGS.includes(agreement[key])) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid hash algorithm '${agreement[key]}'. It must be one of: ${HASH_ALGS.join(', ')}`, ['invalid algorithm']));
                }
                break;
            case 'encAlg':
                if (!ENC_ALGS.includes(agreement[key])) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid encryption algorithm '${agreement[key]}'. It must be one of: ${ENC_ALGS.join(', ')}`, ['invalid algorithm']));
                }
                break;
            case 'signingAlg':
                if (!SIGNING_ALGS.includes(agreement[key])) {
                    errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid signing algorithm '${agreement[key]}'. It must be one of: ${SIGNING_ALGS.join(', ')}`, ['invalid algorithm']));
                }
                break;
            case 'schema':
                break;
            default:
                errors.push(new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format']));
        }
    }
    return errors;
}

async function createProof(payload, privateJwk) {
    if (payload.iss === undefined) {
        throw new Error('Payload iss should be set to either "orig" or "dest"');
    }
    const publicJwk = JSON.parse(payload.exchange[payload.iss]);
    await verifyKeyPair(publicJwk, privateJwk);
    const privateKey = await importJwk(privateJwk);
    const alg = privateJwk.alg;
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

async function verifyProof(proof, expectedPayloadClaims, options) {
    const publicJwk = JSON.parse(expectedPayloadClaims.exchange[expectedPayloadClaims.iss]);
    const verification = await jwsDecode(proof, publicJwk);
    if (verification.payload.iss === undefined) {
        throw new Error('Property "iss" missing');
    }
    if (verification.payload.iat === undefined) {
        throw new Error('Property claim iat missing');
    }
    if (options !== undefined) {
        const timestamp = (options.timestamp === 'iat') ? verification.payload.iat * 1000 : options.timestamp;
        const notBefore = (options.notBefore === 'iat') ? verification.payload.iat * 1000 : options.notBefore;
        const notAfter = (options.notAfter === 'iat') ? verification.payload.iat * 1000 : options.notAfter;
        checkTimestamp(timestamp, notBefore, notAfter, options.tolerance);
    }
    const payload = verification.payload;
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
function checkDataExchange(dataExchange, expectedDataExchange) {
    const claims = ['id', 'orig', 'dest', 'hashAlg', 'cipherblockDgst', 'blockCommitment', 'blockCommitment', 'secretCommitment', 'schema'];
    for (const claim of claims) {
        if (claim !== 'schema' && (dataExchange[claim] === undefined || dataExchange[claim] === '')) {
            throw new Error(`${claim} is missing on dataExchange.\ndataExchange: ${JSON.stringify(dataExchange, undefined, 2)}`);
        }
    }
    for (const key in expectedDataExchange) {
        if (expectedDataExchange[key] !== '' && hashable(expectedDataExchange[key]) !== hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
        }
    }
}

async function verifyPor(por, wallet, connectionTimeout = 10) {
    const { payload: porPayload } = await jwsDecode(por);
    const exchange = porPayload.exchange;
    const dataExchangePreview = { ...exchange };
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
        }, {
            timestamp: 'iat',
            notBefore: pooPayload.iat * 1000,
            notAfter: pooPayload.iat * 1000 + exchange.pooToPorDelay
        });
    }
    catch (error) {
        throw new NrError(error, ['invalid por']);
    }
    let secretHex, iat;
    try {
        const secret = await wallet.getSecretFromLedger(algByteLength(exchange.encAlg), exchange.ledgerSignerAddress, exchange.id, connectionTimeout);
        secretHex = secret.hex;
        iat = secret.iat;
    }
    catch (error) {
        throw new NrError(error, ['cannot verify']);
    }
    try {
        checkTimestamp(iat * 1000, porPayload.iat * 1000, pooPayload.iat * 1000 + exchange.pooToSecretDelay);
    }
    catch (error) {
        throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(pooPayload.iat * 1000 + exchange.pooToSecretDelay)).toUTCString()}`, ['secret not published in time']);
    }
    return {
        pooPayload,
        porPayload,
        secretHex,
        destPublicJwk,
        origPublicJwk
    };
}

async function checkCompleteness(verificationRequest, wallet, connectionTimeout = 10) {
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
        const verified = await verifyPor(vrPayload.por, wallet, connectionTimeout);
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

async function checkDecryption(disputeRequest, wallet) {
    const { payload: drPayload } = await jwsDecode(disputeRequest);
    const { destPublicJwk, origPublicJwk, secretHex, pooPayload, porPayload } = await verifyPor(drPayload.por, wallet);
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
    return {
        pooPayload,
        porPayload,
        drPayload,
        destPublicJwk,
        origPublicJwk
    };
}

class ConflictResolver {
    constructor(jwkPair, dltAgent) {
        this.jwkPair = jwkPair;
        this.dltAgent = dltAgent;
        this.initialized = new Promise((resolve, reject) => {
            this.init().then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async init() {
        await verifyKeyPair(this.jwkPair.publicJwk, this.jwkPair.privateJwk);
    }
    async resolveCompleteness(verificationRequest) {
        await this.initialized;
        const { payload: vrPayload } = await jwsDecode(verificationRequest);
        let porPayload;
        try {
            const decoded = await jwsDecode(vrPayload.por);
            porPayload = decoded.payload;
        }
        catch (error) {
            throw new NrError(error, ['invalid por']);
        }
        const verificationResolution = {
            ...await this._resolution(vrPayload.dataExchangeId, porPayload.exchange[vrPayload.iss]),
            resolution: 'not completed',
            type: 'verification'
        };
        try {
            await checkCompleteness(verificationRequest, this.dltAgent);
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
    async resolveDispute(disputeRequest) {
        await this.initialized;
        const { payload: drPayload } = await jwsDecode(disputeRequest);
        let porPayload;
        try {
            const decoded = await jwsDecode(drPayload.por);
            porPayload = decoded.payload;
        }
        catch (error) {
            throw new NrError(error, ['invalid por']);
        }
        const disputeResolution = {
            ...await this._resolution(drPayload.dataExchangeId, porPayload.exchange[drPayload.iss]),
            resolution: 'denied',
            type: 'dispute'
        };
        try {
            await checkDecryption(disputeRequest, this.dltAgent);
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
    async _resolution(dataExchangeId, sub) {
        return {
            proofType: 'resolution',
            dataExchangeId,
            iat: Math.floor(Date.now() / 1000),
            iss: await parseJwk(this.jwkPair.publicJwk, true),
            sub
        };
    }
}

async function generateVerificationRequest(iss, dataExchangeId, por, privateJwk) {
    const payload = {
        proofType: 'request',
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

async function verifyResolution(resolution, pubJwk) {
    return await jwsDecode(resolution, pubJwk ?? ((header, payload) => {
        return JSON.parse(payload.iss);
    }));
}

var index$2 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    checkCompleteness: checkCompleteness,
    checkDecryption: checkDecryption,
    ConflictResolver: ConflictResolver,
    generateVerificationRequest: generateVerificationRequest,
    verifyPor: verifyPor,
    verifyResolution: verifyResolution
});

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

const defaultDltConfig = {
    gasLimit: 12500000,
    contract: contractConfig
};

async function getSecretFromLedger(contract, signerAddress, exchangeId, timeout, secretLength) {
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
    const hex = parseHex(secretBn.toHexString(), false, secretLength);
    const iat = timestampBn.toNumber();
    return { hex, iat };
}
async function secretUnisgnedTransaction(secretHex, exchangeId, agent) {
    const secret = ethers.BigNumber.from(parseHex(secretHex, true));
    const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId)), true);
    const unsignedTx = await agent.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: agent.dltConfig.gasLimit });
    unsignedTx.nonce = await agent.nextNonce();
    unsignedTx.gasLimit = unsignedTx.gasLimit?._hex;
    unsignedTx.gasPrice = (await agent.provider.getGasPrice())._hex;
    unsignedTx.chainId = (await agent.provider.getNetwork()).chainId;
    const address = await agent.getAddress();
    unsignedTx.from = parseHex(address, true);
    return unsignedTx;
}

class NrpDltAgent {
}

class EthersIoAgent extends NrpDltAgent {
    constructor(dltConfig) {
        super();
        this.initialized = new Promise((resolve, reject) => {
            if (dltConfig !== null && typeof dltConfig === 'object' && typeof dltConfig.then === 'function') {
                dltConfig.then(dltConfig2 => {
                    this.dltConfig = {
                        ...defaultDltConfig,
                        ...dltConfig2
                    };
                    this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
                    this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider);
                    resolve(true);
                }).catch((reason) => reject(reason));
            }
            else {
                this.dltConfig = {
                    ...defaultDltConfig,
                    ...dltConfig
                };
                this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl);
                this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider);
                resolve(true);
            }
        });
    }
    async getContractAddress() {
        await this.initialized;
        return this.contract.address;
    }
}

class EthersIoAgentDest extends EthersIoAgent {
    async getSecretFromLedger(secretLength, signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout, secretLength);
    }
}

class I3mWalletAgent extends EthersIoAgent {
    constructor(wallet, did, dltConfig) {
        const dltConfigPromise = new Promise((resolve, reject) => {
            wallet.providerinfo.get().then((providerInfo) => {
                const rpcProviderUrl = providerInfo.rpcUrl;
                if (rpcProviderUrl === undefined) {
                    reject(new Error('wallet is not connected to RRP endpoint'));
                }
                else {
                    resolve({
                        ...dltConfig,
                        rpcProviderUrl: rpcProviderUrl
                    });
                }
            }).catch((reason) => { reject(reason); });
        });
        super(dltConfigPromise);
        this.wallet = wallet;
        this.did = did;
    }
}

class I3mWalletAgentDest extends I3mWalletAgent {
    async getSecretFromLedger(secretLength, signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout, secretLength);
    }
}

class I3mServerWalletAgent extends EthersIoAgent {
    constructor(serverWallet, did, dltConfig) {
        const dltConfigPromise = new Promise((resolve, reject) => {
            serverWallet.providerinfoGet().then((providerInfo) => {
                const rpcProviderUrl = providerInfo.rpcUrl;
                if (rpcProviderUrl === undefined) {
                    reject(new Error('wallet is not connected to RRP endpoint'));
                }
                else {
                    resolve({
                        ...dltConfig,
                        rpcProviderUrl: rpcProviderUrl
                    });
                }
            }).catch((reason) => { reject(reason); });
        });
        super(dltConfigPromise);
        this.wallet = serverWallet;
        this.did = did;
    }
}

class I3mServerWalletAgentDest extends I3mServerWalletAgent {
    async getSecretFromLedger(secretLength, signerAddress, exchangeId, timeout) {
        await this.initialized;
        return await getSecretFromLedger(this.contract, signerAddress, exchangeId, timeout, secretLength);
    }
}

class EthersIoAgentOrig extends EthersIoAgent {
    constructor(dltConfig, privateKey) {
        super(dltConfig);
        this.count = -1;
        let privKey;
        if (privateKey === undefined) {
            privKey = randBytesSync(32);
        }
        else {
            privKey = (typeof privateKey === 'string') ? new Uint8Array(hexToBuf(privateKey)) : privateKey;
        }
        const signingKey = new SigningKey(privKey);
        this.signer = new Wallet(signingKey, this.provider);
    }
    async deploySecret(secretHex, exchangeId) {
        await this.initialized;
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const signedTx = await this.signer.signTransaction(unsignedTx);
        const setRegistryTx = await this.signer.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        await this.initialized;
        return this.signer.address;
    }
    async nextNonce() {
        await this.initialized;
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending');
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

class I3mWalletAgentOrig extends I3mWalletAgent {
    constructor() {
        super(...arguments);
        this.count = -1;
    }
    async deploySecret(secretHex, exchangeId) {
        await this.initialized;
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const response = await this.wallet.identities.sign({ did: this.did }, {
            type: 'Transaction',
            data: unsignedTx
        });
        const signedTx = response.signature;
        const setRegistryTx = await this.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        await this.initialized;
        const json = await this.wallet.identities.info({ did: this.did });
        if (json.addresses === undefined) {
            throw new NrError(new Error('no addresses for did ' + this.did), ['unexpected error']);
        }
        return json.addresses[0];
    }
    async nextNonce() {
        await this.initialized;
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending');
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

class I3mServerWalletAgentOrig extends I3mServerWalletAgent {
    constructor() {
        super(...arguments);
        this.count = -1;
    }
    async deploySecret(secretHex, exchangeId) {
        await this.initialized;
        const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this);
        const signedTx = (await this.wallet.identitySign({ did: this.did }, { type: 'Transaction', data: unsignedTx })).signature;
        const setRegistryTx = await this.provider.sendTransaction(signedTx);
        this.count = this.count + 1;
        return setRegistryTx.hash;
    }
    async getAddress() {
        await this.initialized;
        const json = await this.wallet.identityInfo({ did: this.did });
        if (json.addresses === undefined) {
            throw new NrError(`Can't get address for did: ${this.did}`, ['unexpected error']);
        }
        return json.addresses[0];
    }
    async nextNonce() {
        await this.initialized;
        const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending');
        if (publishedCount > this.count) {
            this.count = publishedCount;
        }
        return this.count;
    }
}

var index$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EthersIoAgentDest: EthersIoAgentDest,
    I3mWalletAgentDest: I3mWalletAgentDest,
    I3mServerWalletAgentDest: I3mServerWalletAgentDest,
    EthersIoAgentOrig: EthersIoAgentOrig,
    I3mWalletAgentOrig: I3mWalletAgentOrig,
    I3mServerWalletAgentOrig: I3mServerWalletAgentOrig
});

class NonRepudiationDest {
    constructor(agreement, privateJwk, dltAgent) {
        this.initialized = new Promise((resolve, reject) => {
            this.asyncConstructor(agreement, privateJwk, dltAgent).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async asyncConstructor(agreement, privateJwk, dltAgent) {
        const errors = await validateDataExchangeAgreement(agreement);
        if (errors.length > 0) {
            const errorMsg = [];
            let nrErrors = [];
            errors.forEach((error) => {
                errorMsg.push(error.message);
                nrErrors = nrErrors.concat(error.nrErrors);
            });
            nrErrors = [...(new Set(nrErrors))];
            throw new NrError('Resource has not been validated:\n' + errorMsg.join('\n'), nrErrors);
        }
        this.agreement = agreement;
        this.jwkPairDest = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.dest)
        };
        this.publicJwkOrig = JSON.parse(agreement.orig);
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        this.dltAgent = dltAgent;
        const contractAddress = await this.dltAgent.getContractAddress();
        if (this.agreement.ledgerContractAddress !== contractAddress) {
            throw new Error(`Contract address ${contractAddress} does not meet agreed one ${this.agreement.ledgerContractAddress}`);
        }
        this.block = {};
    }
    async verifyPoO(poo, cipherblock, options) {
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
        const currentTimestamp = Date.now();
        const opts = {
            timestamp: currentTimestamp,
            notBefore: 'iat',
            notAfter: 'iat',
            ...options
        };
        const verified = await verifyProof(poo, expectedPayloadClaims, opts);
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
    async verifyPoP(pop, options) {
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
        const opts = {
            timestamp: Date.now(),
            notBefore: 'iat',
            notAfter: this.block.poo.payload.iat * 1000 + this.exchange.pooToPopDelay,
            ...options
        };
        const verified = await verifyProof(pop, expectedPayloadClaims, opts);
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
    async getSecretFromLedger() {
        await this.initialized;
        if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
            throw new Error('Cannot get secret if a PoR has not been sent before');
        }
        const currentTimestamp = Date.now();
        const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay;
        const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000);
        const { hex: secretHex, iat } = await this.dltAgent.getSecretFromLedger(algByteLength(this.agreement.encAlg), this.agreement.ledgerSignerAddress, this.exchange.id, timeout);
        this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex);
        try {
            checkTimestamp(iat * 1000, this.block.por.payload.iat * 1000, this.block.poo.payload.iat * 1000 + this.exchange.pooToSecretDelay);
        }
        catch (error) {
            throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`, ['secret not published in time']);
        }
        return this.block.secret;
    }
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
    async generateVerificationRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange');
        }
        return await generateVerificationRequest('dest', this.exchange.id, this.block.por.jws, this.jwkPairDest.privateJwk);
    }
    async generateDisputeRequest() {
        await this.initialized;
        if (this.block.por === undefined || this.block.jwe === undefined || this.exchange === undefined) {
            throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange and have received the cipherblock');
        }
        const payload = {
            proofType: 'request',
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

class NonRepudiationOrig {
    constructor(agreement, privateJwk, block, dltAgent) {
        this.jwkPairOrig = {
            privateJwk: privateJwk,
            publicJwk: JSON.parse(agreement.orig)
        };
        this.publicJwkDest = JSON.parse(agreement.dest);
        this.block = {
            raw: block
        };
        this.initialized = new Promise((resolve, reject) => {
            this.init(agreement, dltAgent).then(() => {
                resolve(true);
            }).catch((error) => {
                reject(error);
            });
        });
    }
    async init(agreement, dltAgent) {
        const errors = await validateDataExchangeAgreement(agreement);
        if (errors.length > 0) {
            const errorMsg = [];
            let nrErrors = [];
            errors.forEach((error) => {
                errorMsg.push(error.message);
                nrErrors = nrErrors.concat(error.nrErrors);
            });
            nrErrors = [...(new Set(nrErrors))];
            throw new NrError('Resource has not been validated:\n' + errorMsg.join('\n'), nrErrors);
        }
        this.agreement = agreement;
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
        await this._dltSetup(dltAgent);
    }
    async _dltSetup(dltAgent) {
        this.dltAgent = dltAgent;
        const signerAddress = await this.dltAgent.getAddress();
        if (signerAddress !== this.exchange.ledgerSignerAddress) {
            throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address ${signerAddress} derived from the provided private key`);
        }
        const contractAddress = await this.dltAgent.getContractAddress();
        if (contractAddress !== parseHex(this.agreement.ledgerContractAddress, true)) {
            throw new Error(`Contract address in use ${contractAddress} does not meet the agreed one ${this.agreement.ledgerContractAddress}`);
        }
    }
    async generatePoO() {
        await this.initialized;
        this.block.poo = await createProof({
            proofType: 'PoO',
            iss: 'orig',
            exchange: this.exchange
        }, this.jwkPairOrig.privateJwk);
        return this.block.poo;
    }
    async verifyPoR(por, options) {
        await this.initialized;
        if (this.block.poo === undefined) {
            throw new Error('Cannot verify a PoR if not even a PoO have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            poo: this.block.poo.jws
        };
        const pooTs = this.block.poo.payload.iat * 1000;
        const opts = {
            timestamp: Date.now(),
            notBefore: pooTs,
            notAfter: pooTs + this.exchange.pooToPorDelay,
            ...options
        };
        const verified = await verifyProof(por, expectedPayloadClaims, opts);
        this.block.por = {
            jws: por,
            payload: verified.payload
        };
        return this.block.por;
    }
    async generatePoP() {
        await this.initialized;
        if (this.block.por === undefined) {
            throw new Error('Before computing a PoP, you have first to have received and verified the PoR');
        }
        const verificationCode = await this.dltAgent.deploySecret(this.block.secret.hex, this.exchange.id);
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

export { index$2 as ConflictResolution, ENC_ALGS, EthersIoAgentDest, EthersIoAgentOrig, HASH_ALGS, I3mServerWalletAgentDest, I3mServerWalletAgentOrig, I3mWalletAgentDest, I3mWalletAgentOrig, KEY_AGREEMENT_ALGS, index as NonRepudiationProtocol, NrError, SIGNING_ALGS, index$1 as Signers, checkTimestamp, createProof, defaultDltConfig, exchangeId, generateKeys, getDltAddress, importJwk, jsonSort, jweDecrypt, jweEncrypt, jwsDecode, oneTimeSecret, parseAddress, parseHex, parseJwk, sha, validateDataExchange, validateDataExchangeAgreement, validateDataSharingAgreementSchema, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2NvbnN0YW50cy50cyIsIi4uLy4uL3NyYy90cy9lcnJvcnMvTnJFcnJvci50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vZ2VuZXJhdGVLZXlzLnRzIiwiLi4vLi4vc3JjL3RzL2NyeXB0by9pbXBvcnRKd2sudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9jcnlwdG8vandzRGVjb2RlLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2FsZ0J5dGVMZW5ndGgudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL29uZVRpbWVTZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvY3J5cHRvL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvdGltZXN0YW1wcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9qc29uU29ydC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUp3ay50cyIsIi4uLy4uL3NyYy90cy91dGlscy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvcGFyc2VBZGRyZXNzLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2dldERsdEFkZHJlc3MudHMiLCIuLi8uLi9zcmMvdHMvZXhjaGFuZ2UvZXhjaGFuZ2VJZC50cyIsIi4uLy4uL3NyYy90cy9leGNoYW5nZS9jaGVja0FncmVlbWVudC50cyIsIi4uLy4uL3NyYy90cy9wcm9vZnMvY3JlYXRlUHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvcHJvb2ZzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vdmVyaWZ5UG9yLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vY2hlY2tDb21wbGV0ZW5lc3MudHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9jaGVja0RlY3J5cHRpb24udHMiLCIuLi8uLi9zcmMvdHMvY29uZmxpY3QtcmVzb2x1dGlvbi9Db25mbGljdFJlc29sdmVyLnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vZ2VuZXJhdGVWZXJpZmljYXRpb25SZXF1ZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2NvbmZsaWN0LXJlc29sdXRpb24vdmVyaWZ5UmVzb2x1dGlvbi50cyIsIi4uLy4uL3NyYy90cy9kbHQvZGVmYXVsdERsdENvbmZpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL3NlY3JldC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL05ycERsdEFnZW50LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvRXRoZXJzSW9BZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL2Rlc3QvRXRoZXJzSW9BZ2VudERlc3QudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9JM21XYWxsZXRBZ2VudC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL2Rlc3QvSTNtV2FsbGV0QWdlbnREZXN0LnRzIiwiLi4vLi4vc3JjL3RzL2RsdC9hZ2VudHMvSTNtU2VydmVyV2FsbGV0QWdlbnQudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9kZXN0L0kzbVNlcnZlcldhbGxldEFnZW50RGVzdC50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL29yaWcvRXRoZXJzSW9BZ2VudE9yaWcudHMiLCIuLi8uLi9zcmMvdHMvZGx0L2FnZW50cy9vcmlnL0kzbVdhbGxldEFnZW50T3JpZy50cyIsIi4uLy4uL3NyYy90cy9kbHQvYWdlbnRzL29yaWcvSTNtU2VydmVyV2FsbGV0QWdlbnRPcmlnLnRzIiwiLi4vLi4vc3JjL3RzL25vbi1yZXB1ZGlhdGlvbi1wcm90b2NvbC9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiLCIuLi8uLi9zcmMvdHMvbm9uLXJlcHVkaWF0aW9uLXByb3RvY29sL05vblJlcHVkaWF0aW9uT3JpZy50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiaW1wb3J0SldLam9zZSIsInBhcnNlSGV4IiwiYmFzZTY0ZGVjb2RlIiwiYmNQYXJzZUhleCIsImdldFNlY3JldCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7OztBQUFhLE1BQUEsU0FBUyxHQUFHLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQVU7QUFDdEQsTUFBQSxZQUFZLEdBQUcsQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBVTtNQUNuRCxRQUFRLEdBQUcsQ0FBQyxTQUFTLEVBQUUsU0FBUyxFQUFVO0FBQzFDLE1BQUEsa0JBQWtCLEdBQUcsQ0FBQyxTQUFTOztBQ0R0QyxNQUFPLE9BQVEsU0FBUSxLQUFLLENBQUE7SUFHaEMsV0FBYSxDQUFBLEtBQVUsRUFBRSxRQUF1QixFQUFBO1FBQzlDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNaLElBQUksS0FBSyxZQUFZLE9BQU8sRUFBRTtBQUM1QixZQUFBLElBQUksQ0FBQyxRQUFRLEdBQUcsS0FBSyxDQUFDLFFBQVEsQ0FBQTtBQUM5QixZQUFBLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxRQUFRLENBQUMsQ0FBQTtBQUN0QixTQUFBO0FBQU0sYUFBQTtBQUNMLFlBQUEsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUE7QUFDekIsU0FBQTtLQUNGO0lBRUQsR0FBRyxDQUFFLEdBQUcsUUFBdUIsRUFBQTtRQUM3QixNQUFNLE1BQU0sR0FBRyxJQUFJLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUM3QyxRQUFBLElBQUksQ0FBQyxRQUFRLEdBQUcsQ0FBQyxJQUFJLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTtLQUN2QztBQUNGOztBQ1hELE1BQU0sRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsUUFBUSxDQUFBO0FBU3BCLGVBQWUsWUFBWSxDQUFFLEdBQWUsRUFBRSxVQUFnQyxFQUFFLE1BQWdCLEVBQUE7QUFDckcsSUFBQSxJQUFJLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUM7UUFBRSxNQUFNLElBQUksT0FBTyxDQUFDLElBQUksVUFBVSxDQUFDLENBQUEsNkJBQUEsRUFBZ0MsR0FBRyxDQUE4QiwyQkFBQSxFQUFBLFlBQVksQ0FBQyxRQUFRLEVBQUUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFFckwsSUFBQSxJQUFJLFNBQWlCLENBQUE7QUFDckIsSUFBQSxJQUFJLFVBQWtCLENBQUE7QUFDdEIsSUFBQSxRQUFRLEdBQUc7QUFDVCxRQUFBLEtBQUssT0FBTztZQUNWLFVBQVUsR0FBRyxPQUFPLENBQUE7WUFDcEIsU0FBUyxHQUFHLEVBQUUsQ0FBQTtZQUNkLE1BQUs7QUFDUCxRQUFBLEtBQUssT0FBTztZQUNWLFVBQVUsR0FBRyxPQUFPLENBQUE7WUFDcEIsU0FBUyxHQUFHLEVBQUUsQ0FBQTtZQUNkLE1BQUs7QUFDUCxRQUFBO1lBQ0UsVUFBVSxHQUFHLE9BQU8sQ0FBQTtZQUNwQixTQUFTLEdBQUcsRUFBRSxDQUFBO0FBQ2pCLEtBQUE7QUFFRCxJQUFBLElBQUksVUFBa0MsQ0FBQTtJQUN0QyxJQUFJLFVBQVUsS0FBSyxTQUFTLEVBQUU7QUFDNUIsUUFBQSxJQUFJLE9BQU8sVUFBVSxLQUFLLFFBQVEsRUFBRTtZQUNsQyxJQUFJLE1BQU0sS0FBSyxJQUFJLEVBQUU7QUFDbkIsZ0JBQUEsVUFBVSxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFlLENBQUE7QUFDbEQsYUFBQTtBQUFNLGlCQUFBO2dCQUNMLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQTtBQUNsRCxhQUFBO0FBQ0YsU0FBQTtBQUFNLGFBQUE7WUFDTCxVQUFVLEdBQUcsVUFBVSxDQUFBO0FBQ3hCLFNBQUE7QUFDRixLQUFBO0FBQU0sU0FBQTtRQUNMLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNLFNBQVMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFBO0FBQ3hELEtBQUE7QUFFRCxJQUFBLE1BQU0sRUFBRSxHQUFHLElBQUksRUFBRSxDQUFDLEdBQUcsR0FBRyxVQUFVLENBQUMsU0FBUyxDQUFDLFVBQVUsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUNwRSxNQUFNLE1BQU0sR0FBRyxFQUFFLENBQUMsY0FBYyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQzVDLElBQUEsTUFBTSxLQUFLLEdBQUcsTUFBTSxDQUFDLFNBQVMsRUFBRSxDQUFBO0lBRWhDLE1BQU0sSUFBSSxHQUFHLEtBQUssQ0FBQyxJQUFJLEVBQUUsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7SUFDdEUsTUFBTSxJQUFJLEdBQUcsS0FBSyxDQUFDLElBQUksRUFBRSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxRQUFRLENBQUMsU0FBUyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQTtBQUN0RSxJQUFBLE1BQU0sSUFBSSxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLFNBQVMsR0FBRyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFFbEUsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDakQsSUFBQSxNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFFakQsSUFBQSxNQUFNLFVBQVUsR0FBUSxFQUFFLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxHQUFHLEVBQUUsQ0FBQTtBQUVwRSxJQUFBLE1BQU0sU0FBUyxHQUFRLEVBQUUsR0FBRyxVQUFVLEVBQUUsQ0FBQTtJQUN4QyxPQUFPLFNBQVMsQ0FBQyxDQUFDLENBQUE7SUFFbEIsT0FBTztRQUNMLFNBQVM7UUFDVCxVQUFVO0tBQ1gsQ0FBQTtBQUNIOztBQ25FTyxlQUFlLFNBQVMsQ0FBRSxHQUFRLEVBQUUsR0FBWSxFQUFBO0FBQ3JELElBQUEsTUFBTSxNQUFNLEdBQUcsR0FBRyxLQUFLLFNBQVMsR0FBRyxHQUFHLENBQUMsR0FBRyxHQUFHLEdBQUcsQ0FBQTtBQUNoRCxJQUFBLE1BQU0sSUFBSSxHQUFJLFFBQWdDLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFDLE1BQU0sQ0FBQyxrQkFBa0IsQ0FBQyxDQUFBO0FBQzlGLElBQUEsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLEVBQUU7QUFDMUIsUUFBQSxNQUFNLElBQUksT0FBTyxDQUFDLCtCQUErQixHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFDM0YsS0FBQTtJQUNELElBQUk7UUFDRixNQUFNLEdBQUcsR0FBRyxNQUFNQSxTQUFhLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFBO0FBQ3pDLFFBQUEsT0FBTyxHQUFHLENBQUE7QUFDWCxLQUFBO0FBQUMsSUFBQSxPQUFPLEtBQUssRUFBRTtRQUNkLE1BQU0sSUFBSSxPQUFPLENBQUMsS0FBSyxFQUFFLENBQUMsYUFBYSxDQUFDLENBQUMsQ0FBQTtBQUMxQyxLQUFBO0FBQ0g7O0FDSE8sZUFBZSxVQUFVLENBQUUsS0FBaUIsRUFBRSxpQkFBc0IsRUFBRSxNQUFzQixFQUFBO0FBRWpHLElBQUEsSUFBSSxHQUFzQixDQUFBO0FBQzFCLElBQUEsSUFBSSxHQUFrQixDQUFBO0FBRXRCLElBQUEsTUFBTSxHQUFHLEdBQUcsRUFBRSxHQUFHLGlCQUFpQixFQUFFLENBQUE7SUFFcEMsSUFBSyxRQUFnQyxDQUFDLFFBQVEsQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLENBQUMsRUFBRTtRQUVyRSxHQUFHLEdBQUcsS0FBSyxDQUFBO0FBQ1gsUUFBQSxHQUFHLEdBQUcsTUFBTSxLQUFLLFNBQVMsR0FBRyxNQUFNLEdBQUcsaUJBQWlCLENBQUMsR0FBb0IsQ0FBQTtBQUM3RSxLQUFBO0FBQU0sU0FBQSxJQUFLLFlBQW9DLENBQUMsTUFBTSxDQUFDLGtCQUFrQixDQUFDLENBQUMsUUFBUSxDQUFDLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxFQUFFO1FBRTNHLElBQUksTUFBTSxLQUFLLFNBQVMsRUFBRTtBQUN4QixZQUFBLE1BQU0sSUFBSSxPQUFPLENBQUMsK0ZBQStGLEdBQUcsUUFBUSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLG1CQUFtQixDQUFDLENBQUMsQ0FBQTtBQUMvSixTQUFBO1FBQ0QsR0FBRyxHQUFHLE1BQU0sQ0FBQTtRQUNaLEdBQUcsR0FBRyxTQUFTLENBQUE7QUFDZixRQUFBLEdBQUcsQ0FBQyxHQUFHLEdBQUcsR0FBVSxDQUFBO0FBQ3JCLEtBQUE7QUFBTSxTQUFBO0FBQ0wsUUFBQSxNQUFNLElBQUksT0FBTyxDQUFDLENBQTRDLHlDQUFBLEVBQUEsaUJBQWlCLENBQUMsR0FBYSxDQUFBLENBQUUsRUFBRSxDQUFDLG1CQUFtQixFQUFFLGFBQWEsRUFBRSxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFDNUosS0FBQTtBQUNELElBQUEsTUFBTSxHQUFHLEdBQUcsTUFBTSxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUE7QUFFaEMsSUFBQSxJQUFJLEdBQUcsQ0FBQTtJQUNQLElBQUk7QUFDRixRQUFBLEdBQUcsR0FBRyxNQUFNLElBQUksY0FBYyxDQUFDLEtBQUssQ0FBQztBQUNsQyxhQUFBLGtCQUFrQixDQUFDLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsaUJBQWlCLENBQUMsR0FBRyxFQUFFLENBQUM7YUFDNUQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQ2YsUUFBQSxPQUFPLEdBQUcsQ0FBQTtBQUNYLEtBQUE7QUFBQyxJQUFBLE9BQU8sS0FBSyxFQUFFO1FBQ2QsTUFBTSxJQUFJLE9BQU8sQ0FBQyxLQUFLLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFDaEQsS0FBQTtBQUNILENBQUM7QUFRTSxlQUFlLFVBQVUsQ0FBRSxHQUFXLEVBQUUsa0JBQXVCLEVBQUE7SUFDcEUsSUFBSTtBQUNGLFFBQUEsTUFBTSxHQUFHLEdBQUcsRUFBRSxHQUFHLGtCQUFrQixFQUFFLENBQUE7UUFDckMsTUFBTSxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxxQkFBcUIsQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUMvQyxRQUFBLElBQUksR0FBRyxLQUFLLFNBQVMsSUFBSSxHQUFHLEtBQUssU0FBUyxFQUFFO1lBQzFDLE1BQU0sSUFBSSxPQUFPLENBQUMsa0NBQWtDLEVBQUUsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLENBQUE7QUFDMUUsU0FBQTtRQUNELElBQUksR0FBRyxLQUFLLFNBQVMsRUFBRTtBQUNyQixZQUFBLEdBQUcsQ0FBQyxHQUFHLEdBQUcsR0FBVSxDQUFBO0FBQ3JCLFNBQUE7QUFDRCxRQUFBLE1BQU0sR0FBRyxHQUFHLE1BQU0sU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBRWhDLFFBQUEsT0FBTyxNQUFNLGNBQWMsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUUsMkJBQTJCLEVBQUUsQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLENBQUE7QUFDOUUsS0FBQTtBQUFDLElBQUEsT0FBTyxLQUFLLEVBQUU7UUFDZCxNQUFNLE9BQU8sR0FBRyxJQUFJLE9BQU8sQ0FBQyxLQUFLLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFDekQsUUFBQSxNQUFNLE9BQU8sQ0FBQTtBQUNkLEtBQUE7QUFDSDs7QUM3RE8sZUFBZSxTQUFTLENBQTBCLEdBQVcsRUFBRSxTQUErQixFQUFBO0lBQ25HLE1BQU0sS0FBSyxHQUFHLDZEQUE2RCxDQUFBO0lBQzNFLE1BQU0sS0FBSyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLENBQUE7SUFFOUIsSUFBSSxLQUFLLEtBQUssSUFBSSxFQUFFO0FBQ2xCLFFBQUEsTUFBTSxJQUFJLE9BQU8sQ0FBQyxJQUFJLEtBQUssQ0FBQyxDQUFBLEVBQUcsR0FBRyxDQUFBLGFBQUEsQ0FBZSxDQUFDLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFDM0UsS0FBQTtBQUVELElBQUEsSUFBSSxNQUEyQixDQUFBO0FBQy9CLElBQUEsSUFBSSxPQUFVLENBQUE7SUFDZCxJQUFJO0FBQ0YsUUFBQSxNQUFNLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxJQUFJLENBQVcsQ0FBQyxDQUFBO0FBQ3pELFFBQUEsT0FBTyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsSUFBSSxDQUFXLENBQUMsQ0FBQTtBQUMzRCxLQUFBO0FBQUMsSUFBQSxPQUFPLEtBQUssRUFBRTtRQUNkLE1BQU0sSUFBSSxPQUFPLENBQUMsS0FBSyxFQUFFLENBQUMsZ0JBQWdCLEVBQUUsbUJBQW1CLENBQUMsQ0FBQyxDQUFBO0FBQ2xFLEtBQUE7SUFFRCxJQUFJLFNBQVMsS0FBSyxTQUFTLEVBQUU7UUFDM0IsTUFBTSxNQUFNLEdBQUcsQ0FBQyxPQUFPLFNBQVMsS0FBSyxVQUFVLElBQUksTUFBTSxTQUFTLENBQUMsTUFBTSxFQUFFLE9BQU8sQ0FBQyxHQUFHLFNBQVMsQ0FBQTtBQUMvRixRQUFBLE1BQU0sTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQ3RDLElBQUk7WUFDRixNQUFNLFFBQVEsR0FBRyxNQUFNLFNBQVMsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDLENBQUE7WUFDN0MsT0FBTztnQkFDTCxNQUFNLEVBQUUsUUFBUSxDQUFDLGVBQWU7Z0JBQ2hDLE9BQU8sRUFBRSxRQUFRLENBQUMsT0FBdUI7QUFDekMsZ0JBQUEsTUFBTSxFQUFFLE1BQU07YUFDZixDQUFBO0FBQ0YsU0FBQTtBQUFDLFFBQUEsT0FBTyxLQUFLLEVBQUU7WUFDZCxNQUFNLElBQUksT0FBTyxDQUFDLEtBQUssRUFBRSxDQUFDLHlCQUF5QixDQUFDLENBQUMsQ0FBQTtBQUN0RCxTQUFBO0FBQ0YsS0FBQTtBQUVELElBQUEsT0FBTyxFQUFFLE1BQU0sRUFBRSxPQUFPLEVBQUUsQ0FBQTtBQUM1Qjs7QUN4Q00sU0FBVSxhQUFhLENBQUUsR0FBeUMsRUFBQTtBQUN0RSxJQUFBLE1BQU0sSUFBSSxHQUFjLFFBQWdDLENBQUMsTUFBTSxDQUFDLFNBQWdDLENBQUMsQ0FBQyxNQUFNLENBQUMsWUFBbUMsQ0FBQyxDQUFBO0FBQzdJLElBQUEsSUFBSSxJQUFJLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxFQUFFO0FBQ3RCLFFBQUEsT0FBTyxNQUFNLENBQUUsR0FBRyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQXNCLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDL0QsS0FBQTtJQUNELE1BQU0sSUFBSSxPQUFPLENBQUMsdUJBQXVCLEVBQUUsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDLENBQUE7QUFDbkU7O0FDUU8sZUFBZSxhQUFhLENBQUUsTUFBcUIsRUFBRSxNQUEwQixFQUFFLE1BQWdCLEVBQUE7QUFDdEcsSUFBQSxJQUFJLEdBQXlCLENBQUE7QUFFN0IsSUFBQSxJQUFJLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsRUFBRTtRQUM5QixNQUFNLElBQUksT0FBTyxDQUFDLElBQUksS0FBSyxDQUFDLENBQUEsZ0JBQUEsRUFBbUIsTUFBZ0IsQ0FBNEIseUJBQUEsRUFBQSxRQUFRLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQyxFQUFFLENBQUMsbUJBQW1CLENBQUMsQ0FBQyxDQUFBO0FBQzFJLEtBQUE7QUFFRCxJQUFBLE1BQU0sWUFBWSxHQUFHLGFBQWEsQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUUxQyxJQUFJLE1BQU0sS0FBSyxTQUFTLEVBQUU7QUFDeEIsUUFBQSxJQUFJLE9BQU8sTUFBTSxLQUFLLFFBQVEsRUFBRTtZQUM5QixJQUFJLE1BQU0sS0FBSyxJQUFJLEVBQUU7QUFDbkIsZ0JBQUEsR0FBRyxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFlLENBQUE7QUFDdkMsYUFBQTtBQUFNLGlCQUFBO2dCQUNMLE1BQU0sWUFBWSxHQUFHQyxVQUFRLENBQUMsTUFBTSxFQUFFLEtBQUssQ0FBQyxDQUFBO2dCQUM1QyxJQUFJLFlBQVksS0FBS0EsVUFBUSxDQUFDLE1BQU0sRUFBRSxLQUFLLEVBQUUsWUFBWSxDQUFDLEVBQUU7b0JBQzFELE1BQU0sSUFBSSxPQUFPLENBQUMsSUFBSSxVQUFVLENBQUMsQ0FBQSxvQkFBQSxFQUF1QixZQUFZLEdBQUcsQ0FBQyxDQUFBLDRCQUFBLEVBQStCLFlBQVksQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFFLENBQUEsQ0FBQyxFQUFFLENBQUMsYUFBYSxDQUFDLENBQUMsQ0FBQTtBQUNwSixpQkFBQTtnQkFDRCxHQUFHLEdBQUcsSUFBSSxVQUFVLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUE7QUFDdkMsYUFBQTtBQUNGLFNBQUE7QUFBTSxhQUFBO1lBQ0wsR0FBRyxHQUFHLE1BQU0sQ0FBQTtBQUNiLFNBQUE7QUFDRCxRQUFBLElBQUksR0FBRyxDQUFDLE1BQU0sS0FBSyxZQUFZLEVBQUU7QUFDL0IsWUFBQSxNQUFNLElBQUksT0FBTyxDQUFDLElBQUksVUFBVSxDQUFDLDBCQUEwQixZQUFZLENBQUEsNEJBQUEsRUFBK0IsR0FBRyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFBO0FBQ3RJLFNBQUE7QUFDRixLQUFBO0FBQU0sU0FBQTtRQUNMLElBQUk7QUFDRixZQUFBLEdBQUcsR0FBRyxNQUFNLGNBQWMsQ0FBQyxNQUFNLEVBQUUsRUFBRSxXQUFXLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQTtBQUMxRCxTQUFBO0FBQUMsUUFBQSxPQUFPLEtBQUssRUFBRTtZQUNkLE1BQU0sSUFBSSxPQUFPLENBQUMsS0FBSyxFQUFFLENBQUMsa0JBQWtCLENBQUMsQ0FBQyxDQUFBO0FBQy9DLFNBQUE7QUFDRixLQUFBO0FBQ0QsSUFBQSxNQUFNLEdBQUcsR0FBRyxNQUFNLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUdoQyxJQUFBLEdBQUcsQ0FBQyxHQUFHLEdBQUcsTUFBTSxDQUFBO0lBRWhCLE9BQU8sRUFBRSxHQUFHLEVBQUUsR0FBVSxFQUFFLEdBQUcsRUFBRSxRQUFRLENBQUNDLE1BQVksQ0FBQyxHQUFHLENBQUMsQ0FBVyxDQUFlLEVBQUUsS0FBSyxFQUFFLFlBQVksQ0FBQyxFQUFFLENBQUE7QUFDN0c7O0FDbkRPLGVBQWUsYUFBYSxDQUFFLE1BQVcsRUFBRSxPQUFZLEVBQUE7QUFDNUQsSUFBQSxJQUFJLE1BQU0sQ0FBQyxHQUFHLEtBQUssU0FBUyxJQUFJLE9BQU8sQ0FBQyxHQUFHLEtBQUssU0FBUyxJQUFJLE1BQU0sQ0FBQyxHQUFHLEtBQUssT0FBTyxDQUFDLEdBQUcsRUFBRTtBQUN2RixRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsMEVBQTBFLENBQUMsQ0FBQTtBQUM1RixLQUFBO0FBQ0QsSUFBQSxNQUFNLE1BQU0sR0FBRyxNQUFNLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUN0QyxJQUFBLE1BQU0sT0FBTyxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0lBRXhDLElBQUk7QUFDRixRQUFBLE1BQU0sS0FBSyxHQUFHLE1BQU0sU0FBUyxDQUFDLEVBQUUsQ0FBQyxDQUFBO0FBQ2pDLFFBQUEsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJLFdBQVcsQ0FBQyxLQUFLLENBQUM7YUFDckMsWUFBWSxDQUFDLE9BQU8sQ0FBQzthQUNyQixrQkFBa0IsQ0FBQyxFQUFFLEdBQUcsRUFBRSxPQUFPLENBQUMsR0FBRyxFQUFFLENBQUM7QUFDeEMsYUFBQSxJQUFJLEVBQUUsQ0FBQTtBQUNULFFBQUEsTUFBTSxhQUFhLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQyxDQUFBO0FBQ2pDLEtBQUE7QUFBQyxJQUFBLE9BQU8sS0FBSyxFQUFFO1FBQ2QsTUFBTSxJQUFJLE9BQU8sQ0FBQyxLQUFLLEVBQUUsQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDLENBQUE7QUFDL0MsS0FBQTtBQUNIOztBQ3JCTSxTQUFVLGNBQWMsQ0FBRSxTQUFpQixFQUFFLFNBQWlCLEVBQUUsUUFBZ0IsRUFBRSxTQUFBLEdBQW9CLElBQUksRUFBQTtBQUM5RyxJQUFBLElBQUksU0FBUyxHQUFHLFNBQVMsR0FBRyxTQUFTLEVBQUU7QUFDckMsUUFBQSxNQUFNLElBQUksT0FBTyxDQUFDLElBQUksS0FBSyxDQUFDLENBQWEsVUFBQSxHQUFDLElBQUksSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFDLFlBQVksRUFBRSxFQUF3QixvQkFBQSxHQUFDLElBQUksSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFDLFlBQVksRUFBRSxFQUF1QixtQkFBQSxFQUFBLFNBQVMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxFQUFFLENBQUMsbUJBQW1CLENBQUMsQ0FBQyxDQUFBO0FBQzNNLEtBQUE7QUFBTSxTQUFBLElBQUksU0FBUyxHQUFHLFFBQVEsR0FBRyxTQUFTLEVBQUU7QUFDM0MsUUFBQSxNQUFNLElBQUksT0FBTyxDQUFDLElBQUksS0FBSyxDQUFDLENBQWEsVUFBQSxHQUFDLElBQUksSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFDLFlBQVksRUFBRSxFQUFzQixrQkFBQSxHQUFDLElBQUksSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLFlBQVksRUFBRSxFQUF1QixtQkFBQSxFQUFBLFNBQVMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxFQUFFLENBQUMsbUJBQW1CLENBQUMsQ0FBQyxDQUFBO0FBQ3hNLEtBQUE7QUFDSDs7QUNSQSxTQUFTLFFBQVEsQ0FBRSxDQUFNLEVBQUE7QUFDdkIsSUFBQSxPQUFPLE1BQU0sQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsS0FBSyxpQkFBaUIsQ0FBQTtBQUNoRSxDQUFDO0FBRUssU0FBVSxRQUFRLENBQUUsR0FBUSxFQUFBO0FBQ2hDLElBQUEsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFFO1FBQ3RCLE9BQU8sR0FBRyxDQUFDLElBQUksRUFBRSxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUNoQyxLQUFBO0FBQU0sU0FBQSxJQUFJLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFBRTtBQUN4QixRQUFBLE9BQU8sTUFBTTthQUNWLElBQUksQ0FBQyxHQUFHLENBQUM7QUFDVCxhQUFBLElBQUksRUFBRTtBQUNOLGFBQUEsTUFBTSxDQUFDLFVBQVUsQ0FBTSxFQUFFLENBQUMsRUFBQTtZQUN6QixDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQ3ZCLFlBQUEsT0FBTyxDQUFDLENBQUE7U0FDVCxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBQ1QsS0FBQTtBQUVELElBQUEsT0FBTyxHQUFHLENBQUE7QUFDWjs7QUNmTSxTQUFVLFFBQVEsQ0FBRSxDQUFTLEVBQUUsUUFBb0IsR0FBQSxLQUFLLEVBQUUsVUFBbUIsRUFBQTtJQUNqRixJQUFJO1FBQ0YsT0FBT0MsVUFBVSxDQUFDLENBQUMsRUFBRSxRQUFRLEVBQUUsVUFBVSxDQUFDLENBQUE7QUFDM0MsS0FBQTtBQUFDLElBQUEsT0FBTyxLQUFLLEVBQUU7UUFDZCxNQUFNLElBQUksT0FBTyxDQUFDLEtBQUssRUFBRSxDQUFDLGdCQUFnQixDQUFDLENBQUMsQ0FBQTtBQUM3QyxLQUFBO0FBQ0g7O0FDRk8sZUFBZSxRQUFRLENBQUUsR0FBUSxFQUFFLFNBQWtCLEVBQUE7SUFDMUQsSUFBSTtRQUNGLE1BQU0sU0FBUyxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDN0IsUUFBQSxNQUFNLFNBQVMsR0FBRyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDL0IsUUFBQSxPQUFPLENBQUMsU0FBUyxJQUFJLElBQUksQ0FBQyxTQUFTLENBQUMsU0FBUyxDQUFDLEdBQUcsU0FBUyxDQUFBO0FBQzNELEtBQUE7QUFBQyxJQUFBLE9BQU8sS0FBSyxFQUFFO1FBQ2QsTUFBTSxJQUFJLE9BQU8sQ0FBQyxLQUFLLEVBQUUsQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFBO0FBQzFDLEtBQUE7QUFDSDs7QUNYTyxlQUFlLEdBQUcsQ0FBRSxLQUF3QixFQUFFLFNBQWtCLEVBQUE7SUFDckUsTUFBTSxVQUFVLEdBQUcsU0FBUyxDQUFBO0FBQzVCLElBQUEsSUFBSSxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUU7UUFDbkMsTUFBTSxJQUFJLE9BQU8sQ0FBQyxJQUFJLFVBQVUsQ0FBQyxDQUFBLHNDQUFBLEVBQXlDLElBQUksQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsbUJBQW1CLENBQUMsQ0FBQyxDQUFBO0FBQ2hJLEtBQUE7QUFFRCxJQUFBLE1BQU0sT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUE7SUFDakMsTUFBTSxTQUFTLEdBQUcsQ0FBQyxPQUFPLEtBQUssS0FBSyxRQUFRLElBQUksT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxNQUFNLEdBQUcsS0FBSyxDQUFBO0lBRXBGLElBQUk7QUFDRixRQUFBLElBQUksTUFBTSxDQUFBO0FBQ1YsUUFBQSxJQUFJLElBQVUsRUFBRTtBQUNkLFlBQUEsTUFBTSxHQUFHLElBQUksVUFBVSxDQUFDLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLFNBQVMsQ0FBQyxDQUFDLENBQUE7QUFDMUUsU0FFdUMsUUFDdkM7QUFDRCxRQUFBLE9BQU8sTUFBTSxDQUFBO0FBQ2QsS0FBQTtBQUFDLElBQUEsT0FBTyxLQUFLLEVBQUU7UUFDZCxNQUFNLElBQUksT0FBTyxDQUFDLEtBQUssRUFBRSxDQUFDLGtCQUFrQixDQUFDLENBQUMsQ0FBQTtBQUMvQyxLQUFBO0FBQ0g7O0FDakJNLFNBQVUsWUFBWSxDQUFFLENBQVMsRUFBQTtJQUNyQyxNQUFNLFFBQVEsR0FBRyxDQUFDLENBQUMsS0FBSyxDQUFDLHlCQUF5QixDQUFDLENBQUE7SUFDbkQsSUFBSSxRQUFRLElBQUksSUFBSSxFQUFFO0FBQ3BCLFFBQUEsTUFBTSxJQUFJLFVBQVUsQ0FBQywwQkFBMEIsQ0FBQyxDQUFBO0FBQ2pELEtBQUE7SUFDRCxJQUFJO1FBQ0YsTUFBTSxHQUFHLEdBQUcsUUFBUSxDQUFDLENBQUMsRUFBRSxJQUFJLEVBQUUsRUFBRSxDQUFDLENBQUE7UUFDakMsT0FBTyxNQUFNLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUNwQyxLQUFBO0FBQUMsSUFBQSxPQUFPLEtBQUssRUFBRTtRQUNkLE1BQU0sSUFBSSxPQUFPLENBQUMsS0FBSyxFQUFFLENBQUMsd0JBQXdCLENBQUMsQ0FBQyxDQUFBO0FBQ3JELEtBQUE7QUFDSDs7QUNoQk0sU0FBVSxhQUFhLENBQUUsYUFBcUIsRUFBQTtJQUNsRCxNQUFNLFFBQVEsR0FBRyx1REFBdUQsQ0FBQTtJQUN4RSxNQUFNLEtBQUssR0FBRyxhQUFhLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxDQUFBO0lBQzNDLE1BQU0sR0FBRyxHQUFHLENBQUMsS0FBSyxLQUFLLElBQUksSUFBSSxLQUFLLENBQUMsS0FBSyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsR0FBRyxhQUFhLENBQUE7SUFFdEUsSUFBSTtRQUNGLE9BQU8sTUFBTSxDQUFDLEtBQUssQ0FBQyxjQUFjLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDeEMsS0FBQTtBQUFDLElBQUEsT0FBTyxLQUFLLEVBQUU7UUFDZCxNQUFNLElBQUksT0FBTyxDQUFDLDJDQUEyQyxFQUFFLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFBO0FBQ25GLEtBQUE7QUFDSDs7QUNETyxlQUFlLFVBQVUsQ0FBRSxRQUFrQyxFQUFBO0FBQ2xFLElBQUEsT0FBTyxHQUFHLENBQUMsTUFBTSxDQUFDLE1BQU0sR0FBRyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsRUFBRSxTQUFTLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7QUFDMUU7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7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
