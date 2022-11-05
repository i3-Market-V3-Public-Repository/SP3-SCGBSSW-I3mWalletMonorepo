import { ethers, utils } from 'ethers';
import _ from 'lodash';
import * as u8a from 'uint8arrays';
import { v4 } from 'uuid';
import { exchangeId, parseJwk, verifyKeyPair, jwsDecode } from '@i3m/non-repudiation-library';
import { validate } from 'jsonschema';
import { verifyJWT } from 'did-jwt';
import * as crypto from 'crypto';
import crypto__default from 'crypto';
import { digest } from 'object-sha';
import Debug from 'debug';
import { createAgent } from '@veramo/core';
import { AbstractDIDStore, DIDManager } from '@veramo/did-manager';
import { EthrDIDProvider } from '@veramo/did-provider-ethr';
import { WebDIDProvider } from '@veramo/did-provider-web';
import { AbstractKeyManagementSystem, AbstractKeyStore, KeyManager } from '@veramo/key-manager';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import { getResolver } from 'ethr-did-resolver';
import { getResolver as getResolver$1 } from 'web-did-resolver';
import { SelectiveDisclosure, SdrMessageHandler } from '@veramo/selective-disclosure';
import { MessageHandler } from '@veramo/message-handler';
import { JwtMessageHandler } from '@veramo/did-jwt';
import { CredentialIssuer, W3cMessageHandler } from '@veramo/credential-w3c';
import { mkdir, readFile, writeFile, rm } from 'fs/promises';
import { dirname } from 'path';

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

function getCredentialClaims(vc) {
    return Object.keys(vc.credentialSubject)
        .filter(claim => claim !== 'id');
}

var openapi = "3.0.3";
var info = {
	version: "2.1.2",
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
					example: "",
					allowEmptyValue: true,
					schema: {
						description: "a DID using the ethr resolver",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$",
						example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
					},
					description: "Filter the resource associated to an identity DID. Send empty value to get all the resources that are not associated to any identity."
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

// type Dict<T> = T & {
//   [key: string]: any | undefined
// }
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
        const isExpectedPayload = _.isEqual(expectedPayloadMerged, payload);
        if (!isExpectedPayload) {
            return {
                verification: 'failed',
                error: 'some or all the expected payload claims are not in the payload',
                decodedJwt
            };
        }
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

async function validateDataSharingAgreeementSchema(agreement) {
    const errors = [];
    const dataSharingAgreementSchema = spec.components.schemas.DataSharingAgreement;
    const validation = validate(agreement, dataSharingAgreementSchema);
    if (!validation.valid) {
        validation.errors.forEach(error => {
            errors.push(new Error(`[${error.property}]: ${error.message}`));
        });
    }
    return errors;
}
async function validateDataExchange(dataExchange) {
    const errors = [];
    try {
        const { id, ...dataExchangeButId } = dataExchange;
        if (id !== await exchangeId(dataExchangeButId)) {
            errors.push(new Error('Invalid dataExchange id'));
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
        errors.push(new Error('Invalid dataExchange'));
    }
    return errors;
}
async function validateDataExchangeAgreement(dea) {
    const errors = [];
    try {
        if (dea.orig !== await parseJwk(JSON.parse(dea.orig), true)) {
            errors.push(new Error('orig is not a valid stringified JWK with the claims sorted alphabetically: ' + dea.orig));
        }
    }
    catch (error) {
        errors.push(new Error('orig is not a valid stringified JWK with the claims sorted alphabetically'));
    }
    try {
        if (dea.dest !== await parseJwk(JSON.parse(dea.dest), true)) {
            errors.push(new Error('dest is not a valid stringified JWK with the claims sorted alphabetically: ' + dea.dest));
        }
    }
    catch (error) {
        errors.push(new Error('dest is not a valid stringified JWK with the claims sorted alphabetically'));
    }
    try {
        if (dea.ledgerContractAddress !== parseAddress(dea.ledgerContractAddress)) {
            errors.push(new Error('ledgerContractAddress is not a valid EIP-55 ethereum address: ' + dea.ledgerContractAddress));
        }
    }
    catch (error) {
        errors.push(new Error('ledgerContractAddress is not a valid EIP-55 ethereum address'));
    }
    try {
        if (dea.ledgerSignerAddress !== parseAddress(dea.ledgerSignerAddress)) {
            errors.push(new Error('ledgerSignerAddress is not a valid EIP-55 ethereum address: ' + dea.ledgerSignerAddress));
        }
    }
    catch (error) {
        errors.push(new Error('ledgerSignerAddress is not a valid EIP-55 ethereum address'));
    }
    return errors;
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

const jwkSecret = (secret = crypto__default.randomBytes(32)) => {
    const jwk = {
        kid: v4(),
        kty: 'oct',
        k: base64Url.encode(secret)
    };
    return jwk;
};

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

const contractValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const { dataSharingAgreement, keyPair } = resource.resource;
        // Verify schema
        const schemaValidationErrors = await validateDataSharingAgreeementSchema(dataSharingAgreement);
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
    'did:ethr:rinkeby': {
        network: 'rinkeby',
        rpcUrl: 'https://rpc.ankr.com/eth_rinkeby'
    },
    'did:ethr:i3m': {
        network: 'i3m',
        rpcUrl: 'http://95.211.3.250:8545'
    },
    'did:ethr:ganache': {
        network: 'ganache',
        rpcUrl: 'http://127.0.0.1:7545'
    }
};
class Veramo {
    constructor(store, keyWallet, providersData) {
        this.defaultKms = 'keyWallet';
        this.providersData = providersData;
        const ethrDidResolver = getResolver({
            networks: Object.values(this.providersData)
                .map(({ network, rpcUrl }) => ({
                name: network,
                rpcUrl
            }))
        });
        const webDidResolver = getResolver$1();
        const resolver = new Resolver({ ...ethrDidResolver, ...webDidResolver });
        this.providers = {
            'did:web': new WebDIDProvider({ defaultKms: this.defaultKms })
        };
        for (const [key, provider] of Object.entries(this.providersData)) {
            this.providers[key] = new EthrDIDProvider({
                defaultKms: this.defaultKms,
                ...provider
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
        const provider = new ethers.providers.JsonRpcProvider(providerData.rpcUrl);
        const response = await provider.sendTransaction(transaction);
        if (notifyUser) {
            const recipt = await response.wait();
            this.toast.show({
                message: 'Transaction properly executed!',
                type: 'success'
            });
            console.log(recipt);
        }
        else {
            console.log(response);
        }
    }
    async queryBalance() {
        const providerData = this.veramo.providersData[this.provider];
        if (providerData?.rpcUrl === undefined) {
            throw new WalletError('This provider has incomplete information, cannot execute transaction');
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
        const provider = new ethers.providers.JsonRpcProvider(providerData.rpcUrl);
        const address = ethers.utils.computeAddress(`0x${identity.keys[0].publicKeyHex}`);
        const balance = await provider.getBalance(address);
        const ether = ethers.utils.formatEther(balance);
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
        const provider = new ethers.providers.JsonRpcProvider(providerData.rpcUrl);
        const from = ethers.utils.computeAddress(`0x${transactionData.from.keys[0].publicKeyHex}`);
        const nonce = await provider.getTransactionCount(from, 'latest');
        const gasPrice = await provider.getGasPrice();
        const tx = {
            to: transactionData.to,
            value: ethers.utils.parseEther(transactionData.value),
            nonce,
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
     * Gets a resource stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.
     * @returns
     */
    async getResources() {
        return await this.store.get('resources', {});
    }
    async setResource(resource) {
        // If a parentResource is provided, do not allow to store the resource if it does not exist
        if (resource.parentResource !== undefined) {
            if (!await this.store.has(`resources.${resource.parentResource}`)) {
                debug$4('Failed to add resource since parent resource does not exist:\n' + JSON.stringify(resource, undefined, 2));
                throw new Error('Parent resource for provided resource does not exist');
            }
        }
        // If an identity is provided, do not allow to store the resource if it does not exist
        if (resource.identity !== undefined) {
            if (!await this.store.has(`identities.${resource.identity}`)) {
                debug$4('Failed to add resource since the identity is associated to does not exist:\n' + JSON.stringify(resource, undefined, 2));
                throw new Error('Identity for this resource does not exist');
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
        // TODO: Use wallet-protocol token to get the application name
        const consentText = `One application wants to get all the resources${extraConsent.length > 0 ? ' with ' + extraConsent.join(' and ') : ''}.\nDo you agree?`;
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
            message: 'Are you sure you want to delete this identity and all its associated resources (if any)? This action cannot be undone',
            acceptMsg: 'Delete',
            rejectMsg: 'Cancel'
        });
        if (confirmation === true) {
            await this.store.delete(`identities.${did}`);
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
        // Validate resource
        const validation = await this.resourceValidator.validate(resource, this.veramo);
        if (!validation.validated) {
            throw new Error(`Resource type ${resource.type} not supported`);
        }
        if (validation.errors.length > 0) {
            const errorMsg = [];
            validation.errors.forEach((error) => {
                errorMsg.push(error.message);
            });
            throw new WalletError('Resource has not been validated:\n' + errorMsg.join('\n'), { status: 400 });
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
            case 'Contract': {
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add a contract signed by ${resource.resource.dataSharingAgreement.parties.providerDid} and ${resource.resource.dataSharingAgreement.parties.consumerDid} into your wallet?`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
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
        const sdrMessage = await this.veramo.agent.handleMessage({
            raw: sdrRaw,
            save: false
        });
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

class TestStore {
    constructor() {
        this.model = this.defaultModel();
    }
    defaultModel() {
        return {
            resources: {},
            identities: {}
        };
    }
    get(key, defaultValue) {
        return _.get(this.model, key, defaultValue);
    }
    set(key, value) {
        _.set(this.model, key, value);
    }
    has(key) {
        return _.has(this.model, key);
    }
    delete(key) {
        this.model = _.omit(this.model, key);
    }
    clear() {
        this.model = this.defaultModel();
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

/**
 * A class that implements a storage in a file to be used by a wallet
 */
class FileStore {
    /**
     *
     * @param filepath an absolute path to the file that will be used to store wallet data
     * @param password if provided a key will be derived from the password and the store file will be encrypted
     */
    constructor(filepath, password) {
        const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
        if (!isNode) {
            throw new Error('FileStore can only be instantiated from Node.js');
        }
        this.filepath = filepath;
        this.password = password;
        this.init().catch(error => {
            throw error;
        });
    }
    kdf(password, salt) {
        return crypto.scryptSync(password, salt, 32);
    }
    async init() {
        await mkdir(dirname(this.filepath), { recursive: true }).catch();
        const model = await this.getModel();
        await this.setModel(model);
    }
    defaultModel() {
        return {
            resources: {},
            identities: {}
        };
    }
    async getModel() {
        let model = this.defaultModel();
        try {
            const fileBuf = await readFile(this.filepath);
            if (this.password === undefined) {
                model = JSON.parse(fileBuf.toString('utf8'));
            }
            else {
                model = await this.decryptModel(fileBuf);
            }
        }
        catch (error) { }
        return model;
    }
    async setModel(model) {
        if (this.password === undefined) {
            await writeFile(this.filepath, JSON.stringify(model), { encoding: 'utf8' });
        }
        else {
            await writeFile(this.filepath, await this.encryptModel(model));
        }
    }
    async encryptModel(model) {
        if (this.password === undefined) {
            throw new Error('For the store to be encrypted you must provide a password');
        }
        // random initialization vector
        const iv = crypto.randomBytes(16);
        // random salt
        const salt = crypto.randomBytes(64);
        // derive encryption key
        const key = this.kdf(this.password, salt);
        // AES 256 GCM Mode
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        // encrypt the given text
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(model), 'utf8'), cipher.final()]);
        // extract the auth tag
        const tag = cipher.getAuthTag();
        // generate output
        return Buffer.concat([salt, iv, tag, encrypted]);
    }
    async decryptModel(encryptedModel) {
        if (this.password === undefined) {
            throw new Error('For the store to be encrypted you must provide a password');
        }
        // extract all parts
        const buf = Buffer.from(encryptedModel);
        const salt = buf.slice(0, 64);
        const iv = buf.slice(64, 80);
        const tag = buf.slice(80, 96);
        const ciphertext = buf.slice(96);
        // derive encryption key
        const key = this.kdf(this.password, salt);
        // AES 256 GCM Mode
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        // decrypt, pass to JSON string, parse
        const decrypted = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
        return decrypted;
    }
    async get(key, defaultValue) {
        await this.init();
        const model = await this.getModel();
        return _.get(model, key, defaultValue);
    }
    async set(key, value) {
        await this.init();
        const model = await this.getModel();
        _.set(model, key, value);
        await this.setModel(model);
    }
    async has(key) {
        await this.init();
        const model = await this.getModel();
        return _.has(model, key);
    }
    async delete(key) {
        await this.init();
        let model = await this.getModel();
        model = _.omit(model, key);
        await this.setModel(model);
    }
    async clear() {
        await this.init();
        await rm(this.filepath);
    }
}

/**
 * A class that implements a storage in RAM to be used by a wallet
 */
class RamStore {
    constructor() {
        this.model = this.defaultModel();
    }
    defaultModel() {
        return {
            resources: {},
            identities: {}
        };
    }
    get(key, defaultValue) {
        return _.get(this.model, key, defaultValue);
    }
    set(key, value) {
        _.set(this.model, key, value);
    }
    has(key) {
        return _.has(this.model, key);
    }
    delete(key) {
        this.model = _.omit(this.model, key);
    }
    clear() {
        this.model = this.defaultModel();
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

export { BaseWallet, ConsoleToast, FileStore, NullDialog, RamStore, TestDialog, TestStore, TestToast, Veramo, WalletError, base64Url as base64url, didJwtVerify, getCredentialClaims, jwkSecret, parseAddress, parseHex, validateDataExchange, validateDataExchangeAgreement, validateDataSharingAgreeementSchema, verifyDataSharingAgreementSignature };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3V0aWxzL2Jhc2U2NHVybC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9qd3MudHMiLCIuLi8uLi9zcmMvdHMvZXJyb3JzLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2NyZWRlbnRpYWwtY2xhaW1zLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2RpZC1qd3QtdmVyaWZ5LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3BhcnNlQWRkcmVzcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kYXRhLXNoYXJpbmctYWdyZWVtZW50LXZhbGlkYXRpb24udHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZ2VuZXJhdGUtc2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3BhcnNlSGV4LnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL2NvbnRyYWN0LXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9kYXRhRXhjaGFuZ2UtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL25ycC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2Uvb2JqZWN0LXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS92Yy12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvcmVzb3VyY2UtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2Rpc3BsYXktZGlkLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9kaWQtd2FsbGV0LXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9rZXktd2FsbGV0LW1hbmFnZW1lbnQtc3lzdGVtLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9rZXktd2FsbGV0LXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby92ZXJhbW8udHMiLCIuLi8uLi9zcmMvdHMvd2FsbGV0L2Jhc2Utd2FsbGV0LnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3QvZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3Qvc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdGVzdC90b2FzdC50cyIsIi4uLy4uL3NyYy90cy9pbXBsL2RpYWxvZ3MvbnVsbC1kaWFsb2cudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9zdG9yZXMvZmlsZS1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy9pbXBsL3N0b3Jlcy9yYW0tc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC90b2FzdC9jb25zb2xlLXRvYXN0LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJiYXNlNjR1cmwiLCJjcnlwdG8iLCJ1dWlkdjQiLCJkZWJ1ZyIsImV0aHJEaWRHZXRSZXNvbHZlciIsIndlYkRpZEdldFJlc29sdmVyIiwidXVpZCIsImRpZEp3dFZlcmlmeUZuIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxNQUFNLE1BQU0sR0FBRyxDQUFDLEdBQVcsS0FBWTtJQUNyQyxPQUFPLEdBQUcsQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDekYsQ0FBQyxDQUFBO0FBRUQsTUFBTSxNQUFNLEdBQUcsQ0FBQyxHQUFXLEtBQVk7SUFDckMsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxRQUFRLENBQUMsQ0FBQTtBQUNuQyxDQUFDLENBQUE7QUFFRCxnQkFBZTtJQUNiLE1BQU07SUFDTixNQUFNO0NBQ1A7O0FDRkQ7Ozs7Ozs7QUFPRztTQUNhLFlBQVksQ0FBRSxNQUFjLEVBQUUsT0FBZSxFQUFFLFFBQXlCLEVBQUE7SUFDdEYsTUFBTSxhQUFhLEdBQUdBLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUE7SUFDckYsTUFBTSxjQUFjLEdBQUdBLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUE7QUFFdkYsSUFBQSxPQUFPLENBQUcsRUFBQSxhQUFhLENBQUksQ0FBQSxFQUFBLGNBQWMsRUFBRSxDQUFBO0FBQzdDLENBQUM7QUFFRDs7Ozs7O0FBTUc7QUFDYSxTQUFBLFNBQVMsQ0FBRSxHQUFXLEVBQUUsUUFBeUIsRUFBQTtJQUMvRCxNQUFNLEtBQUssR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLHdEQUF3RCxDQUFDLENBQUE7SUFDakYsSUFBSSxLQUFLLElBQUksSUFBSSxFQUFFO1FBQ2pCLE9BQU87QUFDTCxZQUFBLE1BQU0sRUFBRSxJQUFJLENBQUMsS0FBSyxDQUFDQSxTQUFTLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUNqRSxZQUFBLE9BQU8sRUFBRSxJQUFJLENBQUMsS0FBSyxDQUFDQSxTQUFTLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUNsRSxZQUFBLFNBQVMsRUFBRSxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQ25CLElBQUksRUFBRSxDQUFHLEVBQUEsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFBLENBQUEsRUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUUsQ0FBQTtTQUNoQyxDQUFBO0FBQ0YsS0FBQTtBQUNELElBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyx3Q0FBd0MsQ0FBQyxDQUFBO0FBQzNEOztBQ3BDTSxNQUFPLFdBQVksU0FBUSxLQUFLLENBQUE7SUFJcEMsV0FBYSxDQUFBLE9BQWUsRUFBRSxRQUFtQixFQUFBO1FBQy9DLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUNkLElBQUksQ0FBQyxJQUFJLEdBQUcsUUFBUSxFQUFFLElBQUksSUFBSSxDQUFDLENBQUE7UUFDL0IsSUFBSSxDQUFDLE1BQU0sR0FBRyxRQUFRLEVBQUUsTUFBTSxJQUFJLEdBQUcsQ0FBQTtLQUN0QztBQUNGOztBQ2JLLFNBQVUsbUJBQW1CLENBQUUsRUFBd0IsRUFBQTtBQUMzRCxJQUFBLE9BQU8sTUFBTSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsaUJBQWlCLENBQUM7U0FDckMsTUFBTSxDQUFDLEtBQUssSUFBSSxLQUFLLEtBQUssSUFBSSxDQUFDLENBQUE7QUFDcEM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7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
