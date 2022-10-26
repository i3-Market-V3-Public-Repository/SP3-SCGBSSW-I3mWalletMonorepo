'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var ethers = require('ethers');
var _ = require('lodash');
var u8a = require('uint8arrays');
var uuid = require('uuid');
var jsonschema = require('jsonschema');
var objectSha = require('object-sha');
var didJwt = require('did-jwt');
var crypto = require('crypto');
var core = require('@veramo/core');
var didManager = require('@veramo/did-manager');
var didProviderEthr = require('@veramo/did-provider-ethr');
var didProviderWeb = require('@veramo/did-provider-web');
var keyManager = require('@veramo/key-manager');
var didResolver$1 = require('@veramo/did-resolver');
var didResolver = require('did-resolver');
var ethrDidResolver = require('ethr-did-resolver');
var webDidResolver = require('web-did-resolver');
var selectiveDisclosure = require('@veramo/selective-disclosure');
var messageHandler = require('@veramo/message-handler');
var didJwt$1 = require('@veramo/did-jwt');
var credentialW3c = require('@veramo/credential-w3c');
var Debug = require('debug');
var promises = require('fs/promises');
var path = require('path');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

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

var ___default = /*#__PURE__*/_interopDefaultLegacy(_);
var u8a__namespace = /*#__PURE__*/_interopNamespace(u8a);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var crypto__namespace = /*#__PURE__*/_interopNamespace(crypto);
var Debug__default = /*#__PURE__*/_interopDefaultLegacy(Debug);

class WalletError extends Error {
    constructor(message, httpData) {
        super(message);
        this.code = httpData?.code ?? 1;
        this.status = httpData?.status ?? 500;
    }
}

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

function getCredentialClaims(vc) {
    return Object.keys(vc.credentialSubject)
        .filter(claim => claim !== 'id');
}

var openapi = "3.0.2";
var info = {
	version: "1.4.1",
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
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
										title: "DID",
										type: "string",
										pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
										title: "DID",
										type: "string",
										pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
						title: "DID",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
						title: "DID",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
											title: "Ethereum Address",
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
						title: "DID",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
							"Contract"
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
						title: "DID",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
												identity: {
													title: "DID",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
													example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
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
																	title: "DID",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
																	title: "DID",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
												identity: {
													title: "DID",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
													type: "string",
													example: "Contract",
													"enum": [
														"Contract"
													]
												},
												identity: {
													title: "DID",
													type: "string",
													pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
													example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
												},
												resource: {
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
																"dataOfferingVersion",
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
																	title: "DID",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																},
																consumerDid: {
																	title: "DID",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
																	title: "DID",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																},
																dest: {
																	title: "DID",
																	type: "string",
																	pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
																	example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
																},
																encAlg: {
																	type: "string"
																},
																signingAlg: {
																	type: "string"
																},
																hashAlg: {
																	type: "string"
																},
																ledgerContractAddress: {
																	title: "Ethereum Address",
																	type: "string",
																	pattern: "^0x([0-9A-Fa-f]){40}$",
																	example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																},
																ledgerSignerAddress: {
																	title: "Ethereum Address",
																	type: "string",
																	pattern: "^0x([0-9A-Fa-f]){40}$",
																	example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
																},
																pooToPorDelay: {
																	type: "integer"
																},
																pooToPopDelay: {
																	type: "integer"
																},
																pooToSecretDelay: {
																	type: "integer"
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
										identity: {
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
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
															title: "DID",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
															title: "DID",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
										identity: {
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
											type: "string",
											example: "Contract",
											"enum": [
												"Contract"
											]
										},
										identity: {
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										resource: {
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
														"dataOfferingVersion",
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
															title: "DID",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
															example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
														},
														consumerDid: {
															title: "DID",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
															title: "DID",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
															example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
														},
														dest: {
															title: "DID",
															type: "string",
															pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
															example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
														},
														encAlg: {
															type: "string"
														},
														signingAlg: {
															type: "string"
														},
														hashAlg: {
															type: "string"
														},
														ledgerContractAddress: {
															title: "Ethereum Address",
															type: "string",
															pattern: "^0x([0-9A-Fa-f]){40}$",
															example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
														},
														ledgerSignerAddress: {
															title: "Ethereum Address",
															type: "string",
															pattern: "^0x([0-9A-Fa-f]){40}$",
															example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
														},
														pooToPorDelay: {
															type: "integer"
														},
														pooToPopDelay: {
															type: "integer"
														},
														pooToSecretDelay: {
															type: "integer"
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
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
						title: "DID",
						type: "string",
						pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
							identity: {
								title: "DID",
								type: "string",
								pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
								example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
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
												title: "DID",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
												title: "DID",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
							identity: {
								title: "DID",
								type: "string",
								pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
								type: "string",
								example: "Contract",
								"enum": [
									"Contract"
								]
							},
							identity: {
								title: "DID",
								type: "string",
								pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
								example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
							},
							resource: {
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
											"dataOfferingVersion",
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
												title: "DID",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
												example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
											},
											consumerDid: {
												title: "DID",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
												title: "DID",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
												example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
											},
											dest: {
												title: "DID",
												type: "string",
												pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
												example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
											},
											encAlg: {
												type: "string"
											},
											signingAlg: {
												type: "string"
											},
											hashAlg: {
												type: "string"
											},
											ledgerContractAddress: {
												title: "Ethereum Address",
												type: "string",
												pattern: "^0x([0-9A-Fa-f]){40}$",
												example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
											},
											ledgerSignerAddress: {
												title: "Ethereum Address",
												type: "string",
												pattern: "^0x([0-9A-Fa-f]){40}$",
												example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
											},
											pooToPorDelay: {
												type: "integer"
											},
											pooToPopDelay: {
												type: "integer"
											},
											pooToSecretDelay: {
												type: "integer"
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
						identity: {
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
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
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
						identity: {
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
							type: "string",
							example: "Contract",
							"enum": [
								"Contract"
							]
						},
						identity: {
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						resource: {
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
										"dataOfferingVersion",
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
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										consumerDid: {
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										dest: {
											title: "DID",
											type: "string",
											pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
											example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
										},
										encAlg: {
											type: "string"
										},
										signingAlg: {
											type: "string"
										},
										hashAlg: {
											type: "string"
										},
										ledgerContractAddress: {
											title: "Ethereum Address",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										ledgerSignerAddress: {
											title: "Ethereum Address",
											type: "string",
											pattern: "^0x([0-9A-Fa-f]){40}$",
											example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
										},
										pooToPorDelay: {
											type: "integer"
										},
										pooToPopDelay: {
											type: "integer"
										},
										pooToSecretDelay: {
											type: "integer"
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
				identity: {
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
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
									title: "DID",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
									title: "DID",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
				identity: {
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
					type: "string",
					example: "Contract",
					"enum": [
						"Contract"
					]
				},
				identity: {
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				},
				resource: {
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
								"dataOfferingVersion",
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
									title: "DID",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
									example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
								},
								consumerDid: {
									title: "DID",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
									title: "DID",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
									example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
								},
								dest: {
									title: "DID",
									type: "string",
									pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
									example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
								},
								encAlg: {
									type: "string"
								},
								signingAlg: {
									type: "string"
								},
								hashAlg: {
									type: "string"
								},
								ledgerContractAddress: {
									title: "Ethereum Address",
									type: "string",
									pattern: "^0x([0-9A-Fa-f]){40}$",
									example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
								},
								ledgerSignerAddress: {
									title: "Ethereum Address",
									type: "string",
									pattern: "^0x([0-9A-Fa-f]){40}$",
									example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
								},
								pooToPorDelay: {
									type: "integer"
								},
								pooToPopDelay: {
									type: "integer"
								},
								pooToSecretDelay: {
									type: "integer"
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
				"Contract"
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
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
			title: "Ethereum Address",
			type: "string",
			pattern: "^0x([0-9A-Fa-f]){40}$",
			example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
		},
		did: {
			title: "DID",
			type: "string",
			pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
						title: "Ethereum Address",
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
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				},
				dest: {
					title: "DID",
					type: "string",
					pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
					example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
				},
				encAlg: {
					type: "string"
				},
				signingAlg: {
					type: "string"
				},
				hashAlg: {
					type: "string"
				},
				ledgerContractAddress: {
					title: "Ethereum Address",
					type: "string",
					pattern: "^0x([0-9A-Fa-f]){40}$",
					example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
				},
				ledgerSignerAddress: {
					title: "Ethereum Address",
					type: "string",
					pattern: "^0x([0-9A-Fa-f]){40}$",
					example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
				},
				pooToPorDelay: {
					type: "integer"
				},
				pooToPopDelay: {
					type: "integer"
				},
				pooToSecretDelay: {
					type: "integer"
				}
			}
		},
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
						"dataOfferingVersion",
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
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						consumerDid: {
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
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
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						dest: {
							title: "DID",
							type: "string",
							pattern: "^did:ethr:(\\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{22})?)$",
							example: "did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863"
						},
						encAlg: {
							type: "string"
						},
						signingAlg: {
							type: "string"
						},
						hashAlg: {
							type: "string"
						},
						ledgerContractAddress: {
							title: "Ethereum Address",
							type: "string",
							pattern: "^0x([0-9A-Fa-f]){40}$",
							example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
						},
						ledgerSignerAddress: {
							title: "Ethereum Address",
							type: "string",
							pattern: "^0x([0-9A-Fa-f]){40}$",
							example: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
						},
						pooToPorDelay: {
							type: "integer"
						},
						pooToPopDelay: {
							type: "integer"
						},
						pooToSecretDelay: {
							type: "integer"
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
        const expectedClaimsDict = expectedPayloadClaims;
        let error;
        for (const key in expectedClaimsDict) {
            if (payload[key] === undefined)
                error = `Expected key '${key}' not found in payload`;
            if (expectedClaimsDict[key] !== '' && objectSha.hashable(expectedClaimsDict[key]) !== objectSha.hashable(payload[key])) {
                error = `Payload's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedClaimsDict[key], undefined, 2)}`;
            }
        }
        if (error !== undefined) {
            return {
                verification: 'failed',
                error,
                decodedJwt
            };
        }
    }
    const resolver = { resolve: async (didUrl) => await veramo.agent.resolveDid({ didUrl }) };
    try {
        const verifiedJWT = await didJwt.verifyJWT(jwt, { resolver });
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

async function validateDataSharingAgreeementSchema(agreement) {
    const errors = [];
    const dataSharingAgreementSchema = spec.components.schemas.dataSharingAgreement;
    const validation = jsonschema.validate(agreement, dataSharingAgreementSchema);
    if (!validation.valid) {
        validation.errors.forEach(error => {
            errors.push(new Error(`[${error.property}]: ${error.message}`));
        });
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
            errors.push(new Error(`Signing DID does not match expected signer ${expectedSigner}`));
        }
    }
    else {
        errors.push(new Error(verifiedSignature.error));
    }
    return errors;
}

const jwkSecret = (secret = crypto__default["default"].randomBytes(32)) => {
    const jwk = {
        kid: uuid.v4(),
        kty: 'oct',
        k: base64Url.encode(secret)
    };
    return jwk;
};

const contractValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const schemaValidationErrors = await validateDataSharingAgreeementSchema(resource.resource);
        if (schemaValidationErrors.length > 0)
            return schemaValidationErrors;
        const provSigVerificationErrors = await verifyDataSharingAgreementSignature(resource.resource, veramo, 'provider');
        const consSigVerificationErrors = await verifyDataSharingAgreementSignature(resource.resource, veramo, 'consumer');
        provSigVerificationErrors.forEach(err => { errors.push(err); });
        consSigVerificationErrors.forEach(err => { errors.push(err); });
    }
    catch (error) {
        errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'));
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

const debug$6 = Debug__default["default"]('base-wallet:DidWalletStore');
class DIDWalletStore extends didManager.AbstractDIDStore {
    constructor(store) {
        super();
        this.store = store;
    }
    async import(args) {
        await this.store.set(`identities.${args.did}`, args);
        return true;
    }
    async get(args) {
        debug$6('Get ddo');
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

const debug$5 = Debug__default["default"]('base-wallet:KMS');
class KeyWalletManagementSystem extends keyManager.AbstractKeyManagementSystem {
    constructor(keyWallet) {
        super();
        this.keyWallet = keyWallet;
    }
    async createKey(args) {
        const type = args.type;
        // TODO: Add type to createAccountKeyPair function
        const kid = await this.keyWallet.createAccountKeyPair();
        debug$5('Import', args, kid);
        const publicKey = await this.keyWallet.getPublicKey(kid);
        if (!(publicKey instanceof Uint8Array)) {
            // TODO: convert from string
            throw Error('Only Uint8Array supported yet');
        }
        return {
            kid,
            type,
            publicKeyHex: ethers.ethers.utils.hexlify(publicKey).substr(2) // TODO: Remove 0x from the string
        };
    }
    async deleteKey(args) {
        await this.keyWallet.delete(args.kid);
        debug$5('Delete', args);
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
            message = u8a__namespace.fromString(data, 'utf-8');
        }
        else {
            message = data;
        }
        const messageDigest = ethers.ethers.utils.sha256(message);
        const messageDigestBytes = ethers.ethers.utils.arrayify(messageDigest);
        const signature = await this.keyWallet.signDigest(key.kid, messageDigestBytes);
        // Remove recovery parameter
        // (ethers adds a 2 byte recovery parameter at the end )
        const signatureBase64url = u8a__namespace.toString(signature.subarray(0, signature.length - 1), 'base64url');
        return signatureBase64url;
    }
    async signEthTX(args) {
        const { key, transaction } = args;
        const { v, r, s, from, ...tx } = transaction;
        const address = ethers.ethers.utils.computeAddress(`0x${key.publicKeyHex}`);
        if (address.toLowerCase() !== from.toLowerCase()) {
            throw new WalletError('Transaction from parammeter does not match the chosen key.');
        }
        const data = ethers.ethers.utils.serializeTransaction(tx);
        const messageDigest = ethers.ethers.utils.keccak256(data);
        const messageDigestBytes = ethers.ethers.utils.arrayify(messageDigest);
        const signature = await this.keyWallet.signDigest(args.key.kid, messageDigestBytes);
        const signedTransaction = ethers.ethers.utils.serializeTransaction(tx, signature);
        return signedTransaction;
    }
}

const debug$4 = Debug__default["default"]('base-wallet:KeyWalletStore');
class KeyWalletStore extends keyManager.AbstractKeyStore {
    constructor(keyWallet) {
        super();
        this.keyWallet = keyWallet;
    }
    async import(args) {
        debug$4('Import key. Doing nothing');
        return true;
    }
    async get(args) {
        // TODO: Add type to createAccountKeyPair function
        const kid = args.kid;
        debug$4('Get key', args, kid);
        const publicKey = await this.keyWallet.getPublicKey(kid);
        if (!(publicKey instanceof Uint8Array)) {
            throw Error('Only Uint8Array supported yet');
        }
        // TODO: Set type properly
        return {
            kid,
            type: 'Secp256k1',
            kms: 'keyWallet',
            publicKeyHex: ethers.utils.hexlify(publicKey).substr(2)
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
        const ethrDidResolver$1 = ethrDidResolver.getResolver({
            networks: Object.values(this.providersData)
                .map(({ network, rpcUrl }) => ({
                name: network,
                rpcUrl
            }))
        });
        const webDidResolver$1 = webDidResolver.getResolver();
        const resolver = new didResolver.Resolver({ ...ethrDidResolver$1, ...webDidResolver$1 });
        this.providers = {
            'did:web': new didProviderWeb.WebDIDProvider({ defaultKms: this.defaultKms })
        };
        for (const [key, provider] of Object.entries(this.providersData)) {
            this.providers[key] = new didProviderEthr.EthrDIDProvider({
                defaultKms: this.defaultKms,
                ...provider
            });
        }
        this.agent = core.createAgent({
            plugins: [
                new keyManager.KeyManager({
                    store: new KeyWalletStore(keyWallet),
                    kms: {
                        keyWallet: new KeyWalletManagementSystem(keyWallet)
                    }
                }),
                new didManager.DIDManager({
                    store: new DIDWalletStore(store),
                    defaultProvider: DEFAULT_PROVIDER,
                    providers: this.providers
                }),
                new credentialW3c.CredentialIssuer(),
                new selectiveDisclosure.SelectiveDisclosure(),
                // new DataStore(dbConnection),
                // new DataStoreORM(dbConnection),
                new messageHandler.MessageHandler({
                    messageHandlers: [
                        new didJwt$1.JwtMessageHandler(),
                        new selectiveDisclosure.SdrMessageHandler(),
                        new credentialW3c.W3cMessageHandler()
                    ]
                }),
                new didResolver$1.DIDResolverPlugin({
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
        const provider = new ethers.ethers.providers.JsonRpcProvider(providerData.rpcUrl);
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
        const provider = new ethers.ethers.providers.JsonRpcProvider(providerData.rpcUrl);
        const address = ethers.ethers.utils.computeAddress(`0x${identity.keys[0].publicKeyHex}`);
        const balance = await provider.getBalance(address);
        const ether = ethers.ethers.utils.formatEther(balance);
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
        const provider = new ethers.ethers.providers.JsonRpcProvider(providerData.rpcUrl);
        const from = ethers.ethers.utils.computeAddress(`0x${transactionData.from.keys[0].publicKeyHex}`);
        const nonce = await provider.getTransactionCount(from, 'latest');
        const gasPrice = await provider.getGasPrice();
        const tx = {
            to: transactionData.to,
            value: ethers.ethers.utils.parseEther(transactionData.value),
            nonce,
            gasLimit: ethers.ethers.utils.hexlify(100000),
            gasPrice
        };
        let transaction = '';
        if (transactionData.sign) {
            const response = await this.identitySign({ did: transactionData.from.did }, { type: 'Transaction', data: { ...tx, from } });
            transaction = response.signature;
        }
        else {
            transaction = ethers.ethers.utils.serializeTransaction(tx);
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
                    data: u8a__namespace.fromString(data.payload, 'base64url')
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
        const result = ___default["default"].pick(ddo, ['did', 'alias', 'provider']);
        let addresses = [];
        if (ddo.provider.startsWith('did:ethr')) {
            addresses = ddo.keys.map((key) => ethers.ethers.utils.computeAddress(`0x${key.publicKeyHex}`));
        }
        return { ...result, addresses };
    }
    async identityDeployTransaction(pathParameters, requestBody) {
        throw new Error('Method not implemented.');
    }
    /**
     * Gets a resource securey stored in the wallet's vaulr. It is the place where to find stored verfiable credentials.
     * @returns
     */
    async getResources() {
        return await this.store.get('resources', {});
    }
    /**
     * Gets a list of resources (currently just verifiable credentials) stored in the wallet's vault.
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
     * Deletes a given resource
     * @param id
     */
    async deleteResource(id) {
        const confirmation = await this.dialog.confirmation({
            message: 'Once deleted you will not be able to recover it. Proceed?',
            acceptMsg: 'Ok',
            rejectMsg: 'Cancel'
        });
        if (confirmation === true) {
            await this.store.delete(`resources.${id}`);
        }
    }
    /**
     * Deletes a given identity (DID)
     * @param did
     */
    async deleteIdentity(did) {
        const confirmation = await this.dialog.confirmation({
            message: 'Once deleted you will not be able to recover it. Proceed?',
            acceptMsg: 'Ok',
            rejectMsg: 'Cancel'
        });
        if (confirmation === true) {
            await this.store.delete(`identities.${did}`);
        }
    }
    /**
     * Securely stores in the wallet a new resource. Currently only supporting verifiable credentials, which are properly verified before storing them.
     *
     * @param requestBody
     * @returns and identifier of the created resource
     */
    async resourceCreate(requestBody) {
        const resource = requestBody;
        // Validate resource
        const validation = await this.resourceValidator.validate(resource, this.veramo);
        if (!validation.validated) {
            throw new Error(`Resource type ${resource.type} not supported`);
        }
        if (validation.errors.length > 0) {
            throw new WalletError('Wrong resource format', { status: 400 });
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
                    message: 'Do you want to add a contract into your wallet?'
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                break;
            }
            default:
                throw new Error('Resource type not supported');
        }
        // Store resource
        const resourceId = {
            id: uuid.v4()
        };
        const returnResource = Object.assign(resource, resourceId);
        await this.store.set(`resources.${resourceId.id}`, returnResource);
        return resourceId;
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

const debug$3 = Debug__default["default"]('base-wallet:TestDialog');
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
        return ___default["default"].get(this.model, key, defaultValue);
    }
    set(key, value) {
        ___default["default"].set(this.model, key, value);
    }
    has(key) {
        return ___default["default"].has(this.model, key);
    }
    delete(key) {
        this.model = ___default["default"].omit(this.model, key);
    }
    clear() {
        this.model = this.defaultModel();
    }
}

const debug$2 = Debug__default["default"]('base-wallet:TestDialog');
class TestToast {
    show(toast) {
        debug$2('Show message:', toast.message);
    }
    close(toastId) {
        debug$2('Close toast', toastId);
    }
}

const debug$1 = Debug__default["default"]('base-wallet:NullDialog');
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
        return crypto__namespace.scryptSync(password, salt, 32);
    }
    async init() {
        await promises.mkdir(path.dirname(this.filepath), { recursive: true }).catch();
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
            const fileBuf = await promises.readFile(this.filepath);
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
            await promises.writeFile(this.filepath, JSON.stringify(model), { encoding: 'utf8' });
        }
        else {
            await promises.writeFile(this.filepath, await this.encryptModel(model));
        }
    }
    async encryptModel(model) {
        if (this.password === undefined) {
            throw new Error('For the store to be encrypted you must provide a password');
        }
        // random initialization vector
        const iv = crypto__namespace.randomBytes(16);
        // random salt
        const salt = crypto__namespace.randomBytes(64);
        // derive encryption key
        const key = this.kdf(this.password, salt);
        // AES 256 GCM Mode
        const cipher = crypto__namespace.createCipheriv('aes-256-gcm', key, iv);
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
        const decipher = crypto__namespace.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        // decrypt, pass to JSON string, parse
        const decrypted = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
        return decrypted;
    }
    async get(key, defaultValue) {
        await this.init();
        const model = await this.getModel();
        return ___default["default"].get(model, key, defaultValue);
    }
    async set(key, value) {
        await this.init();
        const model = await this.getModel();
        ___default["default"].set(model, key, value);
        await this.setModel(model);
    }
    async has(key) {
        await this.init();
        const model = await this.getModel();
        return ___default["default"].has(model, key);
    }
    async delete(key) {
        await this.init();
        let model = await this.getModel();
        model = ___default["default"].omit(model, key);
        await this.setModel(model);
    }
    async clear() {
        await this.init();
        await promises.rm(this.filepath);
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
        return ___default["default"].get(this.model, key, defaultValue);
    }
    set(key, value) {
        ___default["default"].set(this.model, key, value);
    }
    has(key) {
        return ___default["default"].has(this.model, key);
    }
    delete(key) {
        this.model = ___default["default"].omit(this.model, key);
    }
    clear() {
        this.model = this.defaultModel();
    }
}

const debug = Debug__default["default"]('base-wallet:ConsoleToast');
class ConsoleToast {
    show(toast) {
        debug('Show message:', toast.message);
    }
    close(toastId) {
        debug('Close toast', toastId);
    }
}

exports.BaseWallet = BaseWallet;
exports.ConsoleToast = ConsoleToast;
exports.FileStore = FileStore;
exports.NullDialog = NullDialog;
exports.RamStore = RamStore;
exports.TestDialog = TestDialog;
exports.TestStore = TestStore;
exports.TestToast = TestToast;
exports.Veramo = Veramo;
exports.WalletError = WalletError;
exports.base64url = base64Url;
exports.didJwtVerify = didJwtVerify;
exports.getCredentialClaims = getCredentialClaims;
exports.jwkSecret = jwkSecret;
exports.validateDataSharingAgreeementSchema = validateDataSharingAgreeementSchema;
exports.verifyDataSharingAgreementSignature = verifyDataSharingAgreementSignature;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvYmFzZTY0dXJsLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2NyZWRlbnRpYWwtY2xhaW1zLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2p3cy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kaWQtand0LXZlcmlmeS50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kYXRhLXNoYXJpbmctYWdyZWVtZW50LXZhbGlkYXRpb24udHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZ2VuZXJhdGUtc2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL2NvbnRyYWN0LXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9vYmplY3QtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL3ZjLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9yZXNvdXJjZS12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZGlzcGxheS1kaWQudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2RpZC13YWxsZXQtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2tleS13YWxsZXQtbWFuYWdlbWVudC1zeXN0ZW0udHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2tleS13YWxsZXQtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL3ZlcmFtby50cyIsIi4uLy4uL3NyYy90cy93YWxsZXQvYmFzZS13YWxsZXQudHMiLCIuLi8uLi9zcmMvdHMvdGVzdC9kaWFsb2cudHMiLCIuLi8uLi9zcmMvdHMvdGVzdC9zdG9yZS50cyIsIi4uLy4uL3NyYy90cy90ZXN0L3RvYXN0LnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvZGlhbG9ncy9udWxsLWRpYWxvZy50cyIsIi4uLy4uL3NyYy90cy9pbXBsL3N0b3Jlcy9maWxlLXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvc3RvcmVzL3JhbS1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy9pbXBsL3RvYXN0L2NvbnNvbGUtdG9hc3QudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImJhc2U2NHVybCIsImhhc2hhYmxlIiwidmVyaWZ5SldUIiwidmFsaWRhdGUiLCJjcnlwdG8iLCJ1dWlkdjQiLCJkZWJ1ZyIsIkRlYnVnIiwiQWJzdHJhY3RESURTdG9yZSIsIkFic3RyYWN0S2V5TWFuYWdlbWVudFN5c3RlbSIsImV0aGVycyIsInU4YSIsIkFic3RyYWN0S2V5U3RvcmUiLCJ1dGlscyIsImV0aHJEaWRSZXNvbHZlciIsImV0aHJEaWRHZXRSZXNvbHZlciIsIndlYkRpZFJlc29sdmVyIiwid2ViRGlkR2V0UmVzb2x2ZXIiLCJSZXNvbHZlciIsIldlYkRJRFByb3ZpZGVyIiwiRXRockRJRFByb3ZpZGVyIiwiY3JlYXRlQWdlbnQiLCJLZXlNYW5hZ2VyIiwiRElETWFuYWdlciIsIkNyZWRlbnRpYWxJc3N1ZXIiLCJTZWxlY3RpdmVEaXNjbG9zdXJlIiwiTWVzc2FnZUhhbmRsZXIiLCJKd3RNZXNzYWdlSGFuZGxlciIsIlNkck1lc3NhZ2VIYW5kbGVyIiwiVzNjTWVzc2FnZUhhbmRsZXIiLCJESURSZXNvbHZlclBsdWdpbiIsIl8iLCJ1dWlkIiwiZGlkSnd0VmVyaWZ5Rm4iLCJta2RpciIsImRpcm5hbWUiLCJyZWFkRmlsZSIsIndyaXRlRmlsZSIsInJtIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBTU0sTUFBTyxXQUFZLFNBQVEsS0FBSyxDQUFBO0lBSXBDLFdBQWEsQ0FBQSxPQUFlLEVBQUUsUUFBbUIsRUFBQTtRQUMvQyxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7UUFDZCxJQUFJLENBQUMsSUFBSSxHQUFHLFFBQVEsRUFBRSxJQUFJLElBQUksQ0FBQyxDQUFBO1FBQy9CLElBQUksQ0FBQyxNQUFNLEdBQUcsUUFBUSxFQUFFLE1BQU0sSUFBSSxHQUFHLENBQUE7S0FDdEM7QUFDRjs7QUNmRCxNQUFNLE1BQU0sR0FBRyxDQUFDLEdBQVcsS0FBWTtJQUNyQyxPQUFPLEdBQUcsQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDekYsQ0FBQyxDQUFBO0FBRUQsTUFBTSxNQUFNLEdBQUcsQ0FBQyxHQUFXLEtBQVk7SUFDckMsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxRQUFRLENBQUMsQ0FBQTtBQUNuQyxDQUFDLENBQUE7QUFFRCxnQkFBZTtJQUNiLE1BQU07SUFDTixNQUFNO0NBQ1A7O0FDVEssU0FBVSxtQkFBbUIsQ0FBRSxFQUF3QixFQUFBO0FBQzNELElBQUEsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxpQkFBaUIsQ0FBQztTQUNyQyxNQUFNLENBQUMsS0FBSyxJQUFJLEtBQUssS0FBSyxJQUFJLENBQUMsQ0FBQTtBQUNwQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDSUE7Ozs7Ozs7QUFPRztTQUNhLFlBQVksQ0FBRSxNQUFjLEVBQUUsT0FBZSxFQUFFLFFBQXlCLEVBQUE7SUFDdEYsTUFBTSxhQUFhLEdBQUdBLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUE7SUFDckYsTUFBTSxjQUFjLEdBQUdBLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUE7QUFFdkYsSUFBQSxPQUFPLENBQUcsRUFBQSxhQUFhLENBQUksQ0FBQSxFQUFBLGNBQWMsRUFBRSxDQUFBO0FBQzdDLENBQUM7QUFFRDs7Ozs7O0FBTUc7QUFDYSxTQUFBLFNBQVMsQ0FBRSxHQUFXLEVBQUUsUUFBeUIsRUFBQTtJQUMvRCxNQUFNLEtBQUssR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLHdEQUF3RCxDQUFDLENBQUE7SUFDakYsSUFBSSxLQUFLLElBQUksSUFBSSxFQUFFO1FBQ2pCLE9BQU87QUFDTCxZQUFBLE1BQU0sRUFBRSxJQUFJLENBQUMsS0FBSyxDQUFDQSxTQUFTLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUNqRSxZQUFBLE9BQU8sRUFBRSxJQUFJLENBQUMsS0FBSyxDQUFDQSxTQUFTLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUNsRSxZQUFBLFNBQVMsRUFBRSxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQ25CLElBQUksRUFBRSxDQUFHLEVBQUEsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFBLENBQUEsRUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUUsQ0FBQTtTQUNoQyxDQUFBO0FBQ0YsS0FBQTtBQUNELElBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyx3Q0FBd0MsQ0FBQyxDQUFBO0FBQzNEOztBQ2hDQTs7Ozs7Ozs7QUFRSztBQUNFLGVBQWUsWUFBWSxDQUFFLEdBQVcsRUFBRSxNQUFjLEVBQUUscUJBQTJCLEVBQUE7QUFDMUYsSUFBQSxJQUFJLFVBQVUsQ0FBQTtJQUNkLElBQUk7QUFDRixRQUFBLFVBQVUsR0FBRyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDNUIsS0FBQTtBQUFDLElBQUEsT0FBTyxLQUFLLEVBQUU7UUFDZCxPQUFPO0FBQ0wsWUFBQSxZQUFZLEVBQUUsUUFBUTtBQUN0QixZQUFBLEtBQUssRUFBRSxvQkFBb0I7U0FDNUIsQ0FBQTtBQUNGLEtBQUE7QUFFRCxJQUFBLE1BQU0sT0FBTyxHQUFHLFVBQVUsQ0FBQyxPQUFPLENBQUE7SUFFbEMsSUFBSSxxQkFBcUIsS0FBSyxTQUFTLEVBQUU7UUFDdkMsTUFBTSxrQkFBa0IsR0FBdUMscUJBQXFCLENBQUE7QUFFcEYsUUFBQSxJQUFJLEtBQXlCLENBQUE7QUFDN0IsUUFBQSxLQUFLLE1BQU0sR0FBRyxJQUFJLGtCQUFrQixFQUFFO0FBQ3BDLFlBQUEsSUFBSSxPQUFPLENBQUMsR0FBRyxDQUFDLEtBQUssU0FBUztBQUFFLGdCQUFBLEtBQUssR0FBRyxDQUFBLGNBQUEsRUFBaUIsR0FBRyxDQUFBLHNCQUFBLENBQXdCLENBQUE7WUFDcEYsSUFBSSxrQkFBa0IsQ0FBQyxHQUFHLENBQUMsS0FBSyxFQUFFLElBQUlDLGtCQUFRLENBQUMsa0JBQWtCLENBQUMsR0FBRyxDQUFXLENBQUMsS0FBS0Esa0JBQVEsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFXLENBQUMsRUFBRTtBQUN0SCxnQkFBQSxLQUFLLEdBQUcsQ0FBQSxVQUFBLEVBQWEsR0FBRyxDQUFBLEVBQUEsRUFBSyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsRUFBRSxTQUFTLEVBQUUsQ0FBQyxDQUFDLENBQUEsOEJBQUEsRUFBaUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxrQkFBa0IsQ0FBQyxHQUFHLENBQUMsRUFBRSxTQUFTLEVBQUUsQ0FBQyxDQUFDLEVBQUUsQ0FBQTtBQUNoSyxhQUFBO0FBQ0YsU0FBQTtRQUNELElBQUksS0FBSyxLQUFLLFNBQVMsRUFBRTtZQUN2QixPQUFPO0FBQ0wsZ0JBQUEsWUFBWSxFQUFFLFFBQVE7Z0JBQ3RCLEtBQUs7Z0JBQ0wsVUFBVTthQUNYLENBQUE7QUFDRixTQUFBO0FBQ0YsS0FBQTtJQUNELE1BQU0sUUFBUSxHQUFHLEVBQUUsT0FBTyxFQUFFLE9BQU8sTUFBYyxLQUFLLE1BQU0sTUFBTSxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsRUFBRSxNQUFNLEVBQUUsQ0FBQyxFQUFFLENBQUE7SUFDakcsSUFBSTtRQUNGLE1BQU0sV0FBVyxHQUFHLE1BQU1DLGdCQUFTLENBQUMsR0FBRyxFQUFFLEVBQUUsUUFBUSxFQUFFLENBQUMsQ0FBQTtRQUN0RCxPQUFPO0FBQ0wsWUFBQSxZQUFZLEVBQUUsU0FBUztZQUN2QixVQUFVLEVBQUUsV0FBVyxDQUFDLE9BQU87U0FDaEMsQ0FBQTtBQUNGLEtBQUE7QUFBQyxJQUFBLE9BQU8sS0FBSyxFQUFFO1FBQ2QsSUFBSSxLQUFLLFlBQVksS0FBSyxFQUFFO1lBQzFCLE9BQU87QUFDTCxnQkFBQSxZQUFZLEVBQUUsUUFBUTtnQkFDdEIsS0FBSyxFQUFFLEtBQUssQ0FBQyxPQUFPO2dCQUNwQixVQUFVO2FBQ1gsQ0FBQTtBQUNGLFNBQUE7O0FBQU0sWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLG1DQUFtQyxDQUFDLENBQUE7QUFDNUQsS0FBQTtBQUNIOztBQzNETyxlQUFlLG1DQUFtQyxDQUFFLFNBQXVDLEVBQUE7SUFDaEcsTUFBTSxNQUFNLEdBQVksRUFBRSxDQUFBO0lBRTFCLE1BQU0sMEJBQTBCLEdBQUcsSUFBSSxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUMsb0JBQW9CLENBQUE7SUFDL0UsTUFBTSxVQUFVLEdBQUdDLG1CQUFRLENBQUMsU0FBUyxFQUFFLDBCQUFvQyxDQUFDLENBQUE7QUFDNUUsSUFBQSxJQUFJLENBQUMsVUFBVSxDQUFDLEtBQUssRUFBRTtBQUNyQixRQUFBLFVBQVUsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLEtBQUssSUFBRztBQUNoQyxZQUFBLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxLQUFLLENBQUMsQ0FBSSxDQUFBLEVBQUEsS0FBSyxDQUFDLFFBQVEsTUFBTSxLQUFLLENBQUMsT0FBTyxDQUFFLENBQUEsQ0FBQyxDQUFDLENBQUE7QUFDakUsU0FBQyxDQUFDLENBQUE7QUFDSCxLQUFBO0FBQ0QsSUFBQSxPQUFPLE1BQU0sQ0FBQTtBQUNmLENBQUM7QUFFTSxlQUFlLG1DQUFtQyxDQUFFLFNBQXVDLEVBQUUsTUFBK0IsRUFBRSxNQUErQixFQUFBO0lBQ2xLLE1BQU0sTUFBTSxHQUFZLEVBQUUsQ0FBQTtJQUUxQixNQUFNLEVBQUUsVUFBVSxFQUFFLEdBQUcscUJBQXFCLEVBQUUsR0FBRyxTQUFTLENBQUE7QUFDMUQsSUFBQSxJQUFJLGlCQUEwRCxDQUFBO0FBQzlELElBQUEsSUFBSSxjQUFzQixDQUFBO0lBQzFCLElBQUksTUFBTSxLQUFLLFVBQVUsRUFBRTtBQUN6QixRQUFBLGNBQWMsR0FBRyxxQkFBcUIsQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUFBO0FBQzFELFFBQUEsaUJBQWlCLEdBQUcsTUFBTSxZQUFZLENBQUMsVUFBVSxDQUFDLGlCQUFpQixFQUFFLE1BQU0sRUFBRSxxQkFBcUIsQ0FBQyxDQUFBO0FBQ3BHLEtBQUE7QUFBTSxTQUFBO0FBQ0wsUUFBQSxjQUFjLEdBQUcscUJBQXFCLENBQUMsT0FBTyxDQUFDLFdBQVcsQ0FBQTtBQUMxRCxRQUFBLGlCQUFpQixHQUFHLE1BQU0sWUFBWSxDQUFDLFVBQVUsQ0FBQyxpQkFBaUIsRUFBRSxNQUFNLEVBQUUscUJBQXFCLENBQUMsQ0FBQTtBQUNwRyxLQUFBO0FBRUQsSUFBQSxJQUFJLGlCQUFpQixDQUFDLFlBQVksS0FBSyxTQUFTLEVBQUU7QUFDaEQsUUFBQSxJQUFJLGlCQUFpQixDQUFDLFVBQVUsRUFBRSxHQUFHLEtBQUssY0FBYyxFQUFFO1lBQ3hELE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxLQUFLLENBQUMsQ0FBQSwyQ0FBQSxFQUE4QyxjQUFjLENBQUEsQ0FBRSxDQUFDLENBQUMsQ0FBQTtBQUN2RixTQUFBO0FBQ0YsS0FBQTtBQUFNLFNBQUE7UUFDTCxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUE7QUFDaEQsS0FBQTtBQUVELElBQUEsT0FBTyxNQUFNLENBQUE7QUFDZjs7QUNqQ00sTUFBQSxTQUFTLEdBQUcsQ0FBQyxNQUFpQixHQUFBQywwQkFBTSxDQUFDLFdBQVcsQ0FBQyxFQUFFLENBQUMsS0FBZTtBQUN2RSxJQUFBLE1BQU0sR0FBRyxHQUFjO1FBQ3JCLEdBQUcsRUFBRUMsT0FBTSxFQUFFO0FBQ2IsUUFBQSxHQUFHLEVBQUUsS0FBSztBQUNWLFFBQUEsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDO0tBQzVCLENBQUE7QUFDRCxJQUFBLE9BQU8sR0FBRyxDQUFBO0FBQ1o7O0FDYk8sTUFBTSxpQkFBaUIsR0FBZ0MsT0FBTyxRQUFRLEVBQUUsTUFBTSxLQUFJO0lBQ3ZGLE1BQU0sTUFBTSxHQUFZLEVBQUUsQ0FBQTtJQUUxQixJQUFJO1FBQ0YsTUFBTSxzQkFBc0IsR0FBRyxNQUFNLG1DQUFtQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUMzRixRQUFBLElBQUksc0JBQXNCLENBQUMsTUFBTSxHQUFHLENBQUM7QUFBRSxZQUFBLE9BQU8sc0JBQXNCLENBQUE7QUFFcEUsUUFBQSxNQUFNLHlCQUF5QixHQUFHLE1BQU0sbUNBQW1DLENBQUMsUUFBUSxDQUFDLFFBQVEsRUFBRSxNQUFNLEVBQUUsVUFBVSxDQUFDLENBQUE7QUFDbEgsUUFBQSxNQUFNLHlCQUF5QixHQUFHLE1BQU0sbUNBQW1DLENBQUMsUUFBUSxDQUFDLFFBQVEsRUFBRSxNQUFNLEVBQUUsVUFBVSxDQUFDLENBQUE7QUFFbEgsUUFBQSx5QkFBeUIsQ0FBQyxPQUFPLENBQUMsR0FBRyxJQUFNLEVBQUEsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQSxFQUFFLENBQUMsQ0FBQTtBQUM5RCxRQUFBLHlCQUF5QixDQUFDLE9BQU8sQ0FBQyxHQUFHLElBQU0sRUFBQSxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBLEVBQUUsQ0FBQyxDQUFBO0FBQy9ELEtBQUE7QUFBQyxJQUFBLE9BQU8sS0FBSyxFQUFFO1FBQ2QsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLEtBQUssQ0FBQyxPQUFPLEtBQUssS0FBSyxRQUFRLEdBQUcsS0FBSyxHQUFHLDBCQUEwQixDQUFDLENBQUMsQ0FBQTtBQUN2RixLQUFBO0FBRUQsSUFBQSxPQUFPLE1BQU0sQ0FBQTtBQUNmLENBQUM7O0FDbEJNLE1BQU0sZUFBZSxHQUE4QixPQUFPLFFBQVEsRUFBRSxNQUFNLEtBQUk7SUFDbkYsTUFBTSxNQUFNLEdBQVksRUFBRSxDQUFBO0FBRTFCLElBQUEsT0FBTyxNQUFNLENBQUE7QUFDZixDQUFDOztBQ0hNLE1BQU0sd0JBQXdCLEdBQTRDLE9BQU8sUUFBUSxFQUFFLE1BQU0sS0FBSTtJQUMxRyxNQUFNLE1BQU0sR0FBWSxFQUFFLENBQUE7SUFFMUIsTUFBTSxPQUFPLEdBQUcsUUFBUSxDQUFDLFFBQVEsQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFLENBQUE7QUFDdEQsSUFBQSxRQUFRLENBQUMsUUFBUSxHQUFHLE9BQU8sQ0FBQTs7QUFHM0IsSUFBQSxJQUFJLFFBQVEsQ0FBQyxRQUFRLEtBQUssU0FBUyxFQUFFO1FBQ25DLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxXQUFXLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQTtBQUNqQyxLQUFBO0FBQU0sU0FBQTtRQUNMLElBQUk7QUFDRixZQUFBLE1BQU0sTUFBTSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUM7QUFDL0IsZ0JBQUEsR0FBRyxFQUFFLFFBQVEsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLEdBQUc7QUFDakMsYUFBQSxDQUFDLENBQUE7QUFDSCxTQUFBO0FBQUMsUUFBQSxPQUFPLEVBQUUsRUFBRTtBQUNYLFlBQUEsTUFBTSxDQUFDLElBQUksQ0FBQyxFQUFXLENBQUMsQ0FBQTtBQUN6QixTQUFBO0FBQ0YsS0FBQTtBQUVELElBQUEsT0FBTyxNQUFNLENBQUE7QUFDZixDQUFDOztNQ1RZLGlCQUFpQixDQUFBO0FBRzVCLElBQUEsV0FBQSxHQUFBO0FBQ0UsUUFBQSxJQUFJLENBQUMsVUFBVSxHQUFHLEVBQUUsQ0FBQTtRQUNwQixJQUFJLENBQUMsY0FBYyxFQUFFLENBQUE7S0FDdEI7SUFFTyxjQUFjLEdBQUE7QUFDcEIsUUFBQSxJQUFJLENBQUMsWUFBWSxDQUFDLHNCQUFzQixFQUFFLHdCQUF3QixDQUFDLENBQUE7QUFDbkUsUUFBQSxJQUFJLENBQUMsWUFBWSxDQUFDLFFBQVEsRUFBRSxlQUFlLENBQUMsQ0FBQTtBQUM1QyxRQUFBLElBQUksQ0FBQyxZQUFZLENBQUMsVUFBVSxFQUFFLGlCQUFpQixDQUFDLENBQUE7S0FDakQ7SUFFTyxZQUFZLENBQUUsSUFBa0IsRUFBRSxTQUF5QixFQUFBO0FBQ2pFLFFBQUEsSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsR0FBRyxTQUFTLENBQUE7S0FDbEM7QUFFRCxJQUFBLE1BQU0sUUFBUSxDQUFFLFFBQWtCLEVBQUUsTUFBYyxFQUFBO0FBQ2hELFFBQUEsTUFBTSxVQUFVLEdBQWU7QUFDN0IsWUFBQSxTQUFTLEVBQUUsS0FBSztBQUNoQixZQUFBLE1BQU0sRUFBRSxFQUFFO1NBQ1gsQ0FBQTtRQUVELE1BQU0sU0FBUyxHQUFHLElBQUksQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFBO1FBQ2hELElBQUksU0FBUyxLQUFLLFNBQVMsRUFBRTtZQUMzQixVQUFVLENBQUMsTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLFFBQVEsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUNyRCxZQUFBLFVBQVUsQ0FBQyxTQUFTLEdBQUcsSUFBSSxDQUFBO0FBQzVCLFNBQUE7QUFFRCxRQUFBLE9BQU8sVUFBVSxDQUFBO0tBQ2xCO0FBQ0Y7O0FDOUNNLE1BQU0sVUFBVSxHQUFHLENBQUMsR0FBVyxLQUFZO0lBQ2hELE1BQU0sV0FBVyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDbEMsSUFBQSxJQUFJLFdBQVcsQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO0FBQzVCLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyxrQkFBa0IsQ0FBQyxDQUFBO0FBQ3BDLEtBQUE7QUFBTSxTQUFBLElBQUksV0FBVyxDQUFDLENBQUMsQ0FBQyxLQUFLLE1BQU0sRUFBRTtBQUNwQyxRQUFBLE1BQU0sT0FBTyxHQUFHLFdBQVcsQ0FBQyxHQUFHLEVBQVksQ0FBQTtRQUMzQyxXQUFXLENBQUMsSUFBSSxDQUFDLENBQUcsRUFBQSxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsTUFBTSxPQUFPLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUUsQ0FBQSxDQUFDLENBQUE7QUFDakYsUUFBQSxPQUFPLFdBQVcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDN0IsS0FBQTtBQUFNLFNBQUE7QUFDTCxRQUFBLE9BQU8sR0FBRyxDQUFBO0FBQ1gsS0FBQTtBQUNILENBQUM7O0FDTEQsTUFBTUMsT0FBSyxHQUFHQyx5QkFBSyxDQUFDLDRCQUE0QixDQUFDLENBQUE7QUFFNUIsTUFBQSxjQUEwQyxTQUFRQywyQkFBZ0IsQ0FBQTtBQUNyRixJQUFBLFdBQUEsQ0FBdUIsS0FBZSxFQUFBO0FBQ3BDLFFBQUEsS0FBSyxFQUFFLENBQUE7UUFEYyxJQUFLLENBQUEsS0FBQSxHQUFMLEtBQUssQ0FBVTtLQUVyQztJQUVELE1BQU0sTUFBTSxDQUFFLElBQWlCLEVBQUE7QUFDN0IsUUFBQSxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUEsV0FBQSxFQUFjLElBQUksQ0FBQyxHQUFHLENBQUEsQ0FBRSxFQUFFLElBQUksQ0FBQyxDQUFBO0FBQ3BELFFBQUEsT0FBTyxJQUFJLENBQUE7S0FDWjtJQUlELE1BQU0sR0FBRyxDQUFFLElBQVMsRUFBQTtRQUNsQkYsT0FBSyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0FBQ2hCLFFBQUEsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLENBQUE7QUFDbkQsUUFBQSxJQUFJLElBQUksQ0FBQyxHQUFHLEtBQUssU0FBUyxFQUFFO1lBQzFCLElBQUksSUFBSSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxTQUFTLEVBQUU7Z0JBQ2hDLE1BQU0sSUFBSSxXQUFXLENBQUMsZUFBZSxFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUE7QUFDeEQsYUFBQTtBQUNELFlBQUEsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQ3RCLFNBQUE7QUFBTSxhQUFBLElBQUksSUFBSSxDQUFDLEtBQUssS0FBSyxTQUFTLEVBQUU7WUFDbkMsTUFBTSxJQUFJLFdBQVcsQ0FBQywrQkFBK0IsRUFBRSxFQUFFLE1BQU0sRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFBO0FBQ3hFLFNBQUE7QUFBTSxhQUFBO1lBQ0wsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUM5QixZQUFBLElBQUksSUFBSSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7Z0JBQ3JCLE1BQU0sSUFBSSxXQUFXLENBQUMsZUFBZSxFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUE7QUFDeEQsYUFBQTtZQUNELE9BQU8sSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQ3JCLFNBQUE7S0FDRjtJQUVELE1BQU0sTUFBTSxDQUFFLElBQXFCLEVBQUE7QUFDakMsUUFBQSxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQWMsV0FBQSxFQUFBLElBQUksQ0FBQyxHQUFHLENBQUUsQ0FBQSxDQUFDLENBQUE7QUFDakQsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0lBRUQsTUFBTSxJQUFJLENBQUUsSUFBbUUsRUFBQTtRQUM3RSxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQyxDQUFBO1FBQy9DLElBQUksSUFBSSxLQUFLLFNBQVMsRUFBRTtBQUN0QixZQUFBLE9BQU8sRUFBRSxDQUFBO0FBQ1YsU0FBQTtBQUVELFFBQUEsTUFBTSxFQUFFLEtBQUssRUFBRSxRQUFRLEVBQUUsR0FBRyxJQUFJLENBQUE7QUFDaEMsUUFBQSxPQUFPLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxLQUFJO0FBQ3RDLFlBQUEsSUFBSSxLQUFLLEtBQUssU0FBUyxJQUFJLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxLQUFLLEtBQUssS0FBSyxFQUFFO0FBQ3BELGdCQUFBLE9BQU8sS0FBSyxDQUFBO0FBQ2IsYUFBQTtBQUNELFlBQUEsSUFBSSxRQUFRLEtBQUssU0FBUyxJQUFJLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxRQUFRLEtBQUssUUFBUSxFQUFFO0FBQzdELGdCQUFBLE9BQU8sS0FBSyxDQUFBO0FBQ2IsYUFBQTtBQUNELFlBQUEsT0FBTyxJQUFJLENBQUE7QUFDYixTQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsR0FBRyxJQUFJLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFBO0tBQ3pCO0FBQ0Y7O0FDckRELE1BQU1BLE9BQUssR0FBR0MseUJBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0FBRWpCLE1BQUEseUJBQTBCLFNBQVFFLHNDQUEyQixDQUFBO0FBQ2hGLElBQUEsV0FBQSxDQUF1QixTQUFvQixFQUFBO0FBQ3pDLFFBQUEsS0FBSyxFQUFFLENBQUE7UUFEYyxJQUFTLENBQUEsU0FBQSxHQUFULFNBQVMsQ0FBVztLQUUxQztJQUVELE1BQU0sU0FBUyxDQUFFLElBQW9DLEVBQUE7QUFDbkQsUUFBQSxNQUFNLElBQUksR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFBOztRQUV0QixNQUFNLEdBQUcsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsb0JBQW9CLEVBQUUsQ0FBQTtBQUN2RCxRQUFBSCxPQUFLLENBQUMsUUFBUSxFQUFFLElBQUksRUFBRSxHQUFHLENBQUMsQ0FBQTtRQUUxQixNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsWUFBWSxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQ3hELFFBQUEsSUFBSSxFQUFFLFNBQVMsWUFBWSxVQUFVLENBQUMsRUFBRTs7QUFFdEMsWUFBQSxNQUFNLEtBQUssQ0FBQywrQkFBK0IsQ0FBQyxDQUFBO0FBQzdDLFNBQUE7UUFFRCxPQUFPO1lBQ0wsR0FBRztZQUNILElBQUk7QUFDSixZQUFBLFlBQVksRUFBRUksYUFBTSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztTQUN4RCxDQUFBO0tBQ0Y7SUFFRCxNQUFNLFNBQVMsQ0FBRSxJQUFxQixFQUFBO1FBQ3BDLE1BQU0sSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQ3JDLFFBQUFKLE9BQUssQ0FBQyxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUE7QUFDckIsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0lBRUQsTUFBTSxVQUFVLENBQUUsSUFBd0QsRUFBQTtBQUN4RSxRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsc0NBQXNDLENBQUMsQ0FBQTtLQUN4RDtJQUVELE1BQU0sVUFBVSxDQUFFLElBQWlDLEVBQUE7QUFDakQsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHNDQUFzQyxDQUFDLENBQUE7S0FDeEQ7SUFFRCxNQUFNLE9BQU8sQ0FBRSxJQUE4QyxFQUFBO0FBQzNELFFBQUEsSUFBSSxPQUFtQixDQUFBO0FBQ3ZCLFFBQUEsTUFBTSxFQUFFLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRyxJQUFJLENBQUE7QUFFMUIsUUFBQSxJQUFJLE9BQU8sSUFBSSxLQUFLLFFBQVEsRUFBRTtZQUM1QixPQUFPLEdBQUdLLGNBQUcsQ0FBQyxVQUFVLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxDQUFBO0FBQ3hDLFNBQUE7QUFBTSxhQUFBO1lBQ0wsT0FBTyxHQUFHLElBQUksQ0FBQTtBQUNmLFNBQUE7UUFFRCxNQUFNLGFBQWEsR0FBR0QsYUFBTSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUE7UUFDbEQsTUFBTSxrQkFBa0IsR0FBR0EsYUFBTSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDL0QsUUFBQSxNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsa0JBQWtCLENBQUMsQ0FBQTs7O1FBSTlFLE1BQU0sa0JBQWtCLEdBQUdDLGNBQUcsQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsRUFBRSxXQUFXLENBQUMsQ0FBQTtBQUVqRyxRQUFBLE9BQU8sa0JBQWtCLENBQUE7S0FDMUI7SUFFRCxNQUFNLFNBQVMsQ0FBRSxJQUFxQyxFQUFBO0FBQ3BELFFBQUEsTUFBTSxFQUFFLEdBQUcsRUFBRSxXQUFXLEVBQUUsR0FBRyxJQUFJLENBQUE7QUFDakMsUUFBQSxNQUFNLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsSUFBSSxFQUFFLEdBQUcsRUFBRSxFQUFFLEdBQUcsV0FBVyxDQUFBO0FBQzVDLFFBQUEsTUFBTSxPQUFPLEdBQUdELGFBQU0sQ0FBQyxLQUFLLENBQUMsY0FBYyxDQUFDLENBQUEsRUFBQSxFQUFLLEdBQUcsQ0FBQyxZQUFZLENBQUEsQ0FBRSxDQUFDLENBQUE7UUFFcEUsSUFBSSxPQUFPLENBQUMsV0FBVyxFQUFFLEtBQUssSUFBSSxDQUFDLFdBQVcsRUFBRSxFQUFFO0FBQ2hELFlBQUEsTUFBTSxJQUFJLFdBQVcsQ0FBQyw0REFBNEQsQ0FBQyxDQUFBO0FBQ3BGLFNBQUE7UUFFRCxNQUFNLElBQUksR0FBR0EsYUFBTSxDQUFDLEtBQUssQ0FBQyxvQkFBb0IsQ0FBQyxFQUFFLENBQUMsQ0FBQTtRQUVsRCxNQUFNLGFBQWEsR0FBR0EsYUFBTSxDQUFDLEtBQUssQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDbEQsTUFBTSxrQkFBa0IsR0FBR0EsYUFBTSxDQUFDLEtBQUssQ0FBQyxRQUFRLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDL0QsUUFBQSxNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFLGtCQUFrQixDQUFDLENBQUE7QUFDbkYsUUFBQSxNQUFNLGlCQUFpQixHQUFHQSxhQUFNLENBQUMsS0FBSyxDQUFDLG9CQUFvQixDQUFDLEVBQUUsRUFBRSxTQUFTLENBQUMsQ0FBQTtBQUUxRSxRQUFBLE9BQU8saUJBQWlCLENBQUE7S0FDekI7QUFDRjs7QUNqRkQsTUFBTUosT0FBSyxHQUFHQyx5QkFBSyxDQUFDLDRCQUE0QixDQUFDLENBQUE7QUFFNUIsTUFBQSxjQUFlLFNBQVFLLDJCQUFnQixDQUFBO0FBQzFELElBQUEsV0FBQSxDQUF1QixTQUFvQixFQUFBO0FBQ3pDLFFBQUEsS0FBSyxFQUFFLENBQUE7UUFEYyxJQUFTLENBQUEsU0FBQSxHQUFULFNBQVMsQ0FBVztLQUUxQztJQUVELE1BQU0sTUFBTSxDQUFFLElBQVUsRUFBQTtRQUN0Qk4sT0FBSyxDQUFDLDJCQUEyQixDQUFDLENBQUE7QUFDbEMsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0lBRUQsTUFBTSxHQUFHLENBQUUsSUFBcUIsRUFBQTs7QUFFOUIsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFBO0FBQ3BCLFFBQUFBLE9BQUssQ0FBQyxTQUFTLEVBQUUsSUFBSSxFQUFFLEdBQUcsQ0FBQyxDQUFBO1FBRTNCLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLFNBQVMsQ0FBQyxZQUFZLENBQUMsR0FBRyxDQUFDLENBQUE7QUFDeEQsUUFBQSxJQUFJLEVBQUUsU0FBUyxZQUFZLFVBQVUsQ0FBQyxFQUFFO0FBQ3RDLFlBQUEsTUFBTSxLQUFLLENBQUMsK0JBQStCLENBQUMsQ0FBQTtBQUM3QyxTQUFBOztRQUdELE9BQU87WUFDTCxHQUFHO0FBQ0gsWUFBQSxJQUFJLEVBQUUsV0FBVztBQUNqQixZQUFBLEdBQUcsRUFBRSxXQUFXO1lBQ2hCLFlBQVksRUFBRU8sWUFBSyxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO1NBQ2pELENBQUE7S0FDRjtJQUVELE1BQU0sTUFBTSxDQUFFLElBQXFCLEVBQUE7QUFDakMsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0FBQ0Y7O0FDekNEO0FBd0NPLE1BQU0sZ0JBQWdCLEdBQUcsY0FBYyxDQUFBO0FBQ3ZDLE1BQU0sc0JBQXNCLEdBQUc7QUFDcEMsSUFBQSxrQkFBa0IsRUFBRTtBQUNsQixRQUFBLE9BQU8sRUFBRSxTQUFTO0FBQ2xCLFFBQUEsTUFBTSxFQUFFLGtDQUFrQztBQUMzQyxLQUFBO0FBQ0QsSUFBQSxjQUFjLEVBQUU7QUFDZCxRQUFBLE9BQU8sRUFBRSxLQUFLO0FBQ2QsUUFBQSxNQUFNLEVBQUUsMEJBQTBCO0FBQ25DLEtBQUE7QUFDRCxJQUFBLGtCQUFrQixFQUFFO0FBQ2xCLFFBQUEsT0FBTyxFQUFFLFNBQVM7QUFDbEIsUUFBQSxNQUFNLEVBQUUsdUJBQXVCO0FBQ2hDLEtBQUE7Q0FDRixDQUFBO0FBRWEsTUFBTyxNQUFNLENBQUE7QUFNekIsSUFBQSxXQUFBLENBQWEsS0FBZSxFQUFFLFNBQW9CLEVBQUUsYUFBMkMsRUFBQTtRQUh4RixJQUFVLENBQUEsVUFBQSxHQUFHLFdBQVcsQ0FBQTtBQUk3QixRQUFBLElBQUksQ0FBQyxhQUFhLEdBQUcsYUFBYSxDQUFBO1FBRWxDLE1BQU1DLGlCQUFlLEdBQUdDLDJCQUFrQixDQUFDO1lBQ3pDLFFBQVEsRUFBRSxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUM7aUJBQ3hDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsT0FBTyxFQUFFLE1BQU0sRUFBRSxNQUFNO0FBQzdCLGdCQUFBLElBQUksRUFBRSxPQUFPO2dCQUNiLE1BQU07QUFDUCxhQUFBLENBQUMsQ0FBQztBQUNOLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxNQUFNQyxnQkFBYyxHQUFHQywwQkFBaUIsRUFBRSxDQUFBO0FBRTFDLFFBQUEsTUFBTSxRQUFRLEdBQUcsSUFBSUMsb0JBQVEsQ0FBQyxFQUFFLEdBQUdKLGlCQUFlLEVBQUUsR0FBR0UsZ0JBQXFCLEVBQUUsQ0FBQyxDQUFBO1FBRS9FLElBQUksQ0FBQyxTQUFTLEdBQUc7WUFDZixTQUFTLEVBQUUsSUFBSUcsNkJBQWMsQ0FBQyxFQUFFLFVBQVUsRUFBRSxJQUFJLENBQUMsVUFBVSxFQUFFLENBQUM7U0FDL0QsQ0FBQTtBQUNELFFBQUEsS0FBSyxNQUFNLENBQUMsR0FBRyxFQUFFLFFBQVEsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxFQUFFO1lBQ2hFLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSUMsK0JBQWUsQ0FBQztnQkFDeEMsVUFBVSxFQUFFLElBQUksQ0FBQyxVQUFVO0FBQzNCLGdCQUFBLEdBQUcsUUFBUTtBQUNaLGFBQUEsQ0FBQyxDQUFBO0FBQ0gsU0FBQTtBQUVELFFBQUEsSUFBSSxDQUFDLEtBQUssR0FBR0MsZ0JBQVcsQ0FBWTtBQUNsQyxZQUFBLE9BQU8sRUFBRTtBQUNQLGdCQUFBLElBQUlDLHFCQUFVLENBQUM7QUFDYixvQkFBQSxLQUFLLEVBQUUsSUFBSSxjQUFjLENBQUMsU0FBUyxDQUFDO0FBQ3BDLG9CQUFBLEdBQUcsRUFBRTtBQUNILHdCQUFBLFNBQVMsRUFBRSxJQUFJLHlCQUF5QixDQUFDLFNBQVMsQ0FBQztBQUNwRCxxQkFBQTtpQkFDRixDQUFDO0FBQ0YsZ0JBQUEsSUFBSUMscUJBQVUsQ0FBQztBQUNiLG9CQUFBLEtBQUssRUFBRSxJQUFJLGNBQWMsQ0FBSSxLQUFLLENBQUM7QUFDbkMsb0JBQUEsZUFBZSxFQUFFLGdCQUFnQjtvQkFDakMsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTO2lCQUMxQixDQUFDO0FBQ0YsZ0JBQUEsSUFBSUMsOEJBQWdCLEVBQUU7QUFDdEIsZ0JBQUEsSUFBSUMsdUNBQW1CLEVBQUU7OztBQUd6QixnQkFBQSxJQUFJQyw2QkFBYyxDQUFDO0FBQ2pCLG9CQUFBLGVBQWUsRUFBRTtBQUNmLHdCQUFBLElBQUlDLDBCQUFpQixFQUFFO0FBQ3ZCLHdCQUFBLElBQUlDLHFDQUFpQixFQUFFO0FBQ3ZCLHdCQUFBLElBQUlDLCtCQUFpQixFQUFFO0FBQ3hCLHFCQUFBO2lCQUNGLENBQUM7QUFDRixnQkFBQSxJQUFJQywrQkFBaUIsQ0FBQztvQkFDcEIsUUFBUTtpQkFDVCxDQUFDO0FBQ0gsYUFBQTtBQUNGLFNBQUEsQ0FBQyxDQUFBO0tBQ0g7QUFFRCxJQUFBLFdBQVcsQ0FBRSxJQUFZLEVBQUE7UUFDdkIsTUFBTSxRQUFRLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUNyQyxJQUFJLFFBQVEsS0FBSyxTQUFTO0FBQUUsWUFBQSxNQUFNLElBQUksV0FBVyxDQUFDLHNDQUFzQyxHQUFHLElBQUksQ0FBQyxDQUFBO0FBQ2hHLFFBQUEsT0FBTyxRQUFRLENBQUE7S0FDaEI7QUFDRjs7TUMzRFksVUFBVSxDQUFBO0FBY3JCLElBQUEsV0FBQSxDQUFhLElBQWEsRUFBQTtBQUN4QixRQUFBLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQTtBQUN6QixRQUFBLElBQUksQ0FBQyxLQUFLLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQTtBQUN2QixRQUFBLElBQUksQ0FBQyxLQUFLLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQTtBQUN2QixRQUFBLElBQUksQ0FBQyxTQUFTLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FBQTtBQUMvQixRQUFBLElBQUksQ0FBQyxpQkFBaUIsR0FBRyxJQUFJLGlCQUFpQixFQUFFLENBQUE7UUFDaEQsSUFBSSxDQUFDLFFBQVEsR0FBRyxJQUFJLENBQUMsUUFBUSxJQUFJLGdCQUFnQixDQUFBO1FBQ2pELElBQUksQ0FBQyxhQUFhLEdBQUcsSUFBSSxDQUFDLGFBQWEsSUFBSSxzQkFBc0IsQ0FBQTs7QUFHakUsUUFBQSxJQUFJLENBQUMsTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLElBQUksQ0FBQyxLQUFLLEVBQUUsSUFBSSxDQUFDLFNBQVMsRUFBRSxJQUFJLENBQUMsYUFBYSxDQUFDLENBQUE7S0FDekU7QUFFRCxJQUFBLE1BQU0sa0JBQWtCLENBQUUsT0FBQSxHQUE4QixFQUFFLEVBQUE7QUFDeEQsUUFBQSxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDN0QsUUFBQSxJQUFJLFlBQVksRUFBRSxNQUFNLEtBQUssU0FBUyxFQUFFO0FBQ3RDLFlBQUEsTUFBTSxJQUFJLFdBQVcsQ0FBQyxzRUFBc0UsQ0FBQyxDQUFBO0FBQzlGLFNBQUE7QUFDRCxRQUFBLElBQUksV0FBVyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUE7QUFDckMsUUFBQSxNQUFNLFVBQVUsR0FBRyxPQUFPLENBQUMsVUFBVSxJQUFJLElBQUksQ0FBQTtRQUU3QyxJQUFJLFdBQVcsS0FBSyxTQUFTLEVBQUU7QUFDN0IsWUFBQSxXQUFXLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQztBQUNuQyxnQkFBQSxLQUFLLEVBQUUscUJBQXFCO0FBQzVCLGdCQUFBLE9BQU8sRUFBRSwyQ0FBMkM7QUFDckQsYUFBQSxDQUFDLENBQUE7QUFDSCxTQUFBO1FBQ0QsSUFBSSxXQUFXLEtBQUssU0FBUyxJQUFJLENBQUMsV0FBVyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsRUFBRTtZQUM5RCxNQUFNLElBQUksV0FBVyxDQUFDLENBQUEsb0JBQUEsRUFBdUIsV0FBVyxJQUFJLGFBQWEsQ0FBRSxDQUFBLENBQUMsQ0FBQTtBQUM3RSxTQUFBO0FBRUQsUUFBQSxNQUFNLFFBQVEsR0FBRyxJQUFJcEIsYUFBTSxDQUFDLFNBQVMsQ0FBQyxlQUFlLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQzFFLE1BQU0sUUFBUSxHQUFHLE1BQU0sUUFBUSxDQUFDLGVBQWUsQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUM1RCxRQUFBLElBQUksVUFBVSxFQUFFO0FBQ2QsWUFBQSxNQUFNLE1BQU0sR0FBRyxNQUFNLFFBQVEsQ0FBQyxJQUFJLEVBQUUsQ0FBQTtBQUNwQyxZQUFBLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO0FBQ2QsZ0JBQUEsT0FBTyxFQUFFLGdDQUFnQztBQUN6QyxnQkFBQSxJQUFJLEVBQUUsU0FBUztBQUNoQixhQUFBLENBQUMsQ0FBQTtBQUNGLFlBQUEsT0FBTyxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUNwQixTQUFBO0FBQU0sYUFBQTtBQUNMLFlBQUEsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUN0QixTQUFBO0tBQ0Y7QUFFRCxJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0FBQzdELFFBQUEsSUFBSSxZQUFZLEVBQUUsTUFBTSxLQUFLLFNBQVMsRUFBRTtBQUN0QyxZQUFBLE1BQU0sSUFBSSxXQUFXLENBQUMsc0VBQXNFLENBQUMsQ0FBQTtBQUM5RixTQUFBO1FBRUQsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxjQUFjLEVBQUUsQ0FBQTtRQUMzRCxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDO0FBQ3hDLFlBQUEsT0FBTyxFQUFFLHVDQUF1QztBQUNoRCxZQUFBLE1BQU0sRUFBRSxVQUFVO0FBQ2xCLFlBQUEsT0FBTyxDQUFFLFFBQVEsRUFBQTtBQUNmLGdCQUFBLE9BQU8sUUFBUSxDQUFDLEtBQUssSUFBSSxRQUFRLENBQUMsR0FBRyxDQUFBO2FBQ3RDO0FBQ0YsU0FBQSxDQUFDLENBQUE7UUFDRixJQUFJLFFBQVEsS0FBSyxTQUFTLEVBQUU7QUFDMUIsWUFBQSxNQUFNLElBQUksV0FBVyxDQUFDLHlCQUF5QixDQUFDLENBQUE7QUFDakQsU0FBQTtBQUVELFFBQUEsTUFBTSxRQUFRLEdBQUcsSUFBSUEsYUFBTSxDQUFDLFNBQVMsQ0FBQyxlQUFlLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQzFFLFFBQUEsTUFBTSxPQUFPLEdBQUdBLGFBQU0sQ0FBQyxLQUFLLENBQUMsY0FBYyxDQUFDLENBQUEsRUFBQSxFQUFLLFFBQVEsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsWUFBWSxDQUFBLENBQUUsQ0FBQyxDQUFBO1FBQ2pGLE1BQU0sT0FBTyxHQUFHLE1BQU0sUUFBUSxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUNsRCxNQUFNLEtBQUssR0FBR0EsYUFBTSxDQUFDLEtBQUssQ0FBQyxXQUFXLENBQUMsT0FBTyxDQUFDLENBQUE7QUFFL0MsUUFBQSxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQztBQUNkLFlBQUEsT0FBTyxFQUFFLFNBQVM7QUFDbEIsWUFBQSxPQUFPLEVBQUUsQ0FBQSxhQUFBLEVBQWdCLE9BQU8sQ0FBQSxxQkFBQSxFQUF3QixLQUFLLENBQU8sS0FBQSxDQUFBO0FBQ3BFLFlBQUEsSUFBSSxFQUFFLFNBQVM7QUFDaEIsU0FBQSxDQUFDLENBQUE7S0FDSDtBQUVELElBQUEsTUFBTSxpQkFBaUIsR0FBQTtBQUNyQixRQUFBLE1BQU0sWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUM3RCxRQUFBLElBQUksWUFBWSxFQUFFLE1BQU0sS0FBSyxTQUFTLEVBQUU7QUFDdEMsWUFBQSxNQUFNLElBQUksV0FBVyxDQUFDLHNFQUFzRSxDQUFDLENBQUE7QUFDOUYsU0FBQTtRQUVELE1BQU0sVUFBVSxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsY0FBYyxFQUFFLENBQUE7UUFDM0QsTUFBTSxlQUFlLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBa0I7QUFDOUQsWUFBQSxLQUFLLEVBQUUsb0JBQW9CO0FBQzNCLFlBQUEsV0FBVyxFQUFFO0FBQ1gsZ0JBQUEsSUFBSSxFQUFFO0FBQ0osb0JBQUEsSUFBSSxFQUFFLFFBQVE7QUFDZCxvQkFBQSxPQUFPLEVBQUUsMkJBQTJCO0FBQ3BDLG9CQUFBLE1BQU0sRUFBRSxVQUFVO0FBQ2xCLG9CQUFBLE9BQU8sQ0FBRSxRQUFRLEVBQUE7QUFDZix3QkFBQSxPQUFPLFFBQVEsQ0FBQyxLQUFLLElBQUksV0FBVyxDQUFBO3FCQUNyQztBQUNGLGlCQUFBO2dCQUNELEVBQUUsRUFBRSxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsT0FBTyxFQUFFLDhCQUE4QixFQUFFO2dCQUM3RCxLQUFLLEVBQUUsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLE9BQU8sRUFBRSxxQkFBcUIsRUFBRTtBQUN2RCxnQkFBQSxJQUFJLEVBQUUsRUFBRSxJQUFJLEVBQUUsY0FBYyxFQUFFLE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFBRSxRQUFRLEVBQUU7QUFDekcsYUFBQTtZQUNELEtBQUssRUFBRSxDQUFDLE1BQU0sRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLE1BQU0sQ0FBQztBQUN2QyxTQUFBLENBQUMsQ0FBQTtRQUNGLElBQUksZUFBZSxLQUFLLFNBQVMsRUFBRTtBQUNqQyxZQUFBLE1BQU0sSUFBSSxXQUFXLENBQUMsOEJBQThCLENBQUMsQ0FBQTtBQUN0RCxTQUFBO0FBRUQsUUFBQSxNQUFNLFFBQVEsR0FBRyxJQUFJQSxhQUFNLENBQUMsU0FBUyxDQUFDLGVBQWUsQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLENBQUE7UUFDMUUsTUFBTSxJQUFJLEdBQUdBLGFBQU0sQ0FBQyxLQUFLLENBQUMsY0FBYyxDQUFDLENBQUssRUFBQSxFQUFBLGVBQWUsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLFlBQVksQ0FBRSxDQUFBLENBQUMsQ0FBQTtRQUMxRixNQUFNLEtBQUssR0FBRyxNQUFNLFFBQVEsQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLEVBQUUsUUFBUSxDQUFDLENBQUE7QUFDaEUsUUFBQSxNQUFNLFFBQVEsR0FBRyxNQUFNLFFBQVEsQ0FBQyxXQUFXLEVBQUUsQ0FBQTtBQUU3QyxRQUFBLE1BQU0sRUFBRSxHQUFHO1lBQ1QsRUFBRSxFQUFFLGVBQWUsQ0FBQyxFQUFFO1lBQ3RCLEtBQUssRUFBRUEsYUFBTSxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsZUFBZSxDQUFDLEtBQUssQ0FBQztZQUNyRCxLQUFLO1lBQ0wsUUFBUSxFQUFFQSxhQUFNLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUM7WUFDdEMsUUFBUTtTQUNULENBQUE7UUFFRCxJQUFJLFdBQVcsR0FBVyxFQUFFLENBQUE7UUFDNUIsSUFBSSxlQUFlLENBQUMsSUFBSSxFQUFFO0FBQ3hCLFlBQUEsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsWUFBWSxDQUFDLEVBQUUsR0FBRyxFQUFFLGVBQWUsQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLEVBQUUsRUFBRSxJQUFJLEVBQUUsYUFBYSxFQUFFLElBQUksRUFBRSxFQUFFLEdBQUcsRUFBRSxFQUFFLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQTtBQUMzSCxZQUFBLFdBQVcsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFBO0FBQ2pDLFNBQUE7QUFBTSxhQUFBO1lBQ0wsV0FBVyxHQUFHQSxhQUFNLENBQUMsS0FBSyxDQUFDLG9CQUFvQixDQUFDLEVBQUUsQ0FBQyxDQUFBO0FBQ3BELFNBQUE7QUFFRCxRQUFBLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUM7WUFDN0IsT0FBTyxFQUFFLENBQTBFLHVFQUFBLEVBQUEsV0FBVyxDQUFxQixtQkFBQSxDQUFBO0FBQ25ILFlBQUEsU0FBUyxFQUFFLFVBQVU7QUFDckIsWUFBQSxTQUFTLEVBQUUsRUFBRTtBQUNkLFNBQUEsQ0FBQyxDQUFBO0tBQ0g7QUFFRCxJQUFBLE1BQU0sSUFBSSxHQUFBO1FBQ1IsTUFBTSxZQUFZLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQztBQUNsRCxZQUFBLEtBQUssRUFBRSxnQkFBZ0I7QUFDdkIsWUFBQSxPQUFPLEVBQUUsOENBQThDO0FBQ3ZELFlBQUEsU0FBUyxFQUFFLFFBQVE7QUFDbkIsWUFBQSxTQUFTLEVBQUUsUUFBUTtBQUNwQixTQUFBLENBQUMsQ0FBQTtRQUNGLElBQUksWUFBWSxLQUFLLElBQUksRUFBRTtBQUN6QixZQUFBLE1BQU0sSUFBSSxXQUFXLENBQUMsNEJBQTRCLENBQUMsQ0FBQTtBQUNwRCxTQUFBO1FBRUQsTUFBTSxPQUFPLENBQUMsR0FBRyxDQUFDO0FBQ2hCLFlBQUEsSUFBSSxDQUFDLEtBQUssQ0FBQyxLQUFLLEVBQUU7QUFDbEIsWUFBQSxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksRUFBRTtBQUN0QixTQUFBLENBQUMsQ0FBQTtLQUNIOztJQUdELE1BQU0sY0FBYyxDQUFFLE9BQStCLEVBQUE7UUFDbkQsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxjQUFjLEVBQUUsQ0FBQTtRQUMzRCxNQUFNLE9BQU8sR0FBRyxDQUFHLEVBQUEsT0FBTyxFQUFFLE1BQU0sSUFBSSxpRUFBaUUsQ0FBQSxDQUFFLENBQUE7UUFDekcsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQztZQUN4QyxPQUFPO0FBQ1AsWUFBQSxNQUFNLEVBQUUsVUFBVTtZQUNsQixPQUFPLEVBQUUsQ0FBQyxHQUFHLEtBQUssR0FBRyxDQUFDLEtBQUssS0FBSyxTQUFTLEdBQUcsR0FBRyxDQUFDLEtBQUssR0FBRyxHQUFHLENBQUMsR0FBRztBQUNoRSxTQUFBLENBQUMsQ0FBQTtRQUNGLElBQUksUUFBUSxLQUFLLFNBQVMsRUFBRTtBQUMxQixZQUFBLE1BQU0sSUFBSSxXQUFXLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtBQUN6QyxTQUFBO0FBQ0QsUUFBQSxPQUFPLFFBQVEsQ0FBQTtLQUNoQjtJQUVELE1BQU0sdUJBQXVCLENBQUUsVUFBb0IsRUFBQTtBQUNqRCxRQUFBLElBQUksVUFBVSxDQUFDLElBQUksS0FBSyxJQUFJLElBQUksVUFBVSxDQUFDLElBQUksS0FBSyxTQUFTLElBQUksVUFBVSxDQUFDLElBQUksS0FBSyxTQUFTLEVBQUU7WUFDOUYsT0FBTTtBQUNQLFNBQUE7QUFFRCxRQUFBLE1BQU0sT0FBTyxHQUFHLFVBQVUsQ0FBQyxJQUErQixDQUFBOzs7UUFLMUQsTUFBTSxtQkFBbUIsR0FBd0IsRUFBRSxDQUFBO0FBQ25ELFFBQUEsTUFBTSxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxXQUFXLEVBQUUsRUFBRSxDQUFDLENBQUE7UUFDdkQsS0FBSyxNQUFNLFFBQVEsSUFBSSxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxFQUFFO1lBQy9DLElBQUksUUFBUSxDQUFDLElBQUksS0FBSyxzQkFBc0IsSUFBSSxRQUFRLENBQUMsUUFBUSxLQUFLLFNBQVM7Z0JBQUUsU0FBUTtBQUV6RixZQUFBLEtBQUssTUFBTSxLQUFLLElBQUksTUFBTSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLGlCQUFpQixDQUFDLEVBQUU7Z0JBQ3BFLElBQUksS0FBSyxLQUFLLElBQUk7b0JBQUUsU0FBUTtBQUU1QixnQkFBQSxNQUFNLGFBQWEsR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLENBQUMsU0FBUyxLQUFLLEtBQUssQ0FBQyxDQUFBO2dCQUN2RSxJQUFJLGFBQWEsS0FBSyxTQUFTLEVBQUU7b0JBQy9CLElBQUksaUJBQWlCLEdBQUcsbUJBQW1CLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxDQUFBO29CQUM5RCxJQUFJLGlCQUFpQixLQUFLLFNBQVMsRUFBRTt3QkFDbkMsaUJBQWlCLEdBQUcsRUFBRSxDQUFBO0FBQ3RCLHdCQUFBLG1CQUFtQixDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsR0FBRyxpQkFBaUIsQ0FBQTtBQUMzRCxxQkFBQTtvQkFFRCxJQUFJLGNBQWMsR0FBRyxpQkFBaUIsQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUE7b0JBQy9ELElBQUksY0FBYyxLQUFLLFNBQVMsRUFBRTtBQUNoQyx3QkFBQSxjQUFjLEdBQUc7QUFDZiw0QkFBQSxHQUFHLGFBQWE7QUFDaEIsNEJBQUEsV0FBVyxFQUFFLEVBQUU7eUJBQ2hCLENBQUE7QUFDRCx3QkFBQSxpQkFBaUIsQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLEdBQUcsY0FBYyxDQUFBO0FBQzVELHFCQUFBO29CQUVELGNBQWMsQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUNuRCxpQkFBQTtBQUNGLGFBQUE7QUFDRixTQUFBOztRQUlELE1BQU0sZUFBZSxHQUF3QixFQUFFLENBQUE7QUFDL0MsUUFBQSxNQUFNLGVBQWUsR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLEtBQUssS0FBSyxLQUFLLENBQUMsU0FBUyxLQUFLLElBQUksQ0FBQyxDQUFBO1FBQ2xGLEtBQUssTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxFQUFFO0FBQ2xELFlBQUEsTUFBTSxpQkFBaUIsR0FBRyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMsQ0FBQTs7WUFHbEQsSUFBSSxLQUFLLEdBQUcsSUFBSSxDQUFBO0FBQ2hCLFlBQUEsS0FBSyxNQUFNLGNBQWMsSUFBSSxlQUFlLEVBQUU7Z0JBQzVDLElBQUksaUJBQWlCLENBQUMsY0FBYyxDQUFDLFNBQVMsQ0FBQyxLQUFLLFNBQVMsRUFBRTtvQkFDN0QsS0FBSyxHQUFHLEtBQUssQ0FBQTtvQkFDYixNQUFLO0FBQ04saUJBQUE7QUFDRixhQUFBO0FBRUQsWUFBQSxJQUFJLEtBQUssRUFBRTtBQUNULGdCQUFBLGVBQWUsQ0FBQyxHQUFHLENBQUMsR0FBRyxpQkFBaUIsQ0FBQTtBQUN6QyxhQUFBO0FBQ0YsU0FBQTs7QUFJRCxRQUFBLElBQUksV0FBK0IsQ0FBQTtRQUNuQyxNQUFNLFNBQVMsR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDLGVBQWUsQ0FBQyxDQUFBO0FBQzlDLFFBQUEsSUFBSSxTQUFTLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRSxDQUUzQjtBQUFNLGFBQUEsSUFBSSxTQUFTLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTs7WUFFakMsV0FBVyxHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsZUFBZSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDOUMsU0FBQTtBQUFNLGFBQUE7O0FBRUwsWUFBQSxNQUFNLFVBQVUsR0FBRyxDQUFDLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsY0FBYyxFQUFFLEVBQUUsTUFBTSxDQUFDLFFBQVEsSUFBSSxTQUFTLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFBO1lBQ2xILE1BQU0sT0FBTyxHQUFHLENBQW9CLGlCQUFBLEVBQUEsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsS0FBSyxJQUFJLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUEsNEVBQUEsQ0FBOEUsQ0FBQTtZQUN4SyxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDO2dCQUN4QyxPQUFPO0FBQ1AsZ0JBQUEsTUFBTSxFQUFFLFVBQVU7QUFDbEIsZ0JBQUEsT0FBTyxFQUFFLENBQUMsUUFBUSxLQUFJO0FBQ3BCLG9CQUFBLE9BQU8sUUFBUSxDQUFDLEtBQUssS0FBSyxTQUFTLEdBQUcsQ0FBRyxFQUFBLFFBQVEsQ0FBQyxLQUFLLENBQUssRUFBQSxFQUFBLFVBQVUsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUEsQ0FBQSxDQUFHLEdBQUcsVUFBVSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQTtpQkFDbkg7QUFDRixhQUFBLENBQUMsQ0FBQTtZQUNGLElBQUksUUFBUSxLQUFLLFNBQVMsRUFBRTtBQUMxQixnQkFBQSxXQUFXLEdBQUcsUUFBUSxDQUFDLEdBQUcsQ0FBQTtBQUMzQixhQUFBO0FBQ0YsU0FBQTtRQUVELElBQUksV0FBVyxLQUFLLFNBQVMsRUFBRTtBQUM3QixZQUFBLE1BQU0sSUFBSSxXQUFXLENBQUMsNkNBQTZDLENBQUMsQ0FBQTtBQUNyRSxTQUFBO0FBQ0QsUUFBQSxNQUFNLGdCQUFnQixHQUFHLGVBQWUsQ0FBQyxXQUFXLENBQUMsQ0FBQTs7UUFHckQsTUFBTSxXQUFXLEdBQTJCLEVBQUUsQ0FBQTtRQUM5QyxHQUFHO1lBQ0QsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBMEI7QUFDakUsZ0JBQUEsS0FBSyxFQUFFLHNCQUFzQjtBQUM3QixnQkFBQSxXQUFXLEVBQUUsTUFBTSxDQUFDLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksRUFBRSxLQUFLLEtBQUk7QUFDbEUsb0JBQUEsTUFBTSxXQUFXLEdBQTRDO0FBQzNELHdCQUFBLEdBQUcsSUFBSTtBQUNQLHdCQUFBLENBQUMsS0FBSyxDQUFDLFNBQVMsR0FBRztBQUNqQiw0QkFBQSxJQUFJLEVBQUUsUUFBUTs0QkFDZCxPQUFPLEVBQUUsQ0FBRyxFQUFBLFVBQVUsQ0FBQyxJQUFJLElBQUksU0FBUyxDQUFBLDRCQUFBLEVBQStCLEtBQUssQ0FBQyxTQUFTLENBQUEsaUlBQUEsRUFBb0ksS0FBSyxDQUFDLFNBQVMsS0FBSyxJQUFJLEdBQUcsa0ZBQWtGLEdBQUcsRUFBRSxDQUFFLENBQUE7NEJBQzlVLE1BQU0sRUFBRSxDQUFDLFNBQVMsRUFBRSxHQUFHLEtBQUssQ0FBQyxXQUFXLENBQUM7QUFFekMsNEJBQUEsT0FBTyxDQUFFLFVBQVUsRUFBQTtnQ0FDakIsSUFBSSxVQUFVLEtBQUssU0FBUyxFQUFFO0FBQzVCLG9DQUFBLE9BQU8saUJBQWlCLENBQUE7QUFDekIsaUNBQUE7Z0NBQ0QsTUFBTSxLQUFLLEdBQUcsVUFBVSxDQUFDLGlCQUFpQixDQUFDLEtBQUssQ0FBQyxTQUFTLENBQVcsQ0FBQTtBQUNyRSxnQ0FBQSxPQUFPLEdBQUcsS0FBSyxDQUFDLFNBQVMsQ0FBQSxDQUFBLEVBQUksS0FBSyxDQUFRLEtBQUEsRUFBQSxVQUFVLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFBOzZCQUM5RTtBQUNELDRCQUFBLFVBQVUsQ0FBRSxVQUFVLEVBQUE7Z0NBQ3BCLE9BQU8sVUFBVSxLQUFLLFNBQVMsR0FBRyxTQUFTLEdBQUcsUUFBUSxDQUFBOzZCQUN2RDtBQUNGLHlCQUFBO3FCQUNGLENBQUE7QUFFRCxvQkFBQSxPQUFPLFdBQVcsQ0FBQTtpQkFDbkIsRUFBRSxFQUFFLENBQUM7QUFDTixnQkFBQSxLQUFLLEVBQUUsTUFBTSxDQUFDLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQztBQUNyQyxhQUFBLENBQUMsQ0FBQTtZQUVGLElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTtnQkFDNUIsTUFBTSxNQUFNLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQztBQUM1QyxvQkFBQSxPQUFPLEVBQUUsdURBQXVEO0FBQ2hFLG9CQUFBLFNBQVMsRUFBRSxLQUFLO0FBQ2hCLG9CQUFBLFNBQVMsRUFBRSxJQUFJO0FBQ2Ysb0JBQUEsV0FBVyxFQUFFLEtBQUs7QUFDbkIsaUJBQUEsQ0FBQyxDQUFBO2dCQUNGLElBQUksTUFBTSxLQUFLLElBQUksRUFBRTtBQUNuQixvQkFBQSxNQUFNLElBQUksV0FBVyxDQUFDLDZCQUE2QixDQUFDLENBQUE7QUFDckQsaUJBQUE7QUFDRixhQUFBO0FBQU0saUJBQUE7Z0JBQ0wsTUFBTSxpQkFBaUIsR0FBYSxFQUFFLENBQUE7QUFDdEMsZ0JBQUEsS0FBSyxNQUFNLENBQUMsU0FBUyxFQUFFLFVBQVUsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLEVBQUU7b0JBQ2hFLElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTs7QUFFNUIsd0JBQUEsTUFBTSxLQUFLLEdBQUcsZUFBZSxDQUFDLElBQUksQ0FBQyxDQUFDLEtBQUssS0FBSyxLQUFLLENBQUMsU0FBUyxLQUFLLFNBQVMsQ0FBQyxDQUFBO3dCQUM1RSxJQUFJLEtBQUssS0FBSyxTQUFTLEVBQUU7QUFDdkIsNEJBQUEsaUJBQWlCLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFBO0FBQ2xDLHlCQUFBO3dCQUNELFNBQVE7QUFDVCxxQkFBQTtBQUNELG9CQUFBLFdBQVcsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDN0IsaUJBQUE7QUFFRCxnQkFBQSxJQUFJLDJCQUFnRCxDQUFBO0FBQ3BELGdCQUFBLElBQUksaUJBQWlCLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBRTtBQUNoQyxvQkFBQSwyQkFBMkIsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO3dCQUMzRCxPQUFPLEVBQUUscUNBQXFDLGlCQUFpQixDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBaUUsK0RBQUEsQ0FBQTtBQUMzSSx3QkFBQSxTQUFTLEVBQUUsSUFBSTtBQUNmLHdCQUFBLFNBQVMsRUFBRSxLQUFLO0FBQ2hCLHdCQUFBLFdBQVcsRUFBRSxLQUFLO0FBQ25CLHFCQUFBLENBQUMsQ0FBQTtBQUNILGlCQUFBO0FBQU0scUJBQUEsSUFBSSxXQUFXLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtBQUNuQyxvQkFBQSwyQkFBMkIsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO0FBQzNELHdCQUFBLE9BQU8sRUFBRSw0RkFBNEY7QUFDckcsd0JBQUEsU0FBUyxFQUFFLElBQUk7QUFDZix3QkFBQSxTQUFTLEVBQUUsS0FBSztBQUNoQix3QkFBQSxXQUFXLEVBQUUsS0FBSztBQUNuQixxQkFBQSxDQUFDLENBQUE7QUFDSCxpQkFBQTtBQUFNLHFCQUFBO29CQUNMLE1BQUs7QUFDTixpQkFBQTtnQkFFRCxJQUFJLDJCQUEyQixLQUFLLEtBQUssRUFBRTtBQUN6QyxvQkFBQSxNQUFNLElBQUksV0FBVyxDQUFDLDZCQUE2QixDQUFDLENBQUE7QUFDckQsaUJBQUE7QUFDRixhQUFBO0FBQ0YsU0FBQSxRQUFRLElBQUksRUFBQzs7UUFJZCxNQUFNLEVBQUUsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLDRCQUE0QixDQUFDO0FBQzlELFlBQUEsWUFBWSxFQUFFO0FBQ1osZ0JBQUEsTUFBTSxFQUFFLFdBQVc7QUFDbkIsZ0JBQUEsUUFBUSxFQUFFLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQztBQUMzQixnQkFBQSxvQkFBb0IsRUFBRSxXQUFXO2dCQUNqQyxPQUFPLEVBQUUsVUFBVSxDQUFDLEdBQUc7QUFDeEIsYUFBQTtBQUNELFlBQUEsV0FBVyxFQUFFLEtBQUs7QUFDbEIsWUFBQSxJQUFJLEVBQUUsS0FBSztBQUNaLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxPQUFPLEVBQUUsQ0FBQTtLQUNWO0lBRUQsWUFBWSxHQUFBO1FBQ1YsT0FBTyxJQUFJLENBQUMsU0FBYyxDQUFBO0tBQzNCO0lBRUQsTUFBTSxJQUFJLENBQUUsZ0JBQXdDLEVBQUE7QUFDbEQsUUFBQSxNQUFPLElBQVksQ0FBQyxnQkFBZ0IsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFBO0tBQzdDOztBQUlEOzs7QUFHRztBQUNILElBQUEsTUFBTSxhQUFhLEdBQUE7UUFDakIsT0FBTyxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLFlBQVksRUFBRSxFQUFFLENBQUMsQ0FBQTtLQUM5QztBQUVEOzs7OztBQUtHO0lBQ0gsTUFBTSxZQUFZLENBQUUsZUFBeUQsRUFBQTtBQUMzRSxRQUFBLE1BQU0sRUFBRSxLQUFLLEVBQUUsR0FBRyxlQUFlLENBQUE7QUFDakMsUUFBQSxNQUFNLFVBQVUsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUE7QUFDcEUsUUFBQSxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsR0FBRyxLQUFLLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxDQUFDLENBQUE7S0FDakQ7QUFFRDs7OztBQUlHO0lBQ0gsTUFBTSxjQUFjLENBQUUsV0FBbUQsRUFBQTtBQUN2RSxRQUFBLE1BQU0sRUFBRSxLQUFLLEVBQUUsR0FBRyxXQUFXLENBQUE7QUFDN0IsUUFBQSxNQUFNLEVBQUUsR0FBRyxFQUFFLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQztZQUN2RCxLQUFLO1lBQ0wsUUFBUSxFQUFFLElBQUksQ0FBQyxRQUFRO0FBQ3hCLFNBQUEsQ0FBQyxDQUFBO1FBQ0YsT0FBTyxFQUFFLEdBQUcsRUFBRSxDQUFBO0tBQ2Y7SUFFRCxNQUFNLGNBQWMsQ0FBRSxlQUEyRCxFQUFBO1FBQy9FLE1BQU0sRUFBRSxHQUFHLEVBQUUsR0FBRyxNQUFNLElBQUksQ0FBQyxjQUFjLENBQUMsZUFBZSxDQUFDLENBQUE7UUFDMUQsT0FBTyxFQUFFLEdBQUcsRUFBRSxDQUFBO0tBQ2Y7QUFFRDs7Ozs7QUFLRztBQUNILElBQUEsTUFBTSxZQUFZLENBQUUsY0FBdUQsRUFBRSxXQUFpRCxFQUFBO0FBQzVILFFBQUEsSUFBSSxRQUFpRCxDQUFBO1FBQ3JELFFBQVEsV0FBVyxDQUFDLElBQUk7WUFDdEIsS0FBSyxhQUFhLEVBQUU7QUFDbEIsZ0JBQUEsTUFBTSxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsR0FBRyxXQUFXLENBQUE7Z0JBQ3pDLElBQUksV0FBVyxLQUFLLFNBQVMsRUFBRTtvQkFDN0IsTUFBTSxJQUFJLFdBQVcsQ0FBQyx1Q0FBdUMsRUFBRSxFQUFFLElBQUksRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFBO0FBQzlFLGlCQUFBO0FBQ0QsZ0JBQUEsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUMsY0FBYyxDQUFDLENBQUE7Z0JBQ3RFLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsbUJBQW1CLENBQUM7b0JBQzVELEdBQUcsRUFBRSxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUc7b0JBQ3pCLFdBQVc7QUFDWixpQkFBQSxDQUFDLENBQUE7QUFDRixnQkFBQSxRQUFRLEdBQUcsRUFBRSxTQUFTLEVBQUUsQ0FBQTtnQkFDeEIsTUFBSztBQUNOLGFBQUE7WUFDRCxLQUFLLEtBQUssRUFBRTtBQUNWLGdCQUFBLE1BQU0sRUFBRSxJQUFJLEVBQUUsR0FBRyxXQUFXLENBQUE7Z0JBQzVCLElBQUksSUFBSSxLQUFLLFNBQVMsRUFBRTtvQkFDdEIsTUFBTSxJQUFJLFdBQVcsQ0FBQyxnQ0FBZ0MsRUFBRSxFQUFFLElBQUksRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFBO0FBQ3ZFLGlCQUFBO0FBQ0QsZ0JBQUEsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUMsY0FBYyxDQUFDLENBQUE7Z0JBQ3RFLE1BQU0sU0FBUyxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsaUJBQWlCLENBQUM7b0JBQzFELEdBQUcsRUFBRSxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUc7b0JBQ3pCLElBQUksRUFBRUMsY0FBRyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLFdBQVcsQ0FBQztBQUNoRCxpQkFBQSxDQUFDLENBQUE7QUFDRixnQkFBQSxRQUFRLEdBQUcsRUFBRSxTQUFTLEVBQUUsQ0FBQTtnQkFDeEIsTUFBSztBQUNOLGFBQUE7WUFDRCxLQUFLLEtBQUssRUFBRTtBQUNWLGdCQUFBLE1BQU0sRUFBRSxJQUFJLEVBQUUsR0FBRyxXQUFXLENBQUE7Z0JBQzVCLElBQUksSUFBSSxLQUFLLFNBQVMsRUFBRTtvQkFDdEIsTUFBTSxJQUFJLFdBQVcsQ0FBQyxnQ0FBZ0MsRUFBRSxFQUFFLElBQUksRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFBO0FBQ3ZFLGlCQUFBO0FBQ0QsZ0JBQUEsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUMsY0FBYyxDQUFDLENBQUE7QUFDdEUsZ0JBQUEsTUFBTSxNQUFNLEdBQUc7QUFDYixvQkFBQSxHQUFJLElBQUksQ0FBQyxNQUFpQixJQUFJLFNBQVM7QUFDdkMsb0JBQUEsR0FBRyxFQUFFLFFBQVE7QUFDYixvQkFBQSxHQUFHLEVBQUUsS0FBSztpQkFDWCxDQUFBO0FBQ0QsZ0JBQUEsTUFBTSxPQUFPLEdBQUc7b0JBQ2QsR0FBSSxJQUFJLENBQUMsT0FBa0I7b0JBQzNCLEdBQUcsRUFBRSxjQUFjLENBQUMsR0FBRztvQkFDdkIsR0FBRyxFQUFFLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxHQUFHLElBQUksQ0FBQztpQkFDbkMsQ0FBQTtnQkFDRCxNQUFNLGFBQWEsR0FBRyxZQUFZLENBQUMsTUFBTSxFQUFFLE9BQU8sQ0FBQyxDQUFBO2dCQUNuRCxNQUFNLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLGlCQUFpQixDQUFDO29CQUMxRCxHQUFHLEVBQUUsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHO0FBQ3pCLG9CQUFBLElBQUksRUFBRSxhQUFhO0FBQ3BCLGlCQUFBLENBQUMsQ0FBQTtnQkFDRixRQUFRLEdBQUcsRUFBRSxTQUFTLEVBQUUsQ0FBQSxFQUFHLGFBQWEsQ0FBSSxDQUFBLEVBQUEsU0FBUyxDQUFFLENBQUEsRUFBRSxDQUFBO2dCQUN6RCxNQUFLO0FBQ04sYUFBQTtBQUNELFlBQUE7QUFDRSxnQkFBQSxNQUFNLElBQUksV0FBVyxDQUFDLHdCQUF3QixDQUFDLENBQUE7QUFDbEQsU0FBQTtBQUVELFFBQUEsT0FBTyxRQUFRLENBQUE7S0FDaEI7QUFFRDs7Ozs7QUFLRztJQUNILE1BQU0sWUFBWSxDQUFFLGNBQXVELEVBQUE7UUFDekUsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUM7WUFDaEQsR0FBRyxFQUFFLGNBQWMsQ0FBQyxHQUFHO0FBQ3hCLFNBQUEsQ0FBQyxDQUFBO0FBQ0YsUUFBQSxNQUFNLE1BQU0sR0FBR29CLHFCQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxDQUFDLEtBQUssRUFBRSxPQUFPLEVBQUUsVUFBVSxDQUFDLENBQUMsQ0FBQTtRQUN4RCxJQUFJLFNBQVMsR0FBYSxFQUFFLENBQUE7UUFDNUIsSUFBSSxHQUFHLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQyxVQUFVLENBQUMsRUFBRTtZQUN2QyxTQUFTLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLEtBQUtyQixhQUFNLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxDQUFBLEVBQUEsRUFBSyxHQUFHLENBQUMsWUFBWSxDQUFBLENBQUUsQ0FBQyxDQUFDLENBQUE7QUFDeEYsU0FBQTtBQUVELFFBQUEsT0FBTyxFQUFFLEdBQUcsTUFBTSxFQUFFLFNBQVMsRUFBRSxDQUFBO0tBQ2hDO0FBRUQsSUFBQSxNQUFNLHlCQUF5QixDQUFFLGNBQW9FLEVBQUUsV0FBaUQsRUFBQTtBQUN0SixRQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMseUJBQXlCLENBQUMsQ0FBQTtLQUMzQztBQUVEOzs7QUFHRztBQUNILElBQUEsTUFBTSxZQUFZLEdBQUE7UUFDaEIsT0FBTyxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLFdBQVcsRUFBRSxFQUFFLENBQUMsQ0FBQTtLQUM3QztBQUVEOzs7QUFHRztJQUNILE1BQU0sWUFBWSxDQUFFLEtBQStDLEVBQUE7UUFDakUsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQWdDLENBQUE7UUFDakUsTUFBTSxZQUFZLEdBQWEsRUFBRSxDQUFBO1FBQ2pDLE1BQU0sT0FBTyxHQUEyQyxFQUFFLENBQUE7QUFFMUQsUUFBQSxJQUFJLE9BQU8sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLEVBQUU7WUFDNUIsWUFBWSxDQUFDLElBQUksQ0FBQyxDQUFlLFlBQUEsRUFBQSxLQUFLLENBQUMsSUFBSSxJQUFJLFNBQVMsQ0FBVSxRQUFBLENBQUEsQ0FBQyxDQUFBO0FBQ25FLFlBQUEsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDLFFBQVEsS0FBSyxRQUFRLENBQUMsSUFBSSxLQUFLLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUN6RCxTQUFBO0FBQ0QsUUFBQSxJQUFJLE9BQU8sQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLEVBQUU7WUFDaEMsSUFBSSxLQUFLLENBQUMsUUFBUSxLQUFLLEVBQUUsSUFBSSxLQUFLLENBQUMsUUFBUSxLQUFLLFNBQVMsRUFBRTtnQkFDekQsWUFBWSxDQUFDLElBQUksQ0FBQyxDQUFBLGdCQUFBLEVBQW1CLEtBQUssQ0FBQyxRQUFRLENBQVUsUUFBQSxDQUFBLENBQUMsQ0FBQTtBQUM5RCxnQkFBQSxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUMsUUFBUSxLQUFLLFFBQVEsQ0FBQyxRQUFRLEtBQUssS0FBSyxDQUFDLFFBQVEsQ0FBQyxDQUFBO0FBQ2pFLGFBQUE7QUFBTSxpQkFBQTtBQUNMLGdCQUFBLFlBQVksQ0FBQyxJQUFJLENBQUMsMkJBQTJCLENBQUMsQ0FBQTtBQUM5QyxnQkFBQSxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUMsUUFBUSxLQUFLLFFBQVEsQ0FBQyxRQUFRLEtBQUssU0FBUyxDQUFDLENBQUE7QUFDNUQsYUFBQTtBQUNGLFNBQUE7O1FBRUQsTUFBTSxXQUFXLEdBQUcsQ0FBQSw4Q0FBQSxFQUFpRCxZQUFZLENBQUMsTUFBTSxHQUFHLENBQUMsR0FBRyxRQUFRLEdBQUcsWUFBWSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLENBQUEsZ0JBQUEsQ0FBa0IsQ0FBQTtRQUMzSixNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO0FBQ2xELFlBQUEsT0FBTyxFQUFFLFdBQVc7QUFDcEIsWUFBQSxTQUFTLEVBQUUsS0FBSztBQUNoQixZQUFBLFNBQVMsRUFBRSxJQUFJO0FBQ2hCLFNBQUEsQ0FBQyxDQUFBO1FBQ0YsSUFBSSxZQUFZLEtBQUssS0FBSyxFQUFFO1lBQzFCLE1BQU0sSUFBSSxXQUFXLENBQUMsOEJBQThCLEVBQUUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUMsQ0FBQTtBQUN2RSxTQUFBO0FBRUQsUUFBQSxNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTtRQUM5QyxNQUFNLFNBQVMsR0FBRyxNQUFNO2FBQ3JCLElBQUksQ0FBQyxZQUFZLENBQUM7YUFDbEIsR0FBRyxDQUFDLEdBQUcsSUFBSSxZQUFZLENBQUMsR0FBRyxDQUFDLENBQUM7YUFDN0IsTUFBTSxDQUFDLENBQUMsUUFBUSxLQUFLLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTSxLQUFLLE9BQU8sSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLEVBQUUsSUFBSSxDQUFDLENBQUMsQ0FBQTtBQUUvRixRQUFBLE9BQU8sU0FBUyxDQUFBO0tBQ2pCO0FBRUQ7OztBQUdHO0lBQ0gsTUFBTSxjQUFjLENBQUUsRUFBVSxFQUFBO1FBQzlCLE1BQU0sWUFBWSxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUM7QUFDbEQsWUFBQSxPQUFPLEVBQUUsMkRBQTJEO0FBQ3BFLFlBQUEsU0FBUyxFQUFFLElBQUk7QUFDZixZQUFBLFNBQVMsRUFBRSxRQUFRO0FBQ3BCLFNBQUEsQ0FBQyxDQUFBO1FBQ0YsSUFBSSxZQUFZLEtBQUssSUFBSSxFQUFFO1lBQ3pCLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsQ0FBYSxVQUFBLEVBQUEsRUFBRSxDQUFFLENBQUEsQ0FBQyxDQUFBO0FBQzNDLFNBQUE7S0FDRjtBQUVEOzs7QUFHRztJQUNILE1BQU0sY0FBYyxDQUFFLEdBQVcsRUFBQTtRQUMvQixNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO0FBQ2xELFlBQUEsT0FBTyxFQUFFLDJEQUEyRDtBQUNwRSxZQUFBLFNBQVMsRUFBRSxJQUFJO0FBQ2YsWUFBQSxTQUFTLEVBQUUsUUFBUTtBQUNwQixTQUFBLENBQUMsQ0FBQTtRQUNGLElBQUksWUFBWSxLQUFLLElBQUksRUFBRTtZQUN6QixNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQWMsV0FBQSxFQUFBLEdBQUcsQ0FBRSxDQUFBLENBQUMsQ0FBQTtBQUM3QyxTQUFBO0tBQ0Y7QUFFRDs7Ozs7QUFLRztJQUNILE1BQU0sY0FBYyxDQUFFLFdBQW1ELEVBQUE7UUFDdkUsTUFBTSxRQUFRLEdBQUcsV0FBVyxDQUFBOztBQUc1QixRQUFBLE1BQU0sVUFBVSxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLFFBQVEsQ0FBQyxRQUFRLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQy9FLFFBQUEsSUFBSSxDQUFDLFVBQVUsQ0FBQyxTQUFTLEVBQUU7WUFDekIsTUFBTSxJQUFJLEtBQUssQ0FBQyxDQUFBLGNBQUEsRUFBaUIsUUFBUSxDQUFDLElBQUksQ0FBZ0IsY0FBQSxDQUFBLENBQUMsQ0FBQTtBQUNoRSxTQUFBO0FBRUQsUUFBQSxJQUFJLFVBQVUsQ0FBQyxNQUFNLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBRTtZQUNoQyxNQUFNLElBQUksV0FBVyxDQUFDLHVCQUF1QixFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUE7QUFDaEUsU0FBQTtRQUVELFFBQVEsUUFBUSxDQUFDLElBQUk7WUFDbkIsS0FBSyxzQkFBc0IsRUFBRTtBQUMzQixnQkFBQSxNQUFNLGlCQUFpQixHQUFHLG1CQUFtQixDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUM7cUJBQzdELEdBQUcsQ0FBQyxLQUFLLElBQUksQ0FBTyxJQUFBLEVBQUEsS0FBSyxDQUFLLEVBQUEsRUFBQSxJQUFJLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsaUJBQWlCLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQSxDQUFFLENBQUM7cUJBQzNGLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtnQkFDYixNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO29CQUNsRCxPQUFPLEVBQUUsQ0FBNkQsMERBQUEsRUFBQSxpQkFBaUIsQ0FBRSxDQUFBO0FBQzFGLGlCQUFBLENBQUMsQ0FBQTtnQkFDRixJQUFJLFlBQVksS0FBSyxJQUFJLEVBQUU7b0JBQ3pCLE1BQU0sSUFBSSxXQUFXLENBQUMsOEJBQThCLEVBQUUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUMsQ0FBQTtBQUN2RSxpQkFBQTtnQkFDRCxNQUFLO0FBQ04sYUFBQTtZQUNELEtBQUssUUFBUSxFQUFFO2dCQUNiLE1BQU0sWUFBWSxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUM7QUFDbEQsb0JBQUEsT0FBTyxFQUFFLGdEQUFnRDtBQUMxRCxpQkFBQSxDQUFDLENBQUE7Z0JBQ0YsSUFBSSxZQUFZLEtBQUssSUFBSSxFQUFFO29CQUN6QixNQUFNLElBQUksV0FBVyxDQUFDLDhCQUE4QixFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUE7QUFDdkUsaUJBQUE7Z0JBQ0QsTUFBSztBQUNOLGFBQUE7WUFDRCxLQUFLLFVBQVUsRUFBRTtnQkFDZixNQUFNLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO0FBQ2xELG9CQUFBLE9BQU8sRUFBRSxpREFBaUQ7QUFDM0QsaUJBQUEsQ0FBQyxDQUFBO2dCQUNGLElBQUksWUFBWSxLQUFLLElBQUksRUFBRTtvQkFDekIsTUFBTSxJQUFJLFdBQVcsQ0FBQyw4QkFBOEIsRUFBRSxFQUFFLE1BQU0sRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFBO0FBQ3ZFLGlCQUFBO2dCQUNELE1BQUs7QUFDTixhQUFBO0FBRUQsWUFBQTtBQUNFLGdCQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsNkJBQTZCLENBQUMsQ0FBQTtBQUNqRCxTQUFBOztBQUdELFFBQUEsTUFBTSxVQUFVLEdBQUc7WUFDakIsRUFBRSxFQUFFc0IsT0FBSSxFQUFFO1NBQ1gsQ0FBQTtRQUNELE1BQU0sY0FBYyxHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUFFLFVBQVUsQ0FBQyxDQUFBO0FBQzFELFFBQUEsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFBLFVBQUEsRUFBYSxVQUFVLENBQUMsRUFBRSxDQUFBLENBQUUsRUFBRSxjQUFjLENBQUMsQ0FBQTtBQUNsRSxRQUFBLE9BQU8sVUFBVSxDQUFBO0tBQ2xCO0FBRUQ7Ozs7QUFJRztJQUNILE1BQU0sbUJBQW1CLENBQUUsY0FBOEQsRUFBQTtBQUN2RixRQUFBLE1BQU0sTUFBTSxHQUFHLGNBQWMsQ0FBQyxHQUFHLENBQUE7UUFDakMsTUFBTSxVQUFVLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUM7QUFDdkQsWUFBQSxHQUFHLEVBQUUsTUFBTTtBQUNYLFlBQUEsSUFBSSxFQUFFLEtBQUs7QUFDWixTQUFBLENBQUMsQ0FBQTtBQUVGLFFBQUEsSUFBSSxVQUFVLENBQUMsSUFBSSxLQUFLLFNBQVMsRUFBRTtBQUNqQyxZQUFBLE1BQU0sSUFBSSxXQUFXLENBQUMsaURBQWlELENBQUMsQ0FBQTtBQUN6RSxTQUFBO1FBRUQsTUFBTSxFQUFFLEdBQUcsTUFBTSxJQUFJLENBQUMsdUJBQXVCLENBQUMsVUFBVSxDQUFDLENBQUE7UUFDekQsSUFBSSxFQUFFLEtBQUssU0FBUyxFQUFFO0FBQ3BCLFlBQUEsTUFBTSxJQUFJLFdBQVcsQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFBO0FBQzVELFNBQUE7UUFFRCxPQUFPO0FBQ0wsWUFBQSxHQUFHLEVBQUUsRUFBRSxDQUFDLEtBQUssQ0FBQyxHQUFHO1NBQ2xCLENBQUE7S0FDRjtBQUVEOzs7O0FBSUc7SUFDSCxNQUFNLGlCQUFpQixDQUFFLFdBQXVELEVBQUE7UUFDOUUsTUFBTSxJQUFJLENBQUMsa0JBQWtCLENBQUM7WUFDNUIsV0FBVyxFQUFFLFdBQVcsQ0FBQyxXQUFXO0FBQ3JDLFNBQUEsQ0FBQyxDQUFBO0FBQ0YsUUFBQSxPQUFPLEVBQUUsQ0FBQTtLQUNWO0FBRUQ7Ozs7Ozs7O0FBUUc7SUFDSCxNQUFNLFlBQVksQ0FBRSxXQUFpRCxFQUFBO1FBQ25FLElBQUk7QUFDRixZQUFBLE9BQU8sTUFBTUMsWUFBYyxDQUFDLFdBQVcsQ0FBQyxHQUFHLEVBQUUsSUFBSSxDQUFDLE1BQU0sRUFBRSxXQUFXLENBQUMscUJBQXFCLENBQUMsQ0FBQTtBQUM3RixTQUFBO0FBQUMsUUFBQSxPQUFPLEtBQUssRUFBRTtBQUNkLFlBQUEsSUFBSSxPQUFPLEtBQUssS0FBSyxRQUFRLEVBQUU7QUFBRSxnQkFBQSxNQUFNLElBQUksV0FBVyxDQUFDLEtBQUssQ0FBQyxDQUFBO0FBQUUsYUFBQTtBQUMvRCxZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsT0FBTyxLQUFLLEtBQUssUUFBUSxHQUFHLEtBQUssR0FBRyxlQUFlLENBQUMsQ0FBQTtBQUNyRSxTQUFBO0tBQ0Y7QUFFRDs7O0FBR0c7QUFDSCxJQUFBLE1BQU0sZUFBZSxHQUFBO0FBQ25CLFFBQUEsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO1FBQzdELE9BQU87WUFDTCxRQUFRLEVBQUUsSUFBSSxDQUFDLFFBQVE7QUFDdkIsWUFBQSxHQUFHLFlBQVk7U0FDaEIsQ0FBQTtLQUNGO0FBQ0Y7O0FDOXZCRCxNQUFNM0IsT0FBSyxHQUFHQyx5QkFBSyxDQUFDLHdCQUF3QixDQUFDLENBQUE7TUFRaEMsVUFBVSxDQUFBO0FBQXZCLElBQUEsV0FBQSxHQUFBOztBQUVtQixRQUFBLElBQUEsQ0FBQSxXQUFXLEdBQWEsQ0FBQztBQUN4QyxnQkFBQSxJQUFJLEVBQUUseUJBQXlCO0FBQy9CLGdCQUFBLFlBQVksRUFBRSxJQUFJO0FBQ2xCLGdCQUFBLFNBQVMsQ0FBRSxNQUFNLEVBQUE7QUFDZixvQkFBQSxJQUFJLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFFO0FBQ3JCLHdCQUFBLE9BQU8sTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQ2pCLHFCQUFBO0FBQ0Qsb0JBQUEsT0FBTyxTQUFTLENBQUE7aUJBQ2pCO0FBQ0YsYUFBQSxDQUFDLENBQUE7S0EyREg7QUF6REMsSUFBQSxJQUFXLE1BQU0sR0FBQTtBQUNmLFFBQUEsT0FBTyxJQUFJLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFBO0tBQ3JEO0FBRUQsSUFBQSxNQUFNLFNBQVMsQ0FBRSxNQUF1QixFQUFFLEVBQXVCLEVBQUE7QUFDL0QsUUFBQSxJQUFJLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLEVBQUUsRUFBRSxJQUFJLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUE7UUFDN0QsTUFBTSxFQUFFLEVBQUUsQ0FBQTtBQUNWLFFBQUEsSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLEVBQUUsQ0FBQTtLQUN2Qjs7SUFHRCxNQUFNLElBQUksQ0FBRSxPQUFvQixFQUFBO1FBQzlCRCxPQUFLLENBQUMseUJBQXlCLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUNsRCxRQUFBLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUE7S0FDeEI7SUFFRCxNQUFNLFlBQVksQ0FBRSxPQUE0QixFQUFBO1FBQzlDQSxPQUFLLENBQUMsNEJBQTRCLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQUM3RCxRQUFBLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUE7S0FDaEM7SUFFRCxNQUFNLE1BQU0sQ0FBSyxPQUF5QixFQUFBO0FBQ3hDLFFBQUEsTUFBTSxLQUFLLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQ25EQSxPQUFLLENBQUMsWUFBWSxFQUFFLEtBQUssRUFBRSxRQUFRLEVBQUUsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQ3BELFFBQUEsT0FBTyxLQUFLLENBQUE7S0FDYjtBQUVELElBQUEsTUFBTSxZQUFZLEdBQUE7QUFDaEIsUUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLHlCQUF5QixDQUFDLENBQUE7S0FDM0M7SUFFRCxNQUFNLElBQUksQ0FBSyxPQUF1QixFQUFBO1FBQ3BDLE1BQU0sU0FBUyxHQUFlLEVBQUUsQ0FBQTtRQUVoQyxNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQTRCLENBQUE7QUFDeEUsUUFBQSxLQUFLLE1BQU0sR0FBRyxJQUFJLElBQUksRUFBRTtBQUN0QixZQUFBLElBQUksUUFBeUMsQ0FBQTtZQUM3QyxNQUFNLFVBQVUsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxDQUFBO1lBQzNDLFFBQVEsVUFBVSxDQUFDLElBQUk7QUFDckIsZ0JBQUEsS0FBSyxjQUFjO0FBQ2pCLG9CQUFBLFFBQVEsR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUN4QyxNQUFLO0FBQ1AsZ0JBQUEsS0FBSyxRQUFRO0FBQ1gsb0JBQUEsUUFBUSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ2xDLE1BQUs7QUFDUCxnQkFBQSxLQUFLLE1BQU07QUFDVCxvQkFBQSxRQUFRLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDaEMsTUFBSztBQUNSLGFBQUE7WUFFRCxJQUFJLFFBQVEsS0FBSyxTQUFTLEVBQUU7QUFDMUIsZ0JBQUEsU0FBUyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE1BQU0sUUFBUSxDQUFBO0FBQ2hDLGFBQUE7QUFDRixTQUFBO0FBRUQsUUFBQSxPQUFPLFNBQWMsQ0FBQTtLQUN0QjtBQUNGOztNQ3BGWSxTQUFTLENBQUE7QUFFcEIsSUFBQSxXQUFBLEdBQUE7QUFDRSxRQUFBLElBQUksQ0FBQyxLQUFLLEdBQUcsSUFBSSxDQUFDLFlBQVksRUFBRSxDQUFBO0tBQ2pDO0lBRU8sWUFBWSxHQUFBO1FBQ2xCLE9BQU87QUFDTCxZQUFBLFNBQVMsRUFBRSxFQUFFO0FBQ2IsWUFBQSxVQUFVLEVBQUUsRUFBRTtTQUNmLENBQUE7S0FDRjtJQUVELEdBQUcsQ0FBRSxHQUFRLEVBQUUsWUFBa0IsRUFBQTtBQUMvQixRQUFBLE9BQU95QixxQkFBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxZQUFZLENBQUMsQ0FBQTtLQUM1QztJQUdELEdBQUcsQ0FBRSxHQUFRLEVBQUUsS0FBVSxFQUFBO1FBQ3ZCQSxxQkFBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUMsQ0FBQTtLQUM5QjtBQUVELElBQUEsR0FBRyxDQUF5QixHQUFRLEVBQUE7UUFDbEMsT0FBT0EscUJBQUMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQTtLQUM5QjtBQUVELElBQUEsTUFBTSxDQUEwQixHQUFRLEVBQUE7QUFDdEMsUUFBQSxJQUFJLENBQUMsS0FBSyxHQUFHQSxxQkFBQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBUSxDQUFBO0tBQzVDO0lBRUQsS0FBSyxHQUFBO0FBQ0gsUUFBQSxJQUFJLENBQUMsS0FBSyxHQUFHLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTtLQUNqQztBQUNGOztBQy9CRCxNQUFNekIsT0FBSyxHQUFHQyx5QkFBSyxDQUFDLHdCQUF3QixDQUFDLENBQUE7TUFFaEMsU0FBUyxDQUFBO0FBQ3BCLElBQUEsSUFBSSxDQUFFLEtBQW1CLEVBQUE7QUFDdkIsUUFBQUQsT0FBSyxDQUFDLGVBQWUsRUFBRSxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7S0FDdEM7QUFFRCxJQUFBLEtBQUssQ0FBRSxPQUFlLEVBQUE7QUFDcEIsUUFBQUEsT0FBSyxDQUFDLGFBQWEsRUFBRSxPQUFPLENBQUMsQ0FBQTtLQUM5QjtBQUNGOztBQ05ELE1BQU1BLE9BQUssR0FBR0MseUJBQUssQ0FBQyx3QkFBd0IsQ0FBQyxDQUFBO01BUWhDLFVBQVUsQ0FBQTtBQUF2QixJQUFBLFdBQUEsR0FBQTs7QUFFbUIsUUFBQSxJQUFBLENBQUEsV0FBVyxHQUFhLENBQUM7QUFDeEMsZ0JBQUEsSUFBSSxFQUFFLHlCQUF5QjtBQUMvQixnQkFBQSxZQUFZLEVBQUUsSUFBSTtBQUNsQixnQkFBQSxTQUFTLENBQUUsTUFBTSxFQUFBO0FBQ2Ysb0JBQUEsSUFBSSxNQUFNLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBRTtBQUNyQix3QkFBQSxPQUFPLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUNqQixxQkFBQTtBQUNELG9CQUFBLE9BQU8sU0FBUyxDQUFBO2lCQUNqQjtBQUNGLGFBQUEsQ0FBQyxDQUFBO0tBMkRIO0FBekRDLElBQUEsSUFBVyxNQUFNLEdBQUE7QUFDZixRQUFBLE9BQU8sSUFBSSxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQTtLQUNyRDtBQUVELElBQUEsTUFBTSxTQUFTLENBQUUsTUFBdUIsRUFBRSxFQUF1QixFQUFBO0FBQy9ELFFBQUEsSUFBSSxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxFQUFFLEVBQUUsSUFBSSxDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFBO1FBQzdELE1BQU0sRUFBRSxFQUFFLENBQUE7QUFDVixRQUFBLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxFQUFFLENBQUE7S0FDdkI7O0lBR0QsTUFBTSxJQUFJLENBQUUsT0FBb0IsRUFBQTtRQUM5QkQsT0FBSyxDQUFDLHlCQUF5QixFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUE7QUFDbEQsUUFBQSxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFBO0tBQ3hCO0lBRUQsTUFBTSxZQUFZLENBQUUsT0FBNEIsRUFBQTtRQUM5Q0EsT0FBSyxDQUFDLDRCQUE0QixFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDN0QsUUFBQSxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFBO0tBQ2hDO0lBRUQsTUFBTSxNQUFNLENBQUssT0FBeUIsRUFBQTtBQUN4QyxRQUFBLE1BQU0sS0FBSyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUNuREEsT0FBSyxDQUFDLFlBQVksRUFBRSxLQUFLLEVBQUUsUUFBUSxFQUFFLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUNwRCxRQUFBLE9BQU8sS0FBSyxDQUFBO0tBQ2I7QUFFRCxJQUFBLE1BQU0sWUFBWSxHQUFBO0FBQ2hCLFFBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQyx5QkFBeUIsQ0FBQyxDQUFBO0tBQzNDO0lBRUQsTUFBTSxJQUFJLENBQUssT0FBdUIsRUFBQTtRQUNwQyxNQUFNLFNBQVMsR0FBZSxFQUFFLENBQUE7UUFFaEMsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUE0QixDQUFBO0FBQ3hFLFFBQUEsS0FBSyxNQUFNLEdBQUcsSUFBSSxJQUFJLEVBQUU7QUFDdEIsWUFBQSxJQUFJLFFBQXlDLENBQUE7WUFDN0MsTUFBTSxVQUFVLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUMzQyxRQUFRLFVBQVUsQ0FBQyxJQUFJO0FBQ3JCLGdCQUFBLEtBQUssY0FBYztBQUNqQixvQkFBQSxRQUFRLEdBQUcsSUFBSSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDeEMsTUFBSztBQUNQLGdCQUFBLEtBQUssUUFBUTtBQUNYLG9CQUFBLFFBQVEsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFBO29CQUNsQyxNQUFLO0FBQ1AsZ0JBQUEsS0FBSyxNQUFNO0FBQ1Qsb0JBQUEsUUFBUSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7b0JBQ2hDLE1BQUs7QUFDUixhQUFBO1lBRUQsSUFBSSxRQUFRLEtBQUssU0FBUyxFQUFFO0FBQzFCLGdCQUFBLFNBQVMsQ0FBQyxHQUFHLENBQUMsR0FBRyxNQUFNLFFBQVEsQ0FBQTtBQUNoQyxhQUFBO0FBQ0YsU0FBQTtBQUVELFFBQUEsT0FBTyxTQUFjLENBQUE7S0FDdEI7QUFDRjs7QUNuRkQ7O0FBRUc7TUFDVSxTQUFTLENBQUE7QUFJcEI7Ozs7QUFJRztJQUNILFdBQWEsQ0FBQSxRQUFnQixFQUFFLFFBQWlCLEVBQUE7UUFDOUMsTUFBTSxNQUFNLEdBQUcsT0FBTyxPQUFPLEtBQUssV0FBVyxJQUFJLE9BQU8sQ0FBQyxRQUFRLElBQUksSUFBSSxJQUFJLE9BQU8sQ0FBQyxRQUFRLENBQUMsSUFBSSxJQUFJLElBQUksQ0FBQTtRQUMxRyxJQUFJLENBQUMsTUFBTSxFQUFFO0FBQ1gsWUFBQSxNQUFNLElBQUksS0FBSyxDQUFDLGlEQUFpRCxDQUFDLENBQUE7QUFDbkUsU0FBQTtBQUNELFFBQUEsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUE7QUFDeEIsUUFBQSxJQUFJLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQTtRQUN4QixJQUFJLENBQUMsSUFBSSxFQUFFLENBQUMsS0FBSyxDQUFDLEtBQUssSUFBRztBQUN4QixZQUFBLE1BQU0sS0FBSyxDQUFBO0FBQ2IsU0FBQyxDQUFDLENBQUE7S0FDSDtJQUVPLEdBQUcsQ0FBRSxRQUFnQixFQUFFLElBQXVCLEVBQUE7UUFDcEQsT0FBT0YsaUJBQU0sQ0FBQyxVQUFVLENBQUMsUUFBUSxFQUFFLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQTtLQUM3QztBQUVPLElBQUEsTUFBTSxJQUFJLEdBQUE7QUFDaEIsUUFBQSxNQUFNOEIsY0FBSyxDQUFDQyxZQUFPLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxFQUFFLEVBQUUsU0FBUyxFQUFFLElBQUksRUFBRSxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7QUFDaEUsUUFBQSxNQUFNLEtBQUssR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQTtBQUNuQyxRQUFBLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQTtLQUMzQjtJQUVPLFlBQVksR0FBQTtRQUNsQixPQUFPO0FBQ0wsWUFBQSxTQUFTLEVBQUUsRUFBRTtBQUNiLFlBQUEsVUFBVSxFQUFFLEVBQUU7U0FDZixDQUFBO0tBQ0Y7QUFFTyxJQUFBLE1BQU0sUUFBUSxHQUFBO0FBQ3BCLFFBQUEsSUFBSSxLQUFLLEdBQUcsSUFBSSxDQUFDLFlBQVksRUFBRSxDQUFBO1FBQy9CLElBQUk7WUFDRixNQUFNLE9BQU8sR0FBRyxNQUFNQyxpQkFBUSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUM3QyxZQUFBLElBQUksSUFBSSxDQUFDLFFBQVEsS0FBSyxTQUFTLEVBQUU7QUFDL0IsZ0JBQUEsS0FBSyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFBO0FBQzdDLGFBQUE7QUFBTSxpQkFBQTtnQkFDTCxLQUFLLEdBQUcsTUFBTSxJQUFJLENBQUMsWUFBWSxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBQ3pDLGFBQUE7QUFDRixTQUFBO1FBQUMsT0FBTyxLQUFLLEVBQUUsR0FBRTtBQUNsQixRQUFBLE9BQU8sS0FBSyxDQUFBO0tBQ2I7SUFFTyxNQUFNLFFBQVEsQ0FBRSxLQUFzQixFQUFBO0FBQzVDLFFBQUEsSUFBSSxJQUFJLENBQUMsUUFBUSxLQUFLLFNBQVMsRUFBRTtBQUMvQixZQUFBLE1BQU1DLGtCQUFTLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxFQUFFLEVBQUUsUUFBUSxFQUFFLE1BQU0sRUFBRSxDQUFDLENBQUE7QUFDNUUsU0FBQTtBQUFNLGFBQUE7QUFDTCxZQUFBLE1BQU1BLGtCQUFTLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBRSxNQUFNLElBQUksQ0FBQyxZQUFZLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQTtBQUMvRCxTQUFBO0tBQ0Y7SUFFTyxNQUFNLFlBQVksQ0FBRSxLQUFzQixFQUFBO0FBQ2hELFFBQUEsSUFBSSxJQUFJLENBQUMsUUFBUSxLQUFLLFNBQVMsRUFBRTtBQUMvQixZQUFBLE1BQU0sSUFBSSxLQUFLLENBQUMsMkRBQTJELENBQUMsQ0FBQTtBQUM3RSxTQUFBOztRQUdELE1BQU0sRUFBRSxHQUFHakMsaUJBQU0sQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLENBQUE7O1FBR2pDLE1BQU0sSUFBSSxHQUFHQSxpQkFBTSxDQUFDLFdBQVcsQ0FBQyxFQUFFLENBQUMsQ0FBQTs7QUFHbkMsUUFBQSxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUE7O0FBR3pDLFFBQUEsTUFBTSxNQUFNLEdBQUdBLGlCQUFNLENBQUMsY0FBYyxDQUFDLGFBQWEsRUFBRSxHQUFHLEVBQUUsRUFBRSxDQUFDLENBQUE7O1FBRzVELE1BQU0sU0FBUyxHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLEVBQUUsTUFBTSxDQUFDLEVBQUUsTUFBTSxDQUFDLEtBQUssRUFBRSxDQUFDLENBQUMsQ0FBQTs7QUFHL0YsUUFBQSxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUE7O0FBRy9CLFFBQUEsT0FBTyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsU0FBUyxDQUFDLENBQUMsQ0FBQTtLQUNqRDtJQUVPLE1BQU0sWUFBWSxDQUFFLGNBQStCLEVBQUE7QUFDekQsUUFBQSxJQUFJLElBQUksQ0FBQyxRQUFRLEtBQUssU0FBUyxFQUFFO0FBQy9CLFlBQUEsTUFBTSxJQUFJLEtBQUssQ0FBQywyREFBMkQsQ0FBQyxDQUFBO0FBQzdFLFNBQUE7O1FBR0QsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxjQUFjLENBQUMsQ0FBQTtRQUN2QyxNQUFNLElBQUksR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQTtRQUM3QixNQUFNLEVBQUUsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsQ0FBQTtRQUM1QixNQUFNLEdBQUcsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsQ0FBQTtRQUM3QixNQUFNLFVBQVUsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQyxDQUFBOztBQUdoQyxRQUFBLE1BQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBRSxJQUFJLENBQUMsQ0FBQTs7QUFHekMsUUFBQSxNQUFNLFFBQVEsR0FBR0EsaUJBQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxhQUFhLEVBQUUsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFBO0FBQ2hFLFFBQUEsUUFBUSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTs7QUFHeEIsUUFBQSxNQUFNLFNBQVMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxLQUFLLEVBQUUsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUE7QUFFN0csUUFBQSxPQUFPLFNBQVMsQ0FBQTtLQUNqQjtBQUVELElBQUEsTUFBTSxHQUFHLENBQUUsR0FBUSxFQUFFLFlBQWtCLEVBQUE7QUFDckMsUUFBQSxNQUFNLElBQUksQ0FBQyxJQUFJLEVBQUUsQ0FBQTtBQUNqQixRQUFBLE1BQU0sS0FBSyxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFBO1FBQ25DLE9BQU8yQixxQkFBQyxDQUFDLEdBQUcsQ0FBQyxLQUFLLEVBQUUsR0FBRyxFQUFFLFlBQVksQ0FBQyxDQUFBO0tBQ3ZDO0FBR0QsSUFBQSxNQUFNLEdBQUcsQ0FBRSxHQUFRLEVBQUUsS0FBVSxFQUFBO0FBQzdCLFFBQUEsTUFBTSxJQUFJLENBQUMsSUFBSSxFQUFFLENBQUE7QUFDakIsUUFBQSxNQUFNLEtBQUssR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQTtRQUNuQ0EscUJBQUMsQ0FBQyxHQUFHLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUMsQ0FBQTtBQUN4QixRQUFBLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQTtLQUMzQjtJQUVELE1BQU0sR0FBRyxDQUF5QixHQUFRLEVBQUE7QUFDeEMsUUFBQSxNQUFNLElBQUksQ0FBQyxJQUFJLEVBQUUsQ0FBQTtBQUNqQixRQUFBLE1BQU0sS0FBSyxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFBO1FBQ25DLE9BQU9BLHFCQUFDLENBQUMsR0FBRyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQTtLQUN6QjtJQUVELE1BQU0sTUFBTSxDQUF5QixHQUFRLEVBQUE7QUFDM0MsUUFBQSxNQUFNLElBQUksQ0FBQyxJQUFJLEVBQUUsQ0FBQTtBQUNqQixRQUFBLElBQUksS0FBSyxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFBO1FBQ2pDLEtBQUssR0FBR0EscUJBQUMsQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBUSxDQUFBO0FBQ2pDLFFBQUEsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFBO0tBQzNCO0FBRUQsSUFBQSxNQUFNLEtBQUssR0FBQTtBQUNULFFBQUEsTUFBTSxJQUFJLENBQUMsSUFBSSxFQUFFLENBQUE7QUFDakIsUUFBQSxNQUFNTyxXQUFFLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0tBQ3hCO0FBQ0Y7O0FDbEpEOztBQUVHO01BQ1UsUUFBUSxDQUFBO0FBRW5CLElBQUEsV0FBQSxHQUFBO0FBQ0UsUUFBQSxJQUFJLENBQUMsS0FBSyxHQUFHLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTtLQUNqQztJQUVPLFlBQVksR0FBQTtRQUNsQixPQUFPO0FBQ0wsWUFBQSxTQUFTLEVBQUUsRUFBRTtBQUNiLFlBQUEsVUFBVSxFQUFFLEVBQUU7U0FDZixDQUFBO0tBQ0Y7SUFFRCxHQUFHLENBQUUsR0FBUSxFQUFFLFlBQWtCLEVBQUE7QUFDL0IsUUFBQSxPQUFPUCxxQkFBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxZQUFZLENBQUMsQ0FBQTtLQUM1QztJQUdELEdBQUcsQ0FBRSxHQUFRLEVBQUUsS0FBVSxFQUFBO1FBQ3ZCQSxxQkFBQyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUMsQ0FBQTtLQUM5QjtBQUVELElBQUEsR0FBRyxDQUF5QixHQUFRLEVBQUE7UUFDbEMsT0FBT0EscUJBQUMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQTtLQUM5QjtBQUVELElBQUEsTUFBTSxDQUEwQixHQUFRLEVBQUE7QUFDdEMsUUFBQSxJQUFJLENBQUMsS0FBSyxHQUFHQSxxQkFBQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBUSxDQUFBO0tBQzVDO0lBRUQsS0FBSyxHQUFBO0FBQ0gsUUFBQSxJQUFJLENBQUMsS0FBSyxHQUFHLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQTtLQUNqQztBQUNGOztBQ2xDRCxNQUFNLEtBQUssR0FBR3hCLHlCQUFLLENBQUMsMEJBQTBCLENBQUMsQ0FBQTtNQUVsQyxZQUFZLENBQUE7QUFDdkIsSUFBQSxJQUFJLENBQUUsS0FBbUIsRUFBQTtBQUN2QixRQUFBLEtBQUssQ0FBQyxlQUFlLEVBQUUsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0tBQ3RDO0FBRUQsSUFBQSxLQUFLLENBQUUsT0FBZSxFQUFBO0FBQ3BCLFFBQUEsS0FBSyxDQUFDLGFBQWEsRUFBRSxPQUFPLENBQUMsQ0FBQTtLQUM5QjtBQUNGOzs7Ozs7Ozs7Ozs7Ozs7Ozs7OyJ9
