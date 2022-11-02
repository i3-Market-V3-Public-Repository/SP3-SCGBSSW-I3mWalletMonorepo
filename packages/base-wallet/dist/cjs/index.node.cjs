'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var ethers = require('ethers');
var _ = require('lodash');
var u8a = require('uint8arrays');
var uuid = require('uuid');
var nonRepudiationLibrary = require('@i3m/non-repudiation-library');
var jsonschema = require('jsonschema');
var didJwt = require('did-jwt');
var crypto = require('crypto');
var objectSha = require('object-sha');
var Debug = require('debug');
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
	version: "1.6.2",
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
																			minimum: 0,
																			exclusiveMinimum: true,
																			example: 10000
																		},
																		pooToPopDelay: {
																			description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
																			type: "integer",
																			minimum: 0,
																			exclusiveMinimum: true,
																			example: 20000
																		},
																		pooToSecretDelay: {
																			description: "Maximum acceptable time between issued PoO and secret published on the ledger",
																			type: "integer",
																			minimum: 0,
																			exclusiveMinimum: true,
																			example: 180000
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
													type: "string",
													example: "NonRepudiationProof",
													"enum": [
														"NonRepudiationProof"
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
													type: "string",
													pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
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
																	minimum: 0,
																	exclusiveMinimum: true,
																	example: 10000
																},
																pooToPopDelay: {
																	description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
																	type: "integer",
																	minimum: 0,
																	exclusiveMinimum: true,
																	example: 20000
																},
																pooToSecretDelay: {
																	description: "Maximum acceptable time between issued PoO and secret published on the ledger",
																	type: "integer",
																	minimum: 0,
																	exclusiveMinimum: true,
																	example: 180000
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
											type: "string",
											example: "NonRepudiationProof",
											"enum": [
												"NonRepudiationProof"
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
											type: "string",
											pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
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
														minimum: 0,
														exclusiveMinimum: true,
														example: 10000
													},
													pooToPopDelay: {
														description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
														type: "integer",
														minimum: 0,
														exclusiveMinimum: true,
														example: 20000
													},
													pooToSecretDelay: {
														description: "Maximum acceptable time between issued PoO and secret published on the ledger",
														type: "integer",
														minimum: 0,
														exclusiveMinimum: true,
														example: 180000
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
								type: "string",
								example: "NonRepudiationProof",
								"enum": [
									"NonRepudiationProof"
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
								type: "string",
								pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
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
													minimum: 0,
													exclusiveMinimum: true,
													example: 10000
												},
												pooToPopDelay: {
													description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
													type: "integer",
													minimum: 0,
													exclusiveMinimum: true,
													example: 20000
												},
												pooToSecretDelay: {
													description: "Maximum acceptable time between issued PoO and secret published on the ledger",
													type: "integer",
													minimum: 0,
													exclusiveMinimum: true,
													example: 180000
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
							type: "string",
							example: "NonRepudiationProof",
							"enum": [
								"NonRepudiationProof"
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
							type: "string",
							pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
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
											minimum: 0,
											exclusiveMinimum: true,
											example: 10000
										},
										pooToPopDelay: {
											description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
											type: "integer",
											minimum: 0,
											exclusiveMinimum: true,
											example: 20000
										},
										pooToSecretDelay: {
											description: "Maximum acceptable time between issued PoO and secret published on the ledger",
											type: "integer",
											minimum: 0,
											exclusiveMinimum: true,
											example: 180000
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
		NonRepudiationProof: {
			title: "NonRepudiationProof",
			type: "object",
			properties: {
				type: {
					type: "string",
					example: "NonRepudiationProof",
					"enum": [
						"NonRepudiationProof"
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
					type: "string",
					pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
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
					minimum: 0,
					exclusiveMinimum: true,
					example: 10000
				},
				pooToPopDelay: {
					description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
					type: "integer",
					minimum: 0,
					exclusiveMinimum: true,
					example: 20000
				},
				pooToSecretDelay: {
					description: "Maximum acceptable time between issued PoO and secret published on the ledger",
					type: "integer",
					minimum: 0,
					exclusiveMinimum: true,
					example: 180000
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
							minimum: 0,
							exclusiveMinimum: true,
							example: 10000
						},
						pooToPopDelay: {
							description: "Maximum acceptable time in milliseconds between issued PoO and issued PoP",
							type: "integer",
							minimum: 0,
							exclusiveMinimum: true,
							example: 20000
						},
						pooToSecretDelay: {
							description: "Maximum acceptable time between issued PoO and secret published on the ledger",
							type: "integer",
							minimum: 0,
							exclusiveMinimum: true,
							example: 180000
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
        const expectedPayloadMerged = ___default["default"].cloneDeep(expectedPayloadClaims);
        ___default["default"].defaultsDeep(expectedPayloadMerged, payload);
        const isExpectedPayload = ___default["default"].isEqual(expectedPayloadMerged, payload);
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
    return ethers.ethers.utils.getAddress('0x' + hex);
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
async function validateDataExchangeAgreement(dea) {
    const errors = [];
    try {
        if (dea.orig !== await nonRepudiationLibrary.parseJwk(JSON.parse(dea.orig), true)) {
            errors.push(new Error('orig is not a valid stringified JWK with the claims sorted alphabetically: ' + dea.orig));
        }
    }
    catch (error) {
        errors.push(new Error('orig is not a valid stringified JWK with the claims sorted alphabetically'));
    }
    try {
        if (dea.dest !== await nonRepudiationLibrary.parseJwk(JSON.parse(dea.dest), true)) {
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
            errors.push(new Error('ledgerSignerAddress is not a valid EIP-55 ethereum address' + dea.ledgerSignerAddress));
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
        await nonRepudiationLibrary.verifyKeyPair(JSON.parse(keyPair.publicJwk), JSON.parse(keyPair.privateJwk));
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
        // Let us change the resource name to something more human readable (instead of a uuid)
        resource.name = `[${role}] ${dataSharingAgreement.dataOfferingDescription.title ?? dataSharingAgreement.dataOfferingDescription.dataOfferingId}`;
        // Let us use a unique id that can be easily found. This way it can be easily linked to NR proofs
        resource.id = await objectSha.digest(dataSharingAgreement.dataExchangeAgreement);
    }
    catch (error) {
        errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'));
    }
    return errors;
};

const debug$7 = Debug__default["default"]('base-wallet:NrpValidator');
const nrpValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const jws = resource.resource;
        const decodedProof = await nonRepudiationLibrary.jwsDecode(jws, (header, payload) => {
            const key = payload.iss;
            return JSON.parse(payload.exchange[key]);
        });
        const { id, cipherblockDgst, blockCommitment, secretCommitment, ...dataExchangeAgreement } = decodedProof.payload.exchange;
        const deaErrors = await validateDataExchangeAgreement(dataExchangeAgreement);
        if (deaErrors.length > 0) {
            deaErrors.forEach((error) => {
                errors.push(error);
            });
        }
        else {
            // The proof is associated to a given data sharing agreement
            resource.parentResource = await objectSha.digest(dataExchangeAgreement);
            debug$7('Received data exchange agreeement:\n' + JSON.stringify(dataExchangeAgreement, undefined, 2));
            debug$7(`Parent resource id: ${resource.parentResource}`);
            // The proof name is the type along with the dataExchangeId (there could be multiple dataExchanges for the same data sharing agreeement)
            resource.name = `[${decodedProof.payload.proofType}] ${await nonRepudiationLibrary.exchangeId(decodedProof.payload.exchange)}`;
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
     * Securely stores in the wallet a new resource.
     *
     * @param requestBody
     * @returns and identifier of the created resource
     */
    async resourceCreate(requestBody) {
        const resource = { ...requestBody, id: uuid.v4() };
        // Validate resource
        const validation = await this.resourceValidator.validate(resource, this.veramo);
        if (!validation.validated) {
            throw new Error(`Resource type ${resource.type} not supported`);
        }
        if (validation.errors.length > 0) {
            throw new WalletError('Resource has not been validated:\n' + JSON.stringify(validation.errors, undefined, 2), { status: 400 });
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
            case 'NonRepudiationProof': {
                const confirmation = await this.dialog.confirmation({
                    message: 'Do you want to add a non repudiation proof into your wallet?'
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                break;
            }
            default:
                throw new Error('Resource type not supported');
        }
        await this.store.set(`resources.${resource.id}`, resource);
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
exports.parseAddress = parseAddress;
exports.parseHex = parseHex;
exports.validateDataExchangeAgreement = validateDataExchangeAgreement;
exports.validateDataSharingAgreeementSchema = validateDataSharingAgreeementSchema;
exports.verifyDataSharingAgreementSignature = verifyDataSharingAgreementSignature;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvYmFzZTY0dXJsLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2NyZWRlbnRpYWwtY2xhaW1zLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2p3cy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kaWQtand0LXZlcmlmeS50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUFkZHJlc3MudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZGF0YS1zaGFyaW5nLWFncmVlbWVudC12YWxpZGF0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2dlbmVyYXRlLXNlY3JldC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9jb250cmFjdC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvbnJwLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9vYmplY3QtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL3ZjLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9yZXNvdXJjZS12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZGlzcGxheS1kaWQudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2RpZC13YWxsZXQtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2tleS13YWxsZXQtbWFuYWdlbWVudC1zeXN0ZW0udHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL2tleS13YWxsZXQtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdmVyYW1vL3ZlcmFtby50cyIsIi4uLy4uL3NyYy90cy93YWxsZXQvYmFzZS13YWxsZXQudHMiLCIuLi8uLi9zcmMvdHMvdGVzdC9kaWFsb2cudHMiLCIuLi8uLi9zcmMvdHMvdGVzdC9zdG9yZS50cyIsIi4uLy4uL3NyYy90cy90ZXN0L3RvYXN0LnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvZGlhbG9ncy9udWxsLWRpYWxvZy50cyIsIi4uLy4uL3NyYy90cy9pbXBsL3N0b3Jlcy9maWxlLXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvc3RvcmVzL3JhbS1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy9pbXBsL3RvYXN0L2NvbnNvbGUtdG9hc3QudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImJhc2U2NHVybCIsIl8iLCJ2ZXJpZnlKV1QiLCJldGhlcnMiLCJ2YWxpZGF0ZSIsInBhcnNlSndrIiwiY3J5cHRvIiwidXVpZHY0IiwidmVyaWZ5S2V5UGFpciIsImRpZ2VzdCIsImRlYnVnIiwiRGVidWciLCJqd3NEZWNvZGUiLCJleGNoYW5nZUlkIiwiQWJzdHJhY3RESURTdG9yZSIsIkFic3RyYWN0S2V5TWFuYWdlbWVudFN5c3RlbSIsInU4YSIsIkFic3RyYWN0S2V5U3RvcmUiLCJ1dGlscyIsImV0aHJEaWRSZXNvbHZlciIsImV0aHJEaWRHZXRSZXNvbHZlciIsIndlYkRpZFJlc29sdmVyIiwid2ViRGlkR2V0UmVzb2x2ZXIiLCJSZXNvbHZlciIsIldlYkRJRFByb3ZpZGVyIiwiRXRockRJRFByb3ZpZGVyIiwiY3JlYXRlQWdlbnQiLCJLZXlNYW5hZ2VyIiwiRElETWFuYWdlciIsIkNyZWRlbnRpYWxJc3N1ZXIiLCJTZWxlY3RpdmVEaXNjbG9zdXJlIiwiTWVzc2FnZUhhbmRsZXIiLCJKd3RNZXNzYWdlSGFuZGxlciIsIlNkck1lc3NhZ2VIYW5kbGVyIiwiVzNjTWVzc2FnZUhhbmRsZXIiLCJESURSZXNvbHZlclBsdWdpbiIsInV1aWQiLCJkaWRKd3RWZXJpZnlGbiIsIm1rZGlyIiwiZGlybmFtZSIsInJlYWRGaWxlIiwid3JpdGVGaWxlIiwicm0iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBTU0sTUFBTyxXQUFZLFNBQVEsS0FBSyxDQUFBO0lBSXBDLFdBQWEsQ0FBQSxPQUFlLEVBQUUsUUFBbUIsRUFBQTtRQUMvQyxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7UUFDZCxJQUFJLENBQUMsSUFBSSxHQUFHLFFBQVEsRUFBRSxJQUFJLElBQUksQ0FBQyxDQUFBO1FBQy9CLElBQUksQ0FBQyxNQUFNLEdBQUcsUUFBUSxFQUFFLE1BQU0sSUFBSSxHQUFHLENBQUE7S0FDdEM7QUFDRjs7QUNmRCxNQUFNLE1BQU0sR0FBRyxDQUFDLEdBQVcsS0FBWTtJQUNyQyxPQUFPLEdBQUcsQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUE7QUFDekYsQ0FBQyxDQUFBO0FBRUQsTUFBTSxNQUFNLEdBQUcsQ0FBQyxHQUFXLEtBQVk7SUFDckMsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxRQUFRLENBQUMsQ0FBQTtBQUNuQyxDQUFDLENBQUE7QUFFRCxnQkFBZTtJQUNiLE1BQU07SUFDTixNQUFNO0NBQ1A7O0FDVEssU0FBVSxtQkFBbUIsQ0FBRSxFQUF3QixFQUFBO0FBQzNELElBQUEsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxpQkFBaUIsQ0FBQztTQUNyQyxNQUFNLENBQUMsS0FBSyxJQUFJLEtBQUssS0FBSyxJQUFJLENBQUMsQ0FBQTtBQUNwQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7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
