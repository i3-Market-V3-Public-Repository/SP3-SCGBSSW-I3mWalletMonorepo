'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jose = require('jose');
var bigintCryptoUtils = require('bigint-crypto-utils');
var objectSha = require('object-sha');
var ethers = require('ethers');
var bigintConversion = require('bigint-conversion');
var base64 = require('@juanelas/base64');

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

var base64__namespace = /*#__PURE__*/_interopNamespace(base64);

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
 * @param issuer - if the issuer of the proof is the origin 'orig' or the destination 'dest' of the data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` should be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
async function createProof(payload, privateJwk) {
    // Check that that the privateKey is the complement to the public key of the issuer
    const publicJwk = JSON.parse(payload.exchange[payload.iss]);
    await verifyKeyPair(publicJwk, privateJwk); // if verification fails it throws an error and the following is not executed
    const privateKey = await jose.importJWK(privateJwk);
    const alg = privateJwk.alg; // if alg wer undefined the previous import throws error
    return await new jose.SignJWT(payload)
        .setProtectedHeader({ alg })
        .setIssuedAt()
        .sign(privateKey);
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
 * @param dateTolerance - specifies a time window to accept the proof. An example could be
 * {
 *   currentDate: new Date('2021-10-17T03:24:00'), // Date to use when comparing NumericDate claims, defaults to new Date().
 *   clockTolerance: 10  // string|number Expected clock tolerance in seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours")
 * }
 *
 * @returns The JWT protected header and payload if the proof is validated
 */
async function verifyProof(proof, publicJwk, expectedPayloadClaims, dateTolerance) {
    const pubKey = await jose.importJWK(publicJwk);
    const verification = await jose.jwtVerify(proof, pubKey, dateTolerance);
    const payload = verification.payload;
    // Check that that the publicKey is the public key of the issuer
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
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
async function jweEncrypt(exchangeId, block, secret, encAlg) {
    // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
    const key = await jose.importJWK(secret);
    return await new jose.CompactEncrypt(block)
        .setProtectedHeader({ alg: 'dir', enc: encAlg, exchangeId, kid: secret.kid })
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

/**
 * Create a random (high entropy) symmetric secret for AES-256-GCM
 *
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */
async function oneTimeSecret(encAlg) {
    const key = await jose.generateSecret(encAlg, { extractable: true });
    const jwk = await jose.exportJWK(key);
    const thumbprint = await jose.calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = encAlg;
    return { jwk, hex: bigintConversion.bufToHex(base64.decode(jwk.k)) };
}

var contractConfigDefault = {
  address: '0x7B7C7c0c8952d1BDB7E4D90B1B7b7C48c13355D1',
  abi: [
    {
      anonymous: false,
      inputs: [
        {
          indexed: false,
          internalType: 'address',
          name: 'sender',
          type: 'address'
        },
        {
          indexed: false,
          internalType: 'uint256',
          name: 'dataExchangeId',
          type: 'uint256'
        },
        {
          indexed: false,
          internalType: 'uint256',
          name: 'secret',
          type: 'uint256'
        }
      ],
      name: 'Registration',
      type: 'event'
    },
    {
      inputs: [
        {
          internalType: 'address',
          name: '',
          type: 'address'
        },
        {
          internalType: 'uint256',
          name: '',
          type: 'uint256'
        }
      ],
      name: 'registry',
      outputs: [
        {
          internalType: 'uint256',
          name: '',
          type: 'uint256'
        }
      ],
      stateMutability: 'view',
      type: 'function'
    },
    {
      inputs: [
        {
          internalType: 'uint256',
          name: '_dataExchangeId',
          type: 'uint256'
        },
        {
          internalType: 'uint256',
          name: '_secret',
          type: 'uint256'
        }
      ],
      name: 'setRegistry',
      outputs: [],
      stateMutability: 'nonpayable',
      type: 'function'
    }
  ],
  transactionHash: '0xc5893d949c2f0e15b9fdc81a614422767c6027992b92dc090d34ea8376c6a79f',
  receipt: {
    to: null,
    from: '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903',
    contractAddress: '0x7B7C7c0c8952d1BDB7E4D90B1B7b7C48c13355D1',
    transactionIndex: 0,
    gasUsed: '235574',
    logsBloom: '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    blockHash: '0xd89ff96a8815646c586db267e1e829bbf1934c73c7b5b65bdf921604a706953b',
    transactionHash: '0xc5893d949c2f0e15b9fdc81a614422767c6027992b92dc090d34ea8376c6a79f',
    logs: [],
    blockNumber: 110833,
    cumulativeGasUsed: '235574',
    status: 1,
    byzantium: true
  },
  args: [],
  solcInputHash: 'fa99dbc561556e730ddad9bdcf162967',
  metadata: '{"compiler":{"version":"0.8.4+commit.c7e474f2"},"language":"Solidity","output":{"abi":[{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint256","name":"dataExchangeId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"secret","type":"uint256"}],"name":"Registration","type":"event"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"registry","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_dataExchangeId","type":"uint256"},{"internalType":"uint256","name":"_secret","type":"uint256"}],"name":"setRegistry","outputs":[],"stateMutability":"nonpayable","type":"function"}],"devdoc":{"kind":"dev","methods":{},"version":1},"userdoc":{"kind":"user","methods":{},"version":1}},"settings":{"compilationTarget":{"contracts/NonRepudiation.sol":"NonRepudiation"},"evmVersion":"istanbul","libraries":{},"metadata":{"bytecodeHash":"ipfs","useLiteralContent":true},"optimizer":{"enabled":false,"runs":200},"remappings":[]},"sources":{"contracts/NonRepudiation.sol":{"content":"//SPDX-License-Identifier: Unlicense\\npragma solidity ^0.8.0;\\n\\ncontract NonRepudiation {\\n    mapping(address => mapping (uint256 => uint256)) public registry;\\n    event Registration(address sender, uint256 dataExchangeId, uint256 secret);\\n\\n    function setRegistry(uint256 _dataExchangeId, uint256 _secret) public {\\n        require(registry[msg.sender][_dataExchangeId] == 0);\\n        registry[msg.sender][_dataExchangeId] = _secret;\\n        emit Registration(msg.sender, _dataExchangeId, _secret);\\n    }\\n}\\n","keccak256":"0x4de6bfe24e978d02e4bc36e8891a9503b0e418b6726103716fa7ced46350df96","license":"Unlicense"}},"version":1}',
  bytecode: '0x608060405234801561001057600080fd5b5061034d806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b61005560048036038101906100509190610201565b610087565b005b610071600480360381019061006c91906101c5565b610176565b60405161007e9190610292565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002054146100e357600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000848152602001908152602001600020819055507f0d6d8be58ef6918a4e19027a89943222bc99e02d838bd0b3e41004fd72d7f34433838360405161016a9392919061025b565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150505481565b6000813590506101aa816102e9565b92915050565b6000813590506101bf81610300565b92915050565b600080604083850312156101d857600080fd5b60006101e68582860161019b565b92505060206101f7858286016101b0565b9150509250929050565b6000806040838503121561021457600080fd5b6000610222858286016101b0565b9250506020610233858286016101b0565b9150509250929050565b610246816102ad565b82525050565b610255816102df565b82525050565b6000606082019050610270600083018661023d565b61027d602083018561024c565b61028a604083018461024c565b949350505050565b60006020820190506102a7600083018461024c565b92915050565b60006102b8826102bf565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6102f2816102ad565b81146102fd57600080fd5b50565b610309816102df565b811461031457600080fd5b5056fea26469706673582212206004e0c3b99c52db1b84221e9cca886d1eb418b718da57ba025235b5d40fcc6c64736f6c63430008040033',
  deployedBytecode: '0x608060405234801561001057600080fd5b50600436106100365760003560e01c8063032439371461003b578063d05cb54514610057575b600080fd5b61005560048036038101906100509190610201565b610087565b005b610071600480360381019061006c91906101c5565b610176565b60405161007e9190610292565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002054146100e357600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000848152602001908152602001600020819055507f0d6d8be58ef6918a4e19027a89943222bc99e02d838bd0b3e41004fd72d7f34433838360405161016a9392919061025b565b60405180910390a15050565b6000602052816000526040600020602052806000526040600020600091509150505481565b6000813590506101aa816102e9565b92915050565b6000813590506101bf81610300565b92915050565b600080604083850312156101d857600080fd5b60006101e68582860161019b565b92505060206101f7858286016101b0565b9150509250929050565b6000806040838503121561021457600080fd5b6000610222858286016101b0565b9250506020610233858286016101b0565b9150509250929050565b610246816102ad565b82525050565b610255816102df565b82525050565b6000606082019050610270600083018661023d565b61027d602083018561024c565b61028a604083018461024c565b949350505050565b60006020820190506102a7600083018461024c565b92915050565b60006102b8826102bf565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6102f2816102ad565b81146102fd57600080fd5b50565b610309816102df565b811461031457600080fd5b5056fea26469706673582212206004e0c3b99c52db1b84221e9cca886d1eb418b718da57ba025235b5d40fcc6c64736f6c63430008040033',
  devdoc: {
    kind: 'dev',
    methods: {},
    version: 1
  },
  userdoc: {
    kind: 'user',
    methods: {},
    version: 1
  },
  storageLayout: {
    storage: [
      {
        astId: 7,
        contract: 'contracts/NonRepudiation.sol:NonRepudiation',
        label: 'registry',
        offset: 0,
        slot: '0',
        type: 't_mapping(t_address,t_mapping(t_uint256,t_uint256))'
      }
    ],
    types: {
      t_address: {
        encoding: 'inplace',
        label: 'address',
        numberOfBytes: '20'
      },
      't_mapping(t_address,t_mapping(t_uint256,t_uint256))': {
        encoding: 'mapping',
        key: 't_address',
        label: 'mapping(address => mapping(uint256 => uint256))',
        numberOfBytes: '32',
        value: 't_mapping(t_uint256,t_uint256)'
      },
      't_mapping(t_uint256,t_uint256)': {
        encoding: 'mapping',
        key: 't_uint256',
        label: 'mapping(uint256 => uint256)',
        numberOfBytes: '32',
        value: 't_uint256'
      },
      t_uint256: {
        encoding: 'inplace',
        label: 'uint256',
        numberOfBytes: '32'
      }
    }
  }
};

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
class NonRepudiationOrig {
    /**
     * @param exchangeId - the id of this data exchange. It MUST be unique for the sender
     * @param jwkPairOrig - a pair of private and public keys owned by this entity (non-repudiation orig)
     * @param publicJwkDest - the public key as a JWK of the other peer (non-repudiation dest)
     * @param block - the block of data to transmit in this data exchange
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     * @param algs - is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GCM)
     */
    constructor(exchangeId, jwkPairOrig, publicJwkDest, block, dltConfig, algs) {
        this.jwkPairOrig = jwkPairOrig;
        this.publicJwkDest = publicJwkDest;
        if (this.jwkPairOrig.privateJwk.alg === undefined || this.jwkPairOrig.publicJwk.alg === undefined || this.publicJwkDest.alg === undefined) {
            throw new TypeError('"alg" argument is required, please add it to your JWKs first');
        }
        this.exchange = {
            id: exchangeId,
            orig: JSON.stringify(this.jwkPairOrig.publicJwk),
            dest: JSON.stringify(this.publicJwkDest),
            hashAlg: 'SHA-256',
            signingAlg: 'ES256',
            encAlg: 'A256GCM',
            ledgerSignerAddress: '',
            ledgerContract: '',
            ...algs
        };
        // @ts-expect-error I will end assigning the complete Block in the async init()
        this.block = {
            raw: block
        };
        // @ts-expect-error I will end assigning the complete Block in the async init()
        this.dltConfig = dltConfig;
        this.initialized = new Promise((resolve, reject) => {
            this.init().then(() => {
                resolve(true);
            }).catch((error) => {
                throw error;
            });
        });
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init() {
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        const secret = await oneTimeSecret(this.exchange.encAlg);
        this.block = {
            ...this.block,
            secret,
            jwe: await jweEncrypt(this.exchange.id, this.block.raw, secret.jwk, this.exchange.encAlg)
        };
        this.exchange = {
            ...this.exchange,
            cipherblockDgst: await sha(this.block.jwe, this.exchange.hashAlg),
            blockCommitment: await sha(this.block.raw, this.exchange.hashAlg),
            secretCommitment: await sha(new Uint8Array(bigintConversion.hexToBuf(this.block.secret.hex)), this.exchange.hashAlg)
        };
        await this._dltSetup();
    }
    async _dltSetup() {
        const dltConfig = {
            // @ts-expect-error I will end assigning the complete Block in the async init()
            gasLimit: 12500000,
            // @ts-expect-error I will end assigning the complete Block in the async init()
            rpcProviderUrl: '***REMOVED***',
            // @ts-expect-error I will end assigning the complete Block in the async init()
            disable: false,
            ...this.dltConfig
        };
        if (!dltConfig.disable) {
            dltConfig.contractConfig = dltConfig.contractConfig ?? contractConfigDefault;
            const rpcProvider = new ethers.ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl);
            if (this.jwkPairOrig.privateJwk.d === undefined) {
                throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key');
            }
            const privateKey = base64__namespace.decode(this.jwkPairOrig.privateJwk.d);
            const signingKey = new ethers.ethers.utils.SigningKey(privateKey);
            const signer = new ethers.ethers.Wallet(signingKey, rpcProvider);
            dltConfig.signer = { address: await signer.getAddress(), signer };
            dltConfig.contract = new ethers.ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, signer);
            this.exchange.ledgerSignerAddress = dltConfig.signer.address;
            this.exchange.ledgerContract = dltConfig.contractConfig.address;
        }
        this.dltConfig = dltConfig;
    }
    /**
     * Creates the proof of origin (PoO).
     * Besides returning its value, it is also stored in this.block.poo
     *
     * @returns a compact JWS with the PoO
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
     * @returns the verified payload and protected header
     */
    async verifyPoR(por) {
        await this.initialized;
        if (this.block?.poo === undefined) {
            throw new Error('Cannot verify a PoR if not even a PoO have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            pooDgst: await sha(this.block.poo, this.exchange.hashAlg)
        };
        const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims);
        this.block.por = por;
        return verified;
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
            // TO-DO: it fails because the account hasn't got any funds (ether). Do we have a faucet? Set gas prize to 0?
            const setRegistryTx = await this.dltConfig.contract?.setRegistry(this.exchange.id, secret, { gasLimit: this.dltConfig.gasLimit });
            verificationCode = JSON.stringify(setRegistryTx);
            // TO-DO: I would say that we can remove the next wait
            await setRegistryTx.wait();
            // TO-DO: Next line is completely useless. Here for testing but we could remove it.
            await this.dltConfig.contract?.registry(this.dltConfig.signer?.address, this.exchange.id);
        }
        const payload = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            porDgst: await sha(this.block.por, this.exchange.hashAlg),
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
     *
     * @param exchangeId - the id of this data exchange. It MUST be unique
     * @param jwkPairDest - a pair of private and public keys owned by this entity (non-repudiation dest)
     * @param publicJwkOrig - the public key as a JWK of the other peer (non-repudiation orig)
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     * @param algs - is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GM)
     */
    constructor(exchangeId, jwkPairDest, publicJwkOrig, dltConfig, algs) {
        this.jwkPairDest = jwkPairDest;
        this.publicJwkOrig = publicJwkOrig;
        this.exchange = {
            id: exchangeId,
            orig: JSON.stringify(this.publicJwkOrig),
            dest: JSON.stringify(this.jwkPairDest.publicJwk),
            hashAlg: 'SHA-256',
            signingAlg: 'ES256',
            encAlg: 'A256GCM',
            ledgerContract: '',
            ledgerSignerAddress: '',
            ...algs
        };
        this.block = {};
        this.dltConfig = this._dltSetup(dltConfig);
        this.initialized = new Promise((resolve, reject) => {
            this.init().then(() => {
                resolve(true);
            }).catch((error) => {
                throw error;
            });
        });
    }
    _dltSetup(providedDltConfig) {
        const dltConfig = {
            gasLimit: 12500000,
            rpcProviderUrl: '***REMOVED***',
            disable: false,
            ...providedDltConfig
        };
        if (!dltConfig.disable) {
            dltConfig.contractConfig = dltConfig.contractConfig ?? contractConfigDefault;
            const rpcProvider = new ethers.ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl);
            dltConfig.contract = new ethers.ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, rpcProvider);
        }
        return dltConfig;
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
     * @returns the verified payload and protected header
     *
     */
    async verifyPoO(poo, cipherblock) {
        await this.initialized;
        const dataExchange = {
            ...this.exchange,
            cipherblockDgst: await sha(cipherblock, this.exchange.hashAlg)
        };
        const expectedPayloadClaims = {
            proofType: 'PoO',
            iss: 'orig',
            exchange: dataExchange
        };
        const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims);
        this.block = {
            jwe: cipherblock,
            poo: poo
        };
        this.exchange = verified.payload.exchange;
        return verified;
    }
    /**
     * Creates the proof of reception (PoR).
     * Besides returning its value, it is also stored in `this.block.por`
     *
     * @returns a compact JWS with the PoR
     */
    async generatePoR() {
        await this.initialized;
        if (this.block.poo === undefined) {
            throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO');
        }
        const payload = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            pooDgst: await sha(this.block.poo, this.exchange.hashAlg)
        };
        this.block.por = await createProof(payload, this.jwkPairDest.privateJwk);
        return this.block.por;
    }
    /**
     * Verifies a received Proof of Publication (PoP) and returns the secret
     * @param pop - a PoP in compact JWS
     * @param secret - the JWK secret that was used to encrypt the block
     * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
     */
    async verifyPoP(pop) {
        await this.initialized;
        if (this.block.por === undefined) {
            throw new Error('Cannot verify a PoP if not even a PoR have been created');
        }
        const expectedPayloadClaims = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            porDgst: await sha(this.block.por, this.exchange.hashAlg),
            secret: '',
            verificationCode: ''
        };
        const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims);
        const secret = JSON.parse(verified.payload.secret);
        this.block.secret = {
            hex: bigintConversion.bufToHex(base64__namespace.decode(secret.k)),
            jwk: secret
        };
        this.block.pop = pop;
        return verified;
    }
    /**
     * Just in case the PoP is not received, the secret can be downloaded from the ledger
     *
     * @param timeout - the time in seconds to wait for the query to get the value
     *
     * @returns the secret
     */
    async getSecretFromLedger(timeout = 20) {
        let secretBn = ethers.ethers.BigNumber.from(0);
        let counter = 0;
        do {
            secretBn = await this.dltConfig.contract.registry(this.exchange.ledgerSignerAddress, this.exchange.id);
            if (secretBn.isZero()) {
                counter++;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        } while (secretBn.isZero() && counter < timeout);
        if (secretBn.isZero()) {
            throw new Error(`timeout of ${timeout}s exceeded when querying the ledger`);
        }
        const secretHex = secretBn.toHexString();
        const jwk = await jose.exportJWK(new Uint8Array(bigintConversion.hexToBuf(secretHex)));
        this.block.secret = { hex: secretHex, jwk };
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
        const decryptedDgst = await sha(decryptedBlock, this.exchange.hashAlg);
        if (decryptedDgst !== this.exchange.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.raw = decryptedBlock;
        return decryptedBlock;
    }
}

exports.NonRepudiationDest = NonRepudiationDest;
exports.NonRepudiationOrig = NonRepudiationOrig;
exports.createProof = createProof;
exports.jweDecrypt = jweDecrypt;
exports.jweEncrypt = jweEncrypt;
exports.oneTimeSecret = oneTimeSecret;
exports.sha = sha;
exports.verifyKeyPair = verifyKeyPair;
exports.verifyProof = verifyProof;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy92ZXJpZnlLZXlQYWlyLnRzIiwiLi4vLi4vc3JjL3RzL2NyZWF0ZVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmlmeVByb29mLnRzIiwiLi4vLi4vc3JjL3RzL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvb25lVGltZVNlY3JldC50cyIsIi4uLy4uL3NyYy9iZXN1L05vblJlcHVkaWF0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uT3JpZy50cyIsIi4uLy4uL3NyYy90cy9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbImltcG9ydEpXSyIsInJhbmRCeXRlcyIsIkdlbmVyYWxTaWduIiwiZ2VuZXJhbFZlcmlmeSIsIlNpZ25KV1QiLCJqd3RWZXJpZnkiLCJoYXNoYWJsZSIsIkNvbXBhY3RFbmNyeXB0IiwiY29tcGFjdERlY3J5cHQiLCJnZW5lcmF0ZVNlY3JldCIsImV4cG9ydEpXSyIsImNhbGN1bGF0ZUp3a1RodW1icHJpbnQiLCJidWZUb0hleCIsImJhc2U2NGRlY29kZSIsImhleFRvQnVmIiwiZXRoZXJzIiwiYmFzZTY0Il0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBR08sZUFBZSxhQUFhLENBQUUsTUFBVyxFQUFFLE9BQVk7SUFDNUQsSUFBSSxNQUFNLENBQUMsR0FBRyxLQUFLLFNBQVMsSUFBSSxPQUFPLENBQUMsR0FBRyxLQUFLLFNBQVMsSUFBSSxNQUFNLENBQUMsR0FBRyxLQUFLLE9BQU8sQ0FBQyxHQUFHLEVBQUU7UUFDdkYsTUFBTSxJQUFJLEtBQUssQ0FBQywwRUFBMEUsQ0FBQyxDQUFBO0tBQzVGO0lBQ0QsTUFBTSxNQUFNLEdBQUcsTUFBTUEsY0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFBO0lBQ3RDLE1BQU0sT0FBTyxHQUFHLE1B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
