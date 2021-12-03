import { importJWK, GeneralSign, generalVerify, SignJWT, jwtVerify, CompactEncrypt, compactDecrypt, generateSecret, exportJWK, calculateJwkThumbprint } from 'jose';
import { randBytes } from 'bigint-crypto-utils';
import { hashable } from 'object-sha';
import { ethers } from 'ethers';

async function verifyKeyPair(pubJWK, privJWK, alg) {
    const pubKey = await importJWK(pubJWK, alg);
    const privKey = await importJWK(privJWK, alg);
    const nonce = await randBytes(16);
    const jws = await new GeneralSign(nonce)
        .addSignature(privKey)
        .setProtectedHeader({ alg: privJWK.alg })
        .sign();
    await generalVerify(jws, pubKey); // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
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
    const privateKey = await importJWK(privateJwk);
    const alg = privateJwk.alg; // if alg wer undefined the previous import throws error
    return await new SignJWT(payload)
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
 * @param expectedPayloadClaims - The expected values of the proof's payload claims. An example could be:
 * {
 *   proofType: 'PoO',
 *   iss: 'orig',
 *   exchange: {
 *     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
 *     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)
 *     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)
 *     hash_alg: 'SHA-256',
 *     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding
 *     block_commitment: 'iHAdgHDQVo6qaD0KqJ9ZMlVmVA3f3AI6uZG0jFqeu14', // hash of the plaintext block in base64url with no padding
 *     secret_commitment: 'svipVfsi6vsoj3Zk_6LWi3k6mMdQOSSY1OrHGnaM5eA' // hash of the secret that can be used to decrypt the block in base64url with no padding
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
    const pubKey = await importJWK(publicJwk);
    const verification = await jwtVerify(proof, pubKey, dateTolerance);
    const payload = verification.payload;
    // Check that that the publicKey is the public key of the issuer
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
        else {
            if (hashable(expectedPayloadClaims[key]) !== hashable(payload[key])) {
                throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedPayloadClaims[key], undefined, 2)}`);
            }
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
        if (hashable(expectedDataExchange[key]) !== hashable(dataExchange[key])) {
            throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key], undefined, 2)}`);
        }
    }
}

const HASH_ALG = 'SHA-256'; // 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'
const SIGNING_ALG = 'RS256';
const ENC_ALG = 'A256GCM';

/**
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @returns a Compact JWE
 */
async function jweEncrypt(exchangeId, block, secret) {
    // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
    const key = await importJWK(secret);
    return await new CompactEncrypt(block)
        .setProtectedHeader({ alg: 'dir', enc: ENC_ALG, exchangeId, kid: secret.kid })
        .encrypt(key);
}
/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @returns the plaintext
 */
async function jweDecrypt(jwe, secret) {
    const key = await importJWK(secret);
    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [ENC_ALG] });
}

async function sha(input, algorithm = HASH_ALG) {
    const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
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
 * Create a random (high entropy) symmetric JWK secret for AES-256-GCM
 *
 * @returns a promise that resolves to a JWK
 */
async function oneTimeSecret() {
    const key = await generateSecret(ENC_ALG, { extractable: true });
    const jwk = await exportJWK(key);
    const thumbprint = await calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = ENC_ALG;
    return jwk;
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
     */
    constructor(exchangeId, jwkPairOrig, publicJwkDest, block, dltConfig) {
        this.jwkPairOrig = jwkPairOrig;
        this.publicJwkDest = publicJwkDest;
        if (this.jwkPairOrig.privateJwk.alg === undefined || this.jwkPairOrig.publicJwk.alg === undefined || this.publicJwkDest.alg === undefined) {
            throw new TypeError('"alg" argument is required, please add it to your JWKs first');
        }
        this.exchange = {
            id: exchangeId,
            orig: JSON.stringify(this.jwkPairOrig.publicJwk),
            dest: JSON.stringify(this.publicJwkDest),
            hashAlg: HASH_ALG
        };
        this.block = {
            raw: block
        };
        this.dltConfig = this._dltSetup(dltConfig);
        this.checked = false;
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
            const rpcProvider = new ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl);
            /** TODO: it should be jwkPairDest.privateJwk */
            const privKeyHex = '***REMOVED***';
            const signer = new ethers.Wallet(privKeyHex, rpcProvider);
            dltConfig.contract = new ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, signer);
        }
        return dltConfig;
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init() {
        await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk);
        this.block.secret = await oneTimeSecret();
        const secretStr = JSON.stringify(this.block.secret);
        this.block.jwe = await jweEncrypt(this.exchange.id, this.block.raw, this.block.secret);
        this.exchange = {
            ...this.exchange,
            cipherblockDgst: await sha(this.block.jwe, this.exchange.hashAlg),
            blockCommitment: await sha(this.block.raw, this.exchange.hashAlg),
            secretCommitment: await sha(secretStr, this.exchange.hashAlg)
        };
        this.checked = true;
    }
    /**
     * Creates the proof of origin (PoO).
     * Besides returning its value, it is also stored in this.block.poo
     *
     * @returns a compact JWS with the PoO
     */
    async generatePoO() {
        this._checkInit();
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
        this._checkInit();
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
        this._checkInit();
        if (this.block?.por === undefined) {
            throw new Error('Before computing a PoP, you have first to receive a verify a PoR');
        }
        /**
         * TO-DO: obtain verification code from the blockchain
         * TO-DO: Pass secret to raw hex
         */
        let verificationCode = 'verificationCode';
        if (this.dltConfig.disable !== true) {
            const secretHex = '1234567890';
            const setRegistryTx = await this.dltConfig.contract?.setRegistry(this.exchange.id, secretHex, { gasLimit: this.dltConfig.gasLimit });
            await setRegistryTx.wait();
            const address = await this.dltConfig.contract?.signer.getAddress();
            verificationCode = await this.dltConfig.contract?.registry(address, this.exchange.id);
        }
        const payload = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            porDgst: await sha(this.block.por, this.exchange.hashAlg),
            secret: JSON.stringify(this.block.secret),
            verificationCode
        };
        this.block.pop = await createProof(payload, this.jwkPairOrig.privateJwk);
        return this.block.pop;
    }
    _checkInit() {
        if (!this.checked) {
            throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()');
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
     *
     * @param exchangeId - the id of this data exchange. It MUST be unique
     * @param jwkPairDest - a pair of private and public keys owned by this entity (non-repudiation dest)
     * @param publicJwkOrig - the public key as a JWK of the other peer (non-repudiation orig)
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     */
    constructor(exchangeId, jwkPairDest, publicJwkOrig, dltConfig) {
        this.jwkPairDest = jwkPairDest;
        this.publicJwkOrig = publicJwkOrig;
        this.exchange = {
            id: exchangeId,
            orig: JSON.stringify(this.publicJwkOrig),
            dest: JSON.stringify(this.jwkPairDest.publicJwk),
            hashAlg: HASH_ALG
        };
        this.dltConfig = this._dltSetup(dltConfig);
        this.checked = false;
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
            const rpcProvider = new ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl);
            dltConfig.contract = new ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, rpcProvider);
        }
        return dltConfig;
    }
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    async init() {
        await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk);
        this.checked = true;
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
        this._checkInit();
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
        this._checkInit();
        if (this.block?.poo === undefined) {
            throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO');
        }
        const payload = {
            proofType: 'PoR',
            iss: 'dest',
            exchange: this.exchange,
            pooDgst: await sha(this.block.poo)
        };
        this.block.por = await createProof(payload, this.jwkPairDest.privateJwk);
        return this.block.por;
    }
    /**
     * Verifies a received Proof of Publication (PoP) with the received secret and verificationCode
     * @param pop - a PoP in compact JWS
     * @param secret - the JWK secret that was used to encrypt the block
     * @returns the verified payload and protected header
     */
    async verifyPoP(pop, secret) {
        this._checkInit();
        if (this.block?.por === undefined) {
            throw new Error('Cannot verify a PoP if not even a PoR have been created');
        }
        /**
         * TO-DO: obtain verification code from the blockchain
         * TO-DO: Pass secret to raw hex
         */
        let verificationCode = 'verificationCode';
        if (this.dltConfig.disable !== true) {
            const signerAddress = '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903';
            verificationCode = await new Promise((resolve, reject) => {
                this.dltConfig.contract?.on('Registration', (sender, dataExchangeId, secret) => {
                    if (sender === signerAddress) {
                        resolve(secret.toHexString());
                    }
                });
            });
        }
        const expectedPayloadClaims = {
            proofType: 'PoP',
            iss: 'orig',
            exchange: this.exchange,
            porDgst: await sha(this.block.por),
            secret: JSON.stringify(secret),
            verificationCode
        };
        const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims);
        this.block.secret = secret;
        this.block.pop = pop;
        return verified;
    }
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     *
     * @throws Error if the previous proofs have not been verified or the decrypted block does not meet the committed one
     */
    async decrypt() {
        this._checkInit();
        if (this.block?.pop === undefined || this.block?.secret === undefined) {
            throw new Error('Cannot decrypt if the PoP/secret has not been verified ');
        }
        const decryptedBlock = (await jweDecrypt(this.block.jwe, this.block.secret)).plaintext;
        const decryptedDgst = await sha(decryptedBlock);
        if (decryptedDgst !== this.exchange.blockCommitment) {
            throw new Error('Decrypted block does not meet the committed one');
        }
        this.block.raw = decryptedBlock;
        return decryptedBlock;
    }
    _checkInit() {
        if (!this.checked) {
            throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()');
        }
    }
}

export { ENC_ALG, HASH_ALG, NonRepudiationDest, NonRepudiationOrig, SIGNING_ALG, createProof, jweDecrypt, jweEncrypt, oneTimeSecret, sha, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvY3JlYXRlUHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvdmVyaWZ5UHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvY29uc3RhbnRzLnRzIiwiLi4vLi4vc3JjL3RzL2p3ZS50cyIsIi4uLy4uL3NyYy90cy9zaGEudHMiLCIuLi8uLi9zcmMvdHMvb25lVGltZVNlY3JldC50cyIsIi4uLy4uL3NyYy9iZXN1L05vblJlcHVkaWF0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uT3JpZy50cyIsIi4uLy4uL3NyYy90cy9Ob25SZXB1ZGlhdGlvbkRlc3QudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBR08sZUFBZSxhQUFhLENBQUUsTUFBVyxFQUFFLE9BQVksRUFBRSxHQUFZO0lBQzFFLE1BQU0sTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sRUFBRSxHQUFHLENBQUMsQ0FBQTtJQUMzQyxNQUFNLE9BQU8sR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLEVBQUUsR0FBRyxDQUFDLENBQUE7SUFDN0MsTUFBTSxLQUFLLEdBQUcsTUFBTSxTQUFTLENBQUMsRUFBRSxDQUFDLENBQUE7SUFDakMsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJLFdBQVcsQ0FBQyxLQUFLLENBQUM7U0FDckMsWUFBWSxDQUFDLE9BQU8sQ0FBQztTQUNyQixrQkFBa0IsQ0FBQyxFQUFFLEdBQUcsRUFBRSxPQUFPLENBQUMsR0FBRyxFQUFFLENBQUM7U0FDeEMsSUFBSSxFQUFFLENBQUE7SUFFVCxNQUFNLGFBQWEsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDLENBQUE7QUFDbEM7O0FDUEE7Ozs7Ozs7OztBQVNPLGVBQWUsV0FBVyxDQUFFLE9BQTBCLEVBQUUsVUFBZTs7SUFFNUUsTUFBTSxTQUFTLEdBQUcs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
