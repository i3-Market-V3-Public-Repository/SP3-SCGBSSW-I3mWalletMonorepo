import { importJWK, GeneralSign, generalVerify, SignJWT, jwtVerify, CompactEncrypt, compactDecrypt, generateSecret, exportJWK, calculateJwkThumbprint } from 'jose';
import { randBytes } from 'bigint-crypto-utils';
import { hashable } from 'object-sha';
import { ethers } from 'ethers';
import { bufToHex, hexToBuf } from 'bigint-conversion';
import * as base64 from '@juanelas/base64';
import { decode } from '@juanelas/base64';

async function verifyKeyPair(pubJWK, privJWK) {
    if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
        throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg');
    }
    const pubKey = await importJWK(pubJWK);
    const privKey = await importJWK(privJWK);
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
        else if (expectedPayloadClaims[key] !== '' && hashable(expectedPayloadClaims[key]) !== hashable(payload[key])) {
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
        if (expectedDataExchange[key] !== '' && hashable(expectedDataExchange[key]) !== hashable(dataExchange[key])) {
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
    const key = await importJWK(secret);
    return await new CompactEncrypt(block)
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
    const key = await importJWK(secret);
    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] });
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
        const buf = await crypto.subtle.digest(algorithm, hashInput);
        const h = '0123456789abcdef';
        (new Uint8Array(buf)).forEach((v) => {
            digest += h[v >> 4] + h[v & 15];
        });
    }
    return digest;
}

/**
 * Create a random (high entropy) symmetric secret for AES-256-GCM
 *
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */
async function oneTimeSecret(encAlg) {
    const key = await generateSecret(encAlg, { extractable: true });
    const jwk = await exportJWK(key);
    const thumbprint = await calculateJwkThumbprint(jwk);
    jwk.kid = thumbprint;
    jwk.alg = encAlg;
    return { jwk, hex: bufToHex(decode(jwk.k)) };
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
            secretCommitment: await sha(new Uint8Array(hexToBuf(this.block.secret.hex)), this.exchange.hashAlg)
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
            const rpcProvider = new ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl);
            if (this.jwkPairOrig.privateJwk.d === undefined) {
                throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key');
            }
            const privateKey = base64.decode(this.jwkPairOrig.privateJwk.d);
            const signingKey = new ethers.utils.SigningKey(privateKey);
            const signer = new ethers.Wallet(signingKey, rpcProvider);
            dltConfig.signer = { address: await signer.getAddress(), signer };
            dltConfig.contract = new ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, signer);
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
            const secret = ethers.BigNumber.from(`0x${this.block.secret.hex}`);
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
            hex: bufToHex(base64.decode(secret.k)),
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
        let secretBn = ethers.BigNumber.from(0);
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
        const jwk = await exportJWK(new Uint8Array(hexToBuf(secretHex)));
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

export { NonRepudiationDest, NonRepudiationOrig, createProof, jweDecrypt, jweEncrypt, oneTimeSecret, sha, verifyKeyPair, verifyProof };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL3ZlcmlmeUtleVBhaXIudHMiLCIuLi8uLi9zcmMvdHMvY3JlYXRlUHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvdmVyaWZ5UHJvb2YudHMiLCIuLi8uLi9zcmMvdHMvandlLnRzIiwiLi4vLi4vc3JjL3RzL3NoYS50cyIsIi4uLy4uL3NyYy90cy9vbmVUaW1lU2VjcmV0LnRzIiwiLi4vLi4vc3JjL2Jlc3UvTm9uUmVwdWRpYXRpb24udHMiLCIuLi8uLi9zcmMvdHMvTm9uUmVwdWRpYXRpb25PcmlnLnRzIiwiLi4vLi4vc3JjL3RzL05vblJlcHVkaWF0aW9uRGVzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiYmFzZTY0ZGVjb2RlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQUdPLGVBQWUsYUFBYSxDQUFFLE1BQVcsRUFBRSxPQUFZO0lBQzVELElBQUksTUFBTSxDQUFDLEdBQUcsS0FBSyxTQUFTLElBQUksT0FBTyxDQUFDLEdBQUcsS0FBSyxTQUFTLElBQUksTUFBTSxDQUFDLEdBQUcsS0FBSyxPQUFPLENBQUMsR0FBRyxFQUFFO1FBQ3ZGLE1BQU0sSUFBSSxLQUFLLENBQUMsMEVBQTBFLENBQUMsQ0FBQTtLQUM1RjtJQUNELE1BQU0sTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFBO0lBQ3RDLE1BQU0sT0FBTyxHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0lBQ3hDLE1BQU0sS0FBSyxHQUFHLE1BQU0sU0FBUyxDQUFDLEVBQUUsQ0FBQyxDQUFBO0lBQ2pDLE1BQU0sR0FBRyxHQUFHLE1BQU0sSUFBSSxXQUFXLENBQUMsS0FBSyxDQUFDO1NBQ3JDLFlBQVksQ0FBQyxPQUFPLENBQUM7U0FDckIsa0JBQWtCLENBQUMsRUFBRSxHQUFHLEVBQUUsT0FBTyxDQUFDLEdBQUcsRUFBRSxDQUFDO1NBQ3hDLElBQUksRUFBRSxDQUFBO0lB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
