'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var ethers = require('ethers');
var _ = require('lodash');
var u8a = require('uint8arrays');
var uuid = require('uuid');
var objectSha = require('object-sha');
var nonRepudiationLibrary = require('@i3m/non-repudiation-library');
var didJwt = require('did-jwt');
var crypto = require('crypto');
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
        await nonRepudiationLibrary.verifyKeyPair(publicJwk, privateJwk);
        // Let us rewrite the JWK strings in sorted order
        keyPair.publicJwk = await nonRepudiationLibrary.parseJwk(publicJwk, true);
        keyPair.privateJwk = await nonRepudiationLibrary.parseJwk(privateJwk, true);
        // Let us use a unique id that can be easily found. This way it can be easily linked to contracts added later
        resource.id = await objectSha.digest(keyPair.publicJwk);
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

const jwkSecret = (secret = crypto__default["default"].randomBytes(32)) => {
    const jwk = {
        kid: uuid.v4(),
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
    return ethers.ethers.utils.getAddress('0x' + hex);
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

const contractValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const { dataSharingAgreement, keyPair } = resource.resource;
        // Verify schema
        const schemaValidationErrors = await nonRepudiationLibrary.validateDataSharingAgreementSchema(dataSharingAgreement);
        if (schemaValidationErrors.length > 0)
            return schemaValidationErrors;
        if (dataSharingAgreement.parties.consumerDid === dataSharingAgreement.parties.providerDid) {
            throw new Error('the same identity cannot be at the same time the consumer and the provider');
        }
        // Validate dataExchangeAgreemeent
        const deaErrors = await nonRepudiationLibrary.validateDataExchangeAgreement(dataSharingAgreement.dataExchangeAgreement);
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
        // Let us use a unique id that can be easily found. This way it can be easily linked to NR proofs
        resource.id = await objectSha.digest(dataSharingAgreement.dataExchangeAgreement);
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

const debug$8 = Debug__default["default"]('base-wallet:NrpValidator');
const nrpValidator = async (resource, veramo) => {
    const errors = [];
    try {
        const jws = resource.resource;
        const decodedProof = await nonRepudiationLibrary.jwsDecode(jws, (header, payload) => {
            const key = payload.iss;
            return JSON.parse(payload.exchange[key]);
        });
        const deErrors = await nonRepudiationLibrary.validateDataExchange(decodedProof.payload.exchange);
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

const debug$7 = Debug__default["default"]('base-wallet:DidWalletStore');
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

const debug$6 = Debug__default["default"]('base-wallet:KMS');
class KeyWalletManagementSystem extends keyManager.AbstractKeyManagementSystem {
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
            publicKeyHex: ethers.ethers.utils.hexlify(publicKey).substr(2) // TODO: Remove 0x from the string
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

const debug$5 = Debug__default["default"]('base-wallet:KeyWalletStore');
class KeyWalletStore extends keyManager.AbstractKeyStore {
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

const debug$4 = Debug__default["default"]('base-wallet:base-wallet.ts');
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
        const resource = { ...requestBody, id: uuid.v4() };
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
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add the a data sharing agreement to your wallet?\n\tofferingId: ${resource.resource.dataSharingAgreement.dataOfferingDescription.dataOfferingId}\n\tproviderDID: ${resource.resource.dataSharingAgreement.parties.providerDid}\n\tconsumerDID: ${resource.resource.dataSharingAgreement.parties.consumerDid}`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
                }
                // A contract parent resource is a keyPair
                const keyPairId = await objectSha.digest(resource.resource.keyPair.publicJwk);
                resource.parentResource = keyPairId;
                // If the keyPair was not yet created, we create it
                if (!await this.store.has(`resources.${resource.parentResource}`)) {
                    const keyPairResource = {
                        id: keyPairId,
                        type: 'KeyPair',
                        resource: { keyPair: resource.resource.keyPair }
                    };
                    try {
                        await this.setResource(keyPairResource);
                    }
                    catch (error) {
                        throw new WalletError('Failed to add resource', { status: 500 });
                    }
                }
                break;
            }
            case 'NonRepudiationProof': {
                const decodedProof = decodeJWS(resource.resource).payload;
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add a non repudiation proof into your wallet?\nType: ${decodedProof.proofType}\nExchangeId: ${await nonRepudiationLibrary.exchangeId(decodedProof.exchange)}`
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
                        parentResource: await objectSha.digest(dataExchangeAgreement),
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
 * A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.
 *
 * `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)
 *
 * The wallet's storage-file can be encrypted for added security by passing an optional `password`.
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
exports.verifyDataSharingAgreementSignature = verifyDataSharingAgreementSignature;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy91dGlscy9iYXNlNjR1cmwudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvandzLnRzIiwiLi4vLi4vc3JjL3RzL2Vycm9ycy50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9rZXlQYWlyLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy91dGlscy9jcmVkZW50aWFsLWNsYWltcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kaWQtand0LXZlcmlmeS50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kYXRhLXNoYXJpbmctYWdyZWVtZW50LXZhbGlkYXRpb24udHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZ2VuZXJhdGUtc2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3BhcnNlQWRkcmVzcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9jb250cmFjdC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvZGF0YUV4Y2hhbmdlLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9ucnAtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL29iamVjdC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvdmMtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL3Jlc291cmNlLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kaXNwbGF5LWRpZC50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8vZGlkLXdhbGxldC1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8va2V5LXdhbGxldC1tYW5hZ2VtZW50LXN5c3RlbS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8va2V5LXdhbGxldC1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8vdmVyYW1vLnRzIiwiLi4vLi4vc3JjL3RzL3dhbGxldC9iYXNlLXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy90ZXN0L2RpYWxvZy50cyIsIi4uLy4uL3NyYy90cy90ZXN0L3N0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3QvdG9hc3QudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9kaWFsb2dzL251bGwtZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvc3RvcmVzL2ZpbGUtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9zdG9yZXMvcmFtLXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvdG9hc3QvY29uc29sZS10b2FzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiYmFzZTY0dXJsIiwidmVyaWZ5S2V5UGFpciIsInBhcnNlSndrIiwiZGlnZXN0IiwiXyIsInZlcmlmeUpXVCIsImNyeXB0byIsInV1aWR2NCIsImV0aGVycyIsInZhbGlkYXRlRGF0YVNoYXJpbmdBZ3JlZW1lbnRTY2hlbWEiLCJ2YWxpZGF0ZURhdGFFeGNoYW5nZUFncmVlbWVudCIsImRlYnVnIiwiRGVidWciLCJqd3NEZWNvZGUiLCJ2YWxpZGF0ZURhdGFFeGNoYW5nZSIsIkFic3RyYWN0RElEU3RvcmUiLCJBYnN0cmFjdEtleU1hbmFnZW1lbnRTeXN0ZW0iLCJ1OGEiLCJBYnN0cmFjdEtleVN0b3JlIiwidXRpbHMiLCJldGhyRGlkUmVzb2x2ZXIiLCJldGhyRGlkR2V0UmVzb2x2ZXIiLCJ3ZWJEaWRSZXNvbHZlciIsIndlYkRpZEdldFJlc29sdmVyIiwiUmVzb2x2ZXIiLCJXZWJESURQcm92aWRlciIsIkV0aHJESURQcm92aWRlciIsImNyZWF0ZUFnZW50IiwiS2V5TWFuYWdlciIsIkRJRE1hbmFnZXIiLCJDcmVkZW50aWFsSXNzdWVyIiwiU2VsZWN0aXZlRGlzY2xvc3VyZSIsIk1lc3NhZ2VIYW5kbGVyIiwiSnd0TWVzc2FnZUhhbmRsZXIiLCJTZHJNZXNzYWdlSGFuZGxlciIsIlczY01lc3NhZ2VIYW5kbGVyIiwiRElEUmVzb2x2ZXJQbHVnaW4iLCJ1dWlkIiwiZXhjaGFuZ2VJZCIsImRpZEp3dFZlcmlmeUZuIiwibWtkaXIiLCJkaXJuYW1lIiwicmVhZEZpbGUiLCJ3cml0ZUZpbGUiLCJybSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLE1BQU0sTUFBTSxHQUFHLENBQUMsR0FBVyxLQUFZO0lBQ3JDLE9BQU8sR0FBRyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEVBQUUsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQTtBQUN6RixDQUFDLENBQUE7QUFFRCxNQUFNLE1BQU0sR0FBRyxDQUFDLEdBQVcsS0FBWTtJQUNyQyxPQUFPLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0FBQ25DLENBQUMsQ0FBQTtBQUVELGdCQUFlO0lBQ2IsTUFBTTtJQUNOLE1BQU07Q0FDUDs7QUNGRDs7Ozs7OztBQU9HO1NBQ2EsWUFBWSxDQUFFLE1BQWMsRUFBRSxPQUFlLEVBQUUsUUFBeUIsRUFBQTtJQUN0RixNQUFNLGFBQWEsR0FBR0EsU0FBUyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFDLEVBQUUsUUFBUSxDQUFDLENBQUMsQ0FBQTtJQUNyRixNQUFNLGNBQWMsR0FBR0EsU0FBUyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLEVBQUUsUUFBUSxDQUFDLENBQUMsQ0FBQTtBQUV2RixJQUFBLE9BQU8sQ0FBRyxFQUFBLGFBQWEsQ0FBSSxDQUFBLEVBQUEsY0FBYyxFQUFFLENBQUE7QUFDN0MsQ0FBQztBQUVEOzs7Ozs7QUFNRztB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
