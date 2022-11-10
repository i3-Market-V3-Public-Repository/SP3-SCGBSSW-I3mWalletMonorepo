'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var ethers = require('ethers');
var _ = require('lodash');
var u8a = require('uint8arrays');
var uuid = require('uuid');
var didJwt = require('did-jwt');
var crypto = require('crypto');
var objectSha = require('object-sha');
var nonRepudiationLibrary = require('@i3m/non-repudiation-library');
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
            case 'Contract': {
                const confirmation = await this.dialog.confirmation({
                    message: `Do you want to add the a data sharing agreement to your wallet?\n\tofferingId: ${resource.resource.dataSharingAgreement.dataOfferingDescription.dataOfferingId}\n\tproviderDID: ${resource.resource.dataSharingAgreement.parties.providerDid}\n\tconsumerDID: ${resource.resource.dataSharingAgreement.parties.consumerDid}`
                });
                if (confirmation !== true) {
                    throw new WalletError('User cannceled the operation', { status: 403 });
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
exports.verifyDataSharingAgreementSignature = verifyDataSharingAgreementSignature;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy91dGlscy9iYXNlNjR1cmwudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvandzLnRzIiwiLi4vLi4vc3JjL3RzL2Vycm9ycy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9jcmVkZW50aWFsLWNsYWltcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kaWQtand0LXZlcmlmeS50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kYXRhLXNoYXJpbmctYWdyZWVtZW50LXZhbGlkYXRpb24udHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZ2VuZXJhdGUtc2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL3BhcnNlQWRkcmVzcy50cyIsIi4uLy4uL3NyYy90cy91dGlscy9wYXJzZUhleC50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9jb250cmFjdC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvZGF0YUV4Y2hhbmdlLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9ucnAtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL29iamVjdC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvdmMtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL3Jlc291cmNlLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy91dGlscy9kaXNwbGF5LWRpZC50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8vZGlkLXdhbGxldC1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8va2V5LXdhbGxldC1tYW5hZ2VtZW50LXN5c3RlbS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8va2V5LXdhbGxldC1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8vdmVyYW1vLnRzIiwiLi4vLi4vc3JjL3RzL3dhbGxldC9iYXNlLXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy90ZXN0L2RpYWxvZy50cyIsIi4uLy4uL3NyYy90cy90ZXN0L3N0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3QvdG9hc3QudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9kaWFsb2dzL251bGwtZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvc3RvcmVzL2ZpbGUtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9zdG9yZXMvcmFtLXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvdG9hc3QvY29uc29sZS10b2FzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiYmFzZTY0dXJsIiwiXyIsInZlcmlmeUpXVCIsImNyeXB0byIsInV1aWR2NCIsImV0aGVycyIsInZhbGlkYXRlRGF0YVNoYXJpbmdBZ3JlZW1lbnRTY2hlbWEiLCJ2YWxpZGF0ZURhdGFFeGNoYW5nZUFncmVlbWVudCIsInZlcmlmeUtleVBhaXIiLCJkaWdlc3QiLCJkZWJ1ZyIsIkRlYnVnIiwiandzRGVjb2RlIiwidmFsaWRhdGVEYXRhRXhjaGFuZ2UiLCJBYnN0cmFjdERJRFN0b3JlIiwiQWJzdHJhY3RLZXlNYW5hZ2VtZW50U3lzdGVtIiwidThhIiwiQWJzdHJhY3RLZXlTdG9yZSIsInV0aWxzIiwiZXRockRpZFJlc29sdmVyIiwiZXRockRpZEdldFJlc29sdmVyIiwid2ViRGlkUmVzb2x2ZXIiLCJ3ZWJEaWRHZXRSZXNvbHZlciIsIlJlc29sdmVyIiwiV2ViRElEUHJvdmlkZXIiLCJFdGhyRElEUHJvdmlkZXIiLCJjcmVhdGVBZ2VudCIsIktleU1hbmFnZXIiLCJESURNYW5hZ2VyIiwiQ3JlZGVudGlhbElzc3VlciIsIlNlbGVjdGl2ZURpc2Nsb3N1cmUiLCJNZXNzYWdlSGFuZGxlciIsIkp3dE1lc3NhZ2VIYW5kbGVyIiwiU2RyTWVzc2FnZUhhbmRsZXIiLCJXM2NNZXNzYWdlSGFuZGxlciIsIkRJRFJlc29sdmVyUGx1Z2luIiwidXVpZCIsImV4Y2hhbmdlSWQiLCJkaWRKd3RWZXJpZnlGbiIs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
