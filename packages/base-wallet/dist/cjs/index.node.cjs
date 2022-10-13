'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var ethers = require('ethers');
var _ = require('lodash');
var u8a = require('uint8arrays');
var uuid = require('uuid');
var didJwt$1 = require('did-jwt');
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
var didJwt = require('@veramo/did-jwt');
var credentialW3c = require('@veramo/credential-w3c');
var Debug = require('debug');
var objectSha = require('object-sha');
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

const encode = (buf) => {
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
const decode = (str) => {
    return Buffer.from(str, 'base64');
};
var base64url = {
    encode,
    decode
};

const jwkSecret = (secret = crypto__default["default"].randomBytes(32)) => {
    const jwk = {
        kid: uuid.v4(),
        kty: 'oct',
        k: base64url.encode(secret)
    };
    return jwk;
};

function getCredentialClaims(vc) {
    return Object.keys(vc.credentialSubject)
        .filter(claim => claim !== 'id');
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

/**
 * Prepares header and payload, received as standard JS objects, to be signed as needed for a JWS/JWT signature.
 *
 * @param header
 * @param payload
 * @param encoding
 * @returns <base64url(header)>.<base64url(payload)>
 */
function jwsSignInput(header, payload, encoding) {
    const encodedHeader = base64url.encode(Buffer.from(JSON.stringify(header), 'binary'));
    const encodedPayload = base64url.encode(Buffer.from(JSON.stringify(payload), encoding));
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
            header: JSON.parse(base64url.decode(parts[1]).toString('binary')),
            payload: JSON.parse(base64url.decode(parts[2]).toString(encoding)),
            signature: parts[3],
            data: `${parts[1]}.${parts[2]}`
        };
    }
    throw new Error('invalid_argument: Incorrect format JWS');
}

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
                        new didJwt.JwtMessageHandler(),
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
    async resourceList() {
        const resources = await this.getResources();
        return Object.keys(resources).map(key => ({
            id: resources[key].id
        }));
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
        if (resource.type === 'VerifiableCredential') {
            const credentialSubject = getCredentialClaims(resource.resource)
                .map(claim => `  - ${claim}: ${JSON.stringify(resource.resource.credentialSubject[claim])}`)
                .join('\n');
            const confirmation = await this.dialog.confirmation({
                message: `Do you want to add the following verifiable credential: \n${credentialSubject}`
            });
            if (confirmation !== true) {
                throw new WalletError('User cannceled the operation', { status: 403 });
            }
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
        let decodedJwt;
        try {
            decodedJwt = decodeJWS(requestBody.jwt);
        }
        catch (error) {
            return {
                verification: 'failed',
                error: 'Invalid JWT format'
            };
        }
        const payload = decodedJwt.payload;
        if (requestBody.expectedPayloadClaims !== undefined) {
            const expectedClaimsDict = requestBody.expectedPayloadClaims;
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
        const resolver = { resolve: async (didUrl) => await this.veramo.agent.resolveDid({ didUrl }) };
        try {
            const verifiedJWT = await didJwt$1.verifyJWT(requestBody.jwt, { resolver });
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
                throw new WalletError('unknown error during verification');
        }
    }
    /**
     * Retrieves information regarding the current connection to the DLT.
     * @returns
     */
    async providerinfo() {
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
exports.base64url = base64url;
exports.getCredentialClaims = getCredentialClaims;
exports.jwkSecret = jwkSecret;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvdmMtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3Jlc291cmNlL3Jlc291cmNlLXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy91dGlscy9iYXNlNjR1cmwudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZ2VuZXJhdGUtc2VjcmV0LnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2NyZWRlbnRpYWwtY2xhaW1zLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2Rpc3BsYXktZGlkLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2p3cy50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8vZGlkLXdhbGxldC1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8va2V5LXdhbGxldC1tYW5hZ2VtZW50LXN5c3RlbS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8va2V5LXdhbGxldC1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy92ZXJhbW8vdmVyYW1vLnRzIiwiLi4vLi4vc3JjL3RzL3dhbGxldC9iYXNlLXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy90ZXN0L2RpYWxvZy50cyIsIi4uLy4uL3NyYy90cy90ZXN0L3N0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3QvdG9hc3QudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9kaWFsb2dzL251bGwtZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvc3RvcmVzL2ZpbGUtc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9zdG9yZXMvcmFtLXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL2ltcGwvdG9hc3QvY29uc29sZS10b2FzdC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiY3J5cHRvIiwidXVpZHY0IiwiYmFzZTY0VXJsIiwiZGVidWciLCJEZWJ1ZyIsIkFic3RyYWN0RElEU3RvcmUiLCJBYnN0cmFjdEtleU1hbmFnZW1lbnRTeXN0ZW0iLCJldGhlcnMiLCJ1OGEiLCJBYnN0cmFjdEtleVN0b3JlIiwidXRpbHMiLCJldGhyRGlkUmVzb2x2ZXIiLCJldGhyRGlkR2V0UmVzb2x2ZXIiLCJ3ZWJEaWRSZXNvbHZlciIsIndlYkRpZEdldFJlc29sdmVyIiwiUmVzb2x2ZXIiLCJXZWJESURQcm92aWRlciIsIkV0aHJESURQcm92aWRlciIsImNyZWF0ZUFnZW50IiwiS2V5TWFuYWdlciIsIkRJRE1hbmFnZXIiLCJDcmVkZW50aWFsSXNzdWVyIiwiU2VsZWN0aXZlRGlzY2xvc3VyZSIsIk1lc3NhZ2VIYW5kbGVyIiwiSnd0TWVzc2FnZUhhbmRsZXIiLCJTZHJNZXNzYWdlSGFuZGxlciIsIlczY01lc3NhZ2VIYW5kbGVyIiwiRElEUmVzb2x2ZXJQbHVnaW4iLCJfIiwidXVpZCIsImhhc2hhYmxlIiwidmVyaWZ5SldUIiwibWtkaXIiLCJkaXJuYW1lIiwicmVhZEZpbGUiLCJ3cml0ZUZpbGUiLCJybSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBTU0sTUFBTyxXQUFZLFNBQVEsS0FBSyxDQUFBO0lBSXBDLFdBQWEsQ0FBQSxPQUFlLEVBQUUsUUFBbUIsRUFBQTtRQUMvQyxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7UUFDZCxJQUFJLENBQUMsSUFBSSxHQUFHLFFBQVEsRUFBRSxJQUFJLElBQUksQ0FBQyxDQUFBO1FBQy9CLElBQUksQ0FBQyxNQUFNLEdBQUcsUUFBUSxFQUFFLE1BQU0sSUFBSSxHQUFHLENBQUE7S0FDdEM7QUFDRjs7QUNaTSxNQUFNLHdCQUF3QixHQUFjLE9BQU8sUUFBUSxFQUFFLE1BQU0sS0FBSTtJQUM1RSxNQUFNLE1BQU0sR0FBWSxFQUFFLENBQUE7SUFFMUIsTUFBTSxPQUFPLEdBQUcsUUFBUSxDQUFDLFFBQVEsQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFLENBQUE7QUFDdEQsSUFBQSxRQUFRLENBQUMs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
