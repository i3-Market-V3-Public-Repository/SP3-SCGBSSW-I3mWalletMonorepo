import { ethers, utils } from 'ethers';
import _ from 'lodash';
import * as u8a from 'uint8arrays';
import { v4 } from 'uuid';
import { verifyJWT } from 'did-jwt';
import * as crypto from 'crypto';
import crypto__default from 'crypto';
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
import Debug from 'debug';
import { hashable } from 'object-sha';
import { mkdir, readFile, writeFile, rm } from 'fs/promises';
import { dirname } from 'path';

class WalletError extends Error {
    constructor(message, httpData) {
        super(message);
        this.code = httpData?.code ?? 1;
        this.status = httpData?.status ?? 500;
    }
}

const contractValidator = async (resource, veramo) => {
    const errors = [];
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

const jwkSecret = (secret = crypto__default.randomBytes(32)) => {
    const jwk = {
        kid: v4(),
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

const debug$6 = Debug('base-wallet:DidWalletStore');
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

const debug$5 = Debug('base-wallet:KMS');
class KeyWalletManagementSystem extends AbstractKeyManagementSystem {
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
            publicKeyHex: ethers.utils.hexlify(publicKey).substr(2) // TODO: Remove 0x from the string
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

const debug$4 = Debug('base-wallet:KeyWalletStore');
class KeyWalletStore extends AbstractKeyStore {
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
            id: v4()
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
                if (expectedClaimsDict[key] !== '' && hashable(expectedClaimsDict[key]) !== hashable(payload[key])) {
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
            const verifiedJWT = await verifyJWT(requestBody.jwt, { resolver });
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

export { BaseWallet, ConsoleToast, FileStore, NullDialog, RamStore, TestDialog, TestStore, TestToast, Veramo, WalletError, base64url, getCredentialClaims, jwkSecret };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2Vycm9ycy50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS9jb250cmFjdC12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2Uvb2JqZWN0LXZhbGlkYXRvci50cyIsIi4uLy4uL3NyYy90cy9yZXNvdXJjZS92Yy12YWxpZGF0b3IudHMiLCIuLi8uLi9zcmMvdHMvcmVzb3VyY2UvcmVzb3VyY2UtdmFsaWRhdG9yLnRzIiwiLi4vLi4vc3JjL3RzL3V0aWxzL2Jhc2U2NHVybC50cyIsIi4uLy4uL3NyYy90cy91dGlscy9nZW5lcmF0ZS1zZWNyZXQudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvY3JlZGVudGlhbC1jbGFpbXMudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvZGlzcGxheS1kaWQudHMiLCIuLi8uLi9zcmMvdHMvdXRpbHMvandzLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9kaWQtd2FsbGV0LXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9rZXktd2FsbGV0LW1hbmFnZW1lbnQtc3lzdGVtLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby9rZXktd2FsbGV0LXN0b3JlLnRzIiwiLi4vLi4vc3JjL3RzL3ZlcmFtby92ZXJhbW8udHMiLCIuLi8uLi9zcmMvdHMvd2FsbGV0L2Jhc2Utd2FsbGV0LnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3QvZGlhbG9nLnRzIiwiLi4vLi4vc3JjL3RzL3Rlc3Qvc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvdGVzdC90b2FzdC50cyIsIi4uLy4uL3NyYy90cy9pbXBsL2RpYWxvZ3MvbnVsbC1kaWFsb2cudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC9zdG9yZXMvZmlsZS1zdG9yZS50cyIsIi4uLy4uL3NyYy90cy9pbXBsL3N0b3Jlcy9yYW0tc3RvcmUudHMiLCIuLi8uLi9zcmMvdHMvaW1wbC90b2FzdC9jb25zb2xlLXRvYXN0LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJjcnlwdG8iLCJ1dWlkdjQiLCJiYXNlNjRVcmwiLCJkZWJ1ZyIsImV0aHJEaWRHZXRSZXNvbHZlciIsIndlYkRpZEdldFJlc29sdmVyIiwidXVpZCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQU1NLE1BQU8sV0FBWSxTQUFRLEtBQUssQ0FBQTtJQUlwQyxXQUFhLENBQUEsT0FBZSxFQUFFLFFBQW1CLEVBQUE7UUFDL0MsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFBO1FBQ2QsSUFBSSxDQUFDLElBQUksR0FBRyxRQUFRLEVBQUUsSUFBSSxJQUFJLENBQUMsQ0FBQTtRQUMvQixJQUFJLENBQUMsTUFBTSxHQUFHLFFBQVEsRUFBRSxNQUFNLElBQUksR0FBRyxDQUFBO0tBQ3RDO0FBQ0Y7O0FDWk0sTUFBTSxpQkFBaUIsR0FBZ0MsT0FBTyxRQUFRLEVBQUUsTUFBTSxLQUFJO0lBQ3ZGLE1BQU0sTUFBTSxHQUFZLEVBQUUsQ0FBQTtBQUUxQixJQUFBLE9BQU8sTUFBTSxDQUFBO0FBQ2YsQ0FBQzs7QUNKTSxNQUFNLGVBQWUsR0FBOEIsT0FBTyxRQUFRLEVBQUUsTUFBTSxLQUFJO0lBQ25GLE1BQU0sTUFBTSxHQUFZLEVBQUUsQ0FBQTtBQUUxQixJQUFBLE9BQU8sTUFBTSxDQUFBO0FBQ2YsQ0FBQzs7QUNITSxNQUFNLHdCQUF3QixHQUE0QyxPQUFPLFFBQVEsRUFBRSxNQUFNLEtBQUk7SUFDMUcsTUFBTSxNQUFNLEdBQVksRUFBRSxDQUFBO0lBRTFCLE1BQU0sT0FBTyxHQUFHLFFBQVEsQ0FBQyxRQUFRLENBQUMsaUJBQWlCLENBQUMsRUFBRSxDQUFBO0FBQ3RELElBQUEsUUFBUSxDQUFDLFFBQVEsR0FBRyxPQUFPLENBQUE7O0FBRzNCLElBQUEsSUFBSSxRQUFRLENBQUMsUUFBUSxLQUFLLFNBQVMsRUFBRTtRQUNuQyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksV0FBVyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7QUFDakMsS0FBQTtB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
