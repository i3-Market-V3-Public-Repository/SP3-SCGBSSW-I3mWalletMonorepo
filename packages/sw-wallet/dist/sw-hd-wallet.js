"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SwHdKeyWallet = void 0;
const crypto_1 = __importDefault(require("crypto"));
const ethers_1 = require("ethers");
const hdnode_1 = require("@ethersproject/hdnode");
const u8a = __importStar(require("uint8arrays"));
const errors_1 = require("./errors");
class SwHdKeyWallet {
    constructor(dialog, store) {
        this.dialog = dialog;
        this.store = store;
    }
    get hdData() {
        if (this._hdData === undefined) {
            throw new errors_1.SwWalletError('Hierarchical Deterministic data is undefined');
        }
        return this._hdData;
    }
    get hdNode() {
        if (this._hdNode === undefined) {
            throw new errors_1.SwWalletError('Hierarchical Deterministic node is undefined');
        }
        return this._hdNode;
    }
    async updateHdData() {
        await this.store.set('hdData', this.hdData);
    }
    async initialize() {
        let hdData = await this.store.get('hdData');
        if (hdData === undefined) {
            let mnemonic = await this.dialog.text({
                title: 'Initializing wallet',
                message: 'Use your backed BIP39 mnemmonic words (12 or 24 words) or escape for generating new ones'
            });
            // TODO: Throw execption if invalid mnemonic
            if (mnemonic === undefined || mnemonic.trim() === '') {
                const entropy = crypto_1.default.randomBytes(32);
                mnemonic = ethers_1.ethers.utils.entropyToMnemonic(entropy);
            }
            else if (!ethers_1.ethers.utils.isValidMnemonic(mnemonic)) {
                throw new errors_1.SwWalletError('Not valid mnemonic');
            }
            const confirmation = await this.dialog.confirmation({
                title: 'Init wallet?',
                message: `A new wallet is going to be created. Please note down to a secure place the following list of BIP39 words. It can be used to restore your wallet in the future.\n<input value="${mnemonic}" disabled></input>\n\n Do you want to continue?`
            });
            if (confirmation !== true) {
                throw new errors_1.SwWalletError('Initialization cancelled by the user');
            }
            hdData = { mnemonic, accounts: 0 };
            await this.store.set('hdData', hdData);
        }
        if (!ethers_1.ethers.utils.isValidMnemonic(hdData.mnemonic)) {
            throw new errors_1.SwWalletError('Not valid mnemonic');
        }
        this._hdData = hdData;
        const seed = ethers_1.ethers.utils.mnemonicToSeed(hdData.mnemonic);
        await this.initializeSeed(ethers_1.ethers.utils.arrayify(seed));
    }
    async initializeSeed(seed) {
        this._hdNode = ethers_1.ethers.utils.HDNode.fromSeed(seed);
        /* TODO: Not sure if ethers implement BIP44 Account Discovery, but just in case let us add all the potentially discovered accounts */
        // let accounts = 0
        // for (let i = 0; i <= this.hdNode.depth; i++) {
        //   accounts++
        // }
        // await this.updateAccounts(accounts)
    }
    // TODO: IMPLEMENT METHODS!
    async createAccountKeyPair() {
        const { hdNode, hdData } = this;
        // TODO: Check how paths work on ethers
        let path = hdnode_1.defaultPath;
        if (hdNode.path !== null) {
            path = hdNode.path;
        }
        const pathArr = path.split('/');
        hdData.accounts++;
        pathArr[3] = `${hdData.accounts}'`;
        const kid = pathArr.join('/');
        // Update accounts
        await this.updateHdData();
        return kid;
    }
    async getPublicKey(path) {
        const { hdNode } = this;
        const key = hdNode.derivePath(path);
        return ethers_1.ethers.utils.arrayify(key.publicKey);
    }
    async signDigest(path, messageDigest) {
        const { hdNode } = this;
        // Get signing key
        const childHdNode = hdNode.derivePath(path);
        const key = childHdNode.privateKey;
        const signingKey = new ethers_1.ethers.utils.SigningKey(key);
        // Ask for user confirmation
        const confirmation = await this.dialog.confirmation({
            title: 'Sign?',
            message: `Are you sure you want to sign using key <code>${key}</code> the following hex data: \n<code>${ethers_1.ethers.utils.hexlify(messageDigest)}</code>`,
            // authenticated: false,
            acceptMsg: 'Sign',
            rejectMsg: 'Reject'
        });
        if (confirmation !== true) {
            throw new errors_1.SwWalletError('Signature rejected by user');
        }
        // Sign
        const signature = signingKey.signDigest(messageDigest);
        const signatureHex = ethers_1.ethers.utils.joinSignature(signature);
        // Remove 0x
        const fixedSignature = u8a.fromString(signatureHex.substring(2), 'base16');
        return fixedSignature;
    }
    async delete(id) {
        // Keys are not stored in any place
        return true;
    }
    async wipe() {
        // Perform delete
        delete this._hdNode;
        await this.store.delete('hdData');
        // Reinitialize
        await this.initialize();
    }
}
exports.SwHdKeyWallet = SwHdKeyWallet;
//# sourceMappingURL=sw-hd-wallet.js.map