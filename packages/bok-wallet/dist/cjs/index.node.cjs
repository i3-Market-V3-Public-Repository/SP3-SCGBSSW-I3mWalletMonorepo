'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var crypto = require('crypto');
var ethers = require('ethers');
var uuid = require('uuid');
var u8a = require('uint8arrays');
var baseWallet = require('@i3m/base-wallet');

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

var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var u8a__namespace = /*#__PURE__*/_interopNamespace(u8a);

class BokWalletError extends baseWallet.WalletError {
}

class BokKeyWallet {
    constructor(dialog, store) {
        this.dialog = dialog;
        this.store = store;
    }
    async import(privateKeyHex) {
        const kid = uuid.v4();
        const publicKeyHex = ethers.ethers.utils.computePublicKey(baseWallet.parseHex(privateKeyHex));
        const key = {
            kid,
            type: 'Secp256k1',
            publicKeyHex: baseWallet.parseHex(publicKeyHex, false),
            privateKeyHex: baseWallet.parseHex(privateKeyHex, false)
        };
        const keys = await this.store.get('keys');
        await this.store.set('keys', {
            ...keys,
            [kid]: key
        });
        return key;
    }
    async createAccountKeyPair() {
        const privateKeyHex = crypto__default["default"].randomBytes(32).toString('hex');
        const key = await this.import(privateKeyHex);
        return key.kid;
    }
    async getPublicKey(kid) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        return ethers.ethers.utils.arrayify(baseWallet.parseHex(keys[kid].publicKeyHex));
    }
    async signDigest(kid, messageDigest) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        // Get signing key
        const key = baseWallet.parseHex(keys[kid].privateKeyHex);
        const signingKey = new ethers.ethers.utils.SigningKey(key);
        // Ask for user confirmation
        const confirmation = await this.dialog.confirmation({
            title: 'Sign?',
            message: `Are you sure you want to sign using key <code>${key}</code> the following hex data: \n<code>${ethers.ethers.utils.hexlify(messageDigest)}</code>`,
            // authenticated: false,
            acceptMsg: 'Sign',
            rejectMsg: 'Reject'
        });
        if (confirmation !== true) {
            throw new BokWalletError('Signature rejected by user');
        }
        // Sign
        const signature = signingKey.signDigest(messageDigest);
        const signatureHex = ethers.ethers.utils.joinSignature(signature);
        // Remove 0x
        const fixedSignature = u8a__namespace.fromString(signatureHex.substring(2), 'base16');
        return fixedSignature;
    }
    async delete(kid) {
        await this.store.delete(`keys.${kid}`);
        return true;
    }
    async wipe() { }
}

class BokWallet extends baseWallet.BaseWallet {
    async importDid(importInfo) {
        if (importInfo === undefined) {
            importInfo = await this.dialog.form({
                title: 'Import DID',
                descriptors: {
                    alias: { type: 'text', message: 'Set an alias for your DID' },
                    privateKey: { type: 'text', message: 'Paste the private key' }
                },
                order: ['alias', 'privateKey']
            });
        }
        if (importInfo === undefined) {
            return;
        }
        // if (!importInfo.privateKey.startsWith('0x')) {
        //   throw new BokWalletError('Private key must start with 0x')
        // }
        const keyWallet = this.getKeyWallet();
        const key = await keyWallet.import(baseWallet.parseHex(importInfo.privateKey));
        const compressedPublicKey = ethers.ethers.utils.computePublicKey(baseWallet.parseHex(key.publicKeyHex), true);
        await this.veramo.agent.didManagerImport({
            did: `${this.provider}:${compressedPublicKey}`,
            alias: importInfo.alias,
            controllerKeyId: key.kid,
            keys: [{
                    ...key,
                    type: 'Secp256k1',
                    kms: this.veramo.defaultKms
                }],
            provider: this.provider,
            services: []
        });
    }
}

const builder = async (opts) => {
    const keyWallet = new BokKeyWallet(opts.dialog, opts.store);
    return new BokWallet({ ...opts, keyWallet });
};

exports.BokWallet = BokWallet;
exports["default"] = builder;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMudHMiLCIuLi8uLi9zcmMvdHMvYm9rLWtleS13YWxsZXQudHMiLCIuLi8uLi9zcmMvdHMvYm9rLXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiV2FsbGV0RXJyb3IiLCJ1dWlkIiwiZXRoZXJzIiwicGFyc2VIZXgiLCJjcnlwdG8iLCJ1OGEiLCJCYXNlV2FsbGV0Il0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFFTSxNQUFPLGNBQWUsU0FBUUEsc0JBQVcsQ0FBQTtBQUFHOztNQ1NyQyxZQUFZLENBQUE7SUFDdkIsV0FBdUIsQ0FBQSxNQUFjLEVBQVksS0FBNEIsRUFBQTtRQUF0RCxJQUFNLENBQUEsTUFBQSxHQUFOLE1BQU0sQ0FBUTtRQUFZLElBQUssQ0FBQSxLQUFBLEdBQUwsS0FBSyxDQUF1QjtLQUFLO0lBRWxGLE1BQU0sTUFBTSxDQUFFLGFBQXFCLEVBQUE7QUFDakMsUUFBQSxNQUFNLEdBQUcsR0FBR0MsT0FBSSxFQUFFLENBQUE7QUFDbEIsUUFBQSxNQUFNLFlBQVksR0FBR0MsYUFBTSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQ0MsbUJBQVEsQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFBO0FBRTNFLFFBQUEsTUFBTSxHQUFHLEdBQVE7WUFDZixHQUFHO0FBQ0gsWUFBQSxJQUFJLEVBQUUsV0FBVztBQUNqQixZQUFBLFlBQVksRUFBRUEsbUJBQVEsQ0FBQyxZQUFZLEVBQUUsS0FBSyxDQUFDO0FBQzNDLFlBQUEsYUFBYSxFQUFFQSxtQkFBUSxDQUFDLGFBQWEsRUFBRSxLQUFLLENBQUM7U0FDOUMsQ0FBQTtRQUNELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUE7QUFFekMsUUFBQSxN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
