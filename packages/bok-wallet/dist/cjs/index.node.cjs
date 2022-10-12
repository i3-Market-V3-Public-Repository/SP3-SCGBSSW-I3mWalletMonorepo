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
        const publicKeyHex = ethers.ethers.utils.computePublicKey(`0x${privateKeyHex}`).substring(2);
        const key = {
            kid,
            type: 'Secp256k1',
            publicKeyHex,
            privateKeyHex
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
        return ethers.ethers.utils.arrayify(`0x${keys[kid].publicKeyHex}`);
    }
    async signDigest(kid, messageDigest) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        // Get signing key
        const key = `0x${keys[kid].privateKeyHex}`;
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
        if (!importInfo.privateKey.startsWith('0x')) {
            throw new BokWalletError('Private key must start with 0x');
        }
        const keyWallet = this.getKeyWallet();
        const key = await keyWallet.import(importInfo.privateKey.substring(2));
        const compressedPublicKey = ethers.ethers.utils.computePublicKey(`0x${key.publicKeyHex}`, true);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9lcnJvcnMudHMiLCIuLi8uLi9zcmMvdHMvYm9rLWtleS13YWxsZXQudHMiLCIuLi8uLi9zcmMvdHMvYm9rLXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiV2FsbGV0RXJyb3IiLCJ1dWlkIiwiZXRoZXJzIiwiY3J5cHRvIiwidThhIiwiQmFzZVdhbGxldCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBRU0sTUFBTyxjQUFlLFNBQVFBLHNCQUFXLENBQUE7QUFBRzs7TUNTckMsWUFBWSxDQUFBO0lBQ3ZCLFdBQXVCLENBQUEsTUFBYyxFQUFZLEtBQTRCLEVBQUE7UUFBdEQsSUFBTSxDQUFBLE1BQUEsR0FBTixNQUFNLENBQVE7UUFBWSxJQUFLLENBQUEsS0FBQSxHQUFMLEtBQUssQ0FBdUI7S0FBSztJQUVsRixNQUFNLE1BQU0sQ0FBRSxhQUFxQixFQUFBO0FBQ2pDLFFBQUEsTUFBTSxHQUFHLEdBQUdDLE9BQUksRUFBRSxDQUFBO0FBQ2xCLFFBQUEsTUFBTSxZQUFZLEdBQUdDLGFBQU0sQ0FBQyxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBSyxFQUFBLEVBQUEsYUFBYSxFQUFFLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFFckYsUUFBQSxNQUFNLEdBQUcsR0FBUTtZQUNmLEdBQUc7QUFDSCxZQUFBLElBQUksRUFBRSxXQUFXO1lBQ2pCLFlBQVk7WUFDWixhQUFhO1NBQ2QsQ0FBQTtRQUNELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUE7QUFFekMsUUFBQSxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLE1BQU0sRUFBRTtBQUMzQixZQUFBLEdBQUcsSUFBSTtZQUNQLENBQUMsR0FBRyxHQUFHLEdBQUc7QUFDWCxTQUFBLENBQUMsQ0FBQTtBQUVGLFFBQUEsT0FBTyxHQUFHLENBQUE7S0FDWDtBQUVELElBQUEsTUFBTSxvQkFBb0IsR0FBQTtBQUN4QixRQUFBLE1BQU0sYUFBYSxHQUFHQywwQkFBTSxDQUFDLFdBQVcsQ0FBQyxFQUFFLENBQUMsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUE7UUFDNUQsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLGFBQWEsQ0FBQyxDQUFBO1FBQzVDLE9BQU8sR0FBRyxDQUFDLEdBQUcsQ0FBQTtLQUNmO0lBRUQsTUFBTSxZQUFZLENBQUUsR0FBVyxFQUFBO1FBQzdCLE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUE7UUFDekMsSUFBSSxJQUFJLEtBQUssU0FBUyxFQUFFO0FBQ3RCLFlBQUEsTUFBTSxJQUFJLGNBQWMsQ0FBQyx5QkFBeUIsQ0FBQyxDQUFBO0FBQ3BELFNBQUE7QUFFRCxRQUFBLE9BQU9ELGFBQU0sQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUEsRUFBQSxFQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxZQUFZLENBQUEsQ0FBRSxDQUFDLENBQUE7S0FDNUQ7QUFFRCxJQUFBLE1BQU0sVUFBVSxDQUFFLEdBQVcsRUFBRSxhQUF5QixFQUFBO1FBQ3RELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUE7UUFDekMsSUFBSSxJQUFJLEtBQUssU0FBUyxFQUFFO0FBQ3RCLFlBQUEsTUFBTSxJQUFJLGNBQWMsQ0FBQyx5QkFBeUIsQ0FBQyxDQUFBO0FBQ3BELFNBQUE7O1FBR0QsTUFBTSxHQUFHLEdBQUcsQ0FBQSxFQUFBLEVBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLGFBQWEsQ0FBQSxDQUFFLENBQUE7UUFDMUMsTUFBTSxVQUFVLEdBQUcsSUFBSUEsYUFBTSxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUE7O1FBR25ELE1BQU0sWUFBWSxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUM7QUFDbEQsWUFBQSxLQUFLLEVBQUUsT0FBTztBQUNkLFlBQUEsT0FBTyxFQUFFLENBQUEsOENBQUEsRUFBaUQsR0FBRyxDQUFBLHdDQUFBLEVBQTJDQSxhQUFNLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBUyxPQUFBLENBQUE7O0FBRXBKLFlBQUEsU0FBUyxFQUFFLE1BQU07QUFDakIsWUFBQSxTQUFTLEVBQUUsUUFBUTtBQUNwQixTQUFBLENBQUMsQ0FBQTtRQUNGLElBQUksWUFBWSxLQUFLLElBQUksRUFBRTtBQUN6QixZQUFBLE1BQU0sSUFBSSxjQUFjLENBQUMsNEJBQTRCLENBQUMsQ0FBQTtBQUN2RCxTQUFBOztRQUdELE1BQU0sU0FBUyxHQUFxQixVQUFVLENBQUMsVUFBVSxDQUFDLGFBQWEsQ0FBQyxDQUFBO1FBQ3hFLE1BQU0sWUFBWSxHQUFHQSxhQUFNLENBQUMsS0FBSyxDQUFDLGFBQWEsQ0FBQyxTQUFTLENBQUMsQ0FBQTs7QUFHMUQsUUFBQSxNQUFNLGNBQWMsR0FBR0UsY0FBRyxDQUFDLFVBQVUsQ0FBQyxZQUFZLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0FBRTFFLFFBQUEsT0FBTyxjQUFjLENBQUE7S0FDdEI7SUFFRCxNQUFNLE1BQU0sQ0FBRSxHQUFXLEVBQUE7UUFDdkIsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFRLEtBQUEsRUFBQSxHQUFHLENBQUUsQ0FBQSxDQUFDLENBQUE7QUFDdEMsUUFBQSxPQUFPLElBQUksQ0FBQTtLQUNaO0lBRUQsTUFBTSxJQUFJLEdBQUEsR0FBc0I7QUFDakM7O0FDNUVLLE1BQU8sU0FBVSxTQUFRQyxxQkFBeUMsQ0FBQTtJQUN0RSxNQUFNLFNBQVMsQ0FBRSxVQUF1QixFQUFBO1FBQ3RDLElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTtBQUM1QixZQUFBLFVBQVUsR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFhO0FBQzlDLGdCQUFBLEtBQUssRUFBRSxZQUFZO0FBQ25CLGdCQUFBLFdBQVcsRUFBRTtvQkFDWCxLQUFLLEVBQUUsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLE9BQU8sRUFBRSwyQkFBMkIsRUFBRTtvQkFDN0QsVUFBVSxFQUFFLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxPQUFPLEVBQUUsdUJBQXVCLEVBQUU7QUFDL0QsaUJBQUE7QUFDRCxnQkFBQSxLQUFLLEVBQUUsQ0FBQyxPQUFPLEVBQUUsWUFBWSxDQUFDO0FBQy9CLGFBQUEsQ0FBQyxDQUFBO0FBQ0gsU0FBQTtRQUNELElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTtZQUM1QixPQUFNO0FBQ1AsU0FBQTtRQUVELElBQUksQ0FBQyxVQUFVLENBQUMsVUFBVSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsRUFBRTtBQUMzQyxZQUFBLE1BQU0sSUFBSSxjQUFjLENBQUMsZ0NBQWdDLENBQUMsQ0FBQTtBQUMzRCxTQUFBO0FBRUQsUUFBQSxNQUFNLFNBQVMsR0FBRyxJQUFJLENBQUMsWUFBWSxFQUFnQixDQUFBO0FBQ25ELFFBQUEsTUFBTSxHQUFHLEdBQUcsTUFBTSxTQUFTLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDdEUsUUFBQSxNQUFNLG1CQUFtQixHQUFHSCxhQUFNLENBQUMsS0FBSyxDQUFDLGdCQUFnQixDQUFDLENBQUssRUFBQSxFQUFBLEdBQUcsQ0FBQyxZQUFZLENBQUEsQ0FBRSxFQUFFLElBQUksQ0FBQyxDQUFBO0FBRXhGLFFBQUEsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQztBQUN2QyxZQUFBLEdBQUcsRUFBRSxDQUFHLEVBQUEsSUFBSSxDQUFDLFFBQVEsQ0FBQSxDQUFBLEVBQUksbUJBQW1CLENBQUUsQ0FBQTtZQUM5QyxLQUFLLEVBQUUsVUFBVSxDQUFDLEtBQUs7WUFDdkIsZUFBZSxFQUFFLEdBQUcsQ0FBQyxHQUFHO0FBQ3hCLFlBQUEsSUFBSSxFQUFFLENBQUM7QUFDTCxvQkFBQSxHQUFHLEdBQUc7QUFDTixvQkFBQSxJQUFJLEVBQUUsV0FBVztBQUNqQixvQkFBQSxHQUFHLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFVO2lCQUM1QixDQUFDO1lBQ0YsUUFBUSxFQUFFLElBQUksQ0FBQyxRQUFRO0FBQ3ZCLFlBQUEsUUFBUSxFQUFFLEVBQUU7QUFDYixTQUFBLENBQUMsQ0FBQTtLQUNIO0FBQ0Y7O0FDekNELE1BQU0sT0FBTyxHQUFvQyxPQUFPLElBQUksS0FBSTtBQUM5RCxJQUFBLE1BQU0sU0FBUyxHQUFHLElBQUksWUFBWSxDQUFDLElBQUksQ0FBQyxNQUFNLEVBQUUsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFBO0lBQzNELE9BQU8sSUFBSSxTQUFTLENBQUMsRUFBRSxHQUFHLElBQUksRUFBRSxTQUFTLEVBQUUsQ0FBQyxDQUFBO0FBQzlDOzs7OzsifQ==
