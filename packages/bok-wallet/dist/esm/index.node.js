import crypto from 'crypto';
import { ethers } from 'ethers';
import { v4 } from 'uuid';
import * as u8a from 'uint8arrays';
import { WalletError, parseHex, BaseWallet } from '@i3m/base-wallet';

class BokWalletError extends WalletError {
}

class BokKeyWallet {
    constructor(dialog, store) {
        this.dialog = dialog;
        this.store = store;
    }
    async import(privateKeyHex) {
        const kid = v4();
        const publicKeyHex = ethers.utils.computePublicKey(parseHex(privateKeyHex));
        const key = {
            kid,
            type: 'Secp256k1',
            publicKeyHex: parseHex(publicKeyHex, false),
            privateKeyHex: parseHex(privateKeyHex, false)
        };
        const keys = await this.store.get('keys');
        await this.store.set('keys', {
            ...keys,
            [kid]: key
        });
        return key;
    }
    async createAccountKeyPair() {
        const privateKeyHex = crypto.randomBytes(32).toString('hex');
        const key = await this.import(privateKeyHex);
        return key.kid;
    }
    async getPublicKey(kid) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        return ethers.utils.arrayify(parseHex(keys[kid].publicKeyHex));
    }
    async signDigest(kid, messageDigest) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        // Get signing key
        const key = parseHex(keys[kid].privateKeyHex);
        const signingKey = new ethers.utils.SigningKey(key);
        // Ask for user confirmation
        const confirmation = await this.dialog.confirmation({
            title: 'Sign?',
            message: `Are you sure you want to sign using key <code>${key}</code> the following hex data: \n<code>${ethers.utils.hexlify(messageDigest)}</code>`,
            // authenticated: false,
            acceptMsg: 'Sign',
            rejectMsg: 'Reject'
        });
        if (confirmation !== true) {
            throw new BokWalletError('Signature rejected by user');
        }
        // Sign
        const signature = signingKey.signDigest(messageDigest);
        const signatureHex = ethers.utils.joinSignature(signature);
        // Remove 0x
        const fixedSignature = u8a.fromString(signatureHex.substring(2), 'base16');
        return fixedSignature;
    }
    async delete(kid) {
        await this.store.delete(`keys.${kid}`);
        return true;
    }
    async wipe() { }
}

class BokWallet extends BaseWallet {
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
        const key = await keyWallet.import(parseHex(importInfo.privateKey));
        const compressedPublicKey = ethers.utils.computePublicKey(parseHex(key.publicKeyHex), true);
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

export { BokWallet, builder as default };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2Vycm9ycy50cyIsIi4uLy4uL3NyYy90cy9ib2sta2V5LXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy9ib2std2FsbGV0LnRzIiwiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJ1dWlkIl0sIm1hcHBpbmdzIjoiOzs7Ozs7QUFFTSxNQUFPLGNBQWUsU0FBUSxXQUFXLENBQUE7QUFBRzs7TUNTckMsWUFBWSxDQUFBO0lBQ3ZCLFdBQXVCLENBQUEsTUFBYyxFQUFZLEtBQTRCLEVBQUE7UUFBdEQsSUFBTSxDQUFBLE1BQUEsR0FBTixNQUFNLENBQVE7UUFBWSxJQUFLLENBQUEsS0FBQSxHQUFMLEtBQUssQ0FBdUI7S0FBSztJQUVsRixNQUFNLE1BQU0sQ0FBRSxhQUFxQixFQUFBO0FBQ2pDLFFBQUEsTUFBTSxHQUFHLEdBQUdBLEVBQUksRUFBRSxDQUFBO0FBQ2xCLFFBQUEsTUFBTSxZQUFZLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxRQUFRLENBQUMsYUFBYSxDQUFDLENBQUMsQ0FBQTtBQUUzRSxRQUFBLE1BQU0sR0FBRyxHQUFRO1lBQ2YsR0FBRztBQUNILFlBQUEsSUFBSSxFQUFFLFdBQVc7QUFDakIsWUFBQSxZQUFZLEVBQUUsUUFBUSxDQUFDLFlBQVksRUFBRSxLQUFLLENBQUM7QUFDM0MsWUFBQSxhQUFhLEVBQUUsUUFBUSxDQUFDLGFBQWEsRUFBRSxLQUFLLENBQUM7U0FDOUMsQ0FBQTtRQUNELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUE7QUFFekMsUUFBQSxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLE1BQU0sRUFBRTtBQUMzQixZQUFBLEdBQUcsSUFBSTtZQUNQLENBQUMsR0FBRyxHQUFHLEdBQUc7QUFDWCxTQUFB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
