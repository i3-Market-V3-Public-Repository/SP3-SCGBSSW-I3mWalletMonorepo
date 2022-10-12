import crypto from 'crypto';
import { ethers } from 'ethers';
import { v4 } from 'uuid';
import * as u8a from 'uint8arrays';
import { WalletError, BaseWallet } from '@i3m/base-wallet';

class BokWalletError extends WalletError {
}

class BokKeyWallet {
    constructor(dialog, store) {
        this.dialog = dialog;
        this.store = store;
    }
    async import(privateKeyHex) {
        const kid = v4();
        const publicKeyHex = ethers.utils.computePublicKey(`0x${privateKeyHex}`).substring(2);
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
        const privateKeyHex = crypto.randomBytes(32).toString('hex');
        const key = await this.import(privateKeyHex);
        return key.kid;
    }
    async getPublicKey(kid) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        return ethers.utils.arrayify(`0x${keys[kid].publicKeyHex}`);
    }
    async signDigest(kid, messageDigest) {
        const keys = await this.store.get('keys');
        if (keys === undefined) {
            throw new BokWalletError('No keys initialized yet');
        }
        // Get signing key
        const key = `0x${keys[kid].privateKeyHex}`;
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
        if (!importInfo.privateKey.startsWith('0x')) {
            throw new BokWalletError('Private key must start with 0x');
        }
        const keyWallet = this.getKeyWallet();
        const key = await keyWallet.import(importInfo.privateKey.substring(2));
        const compressedPublicKey = ethers.utils.computePublicKey(`0x${key.publicKeyHex}`, true);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2Vycm9ycy50cyIsIi4uLy4uL3NyYy90cy9ib2sta2V5LXdhbGxldC50cyIsIi4uLy4uL3NyYy90cy9ib2std2FsbGV0LnRzIiwiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJ1dWlkIl0sIm1hcHBpbmdzIjoiOzs7Ozs7QUFFTSxNQUFPLGNBQWUsU0FBUSxXQUFXLENBQUE7QUFBRzs7TUNTckMsWUFBWSxDQUFBO0lBQ3ZCLFdBQXVCLENBQUEsTUFBYyxFQUFZLEtBQTRCLEVBQUE7UUFBdEQsSUFBTSxDQUFBLE1BQUEsR0FBTixNQUFNLENBQVE7UUFBWSxJQUFLLENBQUEsS0FBQSxHQUFMLEtBQUssQ0FBdUI7S0FBSztJQUVsRixNQUFNLE1BQU0sQ0FBRSxhQUFxQixFQUFBO0FBQ2pDLFFBQUEsTUFBTSxHQUFHLEdBQUdBLEVBQUksRUFBRSxDQUFBO0FBQ2xCLFFBQUEsTUFBTSxZQUFZLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFLLEVBQUEsRUFBQSxhQUFhLEVBQUUsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUVyRixRQUFBLE1BQU0sR0FBRyxHQUFRO1lBQ2YsR0FBRztBQUNILFlBQUEsSUFBSSxFQUFFLFdBQVc7WUFDakIsWUFBWTtZQUNaLGFBQWE7U0FDZCxDQUFBO1FBQ0QsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUV6QyxRQUFBLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsTUFBTSxFQUFFO0FBQzNCLFlBQUEsR0FBRyxJQUFJO1lBQ1AsQ0FBQyxHQUFHLEdBQUcsR0FBRztBQUNYLFNBQUEsQ0FBQyxDQUFBO0FBRUYsUUFBQSxPQUFPLEdBQUcsQ0FBQTtLQUNYO0FBRUQsSUFBQSxN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
