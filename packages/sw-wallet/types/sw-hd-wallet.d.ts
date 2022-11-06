import { HDNode } from '@ethersproject/hdnode';
import { KeyLike, Dialog, Store, KeyWallet } from '@i3m/base-wallet';
import { SwWalletModel, HDData } from './types';
export declare class SwHdKeyWallet implements KeyWallet {
    protected dialog: Dialog;
    protected store: Store<SwWalletModel>;
    _hdNode?: HDNode;
    _hdData?: HDData;
    constructor(dialog: Dialog, store: Store<SwWalletModel>);
    protected get hdData(): HDData;
    protected get hdNode(): HDNode;
    protected updateHdData(): Promise<void>;
    initialize(): Promise<void>;
    initializeSeed(seed: Uint8Array): Promise<void>;
    createAccountKeyPair(): Promise<string>;
    getPublicKey(path: string): Promise<KeyLike>;
    signDigest(path: string, messageDigest: Uint8Array): Promise<Uint8Array>;
    delete(id: string): Promise<boolean>;
    wipe(): Promise<void>;
}
