import { WalletComponents } from '@i3m/wallet-desktop-openapi/types';
import { IIdentifier } from '@veramo/core';
import { CanBePromise } from '../utils';
export declare type Resource = WalletComponents.Schemas.Resource & WalletComponents.Schemas.ResourceId & {
    identity?: WalletComponents.Schemas.ObjectResource['identity'];
} & {
    parentResource?: WalletComponents.Schemas.ObjectResource['parentResource'];
};
export declare type VerifiableCredentialResource = Resource & {
    type: 'VerifiableCredential';
};
export declare type ObjectResource = Resource & {
    type: 'Object';
};
export declare type KeyPairResource = Resource & {
    type: 'KeyPair';
};
export declare type ContractResource = Resource & {
    type: 'Contract';
};
export declare type NonRepudiationProofResource = Resource & {
    type: 'NonRepudiationProof';
};
export declare type DataExchangeResource = Resource & {
    type: 'DataExchange';
};
export declare type VerifiableCredential = WalletComponents.Schemas.VerifiableCredential['resource'];
export declare type KeyPair = WalletComponents.Schemas.KeyPair['resource'];
export declare type Contract = WalletComponents.Schemas.Contract['resource'];
export declare type Object = WalletComponents.Schemas.ObjectResource['resource'];
export declare type Identity = IIdentifier;
export interface BaseWalletModel {
    resources: {
        [id: string]: Resource;
    };
    identities: {
        [did: string]: Identity;
    };
}
export interface Store<T extends Record<string, any> = Record<string, unknown>> {
    /**
     * Get an item.
     *
     * @param key - The key of the item to get.
     * @param defaultValue - The default value if the item does not exist.
    */
    get<Key extends keyof T>(key: Key): CanBePromise<T[Key]>;
    get<Key extends keyof T>(key: Key, defaultValue: Required<T>[Key]): CanBePromise<Required<T>[Key]>;
    /**
     * Set multiple keys at once.
     * @param store
     */
    set(store: Partial<T>): CanBePromise<void>;
    /**
     * Set an item.
     * @param key - The key of the item to set
     * @param value - The value to set
     */
    set<Key extends keyof T>(key: Key, value: T[Key]): CanBePromise<void>;
    set(key: string, value: unknown): CanBePromise<void>;
    /**
     * Check if an item exists.
     *
     * @param key - The key of the item to check.
     */
    has<Key extends keyof T>(key: Key): CanBePromise<boolean>;
    has(key: string): CanBePromise<boolean>;
    /**
     * Delete an item.
     * @param key - The key of the item to delete.
     */
    delete<Key extends keyof T>(key: Key): CanBePromise<void>;
    delete(key: string): CanBePromise<void>;
    /**
     * Delete all items.
     */
    clear: () => CanBePromise<void>;
    /**
     * Return a readonly version of the complete store
     * @returns The entire store
     */
    getStore: () => CanBePromise<T>;
    /**
     * Get the path of the store
     * @returns The store path
     */
    getPath: () => string;
}
//# sourceMappingURL=store.d.ts.map