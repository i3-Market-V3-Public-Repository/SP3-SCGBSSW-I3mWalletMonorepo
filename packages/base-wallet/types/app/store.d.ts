import { WalletComponents } from '@i3m/wallet-desktop-openapi/types';
import { IIdentifier } from '@veramo/core';
import { CanBePromise } from '../utils';
export type Resource = WalletComponents.Schemas.Resource & WalletComponents.Schemas.ResourceId & {
    identity?: WalletComponents.Schemas.ObjectResource['identity'];
} & {
    parentResource?: WalletComponents.Schemas.ObjectResource['parentResource'];
};
export type VerifiableCredentialResource = Resource & {
    type: 'VerifiableCredential';
};
export type ObjectResource = Resource & {
    type: 'Object';
};
export type KeyPairResource = Resource & {
    type: 'KeyPair';
};
export type ContractResource = Resource & {
    type: 'Contract';
};
export type NonRepudiationProofResource = Resource & {
    type: 'NonRepudiationProof';
};
export type DataExchangeResource = Resource & {
    type: 'DataExchange';
};
export type VerifiableCredential = WalletComponents.Schemas.VerifiableCredential['resource'];
export type KeyPair = WalletComponents.Schemas.KeyPair['resource'];
export type Contract = WalletComponents.Schemas.Contract['resource'];
export type Object = WalletComponents.Schemas.ObjectResource['resource'];
export type Identity = IIdentifier;
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
    /**
     * Adds the `listener` function to the end of the listeners array for the
     * 'change' event, which is emitted when the store changes its contents.
     * The only argument passed to the listener is the `changedAt` timestamp with
     * the local timestamp (milliseconds ellapsed from EPOCH) when the change happened.
     * No checks are made to see if the `listener` has already been added. Multiple
     * calls for the 'change' event will result in multiple `listener` being added,
     * and called, multiple times when the event is emitted.
     * @param eventName
     * @param listener
     * @returns
     */
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    /**
     * Adds the `listener` function to the end of the listeners array for the
     * 'cleared' event, which is emitted when the store contents are cleared.
     * The only argument passed to the listener is the `changedAt` timestamp with
     * the local timestamp (milliseconds ellapsed from EPOCH) when the change happened.
     * No checks are made to see if the `listener` has already been added. Multiple
     * calls for the 'cleared' event will result in multiple `listener` being added,
     * and called, multiple times when the event is emitted.
     * @param eventName
     * @param listener
     * @returns
     */
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    /**
     * Adds a **one-time**`listener` function for the event named `eventName`. The
     * next time `eventName` is triggered, this listener is removed and then invoked.
     *
     * ```js
     * server.once('connection', (stream) => {
     *   console.log('Ah, we have our first user!');
     * });
     * ```
     *
     * Returns a reference to the `EventEmitter`, so that calls can be chained.
     *
     * By default, event listeners are invoked in the order they are added. The`emitter.prependOnceListener()` method can be used as an alternative to add the
     * event listener to the beginning of the listeners array.
     *
     * ```js
     * const myEE = new EventEmitter();
     * myEE.once('foo', () => console.log('a'));
     * myEE.prependOnceListener('foo', () => console.log('b'));
     * myEE.emit('foo');
     * // Prints:
     * //   b
     * //   a
     * ```
     * @since v0.3.0
     * @param eventName The name of the event.
     * @param listener The callback function
     */
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    /**
     * Synchronously calls each of the listeners registered for the 'change'
     * event, in the order they were registered, passing the `changedAt`argument
     * to each.
     * The 'change' event should be emitted when the store contents change
     * @param eventName
     * @param changedAt timestamp (in milliseconds ellapsed from EPOCH)
     * when the change happened
     */
    emit(eventName: 'changed', changedAt: number): boolean;
    /**
     * Synchronously calls each of the listeners registered for the 'cleared'
     * event, in the order they were registered, passing the `changedAt`argument
     * to each.
     * The 'cleared' event should be emitted when the store contents are cleared.
     * @param eventName
     * @param changedAt timestamp (in milliseconds ellapsed from EPOCH)
     * when the store contents were cleared
     */
    emit(eventName: 'cleared', changedAt: number): boolean;
    /**
     * Synchronously calls each of the listeners registered for the event named`eventName`, in the order they were registered, passing the supplied arguments
     * to each.
     *
     * Returns `true` if the event had listeners, `false` otherwise.
     *
     * ```js
     * const EventEmitter = require('events');
     * const myEmitter = new EventEmitter();
     *
     * // First listener
     * myEmitter.on('event', function firstListener() {
     *   console.log('Helloooo! first listener');
     * });
     * // Second listener
     * myEmitter.on('event', function secondListener(arg1, arg2) {
     *   console.log(`event with parameters ${arg1}, ${arg2} in second listener`);
     * });
     * // Third listener
     * myEmitter.on('event', function thirdListener(...args) {
     *   const parameters = args.join(', ');
     *   console.log(`event with parameters ${parameters} in third listener`);
     * });
     *
     * console.log(myEmitter.listeners('event'));
     *
     * myEmitter.emit('event', 1, 2, 3, 4, 5);
     *
     * // Prints:
     * // [
     * //   [Function: firstListener],
     * //   [Function: secondListener],
     * //   [Function: thirdListener]
     * // ]
     * // Helloooo! first listener
     * // event with parameters 1, 2 in second listener
     * // event with parameters 1, 2, 3, 4, 5 in third listener
     */
    emit(eventName: string | symbol, ...args: any[]): boolean;
}
//# sourceMappingURL=store.d.ts.map