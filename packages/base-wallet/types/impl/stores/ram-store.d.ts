/// <reference types="node" />
import { EventEmitter } from 'events';
import { Store } from '../../app';
import { CanBePromise } from '../../utils';
/**
 * A class that implements a storage in RAM to be used by a wallet
 */
export declare class RamStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter implements Store<T> {
    protected defaultModel: T;
    model: T;
    constructor(defaultModel: T);
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: 'changed', changedAt: number): boolean;
    emit(eventName: 'cleared', changedAt: number): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    get(key: any, defaultValue?: any): any;
    set(keyOrStore?: any, value?: any): CanBePromise<void>;
    has<Key extends 'accounts'>(key: Key): CanBePromise<boolean>;
    delete<Key extends 'accounts'>(key: Key): CanBePromise<void>;
    clear(): CanBePromise<void>;
    getStore(): CanBePromise<T>;
    getPath(): string;
}
//# sourceMappingURL=ram-store.d.ts.map