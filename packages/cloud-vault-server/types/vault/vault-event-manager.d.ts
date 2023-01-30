import { Response } from 'express';
import { OpenApiComponents } from '../../types/openapi';
export interface ConnectedEvent {
    event: 'connected';
    data: {
        timestamp?: OpenApiComponents.Schemas.Timestamp['timestamp'];
    };
}
export interface StorageUpdatedEvent {
    event: 'storage-updated';
    data: {
        timestamp: OpenApiComponents.Schemas.Timestamp['timestamp'];
    };
}
export interface StorageDeletedEvent {
    event: 'storage-deleted';
    data: {};
}
declare class VaultEventManager {
    private clients;
    private connectionToUsernameMap;
    constructor();
    addConnection(username: string, response: Response): string;
    closeConnection(connId: string): void;
    sendEvent(username: string, event: ConnectedEvent | StorageUpdatedEvent | StorageDeletedEvent): void;
}
export declare const vaultEvents: VaultEventManager;
export {};
