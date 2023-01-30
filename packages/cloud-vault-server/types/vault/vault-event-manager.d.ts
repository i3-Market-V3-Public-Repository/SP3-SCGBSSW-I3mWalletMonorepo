import { Response } from 'express';
import { OpenApiComponents } from '../../types/openapi';
export interface CONNECTED_EVENT {
    type: 'connected';
    data: {
        timestamp?: OpenApiComponents.Schemas.Timestamp['timestamp'];
    };
}
export interface STORAGE_UPDATED_EVENT {
    type: 'storage-updated';
    data: {
        timestamp: OpenApiComponents.Schemas.Timestamp['timestamp'];
    };
}
export interface STORAGE_DELETED_EVENT {
    type: 'storage-deleted';
    data: {};
}
declare class VaultEventManager {
    private clients;
    private connectionToUsernameMap;
    constructor();
    addConnection(username: string, response: Response): string;
    closeConnection(connId: string): void;
    sendEvent(to: string, event: CONNECTED_EVENT | STORAGE_UPDATED_EVENT | STORAGE_DELETED_EVENT): void;
}
export declare const vaultEvents: VaultEventManager;
export {};
