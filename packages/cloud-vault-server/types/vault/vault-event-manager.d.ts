import { Response } from 'express';
import { OpenApiComponents } from '../openapi';
export declare const VAULT_MANAGER_MSG_CODES: {
    STORAGE_UPDATED: number;
    STORAGE_DELETED: number;
};
export interface WELLCOME_MSG {
    code: 0;
    timestamp?: OpenApiComponents.Schemas.Timestamp['timestamp'];
}
export interface UPDATE_MSG {
    code: 1;
    timestamp: OpenApiComponents.Schemas.Timestamp['timestamp'];
}
export interface DELETE_MSG {
    code: 2;
}
declare class VaultEventManager {
    private clients;
    private connectionToUsernameMap;
    constructor();
    addConnection(username: string, response: Response): string;
    closeConnection(connId: string): void;
    sendEvent(to: string, event: WELLCOME_MSG | UPDATE_MSG | DELETE_MSG): void;
}
export declare const vaultEvents: VaultEventManager;
export {};
