#!/usr/bin/env node
/// <reference types="node" />
import http from 'http';
export * from './vault';
export interface Server {
    server: http.Server;
    dbConnection: typeof import('./db');
}
export declare const serverPromise: Promise<Server>;
