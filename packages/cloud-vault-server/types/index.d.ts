#!/usr/bin/env node
/// <reference types="node" />
import http from 'http';
export interface Server {
    server: http.Server;
    dbConnection: typeof import('./db');
}
declare const serverPromise: Promise<Server>;
export default serverPromise;
export * from './vault';
