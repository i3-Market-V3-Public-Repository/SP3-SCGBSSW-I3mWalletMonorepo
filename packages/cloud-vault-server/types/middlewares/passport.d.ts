/// <reference types="express" />
/// <reference types="passport" />
export interface User {
    username: string;
}
export declare const passport: import("passport").Authenticator<import("express").Handler, any, any, import("passport").AuthenticateOptions>;
