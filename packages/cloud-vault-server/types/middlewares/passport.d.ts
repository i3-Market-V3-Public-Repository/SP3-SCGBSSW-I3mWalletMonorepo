import passport from 'passport';
export interface User {
    username: string;
}
export interface RegistrationUser {
    idToken: string;
    claims: string[];
    did: string;
    scope: string;
}
export declare const passportPromise: Promise<passport.PassportStatic>;
