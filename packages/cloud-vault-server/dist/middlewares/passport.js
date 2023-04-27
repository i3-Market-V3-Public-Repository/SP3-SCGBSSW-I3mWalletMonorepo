"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.passportPromise = void 0;
// import { HttpError } from 'express-openapi-validator/dist/framework/types'
const openid_client_1 = require("openid-client");
const passport_1 = __importDefault(require("passport"));
const passport_jwt_1 = require("passport-jwt");
const config_1 = require("../config");
const jsonwebtoken_1 = require("jsonwebtoken");
async function passportPromiseFn() {
    const issuer = await openid_client_1.Issuer.discover(config_1.oidcConfig.providerUri);
    console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
    const client = new issuer.Client(config_1.oidcConfig.client);
    passport_1.default.use('jwtBearer', new passport_jwt_1.Strategy({
        jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: config_1.jwt.secret
    }, (jwtPayload, done) => {
        try {
            const user = {
                username: jwtPayload.username
            };
            return done(null, user);
            // return done(new HttpError({
            //   status: 401,
            //   name: 'unauthorized',
            //   path: ''
            // }))
        }
        catch (error) {
            return done(error);
        }
    }));
    passport_1.default.use('oidc', new openid_client_1.Strategy({
        client,
        usePKCE: false,
        passReqToCallback: true
    }, (req, token, done) => {
        const idToken = token.id_token;
        if (idToken === undefined) {
            const err = new Error('no id_token');
            return done(err, undefined);
        }
        const scope = token.scope;
        // const iss = claims.iss
        if (scope === undefined) {
            const err = Error('no scope in token');
            return done(err, undefined);
        }
        try {
            const claims = token.claims();
            const did = claims.sub;
            const user = {
                idToken,
                scope,
                claims: extractClaims(claims),
                did
            };
            return done(null, user);
        }
        catch (error) {
            return done(error, undefined);
        }
    }));
    return passport_1.default;
}
exports.passportPromise = passportPromiseFn();
function extractClaims(claims) {
    const verifiedClaims = claims.verified_claims;
    if (verifiedClaims === undefined)
        return [];
    const claimsTitles = [];
    if (verifiedClaims.trusted.length > 0)
        claimsTitles.push(...decodeAndValidateClaims(verifiedClaims.trusted));
    if (verifiedClaims.untrusted.length > 0)
        claimsTitles.push(...decodeAndValidateClaims(verifiedClaims.untrusted));
    return claimsTitles;
}
function decodeAndValidateClaims(vc) {
    const claims = [];
    const decodeVC = vc.map(v => (0, jsonwebtoken_1.decode)(v).vc);
    decodeVC.forEach(v => {
        claims.push(...Object.keys(v.credentialSubject).filter(k => v.credentialSubject[k]));
    });
    return claims;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicGFzc3BvcnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWlkZGxld2FyZXMvcGFzc3BvcnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsNkVBQTZFO0FBQzdFLGlEQUF5RjtBQUN6Rix3REFBK0I7QUFDL0IsK0NBQWtFO0FBQ2xFLHNDQUEyQztBQUMzQywrQ0FBcUM7QUFhckMsS0FBSyxVQUFVLGlCQUFpQjtJQUM5QixNQUFNLE1BQU0sR0FBRyxNQUFNLHNCQUFNLENBQUMsUUFBUSxDQUFDLG1CQUFVLENBQUMsV0FBVyxDQUFDLENBQUE7SUFDNUQsT0FBTyxDQUFDLEdBQUcsQ0FBQyx5QkFBeUIsRUFBRSxNQUFNLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtJQUV0RSxNQUFNLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxNQUFNLENBQUMsbUJBQVUsQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUVuRCxrQkFBUSxDQUFDLEdBQUcsQ0FBQyxXQUFXLEVBQUUsSUFBSSx1QkFBVyxDQUN2QztRQUNFLGNBQWMsRUFBRSx5QkFBVSxDQUFDLDJCQUEyQixFQUFFO1FBQ3hELFdBQVcsRUFBRSxZQUFHLENBQUMsTUFBTTtLQUN4QixFQUNELENBQUMsVUFBVSxFQUFFLElBQUksRUFBRSxFQUFFO1FBQ25CLElBQUk7WUFDRixNQUFNLElBQUksR0FBUztnQkFDakIsUUFBUSxFQUFFLFVBQVUsQ0FBQyxRQUFRO2FBQzlCLENBQUE7WUFDRCxPQUFPLElBQUksQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUE7WUFDdkIsOEJBQThCO1lBQzlCLGlCQUFpQjtZQUNqQiwwQkFBMEI7WUFDMUIsYUFBYTtZQUNiLE1BQU07U0FDUDtRQUFDLE9BQU8sS0FBSyxFQUFFO1lBQ2QsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUE7U0FDbkI7SUFDSCxDQUFDLENBQ0YsQ0FBQyxDQUFBO0lBRUYsa0JBQVEs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