"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../../config");
const db_1 = require("../../db");
const types_1 = require("express-openapi-validator/dist/framework/types");
const passport_1 = require("../../middlewares/passport");
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const non_repudiation_library_1 = require("@i3m/non-repudiation-library");
async function default_1(router) {
    const passport = await passport_1.passportPromise;
    router.use((0, cookie_parser_1.default)());
    router.get('/public-jwk', async (req, res, next) => {
        try {
            const jwkPair = await config_1.jwksPromise;
            res.json({ jwk: jwkPair.publicJwk });
        }
        catch (error) {
            return next(error);
        }
    });
    router.get('/register/:data', (req, res) => {
        res.cookie('reg-data', req.params.data, { httpOnly: true })
            .cookie('orig', 'register', { httpOnly: true })
            .redirect(config_1.serverConfig.publicUrl + req.baseUrl + '/login');
    });
    router.get('/deregister', (req, res) => {
        res.cookie('orig', 'deregister', { httpOnly: true })
            .redirect(config_1.serverConfig.publicUrl + req.baseUrl + '/login');
    });
    router.get('/login', passport.authenticate('oidc', { scope: 'openid vc vc:provider vc:consumer' }));
    router.get('/cb', passport.authenticate('oidc', { session: false }), async function (req, res, next) {
        const orig = req.cookies.orig;
        const regUser = req.user;
        res.clearCookie('reg-data').clearCookie('orig');
        switch (orig) {
            case 'register': {
                const regData = req.cookies['reg-data'];
                const { username, authkey, did } = await decodeRegData(regData);
                if (req.user === undefined) {
                    throw new Error('Passport authentication error');
                }
                if (regUser.did !== did) {
                    const err = new types_1.HttpError({
                        status: 401,
                        name: 'unauthorized',
                        message: 'authenticated did does not match the one that initiated the flow',
                        path: req.baseUrl + req.path
                    });
                    return next(err);
                }
                else if (!regUser.claims.includes('provider') && !regUser.claims.includes('consumer')) {
                    const err = new types_1.HttpError({
                        status: 401,
                        name: 'unauthorized',
                        message: 'user has not presented a valid credential for having a cloud vallet account',
                        path: req.baseUrl + req.path
                    });
                    return next(err);
                }
                try {
                    await db_1.dbFunctions.registerUser(did, username, authkey);
                    res.status(201).json({
                        status: 'created',
                        username
                    });
                }
                catch (error) {
                    if (error !== null && typeof error === 'object' && 'code' in error && error.code === '23505') {
                        const err = new types_1.HttpError({
                            status: 400,
                            message: 'user already registered',
                            name: 'already-registered',
                            path: req.baseUrl + req.path
                        });
                        return next(err);
                    }
                    return next(error);
                }
                break;
            }
            case 'deregister': {
                await db_1.dbFunctions.deleteStorageByDid(regUser.did).catch((err) => {
                    if (err instanceof Error && err.message === 'not-registered') {
                        const err = new types_1.HttpError({
                            status: 404,
                            message: 'this identity (DID) is not registered',
                            name: 'not-registered',
                            errors: [],
                            path: req.baseUrl + req.path
                        });
                        return next(err);
                    }
                    return next(err);
                });
                res.status(201).json({
                    status: 'deregistered',
                    username: regUser.did
                });
                break;
            }
            default: {
                const err = new types_1.HttpError({
                    status: 400,
                    message: 'you should not reach this enpoint directly',
                    name: 'no-oidc-flow',
                    path: req.baseUrl + req.path
                });
                return next(err);
            }
        }
    });
}
exports.default = default_1;
async function decodeRegData(regData) {
    const jwkPair = await config_1.jwksPromise;
    const { plaintext } = await (0, non_repudiation_library_1.jweDecrypt)(regData, jwkPair.privateJwk);
    const payload = JSON.parse(Buffer.from(plaintext).toString('utf-8'));
    if (!('username' in payload) || !('authkey' in payload) || !('did' in payload)) {
        throw new Error('invalid data for registration');
    }
    return { username: payload.username, authkey: payload.authkey, did: payload.did };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVnaXN0cmF0aW9uLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL3JvdXRlcy9hcGkvcmVnaXN0cmF0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBRUEseUNBQXdEO0FBQ3hELGlDQUE0QztBQUM1QywwRUFBMEU7QUFDMUUseURBQThFO0FBQzlFLGtFQUF3QztBQUN4QywwRUFBOEQ7QUFFL0MsS0FBSyxvQkFBVyxNQUFjO0lBQzNDLE1BQU0sUUFBUSxHQUFHLE1BQU0sMEJBQWUsQ0FBQTtJQUN0QyxNQUFNLENBQUMsR0FBRyxDQUFDLElBQUEsdUJBQVksR0FBRSxDQUFDLENBQUE7SUFFMUIsTUFBTSxDQUFDLEdBQUcsQ0FBQyxhQUFhLEVBQ3RCLEtBQUssRUFBRSxHQUE0QixFQUFFLEdBQXlFLEVBQUUsSUFBSSxFQUFFLEVBQUU7UUFDdEgsSUFBSTtZQUNGLE1BQU0sT0FBTyxHQUFHLE1BQU0sb0JBQVcsQ0FBQTtZQUNqQyxHQUFHLENBQUMsSUFBSSxDQUFDLEVBQUUsR0FBRyxFQUFFLE9BQU8sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxDQUFBO1NBQ3JDO1FBQUMsT0FBTyxLQUFVLEVBQUU7WUFDbkIsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUE7U0FDbkI7SUFDSCxDQUFDLENBQ0YsQ0FBQTtJQUVELE1BQU0sQ0FBQyxHQUFHLENBQUMsaUJBQWlCLEVBQzFCLENBQUMsR0FBd0YsRUFBRSxHQUE2RSxFQUFFLEVBQUU7UUFDMUssR0FBRyxDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsR0FBRyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDeEQsTUFBTSxDQUFDLE1BQU0sRUFBRSxVQUFVLEVBQUUsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDOUMsUUFBUSxDQUFDLHFCQUFZLENBQUMsU0FBUyxHQUFHLEdBQUcsQ0FBQyxPQUFPLEdB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