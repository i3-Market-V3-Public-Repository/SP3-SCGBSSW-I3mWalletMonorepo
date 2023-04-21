"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const types_1 = require("express-openapi-validator/dist/framework/types");
const jsonwebtoken_1 = require("jsonwebtoken");
const pg_1 = require("pg");
const config_1 = require("../../config");
const db_1 = require("../../db");
const passport_1 = require("../../middlewares/passport");
const index_1 = require("../../vault/index");
async function default_1(router) {
    const passport = await passport_1.passportPromise;
    // router.use(passport.initialize())
    router.post('/token', async (req, res, next) => {
        try {
            const username = req.body.username;
            const authkey = req.body.authkey;
            const verified = await db_1.dbFunctions.verifyCredentials(username, authkey);
            if (!verified) {
                const error = new types_1.HttpError({
                    name: 'invalid-credentials',
                    message: 'invalid username and/or authkey',
                    path: req.baseUrl + req.path,
                    status: 404
                });
                throw error;
            }
            const token = (0, jsonwebtoken_1.sign)({
                username
            }, config_1.jwt.secret, {
                algorithm: config_1.jwt.alg,
                expiresIn: config_1.jwt.expiresIn
            });
            res.status(200).json({
                token
            });
        }
        catch (error) {
            return next(error);
        }
    });
    router.get('/events', passport.authenticate('jwtBearer', { session: false }), async (req, res, next) => {
        const { username } = req.user;
        try {
            const connId = index_1.vaultEvents.addConnection(username, res);
            const timestamp = (await db_1.dbFunctions.getTimestamp(username)) ?? undefined;
            index_1.vaultEvents.sendEvent(username, {
                event: 'connected',
                data: {
                    timestamp
                }
            });
            req.on('close', () => {
                index_1.vaultEvents.closeConnection(connId);
            });
        }
        catch (error) {
            return next(error);
        }
    });
    router.get('/timestamp', passport.authenticate('jwtBearer', { session: false }), async (req, res, next) => {
        try {
            const username = req.user.username;
            const timestamp = await db_1.dbFunctions.getTimestamp(username);
            if (timestamp === null) {
                const error = new types_1.HttpError({
                    name: 'no-storage',
                    message: "you haven't upload storage yet",
                    path: req.baseUrl + req.path,
                    status: 404
                });
                throw error;
            }
            res.status(200).json({
                timestamp
            });
        }
        catch (error) {
            return next(error);
        }
    });
    router.get('/', passport.authenticate('jwtBearer', { session: false }), async (req, res, next) => {
        try {
            const username = req.user.username;
            const storage = await db_1.dbFunctions.getStorage(username);
            if (storage === null) {
                const error = new types_1.HttpError({
                    name: 'no-storage',
                    message: "you haven't upload storage yet",
                    path: req.baseUrl + req.path,
                    status: 404
                });
                throw error;
            }
            res.status(200).json(storage);
        }
        catch (error) {
            return next(error);
        }
    });
    router.delete('/', passport.authenticate('jwtBearer', { session: false }), async (req, res, next) => {
        try {
            const { username } = req.user;
            await db_1.dbFunctions.deleteStorageByUsername(username);
            index_1.vaultEvents.sendEvent(username, {
                event: 'storage-deleted',
                data: {}
            });
            res.status(204).end();
        }
        catch (error) {
            if (error instanceof Error && error.message === 'not-registered') {
                return next(new types_1.HttpError({
                    name: 'not-registered',
                    path: req.baseUrl + req.path,
                    status: 404
                }));
            }
            return next(error);
        }
    });
    router.post('/', passport.authenticate('jwtBearer', { session: false }), async (req, res, next) => {
        try {
            const { username } = req.user;
            if (config_1.general.nodeEnv === 'development') {
                console.log('VAULT POST', username, req.body);
            }
            const newTimestamp = await db_1.dbFunctions.setStorage(username, req.body.ciphertext, req.body.timestamp);
            index_1.vaultEvents.sendEvent(username, {
                event: 'storage-updated',
                data: {
                    timestamp: newTimestamp
                }
            });
            res.status(201).json({
                timestamp: newTimestamp
            });
        }
        catch (error) {
            if (error instanceof pg_1.DatabaseError) {
                switch (error.code) {
                    case '22001':
                        return next(new types_1.HttpError({
                            name: 'quota-exceeded',
                            path: req.path,
                            status: 400,
                            message: `encrypted storage in base64url cannot be more than ${config_1.dbConfig.storageCharLength} long (${config_1.dbConfig.storageByteLength} in binary format)`
                        }));
                    default:
                        return next(new types_1.HttpError({
                            name: 'error',
                            path: req.baseUrl + req.path,
                            status: 400,
                            message: 'couldn\'t update storage'
                        }));
                }
            }
            else if (error instanceof Error && (error.message === 'invalid-timestamp' || error.message === 'not-registered')) {
                return next(new types_1.HttpError({
                    name: error.message,
                    path: req.baseUrl + req.path,
                    status: 400
                }));
            }
            return next(error);
        }
    });
}
exports.default = default_1;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmF1bHQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvcm91dGVzL2FwaS92YXVsdC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUNBLDBFQUEwRTtBQUMxRSwrQ0FBOEM7QUFDOUMsMkJBQWtDO0FBRWxDLHlDQUFxRDtBQUNyRCxpQ0FBNEM7QUFDNUMseURBQWtFO0FBQ2xFLDZDQUErQztBQUVoQyxLQUFLLG9CQUFXLE1BQWM7SUFDM0MsTUFBTSxRQUFRLEdBQUcsTUFBTSwwQkFBZSxDQUFBO0lBQ3RDLG9DQUFvQztJQUNwQyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFDbEIsS0FBSyxFQUFFLEdBQXVFLEVBQUUsR0FBK0QsRUFBRSxJQUFJLEVBQUUsRUFBRTtRQUN2SixJQUFJO1lBQ0YsTUFBTSxRQUFRLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUE7WUFDbEMsTUFBTSxPQUFPLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7WUFDaEMsTUFBTSxRQUFRLEdBQUcsTUFBTSxnQkFBRSxDQUFDLGlCQUFpQixDQUFDLFFBQVEsRUFBRSxPQUFPLENBQUMsQ0FBQTtZQUM5RCxJQUFJLENBQUMsUUFBUSxFQUFFO2dCQUNiLE1BQU0sS0FBSyxHQUFHLElBQUksaUJBQVMsQ0FBQztvQkFDMUIsSUFBSSxFQUFFLHFCQUFxQjtvQkFDM0IsT0FBTyxFQUFFLGlDQUFpQztvQkFDMUMsSUFBSSxFQUFFLEdBQUcsQ0FBQyxPQUFPLEdBQUcsR0FBRyxDQUFDLElBQUk7b0JBQzVCLE1BQU0sRUFBRSxHQUFHO2lCQUNaLENBQUMsQ0FBQTtnQkFDRixNQUFNLEtBQUssQ0FBQTthQUNaO1lBQ0QsTUFBTSxLQUFLLEdBQUcsSUFBQSxtQkFBTyxFQUFDO2dCQUNwQixRQUFRO2FBQ1QsRUFBRSxZQUFHLENBQUMsTUFBTSxFQUFFO2dCQUNiLFNBQVMsRUFBRSxZQUFHLENBQUMsR0FBRztnQkFDbEIsU0FBUyxF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