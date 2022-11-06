"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectManager = void 0;
const base_wallet_1 = require("@i3m/base-wallet");
const wallet_protocol_1 = require("@i3m/wallet-protocol");
const cors_1 = require("./cors");
const code_generator_1 = require("./code-generator");
const jose_1 = require("jose");
class ConnectManager {
    locals;
    walletProtocol;
    walletProtocolTransport;
    constructor(locals, key) {
        this.locals = locals;
        const id = {
            name: 'Wallet desktop'
        };
        const codeGenerator = new code_generator_1.JwtCodeGenerator(key, locals);
        const httpTransport = new wallet_protocol_1.HttpResponderTransport({
            id,
            codeGenerator,
            timeout: 60000
        });
        this.walletProtocol = new wallet_protocol_1.WalletProtocol(httpTransport);
        this.walletProtocolTransport = httpTransport;
        this.handleRequest = this.handleRequest.bind(this);
    }
    handleRequest(req, res) {
        const _run = async () => {
            if ((0, cors_1.cors)(req, res)) {
                return;
            }
            await this.walletProtocolTransport.dispatchRequest(req, res);
        };
        _run().catch((err) => {
            if (err instanceof base_wallet_1.WalletError) {
                res.statusCode = err.status;
                res.end(JSON.stringify(err));
                return;
            }
            else if (err instanceof jose_1.errors.JWTExpired || err instanceof jose_1.errors.JWEInvalid) {
                res.statusCode = 401;
                res.end(JSON.stringify({
                    reason: 'Unauthorized token'
                }));
                return;
            }
            else if (err instanceof Error) {
                res.statusCode = 500;
                res.end(JSON.stringify({
                    reason: err.message
                }));
            }
            else {
                res.statusCode = 500;
                res.end(JSON.stringify(err));
            }
            throw err;
        });
    }
    async initialize() {
        const { sharedMemoryManager } = this.locals;
        this.walletProtocol
            .on('connString', (connString) => {
            sharedMemoryManager.update((mem) => ({
                ...mem,
                connectData: {
                    ...mem.connectData,
                    walletProtocol: {
                        ...mem.connectData.walletProtocol,
                        connectString: connString.toString()
                    }
                }
            }));
        })
            .on('finished', () => {
            sharedMemoryManager.update((mem) => ({
                ...mem,
                connectData: {
                    ...mem.connectData,
                    walletProtocol: {
                        ...mem.connectData.walletProtocol,
                        connectString: undefined
                    }
                }
            }));
        });
    }
    startWalletProtocol() {
        this.walletProtocol.run().then(() => {
            // Pairing correct
            this.locals.windowManager.openMainWindow('/wallet/explorer');
            this.locals.toast.show({
                message: 'Successful pairing',
                type: 'success'
            });
        }).catch((err) => {
            // Pairing failed
            this.locals.toast.show({
                message: 'Unsuccessful pairing',
                type: 'error'
            });
            throw err;
        });
    }
}
exports.ConnectManager = ConnectManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29ubmVjdC1tYW5hZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL21haW4vY29ubmVjdC9jb25uZWN0LW1hbmFnZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQ0Esa0RBQThDO0FBQzlDLDBEQUF1RjtBQUd2RixpQ0FBNkI7QUFDN0IscURBQW1EO0FBQ25ELCtCQUFzQztBQUV0QyxNQUFhLGNBQWM7SUFJRjtJQUhiLGNBQWMsQ0FBZ0I7SUFDakMsdUJBQXVCLENBQXdCO0lBRXRELFlBQXVCLE1BQWMsRUFBRSxHQUF5QjtRQUF6QyxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQ25DLE1BQU0sRUFBRSxHQUFhO1lBQ25CLElBQUksRUFBRSxnQkFBZ0I7U0FDdkIsQ0FBQTtRQUNELE1BQU0sYUFBYSxHQUFHLElBQUksaUNBQWdCLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQyxDQUFBO1FBQ3ZELE1BQU0sYUFBYSxHQUFHLElBQUksd0NBQXNCLENBQUM7WUFDL0MsRUFBRTtZQUNGLGFBQWE7WUFDYixPQUFPLEVBQUUsS0FBSztTQUNmLENBQUMsQ0FBQTtRQUNGLElBQUksQ0FBQyxjQUFjLEdBQUcsSUFBSSxnQ0FBYyxDQUFDLGFBQWEsQ0FBQyxDQUFBO1FBQ3ZELElBQUksQ0FBQyx1QkFBdUIsR0FBRyxhQUFhLENBQUE7UUFDNUMsSUFBSSxDQUFDLGFBQWEsR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtJQUNwRCxDQUFDO0lBRUQsYUFBYSxDQUFFLEdBQXlCLEVBQUUsR0FBd0I7UUFDaEUsTUFBTSxJQUFJLEdBQUcsS0FBSyxJQUFtQixFQUFFO1lBQ3JDLElBQUksSUFBQSxXQUFJLEVBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxFQUFFO2dCQUNsQixPQUFNO2FBQ1A7WUFFRCxNQUFNLElBQUksQ0FBQyx1QkFBdUIsQ0FBQyxlQUFlLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FB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