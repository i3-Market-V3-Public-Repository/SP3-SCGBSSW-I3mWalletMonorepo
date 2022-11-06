"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ApiManager = void 0;
const express_1 = __importDefault(require("express"));
const internal_1 = require("@wallet/main/internal");
const server_1 = require("./server");
class ApiManager {
    server;
    app;
    locals;
    port;
    host;
    constructor(locals) {
        this.app = (0, express_1.default)();
        locals.connectManager.walletProtocolTransport.use(this.app);
        this.server = (0, server_1.createServer)(locals.connectManager.handleRequest, {
            useHttps: false
        });
        this.locals = locals;
        // Network settings
        this.port = locals.connectManager.walletProtocolTransport.port;
        this.host = 'localhost';
    }
    async initialize() {
        await (0, server_1.initServer)(this.app, this.locals);
    }
    async listen() {
        const { host, port } = this;
        await new Promise((resolve) => this.server.listen(port, host, () => {
            resolve();
        }));
        // Log connection information
        const publicUri = `http://localhost:${port}`;
        internal_1.logger.info(`Application is listening on port ${port}`);
        internal_1.logger.info('Setup Developer Api to access to the following services:');
        internal_1.logger.info(` - OpenAPI JSON spec at ${publicUri}/api-spec/openapi.json`);
        internal_1.logger.info(` - OpenAPI browsable spec at ${publicUri}/api-spec/ui`);
        internal_1.logger.info(` - Pairing form at ${publicUri}/pairing`);
    }
    async close() {
        await new Promise((resolve) => {
            this.server.close(() => {
                resolve();
            });
        });
    }
}
exports.ApiManager = ApiManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXBpLW1hbmFnZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWFpbi9hcGkvYXBpLW1hbmFnZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsc0RBQTBDO0FBRzFDLG9EQUFzRDtBQUN0RCxxQ0FBbUQ7QUFFbkQsTUFBYSxVQUFVO0lBQ1gsTUFBTSxDQUFhO0lBQ25CLEdBQUcsQ0FBUztJQUNaLE1BQU0sQ0FBUTtJQUNkLElBQUksQ0FBUTtJQUNaLElBQUksQ0FBUTtJQUV0QixZQUFhLE1BQWM7UUFDekIsSUFBSSxDQUFDLEdBQUcsR0FBRyxJQUFBLGlCQUFPLEdBQUUsQ0FBQTtRQUNwQixNQUFNLENBQUMsY0FBYyxDQUFDLHVCQUF1QixDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDM0QsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFBLHFCQUFZLEVBQUMsTUFBTSxDQUFDLGNBQWMsQ0FBQyxhQUFhLEVBQUU7WUFDOUQsUUFBUSxFQUFFLEtBQUs7U0FDaEIsQ0FBQyxDQUFBO1FBQ0YsSUFBSSxDQUFDLE1BQU0sR0FBRyxNQUFNLENBQUE7UUFFcEIsbUJBQW1CO1FBQ25CLElBQUksQ0FBQyxJQUFJLEdBQUcsTUFBTSxDQUFDLGNBQWMsQ0FBQyx1QkFBdUIsQ0FBQyxJQUFJLENBQUE7UUFDOUQsSUFBSSxDQUFDLElBQUksR0FBRyxXQUFXLENBQUE7SUFDekIsQ0FBQztJQUVELEtBQUssQ0FBQyxVQUFVO1FBQ2QsTUFBTSxJQUFBLG1CQUFVLEVBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUE7SUFDekMsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNO1FBQ1YsTUFBTSxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsR0FBRyxJQUFJLENBQUE7UUFDM0IsTUFBTSxJQUFJLE9BQU8sQ0FBTyxDQUFDLE9BQU8sRUFBRSxFQUFFLENBQ2xDLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFO1lBQ2xDLE9BQU8sRUFBRSxDQUFBO1FBQ1gsQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUVMLDZCQUE2QjtRQUM3QixNQUFNLFNBQVMsR0FBRyxvQkFBb0IsSUFBSSxFQUFFLENBQUE7UUFDNUMsaUJBQU0sQ0FBQyxJQUFJLENBQUMsb0NBQW9DLElBQUksRUFBRSxDQUFDLENBQUE7UUFDdkQsaUJBQU0sQ0FBQyxJQUFJLENBQUMsMERBQTBELENBQUMsQ0FBQTtRQUN2RSxpQkFBTSxDQUFDLElBQUksQ0FBQywyQkFBMkIsU0FBUyx3QkFBd0IsQ0FBQyxDQUFBO1FBQ3pFLGlCQUFNLENBQUMsSUFBSSxDQUFDLGdDQUFnQyxTQUFTLGNBQWMsQ0FBQyxDQUFBO1FBQ3BFLGlCQUFNLENBQUMsSUFBSSxDQUFDLHNCQUFzQixTQUFTLFVBQVUsQ0FBQyxDQUFBO0lBQ3hELENBQUM7SUFFRCxLQUFLLENBQUMsS0FBSztRQUNULE1BQU0sSUFBSSxPQUFPLENBQU8sQ0FBQyxPQUFPLEVBQUUsRUFBRTtZQUNsQyxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUU7Z0JBQ3JCLE9BQU8sRUFBRSxDQUFBO1lBQ1gsQ0FBQyxDQUFDLENBQUE7UUFDSixDQUFDLENBQUMsQ0FBQTtJQUNKLENBQUM7Q0FDRjtBQS9DRCxnQ0ErQ0MifQ==