"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initServer = exports.createServer = void 0;
const path_1 = __importDefault(require("path"));
const express_1 = __importDefault(require("express"));
// import cors from 'cors'
const https_1 = __importDefault(require("https"));
const http_1 = __importDefault(require("http"));
const express_openapi_validator_1 = require("express-openapi-validator");
const swagger_ui_express_1 = __importDefault(require("swagger-ui-express"));
const types_1 = require("express-openapi-validator/dist/framework/types");
const wallet_desktop_openapi_1 = __importDefault(require("@i3m/wallet-desktop-openapi"));
const base_wallet_1 = require("@i3m/base-wallet");
const internal_1 = require("@wallet/main/internal");
const developer_api_1 = require("./developer-api");
const directories_1 = require("../directories");
function createServer(app, config) {
    // Log cihpers
    // const ciphers = tls.getCiphers()
    // console.log(ciphers)
    let server;
    if (config.useHttps) {
        // Setup psk ssl
        const options = {};
        const cipher = 'tls_aes_128_gcm_sha256'.toUpperCase();
        console.log(cipher);
        const key = Buffer.from('1b0d885fb69527dd11bea699be51af19', 'hex');
        console.log(key.toString('hex'));
        options.ciphers = cipher;
        options.pskCallback = (socket, identity) => {
            socket.identity = identity;
            return key;
        };
        server = https_1.default.createServer(options, app);
        // Setup events
        server.on('tlsClientError', (err) => {
            console.log(err);
        });
    }
    else {
        server = http_1.default.createServer(app);
    }
    return server;
}
exports.createServer = createServer;
async function initServer(app, locals) {
    (0, internal_1.setLocals)(app, locals);
    // Add middlewares
    app.use(express_1.default.json());
    app.use(internal_1.loggerMiddleware);
    app.use((0, developer_api_1.developerApi)(locals));
    // Add default endpoint
    app.get('/', function (req, res) {
        res.redirect('/api-spec/ui');
    });
    // Add api-spec router
    const apiSpecRouter = express_1.default.Router();
    apiSpecRouter.use('/ui', swagger_ui_express_1.default.serve, swagger_ui_express_1.default.setup(wallet_desktop_openapi_1.default));
    apiSpecRouter.get('/openapi.json', (req, res) => {
        res.json(wallet_desktop_openapi_1.default);
    });
    app.use('/api-spec', apiSpecRouter);
    // Static public folder
    app.use('/pairing', express_1.default.static((0, internal_1.getResourcePath)('pairing')));
    app.use('/pairing/@i3m', express_1.default.static((0, directories_1.getModulesPath)('@i3m')));
    // Add routes using openapi validator middleware
    const openApiMiddleware = (0, express_openapi_validator_1.middleware)({
        apiSpec: wallet_desktop_openapi_1.default,
        validateResponses: true,
        validateRequests: true,
        operationHandlers: path_1.default.join(__dirname, 'routes')
        // unknownFormats: ['my-format'] // <-- to provide custom formats
        // ignorePaths: /^(?!\/?rp).*$/
    });
    app.use(openApiMiddleware);
    // Add error middleware
    const errorMiddleware = (err, req, res, next) => {
        if (err instanceof types_1.HttpError || err instanceof base_wallet_1.WalletError || err instanceof internal_1.ActionError) {
            const status = Number(err.status ?? 400);
            res.status(status).json({
                code: 1,
                message: err.message
            });
        }
        else {
            next(err);
        }
    };
    app.use(errorMiddleware);
}
exports.initServer = initServer;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2VydmVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL21haW4vYXBpL3NlcnZlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxnREFBdUI7QUFDdkIsc0RBQStEO0FBQy9ELDBCQUEwQjtBQUMxQixrREFBeUI7QUFDekIsZ0RBQXVCO0FBQ3ZCLHlFQUEwRTtBQUMxRSw0RUFBMEM7QUFDMUMsMEVBQTBFO0FBQzFFLHlGQUFxRDtBQUNyRCxrREFBOEM7QUFFOUMsb0RBTThCO0FBQzlCLG1EQUE4QztBQUM5QyxnREFBK0M7QUFNL0MsU0FBZ0IsWUFBWSxDQUFFLEdBQXlCLEVBQUUsTUFBb0I7SUFDM0UsY0FBYztJQUNkLG1DQUFtQztJQUNuQyx1QkFBdUI7SUFFdkIsSUFBSSxNQUFtQixDQUFBO0lBRXZCLElBQUksTUFBTSxDQUFDLFFBQVEsRUFBRTtRQUNuQixnQkFBZ0I7UUFDaEIsTUFBTSxPQUFPLEdBQXdCLEVBQUUsQ0FBQTtRQUV2QyxNQUFNLE1BQU0sR0FBRyx3QkFBd0IsQ0FBQyxXQUFXLEVBQUUsQ0FBQTtRQUNyRCxPQUFPLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQ25CLE1BQU0sR0FBRyxHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsa0NBQWtDLEVBQUUsS0FBSyxDQUFDLENBQUE7UUFDbEUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUE7UUFFaEMsT0FBTyxDQUFDLE9BQU8sR0FBRyxNQUFNLENBQUE7UUFDeEIsT0FBTyxDQUFDLFdBQVcsR0FBRyxDQUFDLE1BQU0sRUFBRSxRQUFRLEVBQUUsRUFBRTtZQUN4QyxNQUFjLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQTtZQUNuQyxPQUFPLEdBQUcsQ0FBQTtRQUNaLENBQUMsQ0FBQTtRQUVELE1BQU0sR0FBRyxlQUFLLENBQUMsWUFBWSxDQUFDLE9BQU8sRUFBRSxHQUFH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