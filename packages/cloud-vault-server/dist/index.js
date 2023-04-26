#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.serverPromise = void 0;
const crypto_1 = __importDefault(require("crypto"));
const express_1 = __importDefault(require("express"));
const express_session_1 = __importDefault(require("express-session"));
const fs_1 = require("fs");
const http_1 = __importDefault(require("http"));
const morgan_1 = __importDefault(require("morgan"));
const path_1 = require("path");
const config_1 = require("./config");
const api_1 = __importDefault(require("./routes/api"));
const oas_1 = __importDefault(require("./routes/oas"));
const well_known_cvs_configuration_1 = __importDefault(require("./routes/well-known-cvs-configuration"));
initSpec();
async function startApp() {
    const app = (0, express_1.default)();
    app.use((0, express_session_1.default)({
        secret: crypto_1.default.randomBytes(32).toString('base64'),
        resave: false,
        saveUninitialized: false
    }));
    app.use(express_1.default.json({ limit: config_1.dbConfig.storageCharLength + 1024 }));
    app.use((0, morgan_1.default)(config_1.general.nodeEnv === 'development' ? 'dev' : 'tiny'));
    // Load CORS for the routes
    app.use((await Promise.resolve().then(() => __importStar(require('./middlewares/cors')))).corsMiddleware);
    // Load the .well-known/cvs-configuration
    app.use('/', await (0, well_known_cvs_configuration_1.default)());
    // OAS routes for downloading OAS json and visulaizing it
    app.use('/', await (0, oas_1.default)());
    // Install the OpenApiValidator for the routes
    app.use('/api/' + config_1.apiVersion, (await Promise.resolve().then(() => __importStar(require('./middlewares/openapi')))).openApiValidatorMiddleware);
    // Load API routes
    app.use('/api/' + config_1.apiVersion, await (0, api_1.default)());
    // Handle errors
    app.use((await Promise.resolve().then(() => __importStar(require('./middlewares/error')))).errorMiddleware);
    return app;
}
__exportStar(require("./vault"), exports);
exports.serverPromise = new Promise((resolve, reject) => {
    let dbConnection;
    Promise.resolve().then(() => __importStar(require('./db/index'))).then(module => {
        dbConnection = module;
        dbConnection.db.initialized.then(() => {
            console.log('⚡️[server]: DB connection ready');
        }).catch((error) => {
            throw new Error('DB connection failed\n' + JSON.stringify(error, undefined, 2));
        });
    }).catch((err) => {
        reject(err);
    });
    startApp().then((app) => {
        /**
         * Listen on .env SERVER_PORT or 3000/tcp, on all network interfaces.
         */
        const server = http_1.default.createServer(app);
        const { port, addr, publicUrl } = config_1.serverConfig;
        server.listen(port, addr);
        /**
          * Event listener for HTTP server "listening" event.
          */
        server.on('listening', function () {
            console.log(`⚡️[server]: Server is running at ${publicUrl}`);
            console.log(`⚡️[server]: OpenAPI JSON spec at ${publicUrl}/spec`);
            console.log(`⚡️[server]: OpenAPI browsable spec at ${publicUrl}/spec-ui`);
            resolve({ server, dbConnection });
        });
        server.on('close', () => {
            dbConnection.db.close().catch((err) => {
                reject(err);
            });
        });
    }).catch((e) => {
        console.log(e);
        reject(e);
    });
});
function initSpec() {
    const oasPath = (0, path_1.join)(__dirname, 'spec', 'cvs.json');
    const oas = JSON.parse((0, fs_1.readFileSync)(oasPath, 'utf8'));
    addServers(oas);
    oas.components.securitySchemes.i3m.openIdConnectUrl = oas.components.securitySchemes.i3m.openIdConnectUrl.replace('OIDC_PROVIDER_URI', config_1.oidcConfig.providerUri);
    (0, fs_1.writeFileSync)(oasPath, JSON.stringify(oas, undefined, 2), 'utf-8');
}
function addServers(spec) {
    const localhostServer = {
        url: config_1.serverConfig.localUrl
    };
    spec.servers = [localhostServer];
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQ0Esb0RBQTJCO0FBQzNCLHNEQUEwQztBQUMxQyxzRUFBcUM7QUFDckMsMkJBQWdEO0FBQ2hELGdEQUF1QjtBQUN2QixvREFBMkI7QUFFM0IsK0JBQXVDO0FBQ3ZDLHFDQUFrRjtBQUNsRix1REFBMkM7QUFDM0MsdURBQTJDO0FBQzNDLHlHQUF5RjtBQUV6RixRQUFRLEVBQUUsQ0FBQTtBQUVWLEtBQUssVUFBVSxRQUFRO0lBQ3JCLE1BQU0sR0FBRyxHQUFHLElBQUEsaUJBQU8sR0FBRSxDQUFBO0lBRXJCLEdBQUcsQ0FBQyxHQUFHLENBQUMsSUFBQSx5QkFBTyxFQUFDO1FBQ2QsTUFBTSxFQUFFLGdCQUFNLENBQUMsV0FBVyxDQUFDLEVBQUUsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUM7UUFDakQsTUFBTSxFQUFFLEtBQUs7UUFDYixpQkFBaUIsRUFBRSxLQUFLO0tBQ3pCLENBQUMsQ0FBQyxDQUFBO0lBRUgsR0FBRyxDQUFDLEdBQUcsQ0FBQyxpQkFBTyxDQUFDLElBQUksQ0FBQyxFQUFFLEtBQUssRUFBRSxpQkFBUSxDQUFDLGlCQUFpQixHQUFHLElBQUksRUFBRSxDQUFDLENBQUMsQ0FBQTtJQUNuRSxHQUFHLENBQUMsR0FBRyxDQUFDLElBQUEsZ0JBQU0sRUFBQyxnQkFBTyxDQUFDLE9BQU8sS0FBSyxhQUFhLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQTtJQUVuRSwyQkFBMkI7SUFDM0IsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLHdEQUFhLG9CQUFvQixHQUFDLENBQUMsQ0FBQyxjQUFjLENBQUMsQ0FBQTtJQUU1RCx5Q0FBeUM7SUFDekMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVB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