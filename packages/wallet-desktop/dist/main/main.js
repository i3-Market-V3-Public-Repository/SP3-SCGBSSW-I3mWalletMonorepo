"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
const path_1 = __importDefault(require("path"));
const jose_1 = require("jose");
const lib_1 = require("@wallet/lib");
const internal_1 = require("./internal");
function validProviders(providers) {
    if (providers === undefined || providers.length === 0) {
        return false;
    }
    // Creates an object which parameters say if all providers have this field set
    const filledArguments = providers.reduce((prev, curr) => ({
        name: prev.name || curr.name === undefined,
        provider: prev.provider || curr.provider === undefined,
        network: prev.network || curr.network === undefined,
        rpcUrl: prev.rpcUrl || curr.rpcUrl === undefined,
    }), { name: false, provider: false, network: false, rpcUrl: false });
    return Object.values(filledArguments).reduce((prev, curr) => prev && !curr, true);
}
async function getAppSettings(locals) {
    const sharedMemoryManager = new internal_1.SharedMemoryManager();
    locals.sharedMemoryManager = sharedMemoryManager;
    const settings = (0, internal_1.initSettings)({
        cwd: electron_1.app.getPath('userData')
    }, sharedMemoryManager);
    const providers = settings.get('providers');
    // Setup default providers
    if (!validProviders(providers)) {
        settings.set('providers', [
            { name: 'Rinkeby', provider: 'did:ethr:rinkeby', network: 'rinkeby', rpcUrl: 'https://rpc.ankr.com/eth_rinkeby' },
            { name: 'i3Market', provider: 'did:ethr:i3m', network: 'i3m', rpcUrl: 'http://95.211.3.250:8545' }
        ]);
    }
    const wallet = settings.get('wallet');
    wallet.packages = [
        '@i3m/sw-wallet',
        '@i3m/bok-wallet'
    ];
    settings.set('wallet', wallet);
    const secret = settings.get('secret');
    if (secret === undefined) {
        const key = await (0, jose_1.generateSecret)('HS256', { extractable: true });
        const jwk = await (0, jose_1.exportJWK)(key);
        settings.set('secret', jwk);
    }
    // Syncronize shared memory and settings
    sharedMemoryManager.update((mem) => ({
        ...mem,
        settings: settings.store
    }));
    sharedMemoryManager.on('change', (mem) => {
        settings.set(mem.settings);
    });
    locals.settings = settings;
    const ctx = (0, lib_1.initContext)({
        appPath: path_1.default.resolve(__dirname, '../')
    });
    return ctx;
}
async function initActions(ctx, locals) {
    locals.actionReducer = new internal_1.ActionReducer(locals);
}
async function initUI(ctx, locals) {
    locals.windowManager = new internal_1.WindowManager(locals);
    if (process.env.REACT_DEVTOOLS !== undefined) {
        await electron_1.session.defaultSession.loadExtension(process.env.REACT_DEVTOOLS);
    }
    locals.tray = new internal_1.Tray(locals);
    locals.dialog = new internal_1.ElectronDialog(locals);
    locals.toast = new internal_1.ToastManager(locals);
    // // Quit when all windows are closed, except on macOS. There, it's common
    // // for applications and their menu bar to stay active until the user quits
    // // explicitly with Cmd + Q.
    electron_1.app.on('window-all-closed', () => {
        // if (process.platform !== 'darwin') {
        //   app.quit()
        // }
        // Do not close the application even if all windows are closed
        internal_1.logger.debug('All windows are closed');
    });
    //
    electron_1.app.on('activate', function () {
        // On macOS it's common to re-create a window in the app when the
        // dock icon is clicked and there are no other windows open.
        if (electron_1.BrowserWindow.getAllWindows().length === 0) {
            locals.windowManager.openMainWindow();
        }
    });
}
async function initAuth(ctx, locals) {
    const auth = new internal_1.LocalAuthentication(locals);
    locals.auth = auth;
    await auth.authenticate();
}
async function initFeatureManager(ctx, locals) {
    locals.featureManager = new internal_1.FeatureManager();
    locals.featureContext = {};
}
async function initApi(ctx, locals) {
    // Create and initialize connect manager
    // FIXME: Important bug!? The secret is accesible on the disk...
    // Maybe derivate the secret from the password?
    const jwk = locals.settings.get('secret');
    const key = await (0, jose_1.importJWK)(jwk, 'HS256');
    locals.connectManager = new internal_1.ConnectManager(locals, key);
    await locals.connectManager.initialize();
    // Create and initialize api manager
    locals.apiManager = new internal_1.ApiManager(locals);
    await locals.apiManager.initialize();
}
async function initWalletFactory(ctx, locals) {
    locals.walletFactory = new internal_1.WalletFactory(locals);
    await locals.walletFactory.initialize();
}
/**
 * Desktop Wallet startup function
 */
async function onReady() {
    const locals = {};
    const ctx = await getAppSettings(locals);
    await initActions(ctx, locals);
    await initUI(ctx, locals);
    await initFeatureManager(ctx, locals);
    await initApi(ctx, locals);
    await initAuth(ctx, locals);
    await initWalletFactory(ctx, locals);
    // Launch UI
    const { windowManager } = locals;
    windowManager.openMainWindow('/wallet');
}
exports.default = async (argv) => {
    // This method will be called when Electron has finished
    // initialization and is ready to create browser windows.
    // Some APIs can only be used after this event occurs.
    electron_1.app.on('ready', () => {
        const singleInstance = electron_1.app.requestSingleInstanceLock();
        if (!singleInstance) {
            internal_1.logger.warn('The application is already running');
            electron_1.dialog.showErrorBox('Cannot start', 'The application is already running. Check your tray.');
            electron_1.app.quit();
            return;
        }
        onReady().catch((err) => {
            if (err instanceof internal_1.StartFeatureError && err.exit) {
                return electron_1.app.quit();
            }
            if (err instanceof Error) {
                internal_1.logger.error(err.stack);
            }
            else {
                internal_1.logger.error(err);
            }
        });
    });
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9tYWluL21haW4udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSx1Q0FBOEQ7QUFDOUQsZ0RBQXVCO0FBQ3ZCLCtCQUFnRTtBQUVoRSxxQ0FBbUQ7QUFFbkQseUNBaUJtQjtBQUVuQixTQUFTLGNBQWMsQ0FBRSxTQUFxQjtJQUM1QyxJQUFJLFNBQVMsS0FBSyxTQUFTLElBQUksU0FBUyxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7UUFDckQsT0FBTyxLQUFLLENBQUE7S0FDYjtJQUVELDhFQUE4RTtJQUM5RSxNQUFNLGVBQWUsR0FBRyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxFQUFFLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQztRQUN4RCxJQUFJLEVBQUUsSUFBSSxDQUFDLElBQUksSUFBSSxJQUFJLENBQUMsSUFBSSxLQUFLLFNBQVM7UUFDMUMsUUFBUSxFQUFFLElBQUksQ0FBQyxRQUFRLElBQUksSUFBSSxDQUFDLFFBQVEsS0FBSyxTQUFTO1FBQ3RELE9BQU8sRUFBRSxJQUFJLENBQUMsT0FBTyxJQUFJLElBQUksQ0FBQyxPQUFPLEtBQUssU0FBUztRQUNuRCxNQUFNLEVBQUUsSUFBSSxDQUFDLE1BQU0sSUFBSSxJQUFJLENBQUMsTUFBTSxLQUFLLFNBQVM7S0FDakQsQ0FBQyxFQUFFLEVBQUUsSUFBSSxFQUFFLEtBQUssRUFBRSxRQUFRLEVBQUUsS0FBSyxFQUFFLE9BQU8sRUFBRSxLQUFLLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUE7SUFFcEUsT0FBTyxNQUFNLENBQUMsTUFBTSxDQUFDLGVBQWUsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksRUFBRSxJQUFJLEVBQUUsRUFBRSxDQUFDLElBQUksSUFBSSxDQUFDLElBQUksRUFBRSxJQUFJLENBQUMsQ0FBQTtBQUNuRixDQUFDO0FBRUQsS0FBSyxVQUFVLGNBQWMs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