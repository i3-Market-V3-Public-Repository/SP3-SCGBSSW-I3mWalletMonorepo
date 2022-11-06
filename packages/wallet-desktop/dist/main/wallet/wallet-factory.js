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
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletFactory = void 0;
const internal_1 = require("@wallet/main/internal");
const errors_1 = require("./errors");
const featureMap = {
    store: internal_1.storeFeature
};
class WalletFactory {
    locals;
    _wallet;
    _walletName;
    featuresByWallet;
    constructor(locals) {
        this.locals = locals;
        this._walletName = undefined;
        this.featuresByWallet = {};
        // Change wallet if global state changes
        const { sharedMemoryManager } = locals;
        sharedMemoryManager.on('change', (mem, oldMem) => {
            const current = mem.settings.wallet.current;
            const old = oldMem.settings.wallet.current;
            // Update current wallet
            if (current !== undefined && current !== old) {
                const { walletFactory } = locals;
                walletFactory.changeWallet(current).catch((err) => {
                    console.log(err);
                });
            }
        });
    }
    async initialize() {
        await this.loadWalletsMetadata();
        const wallet = this.locals.settings.get('wallet');
        if (wallet.current === undefined) {
            return;
        }
        await this.changeWallet(wallet.current);
    }
    async loadWalletsMetadata() {
        const walletsMetadata = {};
        for (const walletPackage of this.walletPackages) {
            const packageJson = await Promise.resolve().then(() => __importStar(require(`${walletPackage}/package.json`)));
            internal_1.logger.info(`Loaded metadata for wallet '${walletPackage}'`);
            // Store wallet metadata
            const walletMetadata = packageJson.walletMetadata;
            walletsMetadata[walletPackage] = walletMetadata;
            // Initialize features
            const features = [];
            for (const [name, featureArgs] of Object.entries(walletMetadata.features)) {
                features.push(internal_1.FeatureManager.CreateFeature(featureMap[name], featureArgs));
            }
            this.featuresByWallet[walletPackage] = features;
        }
        const { sharedMemoryManager } = this.locals;
        sharedMemoryManager.update((mem) => ({
            ...mem,
            walletsMetadata
        }));
    }
    async buildWallet(walletName) {
        const { settings, featureContext, featureManager, dialog, toast } = this.locals;
        const { wallets } = settings.get('wallet');
        const providersData = settings.get('providers').reduce((prev, curr) => {
            prev[curr.provider] = curr;
            return prev;
        }, {});
        const walletInfo = wallets[walletName];
        if (walletInfo === undefined) {
            throw new Error('Inconsistent data!');
        }
        try {
            // Init wallet features
            // Initialize all the features
            await featureManager.clearFeatures(this.locals);
            const features = this.featuresByWallet[walletInfo.package];
            if (features !== undefined) {
                for (const feature of features) {
                    featureManager.addFeature(feature);
                }
            }
            await featureManager.start(this.locals);
            // Initialize wallet
            const walletMain = (await Promise.resolve().then(() => __importStar(require(walletInfo.package)))).default;
            const wallet = await walletMain({
                ...walletInfo.args,
                store: featureContext.store,
                toast,
                dialog,
                providersData
            });
            return wallet;
        }
        catch (err) {
            // Start errors should be bypassed
            if (err instanceof internal_1.StartFeatureError) {
                throw err;
            }
            if (err instanceof Error) {
                internal_1.logger.error(err.stack);
            }
            else {
                internal_1.logger.error(err);
            }
            throw new errors_1.InvalidWalletError(`Cannot load the wallet '${walletName}'`);
        }
    }
    async changeWallet(walletName) {
        if (walletName === this._walletName) {
            return;
        }
        internal_1.logger.info(`Change wallet to ${walletName}`);
        const { settings, sharedMemoryManager, apiManager } = this.locals;
        // Stop API
        await apiManager.close();
        // Build the current wallet
        this._walletName = walletName;
        try {
            this._wallet = await this.buildWallet(walletName);
        }
        catch (err) {
            this._wallet = undefined;
            this._walletName = undefined;
            this.locals.toast.show({
                message: 'Wallet initialization',
                details: `Could not initialize the wallet '${walletName}'`,
                type: 'warning'
            });
            this.locals.sharedMemoryManager.update((mem) => ({
                ...mem,
                settings: {
                    ...mem.settings,
                    wallet: {
                        ...mem.settings.wallet,
                        current: undefined
                    }
                }
            }));
            return;
        }
        // Setup the resource list inside shared memory
        const identities = await this.wallet.getIdentities();
        const resources = await this.wallet.getResources();
        await sharedMemoryManager.update((mem) => ({
            ...mem, identities, resources
        }));
        // Update current wallet
        settings.set('wallet.current', walletName);
        // Start API
        await apiManager.listen();
    }
    get walletNames() {
        return Object.keys(this.locals.sharedMemoryManager.memory.settings.wallet.wallets);
    }
    get walletPackages() {
        return this.locals.sharedMemoryManager.memory.settings.wallet.packages;
    }
    get walletName() {
        return this._walletName;
    }
    get wallet() {
        if (this._wallet === undefined) {
            throw new errors_1.NoWalletSelectedError('Wallet not select. Maybe you might initialize the wallet factory first.');
        }
        return this._wallet;
    }
    get hasWalletSelected() {
        return this._wallet !== undefined;
    }
}
exports.WalletFactory = WalletFactory;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2FsbGV0LWZhY3RvcnkuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWFpbi93YWxsZXQvd2FsbGV0LWZhY3RvcnkudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFFQSxvREFROEI7QUFFOUIscUNBQW9FO0FBVXBFLE1BQU0sVUFBVSxHQUFlO0lBQzdCLEtBQUssRUFBRSx1QkFBWTtDQUNwQixDQUFBO0FBRUQsTUFBYSxhQUFhO0lBTUQ7SUFMYixPQUFPLENBQW9CO0lBQzNCLFdBQVcsQ0FBb0I7SUFFL0IsZ0JBQWdCLENBQWtCO0lBRTVDLFlBQXVCLE1BQWM7UUFBZCxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQ25DLElBQUksQ0FBQyxXQUFXLEdBQUcsU0FBUyxDQUFBO1FBQzVCLElBQUksQ0FBQyxnQkFBZ0IsR0FBRyxFQUFFLENBQUE7UUFFMUIsd0NBQXdDO1FBQ3hDLE1BQU0sRUFBRSxtQkFBbUIsRUFBRSxHQUFHLE1BQU0sQ0FBQTtRQUN0QyxtQkFBbUIsQ0FBQyxFQUFFLENBQUMsUUFBUSxFQUFFLENBQUMsR0FBRyxFQUFFLE1BQU0sRUFBRSxFQUFFO1lBQy9DLE1BQU0sT0FBTyxHQUFHLEdBQUcsQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQTtZQUMzQyxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUE7WUFFMUMsd0JBQXdCO1lBQ3hCLElBQUksT0FBTyxLQUFLLFNBQVMsSUFBSSxPQUFPLEtBQUssR0FBRyxFQUFFO2dCQUM1QyxNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsTUFBTSxDQUFBO2dCQUNoQyxhQUFhLENBQUMsWUFBWSxDQUFDLE9BQU8sQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFO29CQUNoRCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNs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