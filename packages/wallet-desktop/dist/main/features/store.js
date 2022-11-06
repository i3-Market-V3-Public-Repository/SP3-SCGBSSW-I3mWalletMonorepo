"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.storeFeature = void 0;
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const lodash_1 = __importDefault(require("lodash"));
const electron_1 = require("electron");
const electron_store_1 = __importDefault(require("electron-store"));
const internal_1 = require("@wallet/main/internal");
const feature_error_1 = require("./feature-error");
const initStore = (storeOptions) => {
    const store = new electron_store_1.default(storeOptions);
    const lastDate = store.get('start');
    if (lastDate !== undefined) {
        internal_1.logger.info(`Previous start at ${lastDate.toString()}`);
    }
    else {
        internal_1.logger.info('This is the first time you start this application!');
    }
    store.set('start', new Date());
    return store;
};
const recoverStore = async (storeOptions, locals) => {
    const { settings, dialog } = locals;
    const walletSettings = settings.get('wallet');
    if (walletSettings.current === undefined) {
        throw new Error('Cannot initialize store if current wallet is not selected');
    }
    const accept = await dialog.confirmation({
        message: 'Seems that the data is stored using an old version. Remove the old wallet to create a new one for this version?',
        acceptMsg: 'Yes',
        rejectMsg: 'No'
    });
    if (accept === true) {
        const file = path_1.default.join(storeOptions.cwd ?? '', `${storeOptions.name ?? ''}.${storeOptions.fileExtension ?? ''}`);
        fs_1.default.unlinkSync(file);
    }
    return initStore(storeOptions);
};
exports.storeFeature = {
    name: 'store',
    async start(opts, locals) {
        const { settings, auth } = locals;
        let store;
        const name = lodash_1.default.get(opts, 'name', 'wallet');
        const storePath = lodash_1.default.get(opts, 'storePath', path_1.default.resolve(electron_1.app.getPath('userData')));
        const encryptionEnabled = lodash_1.default.get(opts, 'encryption.enabled', false);
        const walletSettings = settings.get('wallet');
        if (walletSettings.current === undefined) {
            throw new Error('Cannot initialize store if current wallet is not selected');
        }
        const walletArgs = walletSettings.wallets[walletSettings.current];
        const storeId = walletArgs.store;
        const storeOptions = {
            name: `${name}.${storeId}`,
            cwd: storePath,
            fileExtension: encryptionEnabled ? 'enc.json' : 'json'
        };
        if (encryptionEnabled) {
            storeOptions.encryptionKey = await auth.computeWalletKey(storeId);
            try {
                store = initStore(storeOptions);
            }
            catch (ex) {
                if (ex instanceof SyntaxError) {
                    store = await recoverStore(storeOptions, locals);
                }
            }
        }
        else {
            store = initStore(storeOptions);
        }
        if (store === undefined) {
            throw new feature_error_1.StartFeatureError('Cannot start store', true);
        }
        locals.featureContext.store = store;
        locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: true }));
    },
    async stop(opts, locals) {
        delete locals.featureContext.store;
        locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: false }));
    }
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3RvcmUuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWFpbi9mZWF0dXJlcy9zdG9yZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxnREFBdUI7QUFDdkIsNENBQW1CO0FBQ25CLG9EQUFzQjtBQUN0Qix1Q0FBOEI7QUFFOUIsb0VBQTBDO0FBRTFDLG9EQUFzRDtBQUd0RCxtREFBbUQ7QUFhbkQsTUFBTSxTQUFTLEdBQUcsQ0FBQyxZQUEwQixFQUFTLEVBQUU7SUFDdEQsTUFBTSxLQUFLLEdBQVUsSUFBSSx3QkFBYSxDQUFDLFlBQVksQ0FBQyxDQUFBO0lBRXBELE1BQU0sUUFBUSxHQUFHLEtBQUssQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLENBQUE7SUFDbkMsSUFBSSxRQUFRLEtBQUssU0FBUyxFQUFFO1FBQzFCLGlCQUFNLENBQUMsSUFBSSxDQUFDLHFCQUFxQixRQUFRLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQyxDQUFBO0tBQ3hEO1NBQU07UUFDTCxpQkFBTSxDQUFDLElBQUksQ0FBQyxvREFBb0QsQ0FBQyxDQUFBO0tBQ2xFO0lBQ0QsS0FBSyxDQUFDLEdBQUcsQ0FBQyxPQUFPLEVBQUUsSUFBSSxJQUFJLEVBQUUsQ0FBQyxDQUFBO0lBRTlCLE9BQU8sS0FBSyxDQUFBO0FBQ2QsQ0FBQyxDQUFBO0FBRUQsTUFBTSxZQUFZLEdBQUcsS0FBSyxFQUFFLFlBQTBCLEVBQUUsTUFBYyxFQUFrQixFQUFFO0lBQ3hGLE1BQU0sRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFLEdBQUcsTUFBTSxDQUFBO0lBRW5DLE1BQU0sY0FBYyxHQUFHLFFBQVEsQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLENBQUE7SUFDN0MsSUFBSSxjQUFjLENBQUMsT0FBTyxLQUFLLFNBQVMsRUFBRTtRQUN4QyxNQUFNLElBQUksS0FBSyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7S0FDN0U7SUFFRCxNQUFNLE1BQU0sR0FBRyxNQUFN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