"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WindowManager = void 0;
const electron_1 = require("electron");
const path_1 = __importDefault(require("path"));
const internal_1 = require("@wallet/main/internal");
const custom_window_1 = require("./custom-window");
const menu_bar_1 = require("./menu-bar");
class WindowManager {
    locals;
    windows;
    constructor(locals) {
        this.locals = locals;
        // Setup menu bar
        const menuBar = (0, menu_bar_1.buildMenuBar)(locals);
        electron_1.Menu.setApplicationMenu(menuBar);
        this.windows = new Map();
        const { sharedMemoryManager } = locals;
        sharedMemoryManager.on('change', (sharedMemory, oldSharedMemory, emitter) => {
            for (const [, window] of this.windows) {
                window.updateSharedMemory(emitter);
            }
        });
    }
    convertToArgs(args) {
        const json = JSON.stringify(args);
        return `--args=${Buffer.from(json).toString('base64')}`;
    }
    defaultMapper = (a) => a;
    createWindow(args, creationArgs = {}) {
        internal_1.logger.debug(`Create a new window with name: ${args.name}`);
        return new custom_window_1.CustomWindow(this.locals, {
            height: 600,
            width: 800,
            webPreferences: {
                preload: path_1.default.join(__dirname, 'preload.js'),
                additionalArguments: [this.convertToArgs(args)],
                contextIsolation: false,
                nodeIntegration: true,
                enableRemoteModule: true // TODO: Needed because electron-connect. It is deprecated so electron connect must be removed
            },
            ...creationArgs
        });
    }
    createDialog(args, creationArgs = {}) {
        internal_1.logger.debug(`Create a new dialog with name: ${args.name}`);
        const dialog = new custom_window_1.CustomWindow(this.locals, {
            height: 300,
            width: 400,
            titleBarStyle: 'hidden',
            frame: false,
            resizable: false,
            hasShadow: false,
            webPreferences: {
                preload: path_1.default.join(__dirname, 'preload.js'),
                additionalArguments: [this.convertToArgs(args)],
                contextIsolation: false,
                nodeIntegration: true
            },
            ...creationArgs
        });
        return dialog;
    }
    initWindow(window) {
        // and load the index.html of the app.
        internal_1.logger.debug(`Initialize window with id ${window.id}`);
        const indexPath = (0, internal_1.getResourcePath)('index.html');
        window.loadFile(indexPath).catch((err) => {
            if (err instanceof Error) {
                throw err;
            }
            else {
                throw new Error(`Cannot load page: ${indexPath}`);
            }
        });
        // Open the DevTools.
        if (process.env.NODE_ENV === 'development') {
            window.webContents.openDevTools();
        }
    }
    openWindow(windowArgs) {
        const name = windowArgs.name;
        let window = this.windows.get(name);
        if (window !== undefined) {
            window.focus();
            return window;
        }
        // Create the browser window.
        window = this.createWindow(windowArgs);
        this.initWindow(window);
        this.windows.set(name, window);
        window.on('close', () => {
            this.windows.delete(name);
        });
        return window;
    }
    openMainWindow = (path) => {
        let window = this.getWindow('Main');
        if (window === undefined) {
            window = this.openWindow({
                name: 'Main',
                path: path ?? 'wallet'
            });
        }
        else if (path !== undefined) {
            window.input$.next({
                type: 'navigate',
                path
            });
        }
        return window;
    };
    openSignWindow = (accountId) => this.openWindow({
        name: 'Sign',
        accountId
    });
    openPasswordDialog() {
        // Create the browser window.
        const passwordDialog = this.createDialog({
            name: 'Password'
        });
        this.initWindow(passwordDialog);
        return passwordDialog;
    }
    getWindow(name) {
        return this.windows.get(name);
    }
    closeAllWindow() {
        internal_1.logger.debug('Close all windows');
        for (const [, window] of this.windows) {
            window.close();
        }
        this.windows.clear();
    }
}
exports.WindowManager = WindowManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2luZG93LW1hbmFnZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi91aS93aW5kb3ctbWFuYWdlci93aW5kb3ctbWFuYWdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSx1Q0FBOEM7QUFDOUMsZ0RBQXVCO0FBR3ZCLG9EQUF1RTtBQUN2RSxtREFBc0Q7QUFDdEQseUNBQXlDO0FBR3pDLE1BQWEsYUFBYTtJQUdEO0lBRnZCLE9BQU8sQ0FBMkI7SUFFbEMsWUFBdUIsTUFBYztRQUFkLFdBQU0sR0FBTixNQUFNLENBQVE7UUFDbkMsaUJBQWlCO1FBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUEsdUJBQVksRUFBQyxNQUFNLENBQUMsQ0FBQTtRQUNwQyxlQUFJLENBQUMsa0JBQWtCLENBQUMsT0FBTyxDQUFDLENBQUE7UUFFaEMsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLEdBQUcsRUFBRSxDQUFBO1FBRXhCLE1BQU0sRUFBRSxtQkFBbUIsRUFBRSxHQUFHLE1BQU0sQ0FBQTtRQUN0QyxtQkFBbUIsQ0FBQyxFQUFFLENBQUMsUUFBUSxFQUFFLENBQUMsWUFBWSxFQUFFLGVBQWUsRUFBRSxPQUFPLEVBQUUsRUFBRTtZQUMxRSxLQUFLLE1BQU0sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxJQUFJLElBQUksQ0FBQyxPQUFPLEVBQUU7Z0JBQ3JDLE1BQU0sQ0FBQyxrQkFBa0IsQ0FBQyxPQUFPLENBQUMsQ0FBQTthQUNuQztRQUNILENBQUMsQ0FBQyxDQUFBO0lBQ0osQ0FBQztJQUVELGFBQWEsQ0FBRSxJQUFnQjtRQUM3QixNQUFNLElBQUksR0FBRyxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFBO1FBQ2pDLE9BQU8sVUFBVSxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFBO0lBQ3pELENBQUM7SUFFRCxhQUFhLEdBQWdC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