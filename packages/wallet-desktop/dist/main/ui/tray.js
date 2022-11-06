"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Tray = void 0;
const electron_1 = require("electron");
const lib_1 = require("@wallet/lib");
const internal_1 = require("@wallet/main/internal");
class Tray {
    locals;
    tray;
    iconPath;
    constructor(locals) {
        this.locals = locals;
        this.iconPath = (0, internal_1.getResourcePath)('img/tray.png');
        const { sharedMemoryManager } = locals;
        sharedMemoryManager.on('change', (sharedMemory) => {
            const wallets = Object
                .keys(sharedMemory.settings.wallet.wallets)
                .map(name => ({ name }));
            this.updateContextMenu(wallets);
        });
        this.tray = new electron_1.Tray(this.iconPath);
        this.tray.setToolTip('i3Market wallet');
        this.updateContextMenu([]);
    }
    updateContextMenu(wallets) {
        const { windowManager, sharedMemoryManager, actionReducer } = this.locals;
        const currentWallet = sharedMemoryManager.memory.settings.wallet.current;
        const contextMenu = electron_1.Menu.buildFromTemplate([
            { label: 'Open', type: 'normal', click: () => windowManager.openMainWindow() },
            {
                label: 'Wallet',
                type: 'submenu',
                enabled: wallets.length > 0,
                submenu: wallets.map(walletInfo => ({
                    label: walletInfo.name,
                    type: 'radio',
                    checked: currentWallet === walletInfo.name,
                    click: async () => {
                        await actionReducer.reduce(lib_1.selectWalletAction.create({
                            wallet: walletInfo.name
                        }));
                    }
                }))
            },
            {
                label: 'Close',
                type: 'normal',
                click: () => {
                    windowManager.closeAllWindow();
                    electron_1.app.quit();
                }
            }
        ]);
        this.tray.setContextMenu(contextMenu);
    }
}
exports.Tray = Tray;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHJheS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tYWluL3VpL3RyYXkudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsdUNBQTBEO0FBRzFELHFDQUFnRDtBQUVoRCxvREFBK0Q7QUFNL0QsTUFBYSxJQUFJO0lBSVE7SUFITixJQUFJLENBQWM7SUFDbEIsUUFBUSxDQUFRO0lBRWpDLFlBQXVCLE1BQWM7UUFBZCxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQ25DLElBQUksQ0FBQyxRQUFRLEdBQUcsSUFBQSwwQkFBZSxFQUFDLGNBQWMsQ0FBQyxDQUFBO1FBQy9DLE1BQU0sRUFBRSxtQkFBbUIsRUFBRSxHQUFHLE1BQU0sQ0FBQTtRQUN0QyxtQkFBbUIsQ0FBQyxFQUFFLENBQUMsUUFBUSxFQUFFLENBQUMsWUFBWSxFQUFFLEVBQUU7WUFDaEQsTUFBTSxPQUFPLEdBQWlCLE1BQU07aUJBQ2pDLElBQUksQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUM7aUJBQzFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUMsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDLENBQUE7WUFFMUIsSUFBSSxDQUFDLGlCQUFpQixDQUFDLE9BQU8sQ0FBQyxDQUFBO1FBQ2pDLENBQUMsQ0FBQyxDQUFBO1FBRUYsSUFBSSxDQUFDLElBQUksR0FBRyxJQUFJLGVBQVksQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUE7UUFDM0MsSUFBSSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtRQUN2QyxJQUFJLENBQUMsaUJBQWlCLENBQUMsRUFBRSxDQUFDLENBQUE7SUFDNUIsQ0FBQztJQUVELGlCQUFpQixDQUFFLE9BQXFCO1FBQ3RDLE1BQU0sRUFBRSxhQUFhLEVBQUUsbUJBQW1CLEVBQUUsYUFBYSxFQUFFLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQTtRQUN6RSxNQUFNLGFBQWEsR0FBRyxtQkFBbUIsQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUE7UUFFeEUsTUFBTSxXQUFXLEdBQUcsZUFBSSxDQUFDLGlCQUFpQixDQUFDO1lBQ3pDLEVBQUUsS0FBSyxFQUFFLE1BQU0sRUFBRSxJQUFJLEVBQUUsUUFBUSxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsQ0FBQyxhQUFhLENBQUMsY0FBYyxFQUFFLEVBQUU7WUFDOUU7Z0JBQ0UsS0FBSyxFQUFFLFFBQVE7Z0JBQ2YsSUFBSSxFQUFFLFNBQVM7Z0JBQ2YsT0FBTyxFQUFFLE9BQU8sQ0FBQyxNQUFNLEdBQUcsQ0FBQztnQkFDM0IsT0FBTyxFQUNMLE9BQU8sQ0FBQyxHQUFHLENBQTZCLFVBQVUsQ0FBQyxFQUFFLENBQUMsQ0FBQztvQkFDckQsS0FBSyxFQUFFLFVBQVUsQ0FBQyxJQUFJO29CQUN0QixJQUFJLEVBQUUsT0FBTztvQkFDYixPQUFPLEVBQUUsYUFBYSxLQUFLLFVBQVUsQ0FBQyxJQUFJO29CQUMxQyxLQUFLLEVBQUUsS0FBSyxJQUFJLEVBQUU7d0JBQ2hCLE1BQU0sYUFBYSxDQUFDLE1BQU0sQ0FBQyx3QkFBa0IsQ0FBQyxNQUFNLENBQUM7NEJBQ25ELE1BQU0sRUFBRSxVQUFVLENBQUMsSUFBSTt5QkFDeEIsQ0FBQyxDQUFDLENBQUE7b0JBQ0wsQ0FBQztpQkFDRixDQUFDLENBQUM7YUFDTjtZQUNEO2dCQUNFLEtBQUssRUFBRSxPQUFPO2dCQUNkLElBQUksRUFBRSxRQUFRO2dCQUNkLEtBQUssRUFBRSxHQUFHLEVBQUU7b0JBQ1YsYUFBYSxDQUFDLGNBQWMsRUFBRSxDQUFBO29CQUM5QixjQUFHLENBQUMsSUFBSSxFQUFFLENBQUE7Z0JBQ1osQ0FBQzthQUNGO1NBQ0YsQ0FBQyxDQUFBO1FBQ0YsSUFBSSxDQUFDLElBQUksQ0FBQyxjQUFjLENBQUMsV0FBVyxDQUFDLENBQUE7SUFDdkMsQ0FBQztDQUNGO0FBckRELG9CQXFEQyJ9