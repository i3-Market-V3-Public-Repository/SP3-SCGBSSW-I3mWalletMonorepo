"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createWallet = void 0;
const uuid_1 = require("uuid");
const lib_1 = require("@wallet/lib");
const action_error_1 = require("../action-error");
const createWallet = (locals) => {
    return {
        type: lib_1.createWalletAction.type,
        async handle(action) {
            const { sharedMemoryManager, dialog } = locals;
            const mem = sharedMemoryManager.memory;
            const walletPackages = mem.walletsMetadata;
            const walletCreationForm = await dialog.form({
                title: 'Wallet creation',
                descriptors: {
                    name: { type: 'text', message: 'Introduce a name for the wallet', allowCancel: false },
                    walletMetadata: {
                        type: 'select',
                        message: 'Select a wallet type',
                        values: Object.entries(walletPackages),
                        getText([walletPackage, walletMetadata]) {
                            return walletMetadata.name;
                        }
                    },
                    provider: {
                        type: 'select',
                        message: 'Select a network',
                        values: mem.settings.providers,
                        getText(provider) {
                            return provider.name;
                        }
                    }
                },
                order: ['name', 'walletMetadata', 'provider']
            });
            if (walletCreationForm === undefined) {
                throw new action_error_1.ActionError('Cannot create wallet. Dialog cancelled', action);
            }
            // Wallet already exists
            if (walletCreationForm.name in mem.settings.wallet.wallets) {
                throw new action_error_1.ActionError(`Wallet ${walletCreationForm.name} already exists`, action);
            }
            const wallet = {
                name: walletCreationForm.name,
                package: walletCreationForm.walletMetadata[0],
                store: (0, uuid_1.v4)(),
                args: {
                    provider: walletCreationForm.provider.provider
                }
            };
            const name = walletCreationForm.name;
            sharedMemoryManager.update((mem) => ({
                ...mem,
                settings: {
                    ...mem.settings,
                    wallet: {
                        ...mem.settings.wallet,
                        // If there is no wallet selected, select this wallet
                        current: mem.settings.wallet.current ?? name,
                        // Add the wallet to the wallet map
                        wallets: {
                            ...mem.settings.wallet.wallets,
                            [name]: wallet
                        }
                    }
                }
            }));
            return { response: wallet, status: 201 };
        }
    };
};
exports.createWallet = createWallet;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3JlYXRlLXdhbGxldC5oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy93YWxsZXQvY3JlYXRlLXdhbGxldC5oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLCtCQUFpQztBQUVqQyxxQ0FHb0I7QUFDcEIsa0RBQTZDO0FBY3RDLE1BQU0sWUFBWSxHQUFvRCxDQUMzRSxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsd0JBQWtCLENBQUMsSUFBSTtRQUM3QixLQUFLLENBQUMsTUFBTSxDQUFFLE1BQU07WUFDbEIsTUFBTSxFQUFFLG1CQUFtQixFQUFFLE1BQU0sRUFBRSxHQUFHLE1BQU0sQ0FBQTtZQUM5QyxNQUFNLEdBQUcsR0FBRyxtQkFBbUIsQ0FBQyxNQUFNLENBQUE7WUFDdEMsTUFBTSxjQUFjLEdBQUcsR0FBRyxDQUFDLGVBQWUsQ0FBQTtZQUUxQyxNQUFNLGtCQUFrQixHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBcUI7Z0JBQy9ELEtBQUssRUFBRSxpQkFBaUI7Z0JBQ3hCLFdBQVcsRUFBRTtvQkFDWCxJQUFJLEVBQUUsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLE9BQU8sRUFBRSxpQ0FBaUMsRUFBRSxXQUFXLEVBQUUsS0FBSyxFQUFFO29CQUN0RixjQUFjLEVBQUU7d0JBQ2QsSUFBSSxFQUFFLFFBQVE7d0JBQ2QsT0FBTyxFQUFFLHNCQUFzQjt3QkFDL0IsTUFBTSxFQUFFLE1BQU0sQ0FBQyxPQUFPLENBQWlCLGNBQWMsQ0FBQzt3QkFDdEQsT0FBTyxDQUFFLENBQUMsYUFBYSxFQUFFLGNBQWMsQ0FBQzs0QkFDdEMsT0FBTyxjQUFjLENBQUMsSUFBSSxDQUFBO3dCQUM1QixDQUFDO3FCQUNGO29CQUNELFFBQVEsRUFBRTt3QkFDUixJQUFJLEVBQUUsUUFBUTt3QkFDZCxPQUFPLEVBQUUsa0JBQWtCO3dCQUMzQixNQUFNLEVBQUUsR0FBRyxDQUFDLFFBQVEsQ0FBQyxTQUFTO3dCQUM5QixPQUFPLENBQUUsUUFBUTs0QkFDZixPQUFPLFFBQVEsQ0FBQyxJQUFJLENBQUE7d0JBQ3RCLENBQUM7cUJBQ0Y7aUJBQ0Y7Z0JBQ0QsS0FBSyxFQUFFLENBQUMsTUFBTSxFQUFFLGdCQUFnQixFQUFFLFVBQVUsQ0FBQzthQUM5QyxDQUFDLENBQUE7WUFFRixJQUFJLGtCQUFrQixLQUFLLFNBQVMsRUFBRTtnQkFDcEMsTUFBTSxJQUFJLDBCQUFXLENBQUMsd0NBQXdDLEVBQUUsTUFBTSxDQUFDLENBQUE7YUFDeEU7WUFFRCx3QkFBd0I7WUFDeEIsSUFBSSxrQkFBa0IsQ0FBQyxJQUFJLElBQUksR0FBRyxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFO2dCQUMxRCxNQUFNLElBQUksMEJBQVcsQ0FBQyxVQUFVLGtCQUFrQixDQUFDLElBQUksaUJBQWlCLEVBQUUsTUFBTSxDQUFDLENBQUE7YUFDbEY7WUFFRCxNQUFNLE1BQU0sR0FBZTtnQkFDekIsSUFBSSxFQUFFLGtCQUFrQixDQUFDLElBQUk7Z0JBQzdCLE9BQU8sRUFBRSxrQkFBa0IsQ0FBQyxjQUFjLENBQUMsQ0FBQyxDQUFDO2dCQUM3QyxLQUFLLEVBQUUsSUFBQSxTQUFJLEdBQUU7Z0JBQ2IsSUFBSSxFQUFFO29CQUNKLFFBQVEsRUFBRSxrQkFBa0IsQ0FBQyxRQUFRLENBQUMsUUFBUTtpQkFDL0M7YUFDRixDQUFBO1lBRUQsTUFBTSxJQUFJLEdBQUcsa0JBQWtCLENBQUMsSUFBSSxDQUFBO1lBQ3BDLG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsQ0FBQztnQkFDbkMsR0FBRyxHQUFHO2dCQUNOLFFBQVEsRUFBRTtvQkFDUixHQUFHLEdBQUcsQ0FBQyxRQUFRO29CQUNmLE1BQU0sRUFBRTt3QkFDTixHQUFHLEdBQUcsQ0FBQyxRQUFRLENBQUMsTUFBTTt3QkFFdEIscURBQXFEO3dCQUNyRCxPQUFPLEVBQUUsR0FBRyxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsT0FBTyxJQUFJLElBQUk7d0JBRTVDLG1DQUFtQzt3QkFDbkMsT0FBTyxFQUFFOzRCQUNQLEdBQUcsR0FBRyxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsT0FBTzs0QkFDOUIsQ0FBQyxJQUFJLENBQUMsRUFBRSxNQUFNO3lCQUNmO3FCQUNGO2lCQUNGO2FBQ0YsQ0FBQyxDQUFDLENBQUE7WUFFSCxPQUFPLEVBQUUsUUFBUSxFQUFFLE1BQU0sRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7UUFDMUMsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUEzRVksUUFBQSxZQUFZLGdCQTJFeEIifQ==