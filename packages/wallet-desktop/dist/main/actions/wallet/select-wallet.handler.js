"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.selectWallet = void 0;
const lib_1 = require("@wallet/lib");
const action_error_1 = require("../action-error");
const selectWallet = (locals) => {
    return {
        type: lib_1.selectWalletAction.type,
        async handle(action) {
            const { walletFactory, sharedMemoryManager, dialog } = locals;
            let wallet = action.payload?.wallet;
            if (wallet === undefined) {
                wallet = await dialog.select({ values: walletFactory.walletNames });
            }
            if (wallet === sharedMemoryManager.memory.settings.wallet.current) {
                return { response: wallet };
            }
            if (wallet === undefined) {
                throw new action_error_1.ActionError('Cannot change wallet: no wallet selected', action);
            }
            sharedMemoryManager.update((mem) => ({
                ...mem,
                settings: {
                    ...mem.settings,
                    wallet: {
                        ...mem.settings.wallet,
                        current: wallet
                    }
                },
                identities: {},
                resources: {}
            }));
            locals.toast.show({
                message: 'Wallet change',
                type: 'info',
                details: `Using wallet '${wallet}'`
            });
            return { response: wallet };
        }
    };
};
exports.selectWallet = selectWallet;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2VsZWN0LXdhbGxldC5oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy93YWxsZXQvc2VsZWN0LXdhbGxldC5oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLHFDQUVvQjtBQUNwQixrREFBNkM7QUFHdEMsTUFBTSxZQUFZLEdBQW9ELENBQzNFLE1BQU0sRUFDTixFQUFFO0lBQ0YsT0FBTztRQUNMLElBQUksRUFBRSx3QkFBa0IsQ0FBQyxJQUFJO1FBQzdCLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLEVBQUUsYUFBYSxFQUFFLG1CQUFtQixFQUFFLE1BQU0sRUFBRSxHQUFHLE1BQU0sQ0FBQTtZQUM3RCxJQUFJLE1BQU0sR0FBRyxNQUFNLENBQUMsT0FBTyxFQUFFLE1BQU0sQ0FBQTtZQUNuQyxJQUFJLE1BQU0sS0FBSyxTQUFTLEVBQUU7Z0JBQ3hCLE1BQU0sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsRUFBRSxNQUFNLEVBQUUsYUFBYSxDQUFDLFdBQVcsRUFBRSxDQUFDLENBQUE7YUFDcEU7WUFFRCxJQUFJLE1BQU0sS0FBSyxtQkFBbUIsQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUU7Z0JBQ2pFLE9BQU8sRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFLENBQUE7YUFDNUI7WUFFRCxJQUFJLE1BQU0sS0FBSyxTQUFTLEVBQUU7Z0JBQ3hCLE1BQU0sSUFBSSwwQkFBVyxDQUFDLDBDQUEwQyxFQUFFLE1BQU0sQ0FBQyxDQUFBO2FBQzFFO1lBRUQsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFDO2dCQUNuQyxHQUFHLEdBQUc7Z0JBQ04sUUFBUSxFQUFFO29CQUNSLEdBQUcsR0FBRyxDQUFDLFFBQVE7b0JBQ2YsTUFBTSxFQUFFO3dCQUNOLEdBQUcsR0FBRyxDQUFDLFFBQVEsQ0FBQyxNQUFNO3dCQUN0QixPQUFPLEVBQUUsTUFBTTtxQkFDaEI7aUJBQ0Y7Z0JBQ0QsVUFBVSxFQUFFLEVBQUU7Z0JBQ2QsU0FBUyxFQUFFLEVBQUU7YUFDZCxDQUFDLENBQUMsQ0FBQTtZQUVILE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO2dCQUNoQixPQUFPLEVBQUUsZUFBZTtnQkFDeEIsSUFBSSxFQUFFLE1BQU07Z0JBQ1osT0FBTyxFQUFFLGlCQUFpQixNQUFNLEdBQUc7YUFDcEMsQ0FBQyxDQUFBO1lBRUYsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUUsQ0FBQTtRQUM3QixDQUFDO0tBQ0YsQ0FBQTtBQUNILENBQUMsQ0FBQTtBQTFDWSxRQUFBLFlBQVksZ0JBMEN4QiJ9