"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteResource = void 0;
const lib_1 = require("@wallet/lib");
const action_error_1 = require("../action-error");
const deleteResource = (locals) => {
    return {
        type: lib_1.deleteResourceAction.type,
        async handle(action) {
            let resourceId;
            if (action.payload !== undefined) {
                resourceId = action.payload;
            }
            else {
                throw new action_error_1.ActionError('Not implemented yet', action);
            }
            const { walletFactory, sharedMemoryManager } = locals;
            // Verify wallet
            if (!walletFactory.hasWalletSelected) {
                locals.toast.show({
                    message: 'Wallet not selected',
                    details: 'You must select a wallet before creating identities',
                    type: 'warning'
                });
                return { response: undefined, status: 500 };
            }
            await walletFactory.wallet.deleteResource(resourceId);
            // Update state
            const resources = await walletFactory.wallet.getResources();
            sharedMemoryManager.update((mem) => ({ ...mem, resources }));
            return { response: undefined };
        }
    };
};
exports.deleteResource = deleteResource;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVsZXRlLXJlc291cmNlLmhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hY3Rpb25zL3dhbGxldC9kZWxldGUtcmVzb3VyY2UuaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxxQ0FFb0I7QUFDcEIsa0RBQTZDO0FBR3RDLE1BQU0sY0FBYyxHQUFzRCxDQUMvRSxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsMEJBQW9CLENBQUMsSUFBSTtRQUMvQixLQUFLLENBQUMsTUFBTSxDQUFFLE1BQU07WUFDbEIsSUFBSSxVQUFrQixDQUFBO1lBQ3RCLElBQUksTUFBTSxDQUFDLE9BQU8sS0FBSyxTQUFTLEVBQUU7Z0JBQ2hDLFVBQVUsR0FBRyxNQUFNLENBQUMsT0FBTyxDQUFBO2FBQzVCO2lCQUFNO2dCQUNMLE1BQU0sSUFBSSwwQkFBVyxDQUFDLHFCQUFxQixFQUFFLE1BQU0sQ0FBQyxDQUFBO2FBQ3JEO1lBRUQsTUFBTSxFQUFFLGFBQWEsRUFBRSxtQkFBbUIsRUFBRSxHQUFHLE1BQU0sQ0FBQTtZQUVyRCxnQkFBZ0I7WUFDaEIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxpQkFBaUIsRUFBRTtnQkFDcEMsTUFBTSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUM7b0JBQ2hCLE9BQU8sRUFBRSxxQkFBcUI7b0JBQzlCLE9BQU8sRUFBRSxxREFBcUQ7b0JBQzlELElBQUksRUFBRSxTQUFTO2lCQUNoQixDQUFDLENBQUE7Z0JBQ0YsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFBO2FBQzVDO1lBQ0QsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLGNBQWMsQ0FBQyxVQUFVLENBQUMsQ0FBQTtZQUVyRCxlQUFlO1lBQ2YsTUFBTSxTQUFTLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxDQUFBO1lBQzNELG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsQ0FBQyxFQUFFLEdBQUcsR0FBRyxFQUFFLFNBQVMsRUFBRSxDQUFDLENBQUMsQ0FBQTtZQUU1RCxPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxDQUFBO1FBQ2hDLENBQUM7S0FDRixDQUFBO0FBQ0gsQ0FBQyxDQUFBO0FBakNZLFFBQUEsY0FBYyxrQkFpQzFCIn0=