"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteIdentity = void 0;
const lib_1 = require("@wallet/lib");
const action_error_1 = require("../action-error");
const deleteIdentity = (locals) => {
    return {
        type: lib_1.deleteIdentityAction.type,
        async handle(action) {
            let identityDid;
            if (action.payload !== undefined) {
                identityDid = action.payload;
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
            await walletFactory.wallet.deleteIdentity(identityDid);
            // Update state
            const identities = await walletFactory.wallet.getIdentities();
            sharedMemoryManager.update((mem) => ({ ...mem, identities }));
            return { response: undefined };
        }
    };
};
exports.deleteIdentity = deleteIdentity;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVsZXRlLWlkZW50aXR5LmhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hY3Rpb25zL3dhbGxldC9kZWxldGUtaWRlbnRpdHkuaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxxQ0FFb0I7QUFDcEIsa0RBQTZDO0FBR3RDLE1BQU0sY0FBYyxHQUFzRCxDQUMvRSxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsMEJBQW9CLENBQUMsSUFBSTtRQUMvQixLQUFLLENBQUMsTUFBTSxDQUFFLE1BQU07WUFDbEIsSUFBSSxXQUFtQixDQUFBO1lBQ3ZCLElBQUksTUFBTSxDQUFDLE9BQU8sS0FBSyxTQUFTLEVBQUU7Z0JBQ2hDLFdBQVcsR0FBRyxNQUFNLENBQUMsT0FBTyxDQUFBO2FBQzdCO2lCQUFNO2dCQUNMLE1BQU0sSUFBSSwwQkFBVyxDQUFDLHFCQUFxQixFQUFFLE1BQU0sQ0FBQyxDQUFBO2FBQ3JEO1lBRUQsTUFBTSxFQUFFLGFBQWEsRUFBRSxtQkFBbUIsRUFBRSxHQUFHLE1BQU0sQ0FBQTtZQUVyRCxnQkFBZ0I7WUFDaEIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxpQkFBaUIsRUFBRTtnQkFDcEMsTUFBTSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUM7b0JBQ2hCLE9BQU8sRUFBRSxxQkFBcUI7b0JBQzlCLE9BQU8sRUFBRSxxREFBcUQ7b0JBQzlELElBQUksRUFBRSxTQUFTO2lCQUNoQixDQUFDLENBQUE7Z0JBQ0YsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFBO2FBQzVDO1lBQ0QsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLGNBQWMsQ0FBQyxXQUFXLENBQUMsQ0FBQTtZQUV0RCxlQUFlO1lBQ2YsTUFBTSxVQUFVLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFBO1lBQzdELG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsQ0FBQyxFQUFFLEdBQUcsR0FBRyxFQUFFLFVBQVUsRUFBRSxDQUFDLENBQUMsQ0FBQTtZQUU3RCxPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxDQUFBO1FBQ2hDLENBQUM7S0FDRixDQUFBO0FBQ0gsQ0FBQyxDQUFBO0FBakNZLFFBQUEsY0FBYyxrQkFpQzFCIn0=