"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIdentity = void 0;
const lib_1 = require("@wallet/lib");
const action_error_1 = require("../action-error");
const createIdentity = (locals) => {
    return {
        type: lib_1.createIdentityAction.type,
        async handle(action) {
            const { sharedMemoryManager, dialog, walletFactory } = locals;
            let alias = action.payload.alias;
            if (alias === undefined) {
                alias = await dialog.text({
                    message: 'Input an alias for the identity'
                });
            }
            if (alias === undefined) {
                throw new action_error_1.ActionError('Cannot create identity. Dialog cancelled', action);
            }
            // Create identity
            if (!walletFactory.hasWalletSelected) {
                locals.toast.show({
                    message: 'Wallet not selected',
                    details: 'You must select a wallet before creating identities',
                    type: 'warning'
                });
                return { response: undefined, status: 500 };
            }
            const response = await walletFactory.wallet.identityCreate({ alias });
            // Update state
            const identities = await walletFactory.wallet.getIdentities();
            sharedMemoryManager.update((mem) => ({ ...mem, identities }));
            return { response, status: 201 };
        }
    };
};
exports.createIdentity = createIdentity;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3JlYXRlLWlkZW50aXR5LmhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hY3Rpb25zL3dhbGxldC9jcmVhdGUtaWRlbnRpdHkuaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxxQ0FFb0I7QUFDcEIsa0RBQTZDO0FBR3RDLE1BQU0sY0FBYyxHQUFzRCxDQUMvRSxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsMEJBQW9CLENBQUMsSUFBSTtRQUMvQixLQUFLLENBQUMsTUFBTSxDQUFFLE1BQU07WUFDbEIsTUFBTSxFQUFFLG1CQUFtQixFQUFFLE1BQU0sRUFBRSxhQUFhLEVBQUUsR0FBRyxNQUFNLENBQUE7WUFDN0QsSUFBSSxLQUFLLEdBQXVCLE1BQU0sQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFBO1lBRXBELElBQUksS0FBSyxLQUFLLFNBQVMsRUFBRTtnQkFDdkIsS0FBSyxHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBQztvQkFDeEIsT0FBTyxFQUFFLGlDQUFpQztpQkFDM0MsQ0FBQyxDQUFBO2FBQ0g7WUFFRCxJQUFJLEtBQUssS0FBSyxTQUFTLEVBQUU7Z0JBQ3ZCLE1BQU0sSUFBSSwwQkFBVyxDQUFDLDBDQUEwQyxFQUFFLE1BQU0sQ0FBQyxDQUFBO2FBQzFFO1lBRUQsa0JBQWtCO1lBQ2xCLElBQUksQ0FBQyxhQUFhLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ3BDLE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO29CQUNoQixPQUFPLEVBQUUscUJBQXFCO29CQUM5QixPQUFPLEVBQUUscURBQXFEO29CQUM5RCxJQUFJLEVBQUUsU0FBUztpQkFDaEIsQ0FBQyxDQUFBO2dCQUNGLE9BQU8sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxHQUFHLEVBQUUsQ0FBQTthQUM1QztZQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sYUFBYSxDQUFDLE1BQU0sQ0FBQyxjQUFjLENBQUMsRUFBRSxLQUFLLEVBQUUsQ0FBQyxDQUFBO1lBRXJFLGVBQWU7WUFDZixNQUFNLFVBQVUsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLENBQUE7WUFDN0QsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFDLEVBQUUsR0FBRyxHQUFHLEVBQUUsVUFBVSxFQUFFLENBQUMsQ0FBQyxDQUFBO1lBRTdELE9BQU8sRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFBO1FBQ2xDLENBQUM7S0FDRixDQUFBO0FBQ0gsQ0FBQyxDQUFBO0FBckNZLFFBQUEsY0FBYyxrQkFxQzFCIn0=