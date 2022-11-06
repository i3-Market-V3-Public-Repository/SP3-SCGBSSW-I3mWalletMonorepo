"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callWalletFunction = void 0;
const lib_1 = require("@wallet/lib");
const callWalletFunction = (locals) => {
    return {
        type: lib_1.callWalletFunctionAction.type,
        async handle(action) {
            const { sharedMemoryManager, walletFactory } = locals;
            // Call the internal function
            await walletFactory.wallet.call(action.payload);
            // Refresh all sharedMemory
            const identities = await walletFactory.wallet.getIdentities();
            const resources = await walletFactory.wallet.getResources();
            sharedMemoryManager.update((mem) => ({ ...mem, identities, resources }));
            return { response: undefined, status: 200 };
        }
    };
};
exports.callWalletFunction = callWalletFunction;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2FsbC13YWxsZXQtZnVuY3Rpb24uaGFuZGxlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FjdGlvbnMvd2FsbGV0L2NhbGwtd2FsbGV0LWZ1bmN0aW9uLmhhbmRsZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscUNBRW9CO0FBR2IsTUFBTSxrQkFBa0IsR0FBMEQsQ0FDdkYsTUFBTSxFQUNOLEVBQUU7SUFDRixPQUFPO1FBQ0wsSUFBSSxFQUFFLDhCQUF3QixDQUFDLElBQUk7UUFDbkMsS0FBSyxDQUFDLE1BQU0sQ0FBRSxNQUFNO1lBQ2xCLE1BQU0sRUFBRSxtQkFBbUIsRUFBRSxhQUFhLEVBQUUsR0FBRyxNQUFNLENBQUE7WUFFckQsNkJBQTZCO1lBQzdCLE1BQU0sYUFBYSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFBO1lBRS9DLDJCQUEyQjtZQUMzQixNQUFNLFVBQVUsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLENBQUE7WUFDN0QsTUFBTSxTQUFTLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxDQUFBO1lBQzNELG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsQ0FBQyxFQUFFLEdBQUcsR0FBRyxFQUFFLFVBQVUsRUFBRSxTQUFTLEVBQUUsQ0FBQyxDQUFDLENBQUE7WUFFeEUsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFBO1FBQzdDLENBQUM7S0FDRixDQUFBO0FBQ0gsQ0FBQyxDQUFBO0FBbkJZLFFBQUEsa0JBQWtCLHNCQW1COUIifQ==