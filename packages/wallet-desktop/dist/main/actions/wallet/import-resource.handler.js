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
exports.importResource = void 0;
const electron_1 = require("electron");
const fs = __importStar(require("fs"));
const lib_1 = require("@wallet/lib");
const importResource = (locals) => {
    return {
        type: lib_1.importResourceAction.type,
        async handle(action) {
            const mainWindow = locals.windowManager.getWindow('Main');
            const dialogOptions = {
                title: 'Import resource...'
            };
            let resourcePath;
            if (mainWindow !== undefined) {
                resourcePath = electron_1.dialog.showSaveDialogSync(mainWindow, dialogOptions);
            }
            else {
                resourcePath = electron_1.dialog.showSaveDialogSync(dialogOptions);
            }
            if (resourcePath === undefined) {
                return { response: undefined };
            }
            let resource;
            try {
                resource = JSON.parse(fs.readFileSync(resourcePath).toString('utf-8'));
            }
            catch (ex) {
                locals.toast.show({
                    message: 'Could not import',
                    type: 'warning',
                    details: 'Invalid file format'
                });
                return { response: undefined };
            }
            if (!['VerifiableCredential', 'Contract', 'Object'].includes(resource.type)) {
                locals.toast.show({
                    message: 'Could not import',
                    type: 'warning',
                    details: 'Invalid file format'
                });
                return { response: undefined };
            }
            if (action.payload !== undefined && action.payload !== resource.identity) {
                locals.toast.show({
                    message: 'Could not import',
                    type: 'warning',
                    details: 'This resource is not for the provided identity'
                });
                return { response: undefined };
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
            await walletFactory.wallet.resourceCreate(resource);
            // Update state
            const resources = await walletFactory.wallet.getResources();
            sharedMemoryManager.update((mem) => ({ ...mem, resources }));
            return { response: undefined };
        }
    };
};
exports.importResource = importResource;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW1wb3J0LXJlc291cmNlLmhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hY3Rpb25zL3dhbGxldC9pbXBvcnQtcmVzb3VyY2UuaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLHVDQUFvRDtBQUNwRCx1Q0FBd0I7QUFHeEIscUNBRW9CO0FBR2IsTUFBTSxjQUFjLEdBQXNELENBQy9FLE1BQU0sRUFDTixFQUFFO0lBQ0YsT0FBTztRQUNMLElBQUksRUFBRSwwQkFBb0IsQ0FBQyxJQUFJO1FBQy9CLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLFVBQVUsR0FBRyxNQUFNLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQTtZQUN6RCxNQUFNLGFBQWEsR0FBc0I7Z0JBQ3ZDLEtBQUssRUFBRSxvQkFBb0I7YUFDNUIsQ0FBQTtZQUVELElBQUksWUFBZ0MsQ0FBQTtZQUNwQyxJQUFJLFVBQVUsS0FBSyxTQUFTLEVBQUU7Z0JBQzVCLFlBQVksR0FBRyxpQkFBTSxDQUFDLGtCQUFrQixDQUFDLFVBQVUsRUFBRSxhQUFhLENBQUMsQ0FBQTthQUNwRTtpQkFBTTtnQkFDTCxZQUFZLEdBQUcsaUJBQU0sQ0FBQyxrQkFBa0IsQ0FBQyxhQUFhLENBQUMsQ0FBQTthQUN4RDtZQUVELElBQUksWUFBWSxLQUFLLFNBQVMsRUFBRTtnQkFDOUIsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsQ0FBQTthQUMvQjtZQUVELElBQUksUUFBa0IsQ0FBQTtZQUN0QixJQUFJO2dCQUNGLFFBQVEsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQyxZQUFZLENBQUMsWUFBWSxDQUFDLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUE7YUFDdkU7WUFBQyxPQUFPLEVBQUUsRUFBRTtnQkFDWCxNQUFNLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQztvQkFDaEIsT0FBTyxFQUFFLGtCQUFrQjtvQkFDM0IsSUFBSSxFQUFFLFNBQVM7b0JBQ2YsT0FBTyxFQUFFLHFCQUFxQjtpQkFDL0IsQ0FBQyxDQUFBO2dCQUNGLE9BQU8sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLENBQUE7YUFDL0I7WUFFRCxJQUFJLENBQUMsQ0FBQyxzQkFBc0IsRUFBRSxVQUFVLEVBQUUsUUFBUSxDQUFDLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRTtnQkFDM0UsTUFBTSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUM7b0JBQ2hCLE9BQU8sRUFBRSxrQkFBa0I7b0JBQzNCLElBQUksRUFBRSxTQUFTO29CQUNmLE9BQU8sRUFBRSxxQkFBcUI7aUJBQy9CLENBQUMsQ0FBQTtnQkFDRixPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxDQUFBO2FBQy9CO1lBRUQsSUFBSSxNQUFNLENBQUMsT0FBTyxLQUFLLFNBQVMsSUFBSSxNQUFNLENBQUMsT0FBTyxLQUFLLFFBQVEsQ0FBQyxRQUFRLEVBQUU7Z0JBQ3hFLE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO29CQUNoQixPQUFPLEVBQUUsa0JBQWtCO29CQUMzQixJQUFJLEVBQUUsU0FBUztvQkFDZixPQUFPLEVBQUUsZ0RBQWdEO2lCQUMxRCxDQUFDLENBQUE7Z0JBQ0YsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsQ0FBQTthQUMvQjtZQUVELE1BQU0sRUFBRSxhQUFhLEVBQUUsbUJBQW1CLEVBQUUsR0FBRyxNQUFNLENBQUE7WUFFckQsZ0JBQWdCO1lBQ2hCLElBQUksQ0FBQyxhQUFhLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ3BDLE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO29CQUNoQixPQUFPLEVBQUUscUJBQXFCO29CQUM5QixPQUFPLEVBQUUscURBQXFEO29CQUM5RCxJQUFJLEVBQUUsU0FBUztpQkFDaEIsQ0FBQyxDQUFBO2dCQUNGLE9BQU8sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxHQUFHLEVBQUUsQ0FBQTthQUM1QztZQUNELE1BQU0sYUFBYSxDQUFDLE1BQU0sQ0FBQyxjQUFjLENBQUMsUUFBUSxDQUFDLENBQUE7WUFFbkQsZUFBZTtZQUNmLE1BQU0sU0FBUyxHQUFHLE1BQU0sYUFBYSxDQUFDLE1BQU0sQ0FBQyxZQUFZLEVBQUUsQ0FBQTtZQUMzRCxtQkFBbUIsQ0FBQyxNQUFNLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRSxDQUFDLENBQUMsRUFBRSxHQUFHLEdBQUcsRUFBRSxTQUFTLEVBQUUsQ0FBQyxDQUFDLENBQUE7WUFFNUQsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsQ0FBQTtRQUNoQyxDQUFDO0tBQ0YsQ0FBQTtBQUNILENBQUMsQ0FBQTtBQXhFWSxRQUFBLGNBQWMsa0JBd0UxQiJ9