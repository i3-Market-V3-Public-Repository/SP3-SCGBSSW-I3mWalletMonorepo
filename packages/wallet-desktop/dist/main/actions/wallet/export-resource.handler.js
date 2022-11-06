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
exports.exportResource = void 0;
const electron_1 = require("electron");
const fs = __importStar(require("fs"));
const lib_1 = require("@wallet/lib");
const exportResource = (locals) => {
    return {
        type: lib_1.exportResourceAction.type,
        async handle(action) {
            const { sharedMemoryManager } = locals;
            const sharedMemory = sharedMemoryManager.memory;
            const resource = sharedMemory.resources[action.payload];
            if (resource === undefined) {
                locals.toast.show({
                    message: 'Could not export',
                    type: 'warning',
                    details: 'Resource not found'
                });
                return { response: undefined, status: 400 };
            }
            const mainWindow = locals.windowManager.getWindow('Main');
            const dialogOptions = {
                title: 'Export resource...',
                defaultPath: `${resource.id}.resource.json`
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
            fs.writeFileSync(resourcePath, JSON.stringify(resource, null, 2));
            return { response: undefined };
        }
    };
};
exports.exportResource = exportResource;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXhwb3J0LXJlc291cmNlLmhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hY3Rpb25zL3dhbGxldC9leHBvcnQtcmVzb3VyY2UuaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLHVDQUFvRDtBQUNwRCx1Q0FBd0I7QUFDeEIscUNBRW9CO0FBR2IsTUFBTSxjQUFjLEdBQXNELENBQy9FLE1BQU0sRUFDTixFQUFFO0lBQ0YsT0FBTztRQUNMLElBQUksRUFBRSwwQkFBb0IsQ0FBQyxJQUFJO1FBQy9CLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLEVBQUUsbUJBQW1CLEVBQUUsR0FBRyxNQUFNLENBQUE7WUFDdEMsTUFBTSxZQUFZLEdBQUcsbUJBQW1CLENBQUMsTUFBTSxDQUFBO1lBQy9DLE1BQU0sUUFBUSxHQUFHLFlBQVksQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFBO1lBQ3ZELElBQUksUUFBUSxLQUFLLFNBQVMsRUFBRTtnQkFDMUIsTUFBTSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUM7b0JBQ2hCLE9BQU8sRUFBRSxrQkFBa0I7b0JBQzNCLElBQUksRUFBRSxTQUFTO29CQUNmLE9BQU8sRUFBRSxvQkFBb0I7aUJBQzlCLENBQUMsQ0FBQTtnQkFDRixPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7YUFDNUM7WUFFRCxNQUFNLFVBQVUsR0FBRyxNQUFNLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQTtZQUN6RCxNQUFNLGFBQWEsR0FBc0I7Z0JBQ3ZDLEtBQUssRUFBRSxvQkFBb0I7Z0JBQzNCLFdBQVcsRUFBRSxHQUFHLFFBQVEsQ0FBQyxFQUFFLGdCQUFnQjthQUM1QyxDQUFBO1lBRUQsSUFBSSxZQUFnQyxDQUFBO1lBQ3BDLElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTtnQkFDNUIsWUFBWSxHQUFHLGlCQUFNLENBQUMsa0JBQWtCLENBQUMsVUFBVSxFQUFFLGFBQWEsQ0FBQyxDQUFBO2FBQ3BFO2lCQUFNO2dCQUNMLFlBQVksR0FBRyxpQkFBTSxDQUFDLGtCQUFrQixDQUFDLGFBQWEsQ0FBQyxDQUFBO2FBQ3hEO1lBRUQsSUFBSSxZQUFZLEtBQUssU0FBUyxFQUFFO2dCQUM5QixPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxDQUFBO2FBQy9CO1lBRUQsRUFBRSxDQUFDLGFBQWEsQ0FBQyxZQUFZLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFDakUsT0FBTyxFQUFFLFFBQVEsRUFBRSxTQUFTLEVBQUUsQ0FBQTtRQUNoQyxDQUFDO0tBQ0YsQ0FBQTtBQUNILENBQUMsQ0FBQTtBQXZDWSxRQUFBLGNBQWMsa0JBdUMxQiJ9