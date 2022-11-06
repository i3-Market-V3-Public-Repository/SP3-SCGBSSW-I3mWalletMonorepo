"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToastManager = void 0;
const lib_1 = require("@wallet/lib");
const TOAST_TIMEOUT_MAP = new Map([
    ['info', 2000],
    ['success', 4000],
    ['warning', 7000],
    ['error', 10000]
]);
class ToastManager {
    locals;
    constructor(locals) {
        this.locals = locals;
    }
    show(toastOptions) {
        const { windowManager, sharedMemoryManager } = this.locals;
        const mainWindow = windowManager.openMainWindow();
        if (mainWindow === undefined) {
            throw new Error('No main window');
        }
        const toasts = sharedMemoryManager.memory.toasts;
        const toast = {
            id: (0, lib_1.createDialogId)(),
            ...toastOptions
        };
        toasts.push(toast);
        sharedMemoryManager.update((mem) => ({
            ...mem,
            toasts
        }));
        mainWindow.flashFrame(false);
        mainWindow.flashFrame(true);
        const toastType = toast.type ?? 'info';
        const timeout = toastOptions.timeout ?? TOAST_TIMEOUT_MAP.get(toastType) ?? 0;
        if (timeout !== 0) {
            setTimeout(() => {
                this.close(toast.id);
            }, timeout);
        }
    }
    close(toastId) {
        const { sharedMemoryManager } = this.locals;
        sharedMemoryManager.update((mem) => ({
            ...mem,
            toasts: mem.toasts.filter((toast) => toast.id !== toastId)
        }));
    }
}
exports.ToastManager = ToastManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidG9hc3QuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi91aS90b2FzdC90b2FzdC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFQSxxQ0FBdUQ7QUFHdkQsTUFBTSxpQkFBaUIsR0FBMkIsSUFBSSxHQUFHLENBQUM7SUFDeEQsQ0FBQyxNQUFNLEVBQUUsSUFBSSxDQUFDO0lBQ2QsQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDO0lBQ2pCLENBQUMsU0FBUyxFQUFFLElBQUksQ0FBQztJQUNqQixDQUFDLE9BQU8sRUFBRSxLQUFLLENBQUM7Q0FDakIsQ0FBQyxDQUFBO0FBRUYsTUFBYSxZQUFZO0lBQ0E7SUFBdkIsWUFBdUIsTUFBYztRQUFkLFdBQU0sR0FBTixNQUFNLENBQVE7SUFBSSxDQUFDO0lBRTFDLElBQUksQ0FBRSxZQUEwQjtRQUM5QixNQUFNLEVBQUUsYUFBYSxFQUFFLG1CQUFtQixFQUFFLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQTtRQUMxRCxNQUFNLFVBQVUsR0FBRyxhQUFhLENBQUMsY0FBYyxFQUFFLENBQUE7UUFDakQsSUFBSSxVQUFVLEtBQUssU0FBUyxFQUFFO1lBQzVCLE1BQU0sSUFBSSxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQTtTQUNsQztRQUVELE1BQU0sTUFBTSxHQUFHLG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUE7UUFDaEQsTUFBTSxLQUFLLEdBQWM7WUFDdkIsRUFBRSxFQUFFLElBQUEsb0JBQWMsR0FBRTtZQUNwQixHQUFHLFlBQVk7U0FDaEIsQ0FBQTtRQUNELE1BQU0sQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUE7UUFFbEIsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFDO1lBQ25DLEdBQUcsR0FBRztZQUNOLE1BQU07U0FDUCxDQUFDLENBQUMsQ0FBQTtRQUVILFVBQVUsQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUE7UUFDNUIsVUFBVSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUUzQixNQUFNLFNBQVMsR0FBRyxLQUFLLENBQUMsSUFBSSxJQUFJLE1BQU0sQ0FBQTtRQUN0QyxNQUFNLE9BQU8sR0FBRyxZQUFZLENBQUMsT0FBTyxJQUFJLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDN0UsSUFBSSxPQUFPLEtBQUssQ0FBQyxFQUFFO1lBQ2pCLFVBQVUsQ0FBQyxHQUFHLEVBQUU7Z0JBQ2QsSUFBSSxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLENBQUE7WUFDdEIsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxDQUFBO1NBQ1o7SUFDSCxDQUFDO0lBRUQsS0FBSyxDQUFFLE9BQWU7UUFDcEIsTUFBTSxFQUFFLG1CQUFtQixFQUFFLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQTtRQUMzQyxtQkFBbUIsQ0FBQyxNQUFNLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRSxDQUFDLENBQUM7WUFDbkMsR0FBRyxHQUFHO1lBQ04sTUFBTSxFQUFFLEdBQUcsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUMsS0FBSyxFQUFFLEVBQUUsQ0FBQyxLQUFLLENBQUMsRUFBRSxLQUFLLE9BQU8sQ0FBQztTQUMzRCxDQUFDLENBQUMsQ0FBQTtJQUNMLENBQUM7Q0FDRjtBQXpDRCxvQ0F5Q0MifQ==