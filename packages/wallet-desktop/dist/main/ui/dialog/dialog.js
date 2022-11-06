"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ElectronDialog = void 0;
const lib_1 = require("@wallet/lib");
class ElectronDialog {
    locals;
    resolvers;
    dialogQueue;
    constructor(locals) {
        this.locals = locals;
        this.resolvers = new Map();
        this.dialogQueue = [];
        locals.sharedMemoryManager.on('change', (sharedMemory) => {
            const dialogId = sharedMemory.dialogs.current;
            if (dialogId === undefined) {
                return;
            }
            const { [dialogId]: dialog, ...otherDialogs } = sharedMemory.dialogs.data;
            if (dialog === undefined || !('response' in dialog)) {
                return;
            }
            locals.sharedMemoryManager.update((mem) => ({
                ...mem,
                dialogs: {
                    ...mem.dialogs,
                    current: this.dialogQueue.shift(),
                    data: otherDialogs
                }
            }));
            const resolver = this.resolvers.get(dialog.id);
            if (resolver !== undefined) {
                this.resolvers.delete(dialog.id);
                resolver(dialog.response);
            }
            else {
                // TODO: Handle error
                throw new Error('Dialog not found');
            }
        });
    }
    async launchDialog(dialogData) {
        const { windowManager, sharedMemoryManager } = this.locals;
        const mainWindow = windowManager.openMainWindow();
        if (mainWindow === undefined) {
            throw new Error('No main window');
        }
        let current = sharedMemoryManager.memory.dialogs.current;
        if (current === undefined) {
            current = dialogData.id;
        }
        else {
            this.dialogQueue.push(dialogData.id);
        }
        sharedMemoryManager.update((mem) => ({
            ...mem,
            dialogs: {
                ...mem.dialogs,
                current: current,
                data: {
                    ...mem.dialogs.data,
                    [dialogData.id]: dialogData
                }
            }
        }));
        mainWindow.flashFrame(false);
        mainWindow.flashFrame(true);
        const option = await new Promise(resolve => {
            this.resolvers.set(dialogData.id, resolve);
        });
        return option;
    }
    buildArguments(options) {
        switch (options.type) {
            case 'text':
                {
                    const { title, message, hiddenText, allowCancel } = options;
                    return {
                        id: (0, lib_1.createDialogId)(),
                        title,
                        message,
                        allowCancel,
                        freeAnswer: true,
                        type: 'text',
                        hiddenText
                    };
                }
            case 'confirmation':
                {
                    const { title, message, acceptMsg, rejectMsg, allowCancel } = options;
                    return {
                        id: (0, lib_1.createDialogId)(),
                        title,
                        message: message,
                        allowCancel: allowCancel,
                        type: 'confirmation',
                        acceptMsg: acceptMsg,
                        rejectMsg: rejectMsg
                    };
                }
            case 'select':
                {
                    const { title, message, values, allowCancel } = options;
                    const getText = options.getText ?? ((v) => v);
                    const getContext = options.getContext ?? ((v) => 'success');
                    return {
                        id: (0, lib_1.createDialogId)(),
                        title,
                        message,
                        allowCancel,
                        type: 'select',
                        options: values.map((value, i) => ({
                            index: i,
                            value,
                            text: getText(value),
                            context: getContext(value)
                        }))
                    };
                }
        }
        throw new Error('Unknown type for dialog');
    }
    async text(options) {
        const dialogData = this.buildArguments({
            ...options,
            type: 'text'
        });
        return await this.launchDialog(dialogData);
    }
    async confirmation(options) {
        const dialogData = this.buildArguments({
            ...options,
            type: 'confirmation'
        });
        return await this.launchDialog(dialogData);
    }
    async select(options) {
        const dialogInput = this.buildArguments({
            ...options,
            type: 'select'
        });
        return await this.launchDialog(dialogInput);
    }
    async form(options) {
        const { title, message, allowCancel, descriptors, order } = options;
        const dialogDescriptors = {};
        for (const [key, descriptor] of Object.entries(descriptors)) {
            dialogDescriptors[key] = this.buildArguments(descriptor);
        }
        const dialogData = {
            id: (0, lib_1.createDialogId)(),
            title,
            message,
            allowCancel,
            freeAnswer: true,
            type: 'form',
            descriptors: dialogDescriptors,
            order
        };
        return await this.launchDialog(dialogData);
    }
    async authenticate() {
        throw new Error('NOT IMPLEMENTED');
    }
}
exports.ElectronDialog = ElectronDialog;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGlhbG9nLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vdWkvZGlhbG9nL2RpYWxvZy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFHQSxxQ0FBMkU7QUFHM0UsTUFBYSxjQUFjO0lBS0Y7SUFKYixTQUFTLENBQStDO0lBRXhELFdBQVcsQ0FBVTtJQUUvQixZQUF1QixNQUFjO1FBQWQsV0FBTSxHQUFOLE1BQU0sQ0FBUTtRQUNuQyxJQUFJLENBQUMsU0FBUyxHQUFHLElBQUksR0FBRyxFQUFFLENBQUE7UUFDMUIsSUFBSSxDQUFDLFdBQVcsR0FBRyxFQUFFLENBQUE7UUFDckIsTUFBTSxDQUFDLG1CQUFtQixDQUFDLEVBQUUsQ0FBQyxRQUFRLEVBQUUsQ0FBQyxZQUFZLEVBQUUsRUFBRTtZQUN2RCxNQUFNLFFBQVEsR0FBRyxZQUFZLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQTtZQUM3QyxJQUFJLFFBQVEsS0FBSyxTQUFTLEVBQUU7Z0JBQzFCLE9BQU07YUFDUDtZQUVELE1BQU0sRUFBRSxDQUFDLFFBQVEsQ0FBQyxFQUFFLE1BQU0sRUFBRSxHQUFHLFlBQVksRUFBRSxHQUFHLFlBQVksQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFBO1lBQ3pFLElBQUksTUFBTSxLQUFLLFNBQVMsSUFBSSxDQUFDLENBQUMsVUFBVSxJQUFJLE1BQU0sQ0FBQyxFQUFFO2dCQUNuRCxPQUFNO2FBQ1A7WUFFRCxNQUFNLENBQUMsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxDQUFDO2dCQUMxQyxHQUFHLEdBQUc7Z0JBQ04sT0FBTyxFQUFFO29CQUNQLEdBQUcsR0FBRyxDQUFDLE9BQU87b0JBQ2QsT0FBTyxFQUFFLElBQUksQ0FBQyxXQUFXLENBQUMsS0FBSyxFQUFFO29CQUNqQyxJQUFJLEVBQUUsWUFBWTtpQkFDbkI7YUFDRixDQUFDLENBQUMsQ0FBQTtZQUVILE1BQU0sUUFBUSxH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