"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CustomWindow = void 0;
const electron_1 = require("electron");
const rxjs_1 = require("rxjs");
const operators_1 = require("rxjs/operators");
const lib_1 = require("@wallet/lib");
const internal_1 = require("@wallet/main/internal");
class CustomWindow extends electron_1.BrowserWindow {
    locals;
    input$;
    output$;
    constructor(locals, options) {
        super(options);
        this.locals = locals;
        const { sharedMemoryManager } = this.locals;
        const _response$ = new rxjs_1.Subject();
        this.input$ = new rxjs_1.Subject();
        this.on('focus', () => {
            this.flashFrame(false);
        });
        this.webContents.on('ipc-message', (ev, channel, value) => {
            if (channel === 'output') {
                _response$.next(value);
            }
        });
        this.input$.subscribe(msg => {
            this.webContents.send('input', msg);
        });
        this.on('close', () => {
            _response$.complete();
            this.destroy();
        });
        this.output$ = _response$;
        this.output$
            .pipe((0, lib_1.withType)('memory-sync'))
            .subscribe((memorySync) => {
            sharedMemoryManager.update(memorySync.memory, this);
        });
        this.output$
            .pipe((0, lib_1.withType)('action'), (0, operators_1.switchMap)(async (actionRequest) => {
            await this.locals.actionReducer.reduce(actionRequest.action);
        }), (0, operators_1.catchError)((err, caught) => {
            internal_1.logger.error(err);
            if (err instanceof internal_1.ActionError) {
                this.locals.toast.show({
                    message: 'Action Error',
                    details: err.message,
                    type: 'error'
                });
            }
            else if (err instanceof Error) {
                this.locals.toast.show({
                    message: 'Error',
                    details: err.message,
                    type: 'error'
                });
            }
            return caught;
        }))
            .subscribe();
        this.output$
            .pipe((0, lib_1.withType)('memory-request'), (0, operators_1.pluck)('memory'))
            .subscribe(() => this.updateSharedMemory());
    }
    updateSharedMemory(emitter) {
        if (emitter === this) {
            return;
        }
        const memSync = {
            type: 'memory-sync',
            memory: this.locals.sharedMemoryManager.memory
        };
        // TODO: Fix this ignore?
        // @ts-expect-error
        this.input$.next(memSync);
    }
    // eslint-disable-next-line @typescript-eslint/promise-function-async
    getInput() {
        return this.output$.pipe((0, operators_1.first)()).toPromise();
    }
}
exports.CustomWindow = CustomWindow;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3VzdG9tLXdpbmRvdy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL3VpL3dpbmRvdy1tYW5hZ2VyL2N1c3RvbS13aW5kb3cudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQ0EsdUNBQXlFO0FBQ3pFLCtCQUEwQztBQUMxQyw4Q0FBb0U7QUFFcEUscUNBQStHO0FBQy9HLG9EQUFtRTtBQUluRSxNQUFhLFlBR1gsU0FBUSx3QkFBYTtJQUlFO0lBSHZCLE1BQU0sQ0FBWTtJQUNsQixPQUFPLENBQWU7SUFFdEIsWUFBdUIsTUFBYyxFQUFFLE9BQXlDO1FBQzlFLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQURPLFdBQU0sR0FBTixNQUFNLENBQVE7UUFFbkMsTUFBTSxFQUFFLG1CQUFtQixFQUFFLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQTtRQUMzQyxNQUFNLFVBQVUsR0FBRyxJQUFJLGNBQU8sRUFBSyxDQUFBO1FBQ25DLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxjQUFPLEVBQUssQ0FBQTtRQUU5QixJQUFJLENBQUMsRUFBRSxDQUFDLE9BQU8sRUFBRSxHQUFHLEVBQUU7WUFDcEIsSUFBSSxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUN4QixDQUFDLENBQUMsQ0FBQTtRQUVGLElBQUksQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLGFBQWEsRUFBRSxDQUFDLEVBQUUsRUFBRSxPQUFPLEVBQUUsS0FBUSxFQUFFLEVBQUU7WUFDM0QsSUFBSSxPQUFPLEtBQUssUUFBUSxFQUFFO2dCQUN4QixVQUFVLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFBO2FBQ3ZCO1FBQ0gsQ0FBQyxDQUFDLENBQUE7UUFFRixJQUFJLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRTtZQUMxQixJQUFJLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUUsR0FBRyxDQUFD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