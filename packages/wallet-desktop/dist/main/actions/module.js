"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Module = void 0;
class Module {
    handlerBuilders;
    epics;
    subscriptions;
    constructor(opts) {
        this.handlerBuilders = opts.handlersBuilders ?? [];
        this.epics = opts.epics ?? [];
        this.subscriptions = [];
    }
    bindReducer(reducer$, handlers, locals) {
        // Bind handlers
        for (const hBuilder of this.handlerBuilders) {
            const handler = hBuilder(locals);
            handlers.set(handler.type, handler);
        }
    }
    // TODO: We might need to implement this??
    unbindReducer() {
        throw new Error('Not implemented yet');
    }
}
exports.Module = Module;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibW9kdWxlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy9tb2R1bGUudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBTUEsTUFBYSxNQUFNO0lBQ0UsZUFBZSxDQUF3QjtJQUN2QyxLQUFLLENBQVE7SUFDdEIsYUFBYSxDQUFnQjtJQUV2QyxZQUFhLElBQW1FO1FBQzlFLElBQUksQ0FBQyxlQUFlLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixJQUFJLEVBQUUsQ0FBQTtRQUNsRCxJQUFJLENBQUMsS0FBSyxHQUFHLElBQUksQ0FBQyxLQUFLLElBQUksRUFBRSxDQUFBO1FBQzdCLElBQUksQ0FBQyxhQUFhLEdBQUcsRUFBRSxDQUFBO0lBQ3pCLENBQUM7SUFFRCxXQUFXLENBQ1QsUUFBNEIsRUFDNUIsUUFBb0MsRUFDcEMsTUFBYztRQUVkLGdCQUFnQjtRQUNoQixLQUFLLE1BQU0sUUFBUSxJQUFJLElBQUksQ0FBQyxlQUFlLEVBQUU7WUFDM0MsTUFBTSxPQUFPLEdBQUcsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFBO1lBQ2hDLFFBQVEsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxPQUFPLENBQUMsQ0FBQTtTQUNwQztJQUNILENBQUM7SUFFRCwwQ0FBMEM7SUFDMUMsYUFBYTtRQUNYLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLENBQUMsQ0FBQTtJQUN4QyxDQUFDO0NBQ0Y7QUEzQkQsd0JBMkJDIn0=