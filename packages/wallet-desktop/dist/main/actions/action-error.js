"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActionError = void 0;
class ActionError extends Error {
    action;
    status;
    constructor(msg, action, status) {
        super(msg);
        this.action = action;
        this.status = status;
    }
}
exports.ActionError = ActionError;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWN0aW9uLWVycm9yLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy9hY3Rpb24tZXJyb3IudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBRUEsTUFBYSxXQUFZLFNBQVEsS0FBSztJQUNIO0lBQXVCO0lBQXhELFlBQWEsR0FBVyxFQUFTLE1BQWMsRUFBUyxNQUFlO1FBQ3JFLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQURxQixXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQVMsV0FBTSxHQUFOLE1BQU0sQ0FBUztJQUV2RSxDQUFDO0NBQ0Y7QUFKRCxrQ0FJQyJ9