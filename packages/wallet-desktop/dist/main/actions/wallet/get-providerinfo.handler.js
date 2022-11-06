"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getProviderinfo = void 0;
const lib_1 = require("@wallet/lib");
const getProviderinfo = (locals) => {
    return {
        type: lib_1.getProviderinfoAction.type,
        async handle(action) {
            const { walletFactory } = locals;
            // Create identity
            const response = await walletFactory.wallet.providerinfoGet();
            return { response, status: 200 };
        }
    };
};
exports.getProviderinfo = getProviderinfo;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2V0LXByb3ZpZGVyaW5mby5oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy93YWxsZXQvZ2V0LXByb3ZpZGVyaW5mby5oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLHFDQUVvQjtBQUdiLE1BQU0sZUFBZSxHQUErQyxDQUN6RSxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsMkJBQWEsQ0FBQyxJQUFJO1FBQ3hCLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsTUFBTSxDQUFBO1lBRWhDLGtCQUFrQjtZQUNsQixNQUFNLFFBQVEsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsZUFBZSxFQUFFLENBQUE7WUFDN0QsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7UUFDbEMsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUFiWSxRQUFBLGVBQWUsbUJBYTNCIn0=