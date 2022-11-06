"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = void 0;
const lib_1 = require("@wallet/lib");
const sign = (locals) => {
    return {
        type: lib_1.signAction.type,
        async handle(action) {
            const { walletFactory } = locals;
            // Create identity
            const response = await walletFactory.wallet.identitySign(action.payload.signer, action.payload.body);
            return { response, status: 200 };
        }
    };
};
exports.sign = sign;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2lnbi5oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy93YWxsZXQvc2lnbi5oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLHFDQUVvQjtBQUdiLE1BQU0sSUFBSSxHQUE0QyxDQUMzRCxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsZ0JBQVUsQ0FBQyxJQUFJO1FBQ3JCLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsTUFBTSxDQUFBO1lBRWhDLGtCQUFrQjtZQUNsQixNQUFNLFFBQVEsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7WUFDcEcsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7UUFDbEMsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUFiWSxRQUFBLElBQUksUUFhaEIifQ==