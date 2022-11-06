"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyJWT = void 0;
const lib_1 = require("@wallet/lib");
const verifyJWT = (locals) => {
    return {
        type: lib_1.didJwtVerifyAction.type,
        async handle(action) {
            const { walletFactory } = locals;
            // Create identity
            const response = await walletFactory.wallet.didJwtVerify(action.payload.body);
            return { response, status: 200 };
        }
    };
};
exports.verifyJWT = verifyJWT;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmVyaWZ5LWp3dC5oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy93YWxsZXQvdmVyaWZ5LWp3dC5oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLHFDQUVvQjtBQUdiLE1BQU0sU0FBUyxHQUErQyxDQUNuRSxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsd0JBQWEsQ0FBQyxJQUFJO1FBQ3hCLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsTUFBTSxDQUFBO1lBRWhDLGtCQUFrQjtZQUNsQixNQUFNLFFBQVEsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7WUFDN0UsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7UUFDbEMsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUFiWSxRQUFBLFNBQVMsYUFhckIifQ==