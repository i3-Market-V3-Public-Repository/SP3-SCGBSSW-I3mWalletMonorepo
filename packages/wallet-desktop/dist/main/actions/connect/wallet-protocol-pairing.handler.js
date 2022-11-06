"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.walletProtocolPairing = void 0;
const lib_1 = require("@wallet/lib");
const walletProtocolPairing = (locals) => {
    return {
        type: lib_1.walletProtocolPairingAction.type,
        async handle(action) {
            const { connectManager } = locals;
            // Call the internal function
            connectManager.startWalletProtocol();
            return { response: undefined, status: 200 };
        }
    };
};
exports.walletProtocolPairing = walletProtocolPairing;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2FsbGV0LXByb3RvY29sLXBhaXJpbmcuaGFuZGxlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FjdGlvbnMvY29ubmVjdC93YWxsZXQtcHJvdG9jb2wtcGFpcmluZy5oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLHFDQUVvQjtBQUdiLE1BQU0scUJBQXFCLEdBQTZELENBQzdGLE1BQU0sRUFDTixFQUFFO0lBQ0YsT0FBTztRQUNMLElBQUksRUFBRSxpQ0FBMkIsQ0FBQyxJQUFJO1FBQ3RDLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQixNQUFNLEVBQUUsY0FBYyxFQUFFLEdBQUcsTUFBTSxDQUFBO1lBRWpDLDZCQUE2QjtZQUM3QixjQUFjLENBQUMsbUJBQW1CLEVBQUUsQ0FBQTtZQUVwQyxPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7UUFDN0MsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUFkWSxRQUFBLHFCQUFxQix5QkFjakMifQ==