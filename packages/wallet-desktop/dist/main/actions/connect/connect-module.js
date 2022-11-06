"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.connectModule = void 0;
const module_1 = require("../module");
const wallet_protocol_pairing_handler_1 = require("./wallet-protocol-pairing.handler");
exports.connectModule = new module_1.Module({
    handlersBuilders: [
        wallet_protocol_pairing_handler_1.walletProtocolPairing
    ]
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29ubmVjdC1tb2R1bGUuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hY3Rpb25zL2Nvbm5lY3QvY29ubmVjdC1tb2R1bGUudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsc0NBQWtDO0FBQ2xDLHVGQUF5RTtBQUU1RCxRQUFBLGFBQWEsR0FBRyxJQUFJLGVBQU0sQ0FBQztJQUN0QyxnQkFBZ0IsRUFBRTtRQUNoQix1REFBcUI7S0FDdEI7Q0FDRixDQUFDLENBQUEifQ==