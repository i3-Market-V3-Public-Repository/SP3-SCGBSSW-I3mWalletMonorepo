"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.walletModule = void 0;
const module_1 = require("../module");
const create_wallet_handler_1 = require("./create-wallet.handler");
const select_wallet_handler_1 = require("./select-wallet.handler");
const create_identity_handler_1 = require("./create-identity.handler");
const delete_identity_handler_1 = require("./delete-identity.handler");
const import_resource_handler_1 = require("./import-resource.handler");
const export_resource_handler_1 = require("./export-resource.handler");
const delete_resource_handler_1 = require("./delete-resource.handler");
const sign_handler_1 = require("./sign.handler");
const verify_jwt_handler_1 = require("./verify-jwt.handler");
const call_wallet_function_handler_1 = require("./call-wallet-function.handler");
const get_providerinfo_handler_1 = require("./get-providerinfo.handler");
exports.walletModule = new module_1.Module({
    handlersBuilders: [
        create_wallet_handler_1.createWallet,
        select_wallet_handler_1.selectWallet,
        create_identity_handler_1.createIdentity,
        delete_identity_handler_1.deleteIdentity,
        import_resource_handler_1.importResource,
        export_resource_handler_1.exportResource,
        delete_resource_handler_1.deleteResource,
        sign_handler_1.sign,
        verify_jwt_handler_1.verifyJWT,
        call_wallet_function_handler_1.callWalletFunction,
        get_providerinfo_handler_1.getProviderinfo
    ]
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2FsbGV0LW1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FjdGlvbnMvd2FsbGV0L3dhbGxldC1tb2R1bGUudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsc0NBQWtDO0FBQ2xDLG1FQUFzRDtBQUN0RCxtRUFBc0Q7QUFDdEQsdUVBQTBEO0FBQzFELHVFQUEwRDtBQUMxRCx1RUFBMEQ7QUFDMUQsdUVBQTBEO0FBQzFELHVFQUEwRDtBQUMxRCxpREFBcUM7QUFDckMsNkRBQWdEO0FBQ2hELGlGQUFtRTtBQUNuRSx5RUFBNEQ7QUFFL0MsUUFBQSxZQUFZLEdBQUcsSUFBSSxlQUFNLENBQUM7SUFDckMsZ0JBQWdCLEVBQUU7UUFDaEIsb0NBQVk7UUFDWixvQ0FBWTtRQUNaLHdDQUFjO1FBQ2Qsd0NBQWM7UUFDZCx3Q0FBYztRQUNkLHdDQUFjO1FBQ2Qsd0NBQWM7UUFDZCxtQkFBSTtRQUNKLDhCQUFTO1FBQ1QsaURBQWtCO1FBQ2xCLDBDQUFlO0tBQ2hCO0NBQ0YsQ0FBQyxDQUFBIn0=