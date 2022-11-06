"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.transactionDeploy = void 0;
const locals_1 = require("@wallet/main/locals");
const async_handler_1 = require("./async-handler");
exports.transactionDeploy = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, locals_1.extractLocals)(req.app);
    await walletFactory.wallet.transactionDeploy(req.body);
    res.sendStatus(200);
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHJhbnNhY3Rpb24uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbWFpbi9hcGkvcm91dGVzL3RyYW5zYWN0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUVBLGdEQUFtRDtBQUNuRCxtREFBOEM7QUFFakMsUUFBQSxpQkFBaUIsR0FBRyxJQUFBLDRCQUFZLEVBQWlHLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDL0osTUFBTSxFQUFFLGFBQWEsRUFBRSxHQUFHLElBQUEsc0JBQWEsRUFBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7SUFFaEQsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQTtJQUN0RCxHQUFHLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFBO0FBQ3JCLENBQUMsQ0FBQyxDQUFBIn0=