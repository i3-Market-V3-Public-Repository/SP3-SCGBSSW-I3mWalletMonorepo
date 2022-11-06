"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.selectiveDisclosure = void 0;
const locals_1 = require("@wallet/main/locals");
const async_handler_1 = require("./async-handler");
exports.selectiveDisclosure = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, locals_1.extractLocals)(req.app);
    res.json(await walletFactory.wallet.selectiveDisclosure(req.params));
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGlzY2xvc3VyZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FwaS9yb3V0ZXMvZGlzY2xvc3VyZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFQSxnREFBbUQ7QUFDbkQsbURBQThDO0FBRWpDLFFBQUEsbUJBQW1CLEdBQUcsSUFBQSw0QkFBWSxFQUFpRyxLQUFLLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFO0lBQ2pLLE1BQU0sRUFBRSxhQUFhLEVBQUUsR0FBRyxJQUFBLHNCQUFhLEVBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0lBQ2hELEdBQUcsQ0FBQyxJQUFJLENBQUMsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLG1CQUFtQixDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFBO0FBQ3RFLENBQUMsQ0FBQyxDQUFBIn0=