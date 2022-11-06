"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.didJwtVerify = void 0;
const lib_1 = require("@wallet/lib");
const locals_1 = require("@wallet/main/locals");
const async_handler_1 = require("./async-handler");
exports.didJwtVerify = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { actionReducer } = (0, locals_1.extractLocals)(req.app);
    await actionReducer.fromApi(req, res, lib_1.didJwtVerifyAction.create({
        body: req.body
    }));
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGlkLWp3dC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FwaS9yb3V0ZXMvZGlkLWp3dC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFQSxxQ0FBZ0Q7QUFDaEQsZ0RBQW1EO0FBQ25ELG1EQUE4QztBQUVqQyxRQUFBLFlBQVksR0FBRyxJQUFBLDRCQUFZLEVBQXVGLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDaEosTUFBTSxFQUFFLGFBQWEsRUFBRSxHQUFHLElBQUEsc0JBQWEsRUFBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7SUFDaEQsTUFBTSxhQUFhLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsd0JBQWtCLENBQUMsTUFBTSxDQUFDO1FBQzlELElBQUksRUFBRSxHQUFHLENBQUMsSUFBSTtLQUNmLENBQUMsQ0FBQyxDQUFBO0FBQ0wsQ0FBQyxDQUFDLENBQUEifQ==