"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.identityDeployTransaction = exports.identityInfo = exports.identitySign = exports.identityCreate = exports.identitySelect = exports.identityList = void 0;
const lib_1 = require("@wallet/lib");
const locals_1 = require("@wallet/main/locals");
const async_handler_1 = require("./async-handler");
exports.identityList = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, locals_1.extractLocals)(req.app);
    const response = await walletFactory.wallet.identityList(req.query);
    res.json(response);
});
exports.identitySelect = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, locals_1.extractLocals)(req.app);
    const response = await walletFactory.wallet.identitySelect(req.query);
    res.json(response);
});
exports.identityCreate = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { actionReducer } = (0, locals_1.extractLocals)(req.app);
    await actionReducer.fromApi(req, res, lib_1.createIdentityAction.create(req.body));
});
exports.identitySign = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { actionReducer } = (0, locals_1.extractLocals)(req.app);
    await actionReducer.fromApi(req, res, lib_1.signAction.create({
        signer: req.params,
        body: req.body
    }));
});
exports.identityInfo = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, locals_1.extractLocals)(req.app);
    const response = await walletFactory.wallet.identityInfo(req.params);
    res.json(response);
});
exports.identityDeployTransaction = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, locals_1.extractLocals)(req.app);
    const response = await walletFactory.wallet.identityDeployTransaction(req.query, req.body);
    res.json(response);
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaWRlbnRpdGllcy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FwaS9yb3V0ZXMvaWRlbnRpdGllcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFQSxxQ0FBOEQ7QUFDOUQsZ0RBQW1EO0FBQ25ELG1EQUE4QztBQUVqQyxRQUFBLFlBQVksR0FBRyxJQUFBLDRCQUFZLEVBQWtHLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDM0osTUFBTSxFQUFFLGFBQWEsRUFBRSxHQUFHLElBQUEsc0JBQWEsRUFBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7SUFDaEQsTUFBTSxRQUFRLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUE7SUFDbkUsR0FBRyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQTtBQUNwQixDQUFDLENBQUMsQ0FBQTtBQUVXLFFBQUEsY0FBYyxHQUFHLElBQUEsNEJBQVksRUFBc0csS0FBSyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRTtJQUNqSyxNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsSUFBQSxzQkFBYSxFQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUNoRCxNQUFNLFFBQVEsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsY0FBYyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQTtJQUNyRSxHQUFHLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0FBQ3BCLENBQUMsQ0FBQyxDQUFBO0FBRVcsUUFBQSxjQUFjLEdBQUcsSUFBQSw0QkFBWSxFQUEyRixLQUFLLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFO0lBQ3RKLE1BQU0sRUFBRSxhQUFhLEVBQUUsR0FBRyxJQUFBLHNCQUFhLEVBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0lBQ2hELE1BQU0sYUFBYSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLDBCQUFvQixDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQTtBQUM5RSxDQUFDLENBQUMsQ0FBQTtBQUVXLFFBQUEsWUFBWSxHQUFHLElBQUEsNEJBQVksRUFBeUgsS0FBSyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRTtJQUNsTCxNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsSUFBQSxzQkFBYSxFQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUNoRCxNQUFNLGFBQWEsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxnQkFBVSxDQUFDLE1BQU0sQ0FBQztRQUN0RCxNQUFNLEVBQUUsR0FBRyxDQUFDLE1BQU07UUFDbEIsSUFBSSxFQUFFLEdBQUcsQ0FBQyxJQUFJO0tBQ2YsQ0FBQyxDQUFDLENBQUE7QUFDTCxDQUFDLENBQUMsQ0FBQTtBQUVXLFFBQUEsWUFBWSxHQUFHLElBQUEsNEJBQVksRUFBbUYsS0FBSyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRTtJQUM1SSxNQUFNLEVBQUUsYUFBYSxFQUFFLEdBQUcsSUFBQSxzQkFBYSxFQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUNoRCxNQUFNLFFBQVEsR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUNwRSxHQUFHLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0FBQ3BCLENBQUMsQ0FBQyxDQUFBO0FBRVcsUUFBQSx5QkFBeUIsR0FBRyxJQUFBLDRCQUFZLEVBQWdLLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDdE8sTUFBTSxFQUFFLGFBQWEsRUFBRSxHQUFHLElBQUEsc0JBQWEsRUFBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7SUFDaEQsTUFBTSxRQUFRLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLHlCQUF5QixDQUFDLEdBQUcsQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFBO0lBQzFGLEdBQUcsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDcEIsQ0FBQyxDQUFDLENBQUEifQ==