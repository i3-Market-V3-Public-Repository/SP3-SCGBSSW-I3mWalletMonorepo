"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.providerinfoGet = void 0;
const lib_1 = require("@wallet/lib");
const locals_1 = require("@wallet/main/locals");
const async_handler_1 = require("./async-handler");
exports.providerinfoGet = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { actionReducer } = (0, locals_1.extractLocals)(req.app);
    await actionReducer.fromApi(req, res, lib_1.getProviderinfoAction.create({}));
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicHJvdmlkZXJpbmZvLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYXBpL3JvdXRlcy9wcm92aWRlcmluZm8udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBRUEscUNBQW1EO0FBQ25ELGdEQUFtRDtBQUNuRCxtREFBOEM7QUFFakMsUUFBQSxlQUFlLEdBQUcsSUFBQSw0QkFBWSxFQUEyRCxLQUFLLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFO0lBQ3ZILE1BQU0sRUFBRSxhQUFhLEVBQUUsR0FBRyxJQUFBLHNCQUFhLEVBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0lBQ2hELE1BQU0sYUFBYSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLDJCQUFxQixDQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO0FBQ3pFLENBQUMsQ0FBQyxDQUFBIn0=