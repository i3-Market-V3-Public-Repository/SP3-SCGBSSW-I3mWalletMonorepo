"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const registration_1 = __importDefault(require("./registration"));
const vault_1 = __importDefault(require("./vault"));
const passport_1 = require("../../middlewares/passport");
const router = (0, express_1.Router)();
const registrationRouter = (0, express_1.Router)({ mergeParams: true });
const vaultRouter = (0, express_1.Router)({ mergeParams: true });
exports.default = async () => {
    const passport = await passport_1.passportPromise;
    router.use(passport.initialize());
    const registrationSubPrefix = '/registration';
    await (0, registration_1.default)(registrationRouter);
    router.use(registrationSubPrefix, registrationRouter);
    const vaultSubPrefix = '/vault';
    await (0, vault_1.default)(vaultRouter);
    router.use(vaultSubPrefix, vaultRouter);
    return router;
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvcm91dGVzL2FwaS9pbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLHFDQUFnQztBQUNoQyxrRUFBeUM7QUFDekMsb0RBQTJCO0FBQzNCLHlEQUE0RDtBQUU1RCxNQUFNLE1BQU0sR0FBRyxJQUFBLGdCQUFNLEdBQUUsQ0FBQTtBQUN2QixNQUFNLGtCQUFrQixHQUFHLElBQUEsZ0JBQU0sRUFBQyxFQUFFLFdBQVcsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFBO0FBQ3hELE1BQU0sV0FBVyxHQUFHLElBQUEsZ0JBQU0sRUFBQyxFQUFFLFdBQVcsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFBO0FBRWpELGtCQUFlLEtBQUssSUFBcUIsRUFBRTtJQUN6QyxNQUFNLFFBQVEsR0FBRyxNQUFNLDBCQUFlLENBQUE7SUFDdEMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUMsVUFBVSxFQUFFLENBQUMsQ0FBQTtJQUVqQyxNQUFNLHFCQUFxQixHQUFHLGVBQWUsQ0FBQTtJQUM3QyxNQUFNLElBQUEsc0JBQVksRUFBQyxrQkFBa0IsQ0FBQyxDQUFBO0lBQ3RDLE1BQU0sQ0FBQyxHQUFHLENBQUMscUJBQXFCLEVBQUUsa0JBQWtCLENBQUMsQ0FBQTtJQUVyRCxNQUFNLGNBQWMsR0FBRyxRQUFRLENBQUE7SUFDL0IsTUFBTSxJQUFBLGVBQUssRUFBQyxXQUFXLENBQUMsQ0FBQTtJQUN4QixNQUFNLENBQUMsR0FBRyxDQUFDLGNBQWMsRUFBRSxXQUFXLENBQUMsQ0FBQTtJQUV2QyxPQUFPLE1BQU0sQ0FBQTtBQUNmLENBQUMsQ0FBQSJ9