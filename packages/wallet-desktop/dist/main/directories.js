"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getModulesPath = exports.getResourcePath = void 0;
const path_1 = __importDefault(require("path"));
const lib_1 = require("@wallet/lib");
const getResourcePath = (resPath) => {
    const ctx = (0, lib_1.getContext)();
    return path_1.default.resolve(ctx.appPath, 'res', resPath);
};
exports.getResourcePath = getResourcePath;
const getModulesPath = (modulePath) => {
    const ctx = (0, lib_1.getContext)();
    return path_1.default.resolve(ctx.appPath, '../node_modules', modulePath);
};
exports.getModulesPath = getModulesPath;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGlyZWN0b3JpZXMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWFpbi9kaXJlY3Rvcmllcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxnREFBdUI7QUFDdkIscUNBQXdDO0FBRWpDLE1BQU0sZUFBZSxHQUFHLENBQUMsT0FBZSxFQUFVLEVBQUU7SUFDekQsTUFBTSxHQUFHLEdBQUcsSUFBQSxnQkFBVSxHQUFFLENBQUE7SUFDeEIsT0FBTyxjQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxPQUFPLEVBQUUsS0FBSyxFQUFFLE9BQU8sQ0FBQyxDQUFBO0FBQ2xELENBQUMsQ0FBQTtBQUhZLFFBQUEsZUFBZSxtQkFHM0I7QUFFTSxNQUFNLGNBQWMsR0FBRyxDQUFDLFVBQWtCLEVBQVUsRUFBRTtJQUMzRCxNQUFNLEdBQUcsR0FBRyxJQUFBLGdCQUFVLEdBQUUsQ0FBQTtJQUN4QixPQUFPLGNBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxVQUFVLENBQUMsQ0FBQTtBQUNqRSxDQUFDLENBQUE7QUFIWSxRQUFBLGNBQWMsa0JBRzFCIn0=