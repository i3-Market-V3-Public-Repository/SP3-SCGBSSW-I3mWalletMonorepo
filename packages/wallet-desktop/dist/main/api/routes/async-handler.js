"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.asyncHandler = void 0;
const asyncHandler = (handler) => (req, res, next) => {
    handler(req, res, next).catch(next);
};
exports.asyncHandler = asyncHandler;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXN5bmMtaGFuZGxlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FwaS9yb3V0ZXMvYXN5bmMtaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFTyxNQUFNLFlBQVksR0FBRyxDQUMxQixPQUFnRyxFQUNqRSxFQUFFLENBQUMsQ0FBQyxHQUEyQixFQUFFLEdBQW1CLEVBQUUsSUFBa0IsRUFBRSxFQUFFO0lBQzNHLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLElBQUksQ0FBQyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUNyQyxDQUFDLENBQUE7QUFKWSxRQUFBLFlBQVksZ0JBSXhCIn0=