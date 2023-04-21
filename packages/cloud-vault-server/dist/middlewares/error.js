"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorMiddleware = void 0;
const types_1 = require("express-openapi-validator/dist/framework/types");
const config_1 = require("../config");
function errorMiddleware(err, req, res, next) {
    if (config_1.general.nodeEnv === 'development') {
        console.error(err);
    }
    let error = {
        name: 'error',
        description: 'something bad happened'
    };
    let status = 500;
    if (err instanceof types_1.HttpError) {
        status = err.status;
        error = {
            name: (err.status === 401) ? 'unauthorized' : err.name,
            description: err.message ?? ''
        };
    }
    res.status(status).json(error);
}
exports.errorMiddleware = errorMiddleware;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXJyb3IuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWlkZGxld2FyZXMvZXJyb3IudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQ0EsMEVBQTBFO0FBRTFFLHNDQUFtQztBQUVuQyxTQUFnQixlQUFlLENBQUUsR0FBWSxFQUFFLEdBQVksRUFBRSxHQUFhLEVBQUUsSUFBa0I7SUFDNUYsSUFBSSxnQkFBTyxDQUFDLE9BQU8sS0FBSyxhQUFhLEVBQUU7UUFDckMsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQTtLQUNuQjtJQUNELElBQUksS0FBSyxHQUF1QztRQUM5QyxJQUFJLEVBQUUsT0FBTztRQUNiLFdBQVcsRUFBRSx3QkFBd0I7S0FDdEMsQ0FBQTtJQUNELElBQUksTUFBTSxHQUFHLEdBQUcsQ0FBQTtJQUNoQixJQUFJLEdBQUcsWUFBWSxpQkFBUyxFQUFFO1FBQzVCLE1BQU0sR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFBO1FBQ25CLEtBQUssR0FBRztZQUNOLElBQUksRUFBRSxDQUFDLEdBQUcsQ0FBQyxNQUFNLEtBQUssR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLElBQUk7WUFDdEQsV0FBVyxFQUFFLEdBQUcsQ0FBQyxPQUFPLElBQUksRUFBRTtTQUMvQixDQUFBO0tBQ0Y7SUFDRCxHQUFHLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQTtBQUNoQyxDQUFDO0FBakJELDBDQWlCQyJ9