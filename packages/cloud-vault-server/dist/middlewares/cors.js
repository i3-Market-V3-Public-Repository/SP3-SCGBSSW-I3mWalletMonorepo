"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.corsMiddleware = void 0;
const config_1 = require("../config");
const corsMiddleware = (req, res, next) => {
    res.header('Access-Control-Allow-Origin', config_1.cors.allowedOrigin);
    res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, Connection, Cache-control');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Allow', 'GET, POST, OPTIONS');
    // intercepts OPTIONS method
    if (req.method === 'OPTIONS') {
        // respond with 200
        res.sendStatus(200);
    }
    else {
        // move on
        next();
    }
};
exports.corsMiddleware = corsMiddleware;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29ycy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9taWRkbGV3YXJlcy9jb3JzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUNBLHNDQUFnQztBQUV6QixNQUFNLGNBQWMsR0FBbUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxFQUFFO0lBQy9ELEdBQUcsQ0FBQyxNQUFNLENBQUMsNkJBQTZCLEVBQUUsYUFBSSxDQUFDLGFBQWEsQ0FBQyxDQUFBO0lBQzdELEdBQUcsQ0FBQyxNQUFNLENBQUMsOEJBQThCLEVBQUUsd0RBQXdELENBQUMsQ0FBQTtJQUNwRyxHQUFHLENBQUMsTUFBTSxDQUFDLDhCQUE4QixFQUFFLGlDQUFpQyxDQUFDLENBQUE7SUFDN0UsR0FBRyxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsb0JBQW9CLENBQUMsQ0FBQTtJQUV6Qyw0QkFBNEI7SUFDNUIsSUFBSSxHQUFHLENBQUMsTUFBTSxLQUFLLFNBQVMsRUFBRTtRQUM1QixtQkFBbUI7UUFDbkIsR0FBRyxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtLQUNwQjtTQUFNO1FBQ1AsVUFBVTtRQUNSLElBQUksRUFBRSxDQUFBO0tBQ1A7QUFDSCxDQUFDLENBQUE7QUFkWSxRQUFBLGNBQWMsa0JBYzFCIn0=