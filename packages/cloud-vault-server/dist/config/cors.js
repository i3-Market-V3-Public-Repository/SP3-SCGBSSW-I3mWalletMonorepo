"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cors = void 0;
const parseProcessEnvVar_1 = require("./parseProcessEnvVar");
exports.cors = {
    allowedOrigin: (0, parseProcessEnvVar_1.parseProccessEnvVar)('CORS_ACCESS_CONTROL_ALLOW_ORIGIN', 'string', { defaultValue: '*' })
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29ycy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb25maWcvY29ycy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw2REFBMEQ7QUFNN0MsUUFBQSxJQUFJLEdBQWU7SUFDOUIsYUFBYSxFQUFFLElBQUEsd0NBQW1CLEVBQUMsa0NBQWtDLEVBQUUsUUFBUSxFQUFFLEVBQUUsWUFBWSxFQUFFLEdBQUcsRUFBRSxDQUFDO0NBQ3hHLENBQUEifQ==