"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.general = void 0;
const parseProcessEnvVar_1 = require("./parseProcessEnvVar");
const nodeEnv = (0, parseProcessEnvVar_1.parseProccessEnvVar)('NODE_ENV', 'string', { defaultValue: 'production', allowedValues: ['production', 'development'] });
const version = '2.6.2';
exports.general = {
    nodeEnv,
    version
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2VuZXJhbC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb25maWcvZ2VuZXJhbC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw2REFBMEQ7QUFFMUQsTUFBTSxPQUFPLEdBQUcsSUFBQSx3Q0FBbUIsRUFBQyxVQUFVLEVBQUUsUUFBUSxFQUFFLEVBQUUsWUFBWSxFQUFFLFlBQVksRUFBRSxhQUFhLEVBQUUsQ0FBQyxZQUFZLEVBQUUsYUFBYSxDQUFDLEVBQUUsQ0FBaUMsQ0FBQTtBQUN2SyxNQUFNLE9BQU8sR0FBRyxhQUFhLENBQUE7QUFDaEIsUUFBQSxPQUFPLEdBQUc7SUFDckIsT0FBTztJQUNQLE9BQU87Q0FDUixDQUFBIn0=