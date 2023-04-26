"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jwt = void 0;
const parseProcessEnvVar_1 = require("./parseProcessEnvVar");
const crypto_1 = require("crypto");
const secret = (0, parseProcessEnvVar_1.parseProccessEnvVar)('JWT_SECRET', 'string', { defaultValue: (0, crypto_1.randomBytes)(32).toString('hex') });
const alg = (0, parseProcessEnvVar_1.parseProccessEnvVar)('JWT_ALG', 'string', { defaultValue: 'HS512', allowedValues: ['HS256', 'HS384', 'HS512'] });
const expiresIn = Number((0, parseProcessEnvVar_1.parseProccessEnvVar)('JWT_EXPIRES_IN', 'string', { defaultValue: '7862400' }));
exports.jwt = {
    alg,
    secret,
    expiresIn
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiand0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2NvbmZpZy9qd3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkRBQTBEO0FBQzFELG1DQUFvQztBQUVwQyxNQUFNLE1BQU0sR0FBRyxJQUFBLHdDQUFtQixFQUFDLFlBQVksRUFBRSxRQUFRLEVBQUUsRUFBRSxZQUFZLEVBQUUsSUFBQSxvQkFBVyxFQUFDLEVBQUUsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLENBQUE7QUFDN0csTUFBTSxHQUFHLEdBQUcsSUFBQSx3Q0FBbUIsRUFBQyxTQUFTLEVBQUUsUUFBUSxFQUFFLEVBQUUsWUFBWSxFQUFFLE9BQU8sRUFBRSxhQUFhLEVBQUUsQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLE9BQU8sQ0FBQyxFQUFFLENBQWdDLENBQUE7QUFDMUosTUFBTSxTQUFTLEdBQUcsTUFBTSxDQUFDLElBQUEsd0NBQW1CLEVBQUMsZ0JBQWdCLEVBQUUsUUFBUSxFQUFFLEVBQUUsWUFBWSxFQUFFLFNBQVMsRUFBRSxDQUFDLENBQUMsQ0FBQTtBQUV6RixRQUFBLEdBQUcsR0FBRztJQUNqQixHQUFHO0lBQ0gsTUFBTTtJQUNOLFNBQVM7Q0FDVixDQUFBIn0=