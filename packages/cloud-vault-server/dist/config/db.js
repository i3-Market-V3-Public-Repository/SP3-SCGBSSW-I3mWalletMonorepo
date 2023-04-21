"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.dbConfig = void 0;
const parseProcessEnvVar_1 = require("./parseProcessEnvVar");
const storageByteLength = Number((0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_STORAGE_LIMIT', 'string', { defaultValue: '5242880' }));
const storageCharLength = Math.ceil((Math.ceil(storageByteLength / 16) * 16 + 16 + 16) / 6) * 8;
exports.dbConfig = {
    host: (0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_HOST', 'string'),
    port: Number((0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_PORT', 'string')),
    user: (0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_USER', 'string'),
    password: (0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_PASSWORD', 'string'),
    database: (0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_NAME', 'string'),
    reset: (0, parseProcessEnvVar_1.parseProccessEnvVar)('DB_RESET', 'boolean', { defaultValue: false }),
    storageByteLength,
    storageCharLength
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvY29uZmlnL2RiLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLDZEQUEwRDtBQUUxRCxNQUFNLGlCQUFpQixHQUFHLE1BQU0sQ0FBQyxJQUFBLHdDQUFtQixFQUFDLGtCQUFrQixFQUFFLFFBQVEsRUFBRSxFQUFFLFlBQVksRUFBRSxTQUFTLEVBQUUsQ0FBQyxDQUFDLENBQUE7QUFFaEgsTUFBTSxpQkFBaUIsR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxpQkFBaUIsR0FBRyxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUVsRixRQUFBLFFBQVEsR0FBRztJQUN0QixJQUFJLEVBQUUsSUFBQSx3Q0FBbUIsRUFBQyxTQUFTLEVBQUUsUUFBUSxDQUFDO0lBQzlDLElBQUksRUFBRSxNQUFNLENBQUMsSUFBQSx3Q0FBbUIsRUFBQyxTQUFTLEVBQUUsUUFBUSxDQUFDLENBQUM7SUFDdEQsSUFBSSxFQUFFLElBQUEsd0NBQW1CLEVBQUMsU0FBUyxFQUFFLFFBQVEsQ0FBQztJQUM5QyxRQUFRLEVBQUUsSUFBQSx3Q0FBbUIsRUFBQyxhQUFhLEVBQUUsUUFBUSxDQUFDO0lBQ3RELFFBQVEsRUFBRSxJQUFBLHdDQUFtQixFQUFDLFNBQVMsRUFBRSxRQUFRLENBQUM7SUFDbEQsS0FBSyxFQUFFLElBQUEsd0NBQW1CLEVBQUMsVUFBVSxFQUFFLFNBQVMsRUFBRSxFQUFFLFlBQVksRUFBRSxLQUFLLEVBQUUsQ0FBQztJQUMxRSxpQkFBaUI7SUFDakIsaUJBQWlCO0NBQ2xCLENBQUEifQ==