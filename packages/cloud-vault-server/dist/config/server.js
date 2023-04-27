"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateServerConfig = exports.serverConfig = void 0;
const parseProcessEnvVar_1 = require("./parseProcessEnvVar");
const net_1 = require("net");
function updateServerConfig(vars) {
    const id = vars.id ?? (0, parseProcessEnvVar_1.parseProccessEnvVar)('SERVER_ID', 'string');
    const addr = vars.addr ?? (0, parseProcessEnvVar_1.parseProccessEnvVar)('SERVER_ADDRESS', 'string', { defaultValue: 'localhost' });
    const port = vars.port ?? Number((0, parseProcessEnvVar_1.parseProccessEnvVar)('SERVER_PORT', 'string', { defaultValue: '3000' }));
    const localUrl = vars.localUrl ?? `http://${(0, net_1.isIPv6)(addr) ? '[' + addr + ']' : addr}:${port}`;
    const publicUrl = vars.publicUrl ?? (0, parseProcessEnvVar_1.parseProccessEnvVar)('SERVER_PUBLIC_URL', 'string', { defaultValue: localUrl });
    exports.serverConfig = {
        id,
        addr,
        port,
        localUrl,
        publicUrl
    };
}
exports.updateServerConfig = updateServerConfig;
updateServerConfig({});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2VydmVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2NvbmZpZy9zZXJ2ZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkRBQTBEO0FBQzFELDZCQUE0QjtBQWlCNUIsU0FBZ0Isa0JBQWtCLENBQUUsSUFBMkI7SUFDN0QsTUFBTSxFQUFFLEdBQUcsSUFBSSxDQUFDLEVBQUUsSUFBSSxJQUFBLHdDQUFtQixFQUFDLFdBQVcsRUFBRSxRQUFRLENBQUMsQ0FBQTtJQUVoRSxNQUFNLElBQUksR0FBRyxJQUFJLENBQUMsSUFBSSxJQUFJLElBQUEsd0NBQW1CLEVBQUMsZ0JBQWdCLEVBQUUsUUFBUSxFQUFFLEVBQUUsWUFBWSxFQUFFLFdBQVcsRUFBRSxDQUFDLENBQUE7SUFFeEcsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksSUFBSSxNQUFNLENBQUMsSUFBQSx3Q0FBbUIsRUFBQyxhQUFhLEVBQUUsUUFBUSxFQUFFLEVBQUUsWUFBWSxFQUFFLE1BQU0sRUFBRSxDQUFDLENBQUMsQ0FBQTtJQUV4RyxNQUFNLFFBQVEsR0FBRyxJQUFJLENBQUMsUUFBUSxJQUFJLFVBQVUsSUFBQSxZQUFNLEVBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsR0FBRyxJQUFJLEdBQUcsR0FBRyxDQUFDLENBQUMsQ0FBQyxJQUFJLElBQUksSUFBSSxFQUFFLENBQUE7SUFFNUYsTUFBTSxTQUFTLEdBQUcsSUFBSSxDQUFDLFNBQVMsSUFBSSxJQUFBLHdDQUFtQixFQUFDLG1CQUFtQixFQUFFLFFBQVEsRUFBRSxFQUFFLFlBQVksRUFBRSxRQUFRLEVBQUUsQ0FBQyxDQUFBO0lBRWxILG9CQUFZLEdBQUc7UUFDYixFQUFFO1FBQ0YsSUFBSTtRQUNKLElBQUk7UUFDSixRQUFRO1FBQ1IsU0FBUztLQUNWLENBQUE7QUFDSCxDQUFDO0FBbEJELGdEQWtCQztBQUNELGtCQUFrQixDQUFDLEVBQUUsQ0FBQyxDQUFBIn0=