"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.vaultEvents = void 0;
const lodash_1 = __importDefault(require("lodash"));
const crypto_1 = require("crypto");
const headers = {
    'Content-Type': 'text/event-stream',
    Connection: 'keep-alive',
    'Cache-Control': 'no-cache'
};
class VaultEventManager {
    clients;
    connectionToUsernameMap;
    constructor() {
        this.clients = {};
        this.connectionToUsernameMap = {};
    }
    addConnection(username, response) {
        const connId = (0, crypto_1.randomUUID)(); // create unique ID for this connection
        this.connectionToUsernameMap[connId] = username;
        const connection = {
            connId,
            response
        };
        if (username in this.clients) {
            this.clients[username].connections.push(connection);
        }
        else {
            this.clients[username] = { connections: [connection] };
        }
        response.writeHead(200, headers); // Headers are sent in the first connection
        console.log(`[${username}]: new connection open (${connId})`);
        return connId;
    }
    closeConnection(connId) {
        const username = this.connectionToUsernameMap[connId];
        const connections = this.clients[username].connections;
        lodash_1.default.remove(connections, function (connection) {
            return connection.connId === connId;
        });
        if (connections.length === 0) {
            delete this.clients[username]; // eslint-disable-line @typescript-eslint/no-dynamic-delete
            delete this.connectionToUsernameMap[connId]; // eslint-disable-line @typescript-eslint/no-dynamic-delete
        }
        console.log(`[${username}]: connection closed (${connId})`);
    }
    sendEvent(username, event) {
        if ((username in this.clients)) {
            this.clients[username].connections.forEach(({ response }) => {
                response.write(`event: ${event.event}\n`);
                response.write(`data: ${JSON.stringify(event.data)}\n\n`);
            });
        }
    }
}
exports.vaultEvents = new VaultEventManager();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmF1bHQtZXZlbnQtbWFuYWdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy92YXVsdC92YXVsdC1ldmVudC1tYW5hZ2VyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUNBLG9EQUFzQjtBQUN0QixtQ0FBbUM7QUF1Q25DLE1BQU0sT0FBTyxHQUFHO0lBQ2QsY0FBYyxFQUFFLG1CQUFtQjtJQUNuQyxVQUFVLEVBQUUsWUFBWTtJQUN4QixlQUFlLEVBQUUsVUFBVTtDQUM1QixDQUFBO0FBRUQsTUFBTSxpQkFBaUI7SUFDYixPQUFPLENBQWM7SUFDckIsdUJBQXVCLENBQXlCO0lBRXhEO1FBQ0UsSUFBSSxDQUFDLE9BQU8sR0FBRyxFQUFFLENBQUE7UUFDakIsSUFBSSxDQUFDLHVCQUF1QixHQUFHLEVBQUUsQ0FBQTtJQUNuQyxDQUFDO0lBRUQsYUFBYSxDQUFFLFFBQWdCLEVBQUUsUUFBa0I7UUFDakQsTUFBTSxNQUFNLEdBQUcsSUFBQSxtQkFBVSxHQUFFLENBQUEsQ0FBQyx1Q0FBdUM7UUFDbkUsSUFBSSxDQUFDLHVCQUF1QixDQUFDLE1BQU0sQ0FBQyxHQUFHLFFBQVEsQ0FBQTtRQUUvQyxNQUFNLFVBQVUsR0FBb0I7WUFDbEMsTUFBTTtZQUNOLFFBQVE7U0FDVCxDQUFBO1FBRUQsSUFBSSxRQUFRLElBQUksSUFBSSxDQUFDLE9BQU8sRUFBRTtZQUM1QixJQUFJLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7U0FDcEQ7YUFBTTtZQUNMLElBQUksQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLEdBQUcsRUFBRSxXQUFXLEVBQUUsQ0FBQyxVQUFVLENBQUMsRUFBRSxDQUFBO1NBQ3ZEO1FBRUQsUUFBUSxDQUFDLFNBQVMsQ0FBQyxHQUFHLEVBQUUsT0FBTyxDQUFDLENBQUEsQ0FBQywyQ0FBMkM7UUFFNUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLFFBQVEsMkJBQTJCLE1BQU0sR0FBRyxDQUFDLENBQUE7UUFDN0QsT0FBTyxNQUFNLENBQUE7SUFDZixDQUFDO0lBRUQsZUFBZSxDQUFFLE1BQWM7UUFDN0IsTUFBTSxRQUFRLEdBQUcsSUFBSSxDQUFDLHVCQUF1QixDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQ3JELE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUMsV0FBVyxDQUFBO1FBQ3RELGdCQUFDLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxVQUFVLFVBQVU7WUFDeEMsT0FBTyxVQUFVLENBQUMsTUFBTSxLQUFLLE1BQU0sQ0FBQTtRQUNyQyxDQUFDLENBQUMsQ0FBQTtRQUNGLElBQUksV0FBVyxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7WUFDNUIsT0FBTyxJQUFJLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFBLENBQUMsMkRBQTJEO1lBQ3pGLE9BQU8sSUFBSSxDQUFDLHVCQUF1QixDQUFDLE1BQU0sQ0FBQyxDQUFBLENBQUMsMkRBQTJEO1NBQ3hHO1FBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLFFBQVEseUJBQXlCLE1BQU0sR0FBRyxDQUFDLENBQUE7SUFDN0QsQ0FBQztJQUVELFNBQVMsQ0FBRSxRQUFnQixFQUFFLEtBQWlFO1FBQzVGLElBQUksQ0FBQyxRQUFRLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFO1lBQzlCLElBQUksQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDLEVBQUUsUUFBUSxFQUFFLEVBQUUsRUFBRTtnQkFDMUQsUUFBUSxDQUFDLEtBQUssQ0FBQyxVQUFVLEtBQUssQ0FBQyxLQUFLLElBQUksQ0FBQyxDQUFBO2dCQUN6QyxRQUFRLENBQUMsS0FBSyxDQUFDLFNBQVMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFBO1lBQzNELENBQUMsQ0FBQyxDQUFBO1NBQ0g7SUFDSCxDQUFDO0NBQ0Y7QUFFWSxRQUFBLFdBQVcsR0FBRyxJQUFJLGlCQUFpQixFQUFFLENBQUEifQ==