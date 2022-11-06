"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = exports.loggerMiddleware = void 0;
const morgan_1 = __importDefault(require("morgan"));
const winston_1 = require("winston");
const internal_1 = require("./internal");
// Request logger
const level = internal_1.config.isProd ? 'info' : '\u001b[32minfo\u001b[39m';
morgan_1.default.token('body', (req, res) => {
    return JSON.stringify(req.body);
});
exports.loggerMiddleware = (0, morgan_1.default)(`:date[iso] ${level}: :method :url :status :response-time ms - :res[content-length] :res[location] :body`);
// Extra information logger
const consoleTransport = new winston_1.transports.Console();
function createFormat() {
    const formats = [];
    formats.push(winston_1.format.timestamp());
    if (!internal_1.config.isProd)
        formats.push(winston_1.format.colorize());
    formats.push(winston_1.format.printf((info) => `${info.timestamp} ${info.level}: ${info.message}`));
    return winston_1.format.combine(...formats);
}
exports.logger = (0, winston_1.createLogger)({
    level: internal_1.config.isProd ? 'info' : 'debug',
    transports: [consoleTransport],
    format: createFormat()
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibG9nZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL21haW4vbG9nZ2VyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLG9EQUEyQjtBQUUzQixxQ0FBa0U7QUFFbEUseUNBQW1DO0FBRW5DLGlCQUFpQjtBQUNqQixNQUFNLEtBQUssR0FBRyxpQkFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQywwQkFBMEIsQ0FBQTtBQUNqRSxnQkFBTSxDQUFDLEtBQUssQ0FBVSxNQUFNLEVBQUUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDekMsT0FBTyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUNqQyxDQUFDLENBQUMsQ0FBQTtBQUNXLFFBQUEsZ0JBQWdCLEdBQ3pCLElBQUEsZ0JBQU0sRUFBQyxjQUFjLEtBQUssc0ZBQXNGLENBQUMsQ0FBQTtBQUVySCwyQkFBMkI7QUFDM0IsTUFBTSxnQkFBZ0IsR0FBRyxJQUFJLG9CQUFVLENBQUMsT0FBTyxFQUFFLENBQUE7QUFDakQsU0FBUyxZQUFZO0lBQ25CLE1BQU0sT0FBTyxHQUE0QixFQUFFLENBQUE7SUFDM0MsT0FBTyxDQUFDLElBQUksQ0FBQyxnQkFBTSxDQUFDLFNBQVMsRUFBRSxDQUFDLENBQUE7SUFDaEMsSUFBSSxDQUFDLGlCQUFNLENBQUMsTUFBTTtRQUFFLE9BQU8sQ0FBQyxJQUFJLENBQUMsZ0JBQU0sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxDQUFBO0lBQ25ELE9BQU8sQ0FBQyxJQUFJLENBQ1YsZ0JBQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLEVBQUUsRUFBRSxDQUFDLEdBQUcsSUFBSSxDQUFDLFNBQW1CLElBQUksSUFBSSxDQUFDLEtBQUssS0FBSyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUMsQ0FDdEYsQ0FBQTtJQUVELE9BQU8sZ0JBQU0sQ0FBQyxPQUFPLENBQUMsR0FBRyxPQUFPLENBQUMsQ0FBQTtBQUNuQyxDQUFDO0FBQ1ksUUFBQSxNQUFNLEdBQUcsSUFBQSxzQkFBWSxFQUFDO0lBQ2pDLEtBQUssRUFBRSxpQkFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxPQUFPO0lBQ3ZDLFVBQVUsRUFBRSxDQUFDLGdCQUFnQixDQUFDO0lBQzlCLE1BQU0sRUFBRSxZQUFZLEVBQUU7Q0FDdkIsQ0FBQyxDQUFBIn0=