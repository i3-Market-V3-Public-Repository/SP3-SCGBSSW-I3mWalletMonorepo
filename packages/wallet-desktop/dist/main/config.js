"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
class Config {
    defaults;
    _ngrokUri;
    _host;
    constructor() {
        this.defaults = {
            NODE_ENV: 'development'
        };
    }
    // Conversion functions
    fromBoolean = (v) => v.toLocaleLowerCase() === '1';
    fromArray = (v) => v.split(',');
    fromInteger = parseInt;
    fromImport = (v) => {
        // TODO: Only relative path supported
        const file = path.join(__dirname, '../', v);
        if (fs.existsSync(file)) {
            return require(file);
        }
        else {
            return undefined;
        }
    };
    get(name, convert) {
        const value = process.env[name] ?? this.defaults[name] ?? '';
        if (convert == null) {
            return value;
        }
        return convert(value);
    }
    /**
     * @property Is production environment
     */
    get isProd() {
        return this.get('NODE_ENV', (v) => v === 'production');
    }
    /**
      * @property Server port
      */
    get port() {
        return 8000;
    }
}
exports.config = new Config();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29uZmlnLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL21haW4vY29uZmlnLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsdUNBQXdCO0FBQ3hCLDJDQUE0QjtBQUk1QixNQUFNLE1BQU07SUFDQSxRQUFRLENBQXNDO0lBQzlDLFNBQVMsQ0FBUztJQUNsQixLQUFLLENBQVM7SUFFeEI7UUFDRSxJQUFJLENBQUMsUUFBUSxHQUFHO1lBQ2QsUUFBUSxFQUFFLGFBQWE7U0FDeEIsQ0FBQTtJQUNILENBQUM7SUFFRCx1QkFBdUI7SUFDYixXQUFXLEdBQTZCLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLENBQUMsaUJBQWlCLEVBQUUsS0FBSyxHQUFHLENBQUE7SUFDNUUsU0FBUyxHQUE4QixDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUMxRCxXQUFXLEdBQTRCLFFBQVEsQ0FBQTtJQUMvQyxVQUFVLEdBQXdCLENBQUMsQ0FBQyxFQUFFLEVBQUU7UUFDaEQscUNBQXFDO1FBQ3JDLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUMsQ0FBQTtRQUMzQyxJQUFJLEVBQUUsQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLEVBQUU7WUFDdkIsT0FBTyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7U0FDckI7YUFBTTtZQUNMLE9BQU8sU0FBUyxDQUFBO1NBQ2pCO0lBQ0gsQ0FBQyxDQUFBO0lBWUQsR0FBRyxDQUFhLElBQVksRUFBRSxPQUE0QjtRQUN4RCxNQUFNLEtBQUssR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxJQUFJLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLElBQUksRUFBRSxDQUFBO1FBQzVELElBQUksT0FBTyxJQUFJLElBQUksRUFBRTtZQUNuQixPQUFPLEtBQXFCLENBQUE7U0FDN0I7UUFFRCxPQUFPLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtJQUN2QixDQUFDO0lBRUQ7O09BRUc7SUFDSCxJQUFJLE1BQU07UUFDUixPQUFPLElBQUksQ0FBQyxHQUFHLENBQUMsVUFBVSxFQUFFLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLEtBQUssWUFBWSxDQUFDLENBQUE7SUFDeEQsQ0FBQztJQUVEOztRQUVJO0lBQ0osSUFBSSxJQUFJO1FBQ04sT0FBTyxJQUFJLENBQUE7SUFDYixDQUFDO0NBQ0Y7QUFFWSxRQUFBLE1BQU0sR0FBRyxJQUFJLE1BQU0sRUFBRSxDQUFBIn0=