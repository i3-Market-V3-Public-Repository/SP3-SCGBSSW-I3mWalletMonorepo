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
exports.openApiValidatorMiddleware = void 0;
const OpenApiValidator = __importStar(require("express-openapi-validator"));
const config_1 = require("../config");
exports.openApiValidatorMiddleware = OpenApiValidator.middleware({
    ...config_1.openApi
    // formats: [
    //   {
    //     name: 'compact-jws',
    //     type: 'string',
    //     validate: (input: string): boolean => {
    //       const matched = input.match(/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/)
    //       return matched !== null
    //     }
    //   }
    // ]
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3BlbmFwaS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9taWRkbGV3YXJlcy9vcGVuYXBpLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsNEVBQTZEO0FBQzdELHNDQUFtQztBQUV0QixRQUFBLDBCQUEwQixHQUFHLGdCQUFnQixDQUFDLFVBQVUsQ0FBQztJQUNwRSxHQUFHLGdCQUFPO0lBQ1YsYUFBYTtJQUNiLE1BQU07SUFDTiwyQkFBMkI7SUFDM0Isc0JBQXNCO0lBQ3RCLDhDQUE4QztJQUM5Qyx3RkFBd0Y7SUFDeEYsZ0NBQWdDO0lBQ2hDLFFBQVE7SUFDUixNQUFNO0lBQ04sSUFBSTtDQUNMLENBQUMsQ0FBQSJ9