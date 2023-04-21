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
const express_1 = require("express");
const fs_1 = require("fs");
const path_1 = require("path");
const swaggerUi = __importStar(require("swagger-ui-express"));
const server_1 = require("../../config/server");
function openApiSpecRoute(router) {
    const oasPath = (0, path_1.join)(__dirname, '..', '..', 'spec', 'cvs.json');
    const oas = JSON.parse((0, fs_1.readFileSync)(oasPath, 'utf8'));
    if (oas.servers !== undefined) {
        oas.servers[0].url = server_1.serverConfig.publicUrl;
    }
    else {
        oas.servers = [{ url: server_1.serverConfig.publicUrl }];
    }
    router.get('/spec', (req, res) => {
        res.json(oas);
    });
    router.use('/spec-ui', swaggerUi.serve);
    router.get('/spec-ui', swaggerUi.setup(oas));
}
const router = (0, express_1.Router)();
exports.default = async () => {
    openApiSpecRoute(router);
    return router;
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvcm91dGVzL29hcy9pbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEscUNBQW1EO0FBQ25ELDJCQUFpQztBQUVqQywrQkFBdUM7QUFDdkMsOERBQStDO0FBQy9DLGdEQUFrRDtBQUVsRCxTQUFTLGdCQUFnQixDQUFFLE1BQWM7SUFDdkMsTUFBTSxPQUFPLEdBQUcsSUFBQSxXQUFRLEVBQUMsU0FBUyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLFVBQVUsQ0FBQyxDQUFBO0lBQ25FLE1BQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBQSxpQkFBWSxFQUFDLE9BQU8sRUFBRSxNQUFNLENBQUMsQ0FBdUIsQ0FBQTtJQUMzRSxJQUFJLEdBQUcsQ0FBQyxPQUFPLEtBQUssU0FBUyxFQUFFO1FBQzdCLEdBQUcsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxHQUFHLHFCQUFZLENBQUMsU0FBUyxDQUFBO0tBQzVDO1NBQU07UUFDTCxHQUFHLENBQUMsT0FBTyxHQUFHLENBQUMsRUFBRSxHQUFHLEVBQUUscUJBQVksQ0FBQyxTQUFTLEVBQUUsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxDQUFDLEdBQUcsQ0FBQyxPQUFPLEVBQ2hCLENBQUMsR0FBWSxFQUFFLEdBQWEsRUFBRSxFQUFFO1FBQzlCLEdBQUcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7SUFDZixDQUFDLENBQ0YsQ0FBQTtJQUNELE1BQU0sQ0FBQyxHQUFHLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQyxLQUFLLENBQUMsQ0FBQTtJQUN2QyxNQUFNLENBQUMsR0FBRyxDQUFDLFVBQVUsRUFBRSxTQUFTLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDOUMsQ0FBQztBQUVELE1BQU0sTUFBTSxHQUFHLElBQUEsZ0JBQU0sR0FBRSxDQUFBO0FBRXZCLGtCQUFlLEtBQUssSUFBcUIsRUFBRTtJQUN6QyxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUV4QixPQUFPLE1BQU0sQ0FBQTtBQUNmLENBQUMsQ0FBQSJ9