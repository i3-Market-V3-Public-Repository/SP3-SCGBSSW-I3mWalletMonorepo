"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.openApi = exports.apiVersion = void 0;
const path_1 = require("path");
const general_1 = require("./general");
exports.apiVersion = `v${general_1.general.version.split('.')[0]}`;
exports.openApi = {
    apiSpec: (0, path_1.join)(__dirname, '..', 'spec', 'cvs.yaml'),
    validateResponses: true,
    validateRequests: true,
    validateApiSpec: true,
    ignorePaths: /.*\/registration\/cb$/
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3BlbkFwaS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb25maWcvb3BlbkFwaS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSwrQkFBMkI7QUFDM0IsdUNBQW1DO0FBRXRCLFFBQUEsVUFBVSxHQUFHLElBQUksaUJBQU8sQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUE7QUFDaEQsUUFBQSxPQUFPLEdBQWdFO0lBQ2xGLE9BQU8sRUFBRSxJQUFBLFdBQUksRUFBQyxTQUFTLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxVQUFVLENBQUM7SUFDbEQsaUJBQWlCLEVBQUUsSUFBSTtJQUN2QixnQkFBZ0IsRUFBRSxJQUFJO0lBQ3RCLGVBQWUsRUFBRSxJQUFJO0lBQ3JCLFdBQVcsRUFBRSx1QkFBdUI7Q0FDckMsQ0FBQSJ9