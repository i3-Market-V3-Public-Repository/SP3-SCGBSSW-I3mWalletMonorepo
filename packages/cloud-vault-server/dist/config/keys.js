"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jwksPromise = void 0;
const non_repudiation_library_1 = require("@i3m/non-repudiation-library");
async function createJwks() {
    const keypair = await (0, non_repudiation_library_1.generateKeys)('ES256');
    return {
        publicJwk: keypair.publicJwk,
        privateJwk: keypair.privateJwk
    };
}
exports.jwksPromise = createJwks();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoia2V5cy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb25maWcva2V5cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSwwRUFBMkQ7QUFRM0QsS0FBSyxVQUFVLFVBQVU7SUFDdkIsTUFBTSxPQUFPLEdBQUcsTUFBTSxJQUFBLHNDQUFZLEVBQUMsT0FBTyxDQUFDLENBQUE7SUFDM0MsT0FBTztRQUNMLFNBQVMsRUFBRSxPQUFPLENBQUMsU0FBcUQ7UUFDeEUsVUFBVSxFQUFFLE9BQU8sQ0FBQyxVQUFzRTtLQUMzRixDQUFBO0FBQ0gsQ0FBQztBQUVZLFFBQUEsV0FBVyxHQUFHLFVBQVUsRUFBRSxDQUFBIn0=