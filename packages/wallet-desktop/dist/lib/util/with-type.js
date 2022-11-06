"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.withType = void 0;
const operators_1 = require("rxjs/operators");
const withType = (type) => (obs$) => {
    return obs$.pipe((0, operators_1.filter)((typedObject) => typedObject.type === type));
};
exports.withType = withType;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2l0aC10eXBlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi91dGlsL3dpdGgtdHlwZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSw4Q0FBdUM7QUFTaEMsTUFBTSxRQUFRLEdBQUcsQ0FDdEIsSUFBTyxFQUNQLEVBQUUsQ0FBQyxDQUFDLElBQW1CLEVBQTRCLEVBQUU7SUFDckQsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUEsa0JBQU0sRUFBQyxDQUFDLFdBQVcsRUFBRSxFQUFFLENBQUMsV0FBVyxDQUFDLElBQUksS0FBSyxJQUFJLENBQUMsQ0FBNkIsQ0FBQTtBQUNsRyxDQUFDLENBQUE7QUFKWSxRQUFBLFFBQVEsWUFJcEIifQ==