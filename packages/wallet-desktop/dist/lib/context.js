"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getContext = exports.initContext = exports.AlreadyDefinedContext = exports.UndefinedContext = void 0;
class UndefinedContext extends Error {
    constructor() {
        super('The context is not initialized yet');
    }
}
exports.UndefinedContext = UndefinedContext;
class AlreadyDefinedContext extends Error {
    constructor() {
        super('The context is already initialized');
    }
}
exports.AlreadyDefinedContext = AlreadyDefinedContext;
let context;
const initContext = (ctx) => {
    if (context !== undefined) {
        throw new AlreadyDefinedContext();
    }
    context = ctx;
    return ctx;
};
exports.initContext = initContext;
const getContext = () => {
    if (context === undefined) {
        throw new UndefinedContext();
    }
    return context;
};
exports.getContext = getContext;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29udGV4dC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9saWIvY29udGV4dC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFJQSxNQUFhLGdCQUFpQixTQUFRLEtBQUs7SUFDekM7UUFDRSxLQUFLLENBQUMsb0NBQW9DLENBQUMsQ0FBQTtJQUM3QyxDQUFDO0NBQ0Y7QUFKRCw0Q0FJQztBQUVELE1BQWEscUJBQXNCLFNBQVEsS0FBSztJQUM5QztRQUNFLEtBQUssQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFBO0lBQzdDLENBQUM7Q0FDRjtBQUpELHNEQUlDO0FBRUQsSUFBSSxPQUFnQyxDQUFBO0FBRTdCLE1BQU0sV0FBVyxHQUFHLENBQXdCLEdBQU0sRUFBSyxFQUFFO0lBQzlELElBQUksT0FBTyxLQUFLLFNBQVMsRUFBRTtRQUN6QixNQUFNLElBQUkscUJBQXFCLEVBQUUsQ0FBQTtLQUNsQztJQUVELE9BQU8sR0FBRyxHQUFHLENBQUE7SUFFYixPQUFPLEdBQUcsQ0FBQTtBQUNaLENBQUMsQ0FBQTtBQVJZLFFBQUEsV0FBVyxlQVF2QjtBQUVNLE1BQU0sVUFBVSxHQUFHLEdBQTZCLEVBQUU7SUFDdkQsSUFBSSxPQUFPLEtBQUssU0FBUyxFQUFFO1FBQ3pCLE1BQU0sSUFBSSxnQkFBZ0IsRUFBRSxDQUFBO0tBQzdCO0lBRUQsT0FBTyxPQUFZLENBQUE7QUFDckIsQ0FBQyxDQUFBO0FBTlksUUFBQSxVQUFVLGNBTXRCIn0=