"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setLocals = exports.extractLocals = void 0;
const extractLocals = (app) => {
    return app.locals.appLocals;
};
exports.extractLocals = extractLocals;
const setLocals = (app, locals) => {
    app.locals = {
        ...app.locals,
        appLocals: locals
    };
};
exports.setLocals = setLocals;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWFuYWdlbWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tYWluL2xvY2Fscy9tYW5hZ2VtZW50LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUlPLE1BQU0sYUFBYSxHQUFHLENBQUMsR0FBZ0IsRUFBVSxFQUFFO0lBQ3hELE9BQU8sR0FBRyxDQUFDLE1BQU0sQ0FBQyxTQUFtQixDQUFBO0FBQ3ZDLENBQUMsQ0FBQTtBQUZZLFFBQUEsYUFBYSxpQkFFekI7QUFFTSxNQUFNLFNBQVMsR0FBRyxDQUFDLEdBQWdCLEVBQUUsTUFBYyxFQUFRLEVBQUU7SUFDbEUsR0FBRyxDQUFDLE1BQU0sR0FBRztRQUNYLEdBQUcsR0FBRyxDQUFDLE1BQU07UUFDYixTQUFTLEVBQUUsTUFBTTtLQUNsQixDQUFBO0FBQ0gsQ0FBQyxDQUFBO0FBTFksUUFBQSxTQUFTLGFBS3JCIn0=