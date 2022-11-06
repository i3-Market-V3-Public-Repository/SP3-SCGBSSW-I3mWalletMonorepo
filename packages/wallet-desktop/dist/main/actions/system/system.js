"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.systemModule = void 0;
const module_1 = require("../module");
const reset_handler_1 = require("./reset.handler");
const close_toast_handler_1 = require("./close-toast.handler");
exports.systemModule = new module_1.Module({
    handlersBuilders: [
        reset_handler_1.reset,
        close_toast_handler_1.closeToast
    ]
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3lzdGVtLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYWN0aW9ucy9zeXN0ZW0vc3lzdGVtLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLHNDQUFrQztBQUNsQyxtREFBdUM7QUFDdkMsK0RBQWtEO0FBRXJDLFFBQUEsWUFBWSxHQUFHLElBQUksZUFBTSxDQUFDO0lBQ3JDLGdCQUFnQixFQUFFO1FBQ2hCLHFCQUFLO1FBQ0wsZ0NBQVU7S0FDWDtDQUNGLENBQUMsQ0FBQSJ9