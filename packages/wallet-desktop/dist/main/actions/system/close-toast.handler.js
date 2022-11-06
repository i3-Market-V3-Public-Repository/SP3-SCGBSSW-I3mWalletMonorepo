"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.closeToast = void 0;
const lib_1 = require("@wallet/lib");
const closeToast = (locals) => {
    return {
        type: lib_1.closeToastAction.type,
        async handle(action) {
            const { toast } = locals;
            const toastId = action.payload;
            toast.close(toastId);
            return { response: undefined };
        }
    };
};
exports.closeToast = closeToast;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xvc2UtdG9hc3QuaGFuZGxlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FjdGlvbnMvc3lzdGVtL2Nsb3NlLXRvYXN0LmhhbmRsZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscUNBRW9CO0FBR2IsTUFBTSxVQUFVLEdBQStDLENBQ3BFLE1BQU0sRUFDTixFQUFFO0lBQ0YsT0FBTztRQUNMLElBQUksRUFBRSxzQkFBYSxDQUFDLElBQUk7UUFDeEIsS0FBSyxDQUFDLE1BQU0sQ0FBRSxNQUFNO1lBQ2xCLE1BQU0sRUFBRSxLQUFLLEVBQUUsR0FBRyxNQUFNLENBQUE7WUFDeEIsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLE9BQU8sQ0FBQTtZQUM5QixLQUFLLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFBO1lBRXBCLE9BQU8sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLENBQUE7UUFDaEMsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUFiWSxRQUFBLFVBQVUsY0FhdEIifQ==