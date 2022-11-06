"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.closeToastAction = void 0;
const type = 'system::toast.close';
const create = (toastId) => {
    return { type, payload: toastId };
};
exports.closeToastAction = {
    type: type,
    create
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xvc2UtdG9hc3QuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2FjdGlvbnMvc3lzdGVtL2Nsb3NlLXRvYXN0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUdBLE1BQU0sSUFBSSxHQUFHLHFCQUFxQixDQUFBO0FBS2xDLE1BQU0sTUFBTSxHQUFHLENBQUMsT0FBZSxFQUFVLEVBQUU7SUFDekMsT0FBTyxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsT0FBTyxFQUFFLENBQUE7QUFDbkMsQ0FBQyxDQUFBO0FBRVksUUFBQSxnQkFBZ0IsR0FBbUQ7SUFDOUUsSUFBSSxFQUFFLElBQUk7SUFDVixNQUFNO0NBQ1AsQ0FBQSJ9