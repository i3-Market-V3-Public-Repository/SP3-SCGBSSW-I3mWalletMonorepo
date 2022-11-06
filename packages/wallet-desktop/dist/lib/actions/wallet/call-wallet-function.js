"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callWalletFunctionAction = void 0;
const type = 'wallet::wallet.call';
const create = (payload) => {
    return { type, payload };
};
exports.callWalletFunctionAction = {
    type: type,
    create
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2FsbC13YWxsZXQtZnVuY3Rpb24uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2FjdGlvbnMvd2FsbGV0L2NhbGwtd2FsbGV0LWZ1bmN0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUlBLE1BQU0sSUFBSSxHQUFHLHFCQUFxQixDQUFBO0FBS2xDLE1BQU0sTUFBTSxHQUFHLENBQUMsT0FBZ0IsRUFBVSxFQUFFO0lBQzFDLE9BQU8sRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUE7QUFDMUIsQ0FBQyxDQUFBO0FBRVksUUFBQSx3QkFBd0IsR0FBbUQ7SUFDdEYsSUFBSSxFQUFFLElBQUk7SUFDVixNQUFNO0NBQ1AsQ0FBQSJ9