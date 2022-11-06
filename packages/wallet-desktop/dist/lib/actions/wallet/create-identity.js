"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIdentityAction = void 0;
const type = 'wallet::identity.create';
const create = (payload) => {
    if (payload === undefined) {
        payload = {};
    }
    return { type, payload };
};
exports.createIdentityAction = {
    type: type,
    create
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3JlYXRlLWlkZW50aXR5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2xpYi9hY3Rpb25zL3dhbGxldC9jcmVhdGUtaWRlbnRpdHkudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBSUEsTUFBTSxJQUFJLEdBQUcseUJBQXlCLENBQUE7QUFLdEMsTUFBTSxNQUFNLEdBQUcsQ0FBQyxPQUFpQixFQUFVLEVBQUU7SUFDM0MsSUFBSSxPQUFPLEtBQUssU0FBUyxFQUFFO1FBQ3pCLE9BQU8sR0FBRyxFQUFFLENBQUE7S0FDYjtJQUNELE9BQU8sRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUE7QUFDMUIsQ0FBQyxDQUFBO0FBRVksUUFBQSxvQkFBb0IsR0FBbUQ7SUFDbEYsSUFBSSxFQUFFLElBQUk7SUFDVixNQUFNO0NBQ1AsQ0FBQSJ9