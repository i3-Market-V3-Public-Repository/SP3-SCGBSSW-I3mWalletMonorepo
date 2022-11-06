"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// Before any code is executed, add root path!
const module_alias_1 = __importDefault(require("module-alias"));
const path_1 = require("path");
module_alias_1.default.addAlias('@wallet', (0, path_1.join)(__dirname, '/../'));
// NOTE: This line MUST be after added the alias!
const main_1 = __importDefault(require("./main")); // eslint-disable-line
(0, main_1.default)(process.argv).catch(err => {
    if (err instanceof Error) {
        console.error('Error: ', err.message, err.stack);
        console.error(err);
    }
    else {
        console.error('Cannot start:', err);
    }
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWFpbi9pbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLDhDQUE4QztBQUM5QyxnRUFBc0M7QUFDdEMsK0JBQTJCO0FBQzNCLHNCQUFXLENBQUMsUUFBUSxDQUFDLFNBQVMsRUFBRSxJQUFBLFdBQUksRUFBQyxTQUFTLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQTtBQUV4RCxpREFBaUQ7QUFDakQsa0RBQXlCLENBQUMsc0JBQXNCO0FBQ2hELElBQUEsY0FBSSxFQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLEVBQUU7SUFDN0IsSUFBSSxHQUFHLFlBQVksS0FBSyxFQUFFO1FBQ3hCLE9BQU8sQ0FBQyxLQUFLLENBQUMsU0FBUyxFQUFFLEdBQUcsQ0FBQyxPQUFPLEVBQUUsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ2hELE9BQU8sQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUE7S0FDbkI7U0FBTTtRQUNMLE9BQU8sQ0FBQyxLQUFLLENBQUMsZUFBZSxFQUFFLEdBQUcsQ0FBQyxDQUFBO0tBQ3BDO0FBQ0gsQ0FBQyxDQUFDLENBQUEifQ==