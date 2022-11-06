"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reset = void 0;
const lib_1 = require("@wallet/lib");
const logger_1 = require("@wallet/main/logger");
const electron_1 = require("electron");
const rimraf_1 = __importDefault(require("rimraf"));
const util_1 = require("util");
const rmPromise = (0, util_1.promisify)(rimraf_1.default);
const reset = (locals) => {
    return {
        type: lib_1.resetAction.type,
        async handle(action) {
            // Call the internal function
            if (!locals.auth.authenticated) {
                return { response: undefined, status: 400 };
            }
            const confirm = await locals.dialog.confirmation({
                message: 'The application reset will remove all your personal data. Are you sure?'
            });
            if (confirm === true) {
                logger_1.logger.info('Reset all wallet information');
                const configPath = electron_1.app.getPath('userData');
                await rmPromise(configPath);
                electron_1.app.quit();
            }
            return { response: undefined, status: 200 };
        }
    };
};
exports.reset = reset;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzZXQuaGFuZGxlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL2FjdGlvbnMvc3lzdGVtL3Jlc2V0LmhhbmRsZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEscUNBRW9CO0FBQ3BCLGdEQUE0QztBQUM1Qyx1Q0FBOEI7QUFDOUIsb0RBQXVCO0FBRXZCLCtCQUFnQztBQUVoQyxNQUFNLFNBQVMsR0FBRyxJQUFBLGdCQUFTLEVBQUMsZ0JBQUUsQ0FBQyxDQUFBO0FBRXhCLE1BQU0sS0FBSyxHQUErQyxDQUMvRCxNQUFNLEVBQ04sRUFBRTtJQUNGLE9BQU87UUFDTCxJQUFJLEVBQUUsaUJBQWEsQ0FBQyxJQUFJO1FBQ3hCLEtBQUssQ0FBQyxNQUFNLENBQUUsTUFBTTtZQUNsQiw2QkFBNkI7WUFDN0IsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsYUFBYSxFQUFFO2dCQUM5QixPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7YUFDNUM7WUFFRCxNQUFNLE9BQU8sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO2dCQUMvQyxPQUFPLEVBQUUseUVBQXlFO2FBQ25GLENBQUMsQ0FBQTtZQUNGLElBQUksT0FBTyxLQUFLLElBQUksRUFBRTtnQkFDcEIsZUFBTSxDQUFDLElBQUksQ0FBQyw4QkFBOEIsQ0FBQyxDQUFBO2dCQUMzQyxNQUFNLFVBQVUsR0FBRyxjQUFHLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFBO2dCQUMxQyxNQUFNLFNBQVMsQ0FBQyxVQUFVLENBQUMsQ0FBQTtnQkFDM0IsY0FBRyxDQUFDLElBQUksRUFBRSxDQUFBO2FBQ1g7WUFFRCxPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUE7UUFDN0MsQ0FBQztLQUNGLENBQUE7QUFDSCxDQUFDLENBQUE7QUF4QlksUUFBQSxLQUFLLFNBd0JqQiJ9