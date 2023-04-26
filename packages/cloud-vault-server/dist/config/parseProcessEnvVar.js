"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseProccessEnvVar = void 0;
const dotenv_1 = require("dotenv");
(0, dotenv_1.config)();
function parseEnvValue(a) {
    return (a === undefined) ? '' : a;
}
const invalidMsg = (varname, values) => {
    let ret = `Invalid value for ${varname}. `;
    if (values !== undefined)
        ret += `Allowed values are ${values} `;
    return ret;
};
const booleanFalseAllowedValues = ['0', 'false', 'FALSE'];
const booleanTrueAllowedValues = ['1', 'true', 'FALSE'];
function parseProccessEnvVar(varName, type = 'string', options) {
    switch (type) {
        case 'string':
            return parseProccessEnvString(varName, options);
        case 'boolean':
            return parseProccessEnvBoolean(varName, options);
        default:
            throw new Error("type can only be 'boolean' or 'string'");
    }
}
exports.parseProccessEnvVar = parseProccessEnvVar;
function parseProccessEnvBoolean(varName, options) {
    const value = parseEnvValue(process.env[varName]);
    if (value === '') {
        if (options?.defaultValue !== undefined) {
            return options.defaultValue;
        }
        else {
            throw new Error(`Environment variable ${varName} missing and no default value provided`, { cause: 'you may need to create a .env file or pass the variables/secrets to your container' });
        }
    }
    else {
        if (booleanTrueAllowedValues.includes(value))
            return true;
        if (booleanFalseAllowedValues.includes(value))
            return false;
        throw new RangeError(invalidMsg(varName, booleanTrueAllowedValues.concat(booleanFalseAllowedValues).join(', ')));
    }
}
function parseProccessEnvString(varName, options) {
    const value = parseEnvValue(process.env[varName]);
    if (value === '') {
        if (options?.defaultValue !== undefined) {
            return options.defaultValue;
        }
        else {
            throw new Error(`Environment variable ${varName} missing and no default value provided`, { cause: 'you may need to create a .env file or pass the variables/secrets to your container' });
        }
    }
    else if (options?.allowedValues !== undefined && !options.allowedValues.includes(value)) {
        throw new RangeError(invalidMsg(varName, options.allowedValues.join(', ')));
    }
    return value;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicGFyc2VQcm9jZXNzRW52VmFyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2NvbmZpZy9wYXJzZVByb2Nlc3NFbnZWYXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsbUNBQThDO0FBRTlDLElBQUEsZUFBVyxHQUFFLENBQUE7QUFFYixTQUFTLGFBQWEsQ0FBRSxDQUFxQjtJQUMzQyxPQUFPLENBQUMsQ0FBQyxLQUFLLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUNuQyxDQUFDO0FBRUQsTUFBTSxVQUFVLEdBQUcsQ0FBQyxPQUFlLEVBQUUsTUFBZSxFQUFVLEVBQUU7SUFDOUQsSUFBSSxHQUFHLEdBQUcscUJBQXFCLE9BQU8sSUFBSSxDQUFBO0lBQzFDLElBQUksTUFBTSxLQUFLLFNBQVM7UUFBRSxHQUFHLElBQUksc0JBQXNCLE1BQU0sR0FBRyxDQUFBO0lBQ2hFLE9BQU8sR0FBRyxDQUFBO0FBQ1osQ0FBQyxDQUFBO0FBQ0QsTUFBTSx5QkFBeUIsR0FBRyxDQUFDLEdBQUcsRUFBRSxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUE7QUFDekQsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLEdBQUcsRUFBRSxNQUFNLEVBQUUsT0FBTyxDQUFDLENBQUE7QUFhdkQsU0FBZ0IsbUJBQW1CLENBQUUsT0FBZSxFQUFFLE9BQTZCLFFBQVEsRUFBRSxPQUF3QztJQUNuSSxRQUFRLElBQUksRUFBRTtRQUNaLEtBQUssUUFBUTtZQUNYLE9BQU8sc0JBQXNCLENBQUMsT0FBTyxFQUFFLE9BQW9DLENBQUMsQ0FBQTtRQUM5RSxLQUFLLFNBQVM7WUFDWixPQUFPLHVCQUF1QixDQUFDLE9BQU8sRUFBRSxPQUFxQyxDQUFDLENBQUE7UUFDaEY7WUFDRSxNQUFNLElBQUksS0FBSyxDQUFDLHdDQUF3QyxDQUFDLENBQUE7S0FDNUQ7QUFDSCxDQUFDO0FBVEQsa0RBU0M7QUFFRCxTQUFTLHVCQUF1QixDQUFFLE9BQWUsRUFBRSxPQUF3QjtJQUN6RSxNQUFNLEtBQUssR0FBRyxhQUFhLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFBO0lBQ2pELElBQUksS0FBSyxLQUFLLEVBQUUsRUFBRTtRQUNoQixJQUFJLE9BQU8sRUFBRSxZQUFZLEtBQUssU0FBUyxFQUFFO1lBQ3ZDLE9BQU8sT0FBTyxDQUFDLFlBQVksQ0FBQTtTQUM1QjthQUFNO1lBQ0wsTUFBTSxJQUFJLEtBQUssQ0FBQyx3QkFBd0IsT0FBTyx3Q0FBd0MsRUFBRSxFQUFFLEtBQUssRUFBRSxvRkFBb0YsRUFBRSxDQUFDLENBQUE7U0FDMUw7S0FDRjtTQUFNO1FBQ0wsSUFBSSx3QkFBd0IsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDO1lBQUUsT0FBTyxJQUFJLENBQUE7UUFDekQsSUFBSSx5QkFBeUIsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDO1lBQUUsT0FBTyxLQUFLLENBQUE7UUFDM0QsTUFBTSxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsT0FBTyxFQUFFLHdCQUF3QixDQUFDLE1BQU0sQ0FBQyx5QkFBeUIsQ0FBQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7S0FDakg7QUFDSCxDQUFDO0FBRUQsU0FBUyxzQkFBc0IsQ0FBRSxPQUFlLEVBQUUsT0FBdUI7SUFDdkUsTUFBTSxLQUFLLEdBQUcsYUFBYSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQTtJQUNqRCxJQUFJLEtBQUssS0FBSyxFQUFFLEVBQUU7UUFDaEIsSUFBSSxPQUFPLEVBQUUsWUFBWSxLQUFLLFNBQVMsRUFBRTtZQUN2QyxPQUFPLE9BQU8sQ0FBQyxZQUFZLENBQUE7U0FDNUI7YUFBTTtZQUNMLE1BQU0sSUFBSSxLQUFLLENBQUMsd0JBQXdCLE9BQU8sd0NBQXdDLEVBQUUsRUFBRSxLQUFLLEVBQUUsb0ZBQW9GLEVBQUUsQ0FBQyxDQUFBO1NBQzFMO0tBQ0Y7U0FBTSxJQUFJLE9BQU8sRUFBRSxhQUFhLEtBQUssU0FBUyxJQUFJLENBQUMsT0FBTyxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLEVBQUU7UUFDekYsTUFBTSxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQTtLQUM1RTtJQUNELE9BQU8sS0FBSyxDQUFBO0FBQ2QsQ0FBQyJ9