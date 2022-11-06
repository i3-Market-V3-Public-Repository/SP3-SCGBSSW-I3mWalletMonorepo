"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initSettings = void 0;
const electron_store_1 = __importDefault(require("electron-store"));
const lodash_1 = __importDefault(require("lodash"));
const lib_1 = require("@wallet/lib");
const internal_1 = require("@wallet/main/internal");
const initSettings = (options, sharedMemoryManager) => {
    const fixedOptions = lodash_1.default.merge({
        defaults: (0, lib_1.createDefaultSettings)()
    }, options);
    // TODO: Check if the settings format is corret. If not fix corrupted data
    const settings = new electron_store_1.default(fixedOptions);
    internal_1.logger.debug(`Load settings from '${settings.path}'`);
    return settings;
};
exports.initSettings = initSettings;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2V0dGluZ3MuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWFpbi9zZXR0aW5ncy9zZXR0aW5ncy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxvRUFBK0U7QUFDL0Usb0RBQXNCO0FBRXRCLHFDQUE4RTtBQUM5RSxvREFBbUU7QUFLNUQsTUFBTSxZQUFZLEdBQUcsQ0FBQyxPQUF3QixFQUFFLG1CQUF3QyxFQUFZLEVBQUU7SUFDM0csTUFBTSxZQUFZLEdBQUcsZ0JBQUMsQ0FBQyxLQUFLLENBQW1DO1FBQzdELFFBQVEsRUFBRSxJQUFBLDJCQUFxQixHQUFFO0tBQ2xDLEVBQUUsT0FBTyxDQUFDLENBQUE7SUFFWCwwRUFBMEU7SUFDMUUsTUFBTSxRQUFRLEdBQUcsSUFBSSx3QkFBYSxDQUFnQixZQUFZLENBQUMsQ0FBQTtJQUMvRCxpQkFBTSxDQUFDLEtBQUssQ0FBQyx1QkFBdUIsUUFBUSxDQUFDLElBQUksR0FBRyxDQUFDLENBQUE7SUFFckQsT0FBTyxRQUFRLENBQUE7QUFDakIsQ0FBQyxDQUFBO0FBVlksUUFBQSxZQUFZLGdCQVV4QiJ9