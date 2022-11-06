"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDefaultSharedMemory = void 0;
const internal_1 = require("../internal");
function createDefaultSharedMemory(values) {
    const settings = values?.settings ?? (0, internal_1.createDefaultSettings)();
    return {
        hasStore: false,
        settings,
        identities: {},
        resources: {},
        dialogs: {
            current: undefined,
            data: {}
        },
        walletsMetadata: {},
        connectData: {
            walletProtocol: {}
        },
        toasts: [],
        ...values
    };
}
exports.createDefaultSharedMemory = createDefaultSharedMemory;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2hhcmVkLW1lbW9yeS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvY29tbXVuaWNhdGlvbi9zaGFyZWQtbWVtb3J5LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUNBLDBDQUFzRjtBQThCdEYsU0FBZ0IseUJBQXlCLENBQUUsTUFBOEI7SUFDdkUsTUFBTSxRQUFRLEdBQUcsTUFBTSxFQUFFLFFBQVEsSUFBSSxJQUFBLGdDQUFxQixHQUFFLENBQUE7SUFFNUQsT0FBTztRQUNMLFFBQVEsRUFBRSxLQUFLO1FBQ2YsUUFBUTtRQUNSLFVBQVUsRUFBRSxFQUFFO1FBQ2QsU0FBUyxFQUFFLEVBQUU7UUFDYixPQUFPLEVBQUU7WUFDUCxPQUFPLEVBQUUsU0FBUztZQUNsQixJQUFJLEVBQUUsRUFBRTtTQUNUO1FBQ0QsZUFBZSxFQUFFLEVBQUU7UUFDbkIsV0FBVyxFQUFFO1lBQ1gsY0FBYyxFQUFFLEVBQUU7U0FDbkI7UUFDRCxNQUFNLEVBQUUsRUFBRTtRQUVWLEdBQUcsTUFBTTtLQUNWLENBQUE7QUFDSCxDQUFDO0FBcEJELDhEQW9CQyJ9