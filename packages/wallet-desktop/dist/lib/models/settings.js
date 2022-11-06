"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDefaultSettings = void 0;
function createDefaultSettings() {
    return {
        version: '',
        wallet: {
            wallets: {},
            packages: ['@i3m/sw-wallet']
        },
        providers: [],
        connect: {
            enableTokenExpiration: true,
            tokenTTL: 2419200 // 4 weeks
        },
        developer: {
            enableDeveloperFunctions: false,
            enableDeveloperApi: false
        }
    };
}
exports.createDefaultSettings = createDefaultSettings;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2V0dGluZ3MuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbGliL21vZGVscy9zZXR0aW5ncy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFrREEsU0FBZ0IscUJBQXFCO0lBQ25DLE9BQU87UUFDTCxPQUFPLEVBQUUsRUFBRTtRQUNYLE1BQU0sRUFBRTtZQUNOLE9BQU8sRUFBRSxFQUFFO1lBQ1gsUUFBUSxFQUFFLENBQUMsZ0JBQWdCLENBQUM7U0FDN0I7UUFDRCxTQUFTLEVBQUUsRUFBRTtRQUNiLE9BQU8sRUFBRTtZQUNQLHFCQUFxQixFQUFFLElBQUk7WUFDM0IsUUFBUSxFQUFFLE9BQU8sQ0FBQyxVQUFVO1NBQzdCO1FBQ0QsU0FBUyxFQUFFO1lBQ1Qsd0JBQXdCLEVBQUUsS0FBSztZQUMvQixrQkFBa0IsRUFBRSxLQUFLO1NBQzFCO0tBQ0YsQ0FBQTtBQUNILENBQUM7QUFqQkQsc0RBaUJDIn0=