"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.developerApi = void 0;
const base_wallet_1 = require("@i3m/base-wallet");
const internal_1 = require("@wallet/main/internal");
const developerApi = (locals) => {
    return (req, res, next) => {
        const developerApi = locals.settings.get('developer').enableDeveloperApi;
        if (!developerApi) {
            if (req.walletProtocol !== true) {
                next(new base_wallet_1.WalletError('the request must use wallet protocol', { status: 400 }));
            }
        }
        else {
            internal_1.logger.warn('Using developer api. Not recommended for production!');
        }
        next();
    };
};
exports.developerApi = developerApi;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGV2ZWxvcGVyLWFwaS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tYWluL2FwaS9kZXZlbG9wZXItYXBpLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUNBLGtEQUE4QztBQUM5QyxvREFBc0Q7QUFFL0MsTUFBTSxZQUFZLEdBQUcsQ0FBQyxNQUFjLEVBQWtCLEVBQUU7SUFDN0QsT0FBTyxDQUFDLEdBQVEsRUFBRSxHQUFHLEVBQUUsSUFBSSxFQUFFLEVBQUU7UUFDN0IsTUFBTSxZQUFZLEdBQUcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsV0FBVyxDQUFDLENBQUMsa0JBQWtCLENBQUE7UUFDeEUsSUFBSSxDQUFDLFlBQVksRUFBRTtZQUNqQixJQUFJLEdBQUcsQ0FBQyxjQUFjLEtBQUssSUFBSSxFQUFFO2dCQUMvQixJQUFJLENBQUMsSUFBSSx5QkFBVyxDQUFDLHNDQUFzQyxFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUMsQ0FBQTthQUMvRTtTQUNGO2FBQU07WUFDTCxpQkFBTSxDQUFDLElBQUksQ0FBQyxzREFBc0QsQ0FBQyxDQUFBO1NBQ3BFO1FBQ0QsSUFBSSxFQUFFLENBQUE7SUFDUixDQUFDLENBQUE7QUFDSCxDQUFDLENBQUE7QUFaWSxRQUFBLFlBQVksZ0JBWXhCIn0=