'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var baseWallet = require('@i3m/base-wallet');
var os = require('os');
var path = require('path');
var walletBuilder = require('@i3m/bok-wallet');
var fs = require('fs');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var walletBuilder__default = /*#__PURE__*/_interopDefaultLegacy(walletBuilder);

async function serverWalletBuilder(options) {
    let filepath;
    if (options?.filepath === undefined) {
        const filedir = path.join(os.homedir(), '.server-wallet');
        try {
            fs.mkdirSync(filedir);
        }
        catch (error) { }
        filepath = path.join(filedir, 'store');
    }
    else {
        filepath = options.filepath;
    }
    const dialog = new baseWallet.NullDialog();
    const store = new baseWallet.FileStore(filepath, options?.password);
    const toast = new baseWallet.ConsoleToast();
    return await walletBuilder__default["default"]({
        dialog,
        store,
        toast,
        provider: options?.provider,
        providersData: options?.providerData
    });
}

exports.serverWalletBuilder = serverWalletBuilder;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiam9pbiIsImhvbWVkaXIiLCJta2RpclN5bmMiLCJOdWxsRGlhbG9nIiwiRmlsZVN0b3JlIiwiQ29uc29sZVRvYXN0Iiwid2FsbGV0QnVpbGRlciJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7QUFvQk8sZUFBZSxtQkFBbUIsQ0FBRSxPQUE2QixFQUFBO0FBQ3RFLElBQUEsSUFBSSxRQUFnQixDQUFBO0FBQ3BCLElBQUEsSUFBSSxPQUFPLEVBQUUsUUFBUSxLQUFLLFNBQVMsRUFBRTtRQUNuQyxNQUFNLE9BQU8sR0FBR0EsU0FBSSxDQUFDQyxVQUFPLEVBQUUsRUFBRSxnQkFBZ0IsQ0FBQyxDQUFBO1FBQ2pELElBQUk7WUFDRkMsWUFBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBQ25CLFNBQUE7UUFBQyxPQUFPLEtBQUssRUFBRSxHQUFHO0FBQ25CLFFBQUEsUUFBUSxHQUFHRixTQUFJLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFBO0FBQ2xDLEtBQUE7QUFBTSxTQUFBO0FBQ0wsUUFBQSxRQUFRLEdBQUcsT0FBTyxDQUFDLFFBQVEsQ0FBQTtBQUM1QixLQUFBO0FBQ0QsSUFBQSxNQUFNLE1BQU0sR0FBRyxJQUFJRyxxQkFBVSxFQUFFLENBQUE7SUFDL0IsTUFBTSxLQUFLLEdBQUcsSUFBSUMsb0JBQVMsQ0FBQyxRQUFRLEVBQUUsT0FBTyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0FBQ3hELElBQUEsTUFBTSxLQUFLLEdBQUcsSUFBSUMsdUJBQVksRUFBRSxDQUFBO0lBQ2hDLE9BQU8sTUFBT0MsaUNBQWEsQ0FBQztRQUMxQixNQUFNO1FBQ04sS0FBSztRQUNMLEtBQUs7UUFDTCxRQUFRLEVBQUUsT0FBTyxFQUFFLFFBQVE7UUFDM0IsYUFBYSxFQUFFLE9BQU8sRUFBRSxZQUFZO0FBQ3JDLEtBQUEsQ0FBMkIsQ0FBQTtBQUM5Qjs7OzsifQ==
