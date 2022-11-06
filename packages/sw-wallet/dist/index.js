"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const base_wallet_1 = require("@i3m/base-wallet");
const sw_hd_wallet_1 = require("./sw-hd-wallet");
const builder = async (opts) => {
    const keyWallet = new sw_hd_wallet_1.SwHdKeyWallet(opts.dialog, opts.store);
    await keyWallet.initialize();
    return new base_wallet_1.BaseWallet({
        ...opts,
        keyWallet
    });
};
exports.default = builder;
//# sourceMappingURL=index.js.map