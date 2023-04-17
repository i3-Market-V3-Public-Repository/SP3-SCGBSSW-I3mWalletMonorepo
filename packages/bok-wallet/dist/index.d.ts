import { BaseWalletModel, WalletOptionsSettings, BaseWallet, WalletOptions, WalletBuilder } from '@i3m/base-wallet';

type KeyType = 'Secp256k1';
interface Key {
    kid: string;
    type: KeyType;
    publicKeyHex: string;
    privateKeyHex: string;
}
interface BokWalletModel extends BaseWalletModel {
    keys: {
        [kid: string]: Key;
    };
}
interface BokWalletOptions extends WalletOptionsSettings<BokWalletModel> {
}

interface ImportInfo {
    alias: string;
    privateKey: string;
}
declare class BokWallet extends BaseWallet<WalletOptions<BokWalletModel>> {
    importDid(importInfo?: ImportInfo): Promise<void>;
}

declare const builder: WalletBuilder<BokWalletOptions>;
//# sourceMappingURL=index.d.ts.map

export { BokWallet, BokWalletModel, BokWalletOptions, Key, KeyType, builder as default };
