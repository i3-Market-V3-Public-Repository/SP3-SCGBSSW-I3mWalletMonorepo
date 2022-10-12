import { BaseWallet, WalletOptions } from '@i3m/base-wallet';
import { BokWalletModel } from './types';
interface ImportInfo {
    alias: string;
    privateKey: string;
}
export declare class BokWallet extends BaseWallet<WalletOptions<BokWalletModel>> {
    importDid(importInfo?: ImportInfo): Promise<void>;
}
export {};
//# sourceMappingURL=bok-wallet.d.ts.map