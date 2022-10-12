import { Dialog, Store, BaseWalletModel, Toast } from '../app';
import { KeyWallet } from '../keywallet';
import { ProviderData } from '../veramo';
export interface WalletOptionsCryptoWallet {
    keyWallet: KeyWallet;
}
export interface WalletOptionsSettings<T extends BaseWalletModel> {
    dialog: Dialog;
    store: Store<T>;
    toast: Toast;
    provider?: string;
    providersData?: Record<string, ProviderData>;
}
export declare type WalletOptions<T extends BaseWalletModel> = WalletOptionsSettings<T> & WalletOptionsCryptoWallet;
//# sourceMappingURL=wallet-options.d.ts.map