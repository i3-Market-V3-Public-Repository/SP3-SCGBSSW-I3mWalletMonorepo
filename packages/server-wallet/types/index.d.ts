import { ConsoleToast, FileStore, NullDialog } from '@i3m/base-wallet';
import { BokWallet } from '@i3m/bok-wallet';
import { BokWalletModel, BokWalletOptions } from '@i3m/bok-wallet/types/types';
export interface ServerWallet extends BokWallet {
    dialog: NullDialog;
    store: FileStore<BokWalletModel>;
    toast: ConsoleToast;
}
export interface ServerWalletOptions {
    filepath?: string;
    password?: string;
    provider?: BokWalletOptions['provider'];
    providerData?: BokWalletOptions['providersData'];
    reset?: boolean;
}
export declare function serverWalletBuilder(options?: ServerWalletOptions): Promise<ServerWallet>;
//# sourceMappingURL=index.d.ts.map