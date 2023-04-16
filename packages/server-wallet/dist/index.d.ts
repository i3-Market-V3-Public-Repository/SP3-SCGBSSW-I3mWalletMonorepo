import { NullDialog, FileStore, ConsoleToast } from '@i3m/base-wallet';
import { BokWallet, BokWalletModel, BokWalletOptions } from '@i3m/bok-wallet';

interface ServerWallet extends BokWallet {
    dialog: NullDialog;
    store: FileStore<BokWalletModel>;
    toast: ConsoleToast;
}
interface ServerWalletOptions {
    filepath?: string;
    password?: string;
    provider?: BokWalletOptions['provider'];
    providerData?: BokWalletOptions['providersData'];
    reset?: boolean;
}
declare function serverWalletBuilder(options?: ServerWalletOptions): Promise<ServerWallet>;

export { ServerWallet, ServerWalletOptions, serverWalletBuilder };
