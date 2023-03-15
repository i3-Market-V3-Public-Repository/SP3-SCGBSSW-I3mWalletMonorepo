import { WalletOptionsSettings } from './wallet-options';
import { Wallet } from './wallet';
export type WalletBuilder<Options extends WalletOptionsSettings<any>> = (opts: Options) => Promise<Wallet>;
//# sourceMappingURL=wallet-builder.d.ts.map