import { EthersWalletAgent } from '../EthersWalletAgent';
import { WalletAgentDest } from './WalletAgentDest';
/**
 * A ledger signer using an ethers.io Wallet.
 */
export declare class EthersWalletAgentDest extends EthersWalletAgent implements WalletAgentDest {
    getSecretFromLedger(signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=EthersWalletAgentDest.d.ts.map