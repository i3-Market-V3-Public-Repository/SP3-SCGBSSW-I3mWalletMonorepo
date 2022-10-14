import { NrpDltAgent } from '../NrpDltAgent';
export interface NrpDltAgentOrig extends NrpDltAgent {
    deploySecret: (secretHex: string, exchangeId: string) => Promise<string>;
    getAddress: () => Promise<string>;
}
//# sourceMappingURL=NrpDltAgentOrig.d.ts.map