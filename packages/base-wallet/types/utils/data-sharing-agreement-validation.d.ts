import { BaseWalletModel, ContractResource } from '../app';
import { Veramo } from '../veramo';
export declare function verifyDataSharingAgreementSignature(agreement: ContractResource['resource']['dataSharingAgreement'], veramo: Veramo<BaseWalletModel>, signer: 'provider' | 'consumer'): Promise<Error[]>;
//# sourceMappingURL=data-sharing-agreement-validation.d.ts.map