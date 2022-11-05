import { DataExchange } from '@i3m/non-repudiation-library';
import { WalletComponents } from '@i3m/wallet-desktop-openapi/types';
import { BaseWalletModel, ContractResource } from '../app';
import Veramo from '../veramo';
export declare function validateDataSharingAgreeementSchema(agreement: WalletComponents.Schemas.DataSharingAgreement): Promise<Error[]>;
export declare function validateDataExchange(dataExchange: DataExchange): Promise<Error[]>;
export declare function validateDataExchangeAgreement(dea: WalletComponents.Schemas.DataExchangeAgreement): Promise<Error[]>;
export declare function verifyDataSharingAgreementSignature(agreement: ContractResource['resource']['dataSharingAgreement'], veramo: Veramo<BaseWalletModel>, signer: 'provider' | 'consumer'): Promise<Error[]>;
//# sourceMappingURL=data-sharing-agreement-validation.d.ts.map