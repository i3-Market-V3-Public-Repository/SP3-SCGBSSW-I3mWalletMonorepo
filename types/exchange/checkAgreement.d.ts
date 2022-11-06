import { NrError } from '../errors';
import { DataExchange, DataExchangeAgreement, DataSharingAgreement } from '../types';
export declare function validateDataSharingAgreementSchema(agreement: DataSharingAgreement): Promise<Error[]>;
export declare function validateDataExchange(dataExchange: DataExchange): Promise<Error[]>;
export declare function validateDataExchangeAgreement(agreement: DataExchangeAgreement): Promise<NrError[]>;
//# sourceMappingURL=checkAgreement.d.ts.map