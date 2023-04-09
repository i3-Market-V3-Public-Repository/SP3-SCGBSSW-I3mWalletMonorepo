import { NrError } from '../errors/index.js';
import { DataExchange, DataExchangeAgreement, DataSharingAgreement } from '../types.js';
export declare function validateDataSharingAgreementSchema(agreement: DataSharingAgreement): Promise<Error[]>;
export declare function validateDataExchange(dataExchange: DataExchange): Promise<Error[]>;
export declare function validateDataExchangeAgreement(agreement: DataExchangeAgreement): Promise<NrError[]>;
//# sourceMappingURL=checkAgreement.d.ts.map