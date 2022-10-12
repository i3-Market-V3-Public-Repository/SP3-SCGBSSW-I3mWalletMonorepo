import { WalletComponents } from '@i3m/wallet-desktop-openapi/types';
import Veramo from '../veramo';
interface Validation {
    validated: boolean;
    errors: Error[];
}
export declare type ResourceType = WalletComponents.Schemas.ResourceType;
export declare type Resource = WalletComponents.Schemas.Resource;
export declare type Validator = (resource: Resource, veramo: Veramo) => Promise<Error[]>;
export declare class ResourceValidator {
    protected validators: {
        [key: string]: Validator | undefined;
    };
    constructor();
    private initValidators;
    private setValidator;
    validate(resource: Resource, veramo: Veramo): Promise<Validation>;
}
export {};
//# sourceMappingURL=resource-validator.d.ts.map