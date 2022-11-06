import { MasterKey } from './master-key';
export interface CodeGenerator {
    generate: (masterKey: MasterKey) => Promise<Uint8Array>;
    getMasterKey: (code: Uint8Array) => Promise<MasterKey>;
}
export declare const defaultCodeGenerator: CodeGenerator;
//# sourceMappingURL=code-generator.d.ts.map