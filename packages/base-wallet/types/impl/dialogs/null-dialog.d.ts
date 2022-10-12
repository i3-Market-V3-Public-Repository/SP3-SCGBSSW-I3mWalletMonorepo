import { Dialog, DialogResponse, TextOptions, ConfirmationOptions, SelectOptions, FormOptions } from '../../app';
interface Values {
    text: string | undefined;
    confirmation: boolean | undefined;
    selectMap: <T>(values: T[]) => T | undefined;
}
export declare class NullDialog implements Dialog {
    private readonly valuesStack;
    get values(): Values;
    setValues(values: Partial<Values>, cb: () => Promise<void>): Promise<void>;
    text(options: TextOptions): DialogResponse<string>;
    confirmation(options: ConfirmationOptions): DialogResponse<boolean>;
    select<T>(options: SelectOptions<T>): DialogResponse<T>;
    authenticate(): DialogResponse<boolean>;
    form<T>(options: FormOptions<T>): DialogResponse<T>;
}
export {};
//# sourceMappingURL=null-dialog.d.ts.map