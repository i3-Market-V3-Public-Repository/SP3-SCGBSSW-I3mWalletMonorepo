export interface BaseDialogOptions {
    title?: string;
    message?: string;
    timeout?: number;
    allowCancel?: boolean;
}
export interface TextOptions extends BaseDialogOptions {
    hiddenText?: boolean;
    default?: string;
}
export interface ConfirmationOptions extends BaseDialogOptions {
    acceptMsg?: string;
    rejectMsg?: string;
}
export interface SelectOptions<T> extends BaseDialogOptions {
    values: T[];
    getText?: (obj: T) => string;
    getContext?: (obj: T) => DialogOptionContext;
}
interface TextFormDescriptor extends TextOptions {
    type: 'text';
}
interface ConfirmationFormDescriptor extends ConfirmationOptions {
    type: 'confirmation';
}
interface SelectFormDescriptor<T> extends SelectOptions<T> {
    type: 'select';
}
export declare type DialogOptionContext = 'success' | 'danger';
export declare type Descriptors<T = any> = TextFormDescriptor | ConfirmationFormDescriptor | SelectFormDescriptor<T>;
export declare type DescriptorsMap<T = any> = {
    [K in keyof Partial<T>]: Descriptors<T[K]>;
};
export interface FormOptions<T> extends BaseDialogOptions {
    descriptors: DescriptorsMap<T>;
    order: Array<keyof T>;
}
export declare type DialogResponse<T> = Promise<T | undefined>;
export interface Dialog {
    text: (options: TextOptions) => DialogResponse<string>;
    confirmation: (options: ConfirmationOptions) => DialogResponse<boolean>;
    authenticate: () => DialogResponse<boolean>;
    select: <T>(options: SelectOptions<T>) => DialogResponse<T>;
    form: <T>(options: FormOptions<T>) => DialogResponse<T>;
}
export {};
//# sourceMappingURL=dialog.d.ts.map