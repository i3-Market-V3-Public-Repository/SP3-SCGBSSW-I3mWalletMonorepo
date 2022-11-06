interface Options {
    overlayClass: string;
    modalClass: string;
    titleClass: string;
    messageClass: string;
    inputBoxClass: string;
    inputClass: string;
    buttonClass: string;
}
export declare const openModal: (opts: Partial<Options>) => Promise<string>;
export {};
