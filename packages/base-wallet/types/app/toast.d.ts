export declare type ToastType = 'info' | 'success' | 'warning' | 'error';
export interface ToastOptions {
    message: string;
    type?: ToastType;
    details?: string;
    timeout?: number;
}
export interface Toast {
    show: (toast: ToastOptions) => void;
    close: (toastId: string) => void;
}
//# sourceMappingURL=toast.d.ts.map