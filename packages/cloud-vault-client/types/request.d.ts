interface Options {
    bearerToken?: string;
    responseStatus?: number;
}
declare function get<T>(url: string, options?: Options): Promise<T>;
declare function delet<T>(url: string, options?: Options): Promise<T>;
declare function post<T>(url: string, requestBody: any, options?: Options): Promise<T>;
declare function put<T>(url: string, requestBody: any, options?: Options): Promise<T>;
declare const _default: {
    get: typeof get;
    post: typeof post;
    put: typeof put;
    delete: typeof delet;
};
export default _default;
//# sourceMappingURL=request.d.ts.map