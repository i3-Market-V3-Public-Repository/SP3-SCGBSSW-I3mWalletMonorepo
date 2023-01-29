import type { OpenApiValidatorOpts } from 'express-openapi-validator/dist/openapi.validator';
export declare const apiVersion: string;
export declare const openApi: Omit<OpenApiValidatorOpts, 'apiSpec'> & {
    apiSpec: string;
};
