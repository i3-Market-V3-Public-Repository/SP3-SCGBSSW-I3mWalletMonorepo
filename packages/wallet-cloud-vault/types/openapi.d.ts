export namespace OpenApiComponents {
    export namespace Schemas {
        /**
         * Error
         */
        export interface ApiError {
            name: string;
            description: string;
        }
        /**
         * Jwk
         */
        export interface Jwk {
            publicJwk?: string;
        }
    }
}
export namespace OpenApiPaths {
    export namespace PublicJwk {
        export namespace Get {
            export namespace Responses {
                export type $200 = /* Jwk */ OpenApiComponents.Schemas.Jwk;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
}
