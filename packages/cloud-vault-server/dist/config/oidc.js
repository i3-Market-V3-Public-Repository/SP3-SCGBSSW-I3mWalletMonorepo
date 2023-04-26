"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.oidcConfig = void 0;
const parseProcessEnvVar_1 = require("./parseProcessEnvVar");
const server_1 = require("./server");
const clientId = (0, parseProcessEnvVar_1.parseProccessEnvVar)('OIDC_CLIENT_ID', 'string');
const clientSecret = (0, parseProcessEnvVar_1.parseProccessEnvVar)('OIDC_CLIENT_SECRET', 'string');
const providerUri = (0, parseProcessEnvVar_1.parseProccessEnvVar)('OIDC_PROVIDER_URI', 'string');
exports.oidcConfig = {
    providerUri,
    client: {
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: [`${server_1.serverConfig.publicUrl}/api/v2/registration/cb`],
        application_type: 'web',
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_jwt',
        id_token_signed_response_alg: 'EdDSA' // One of 'HS256', 'PS256', 'RS256', 'ES256', 'EdDSA'
    }
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb25maWcvb2lkYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSw2REFBMEQ7QUFDMUQscUNBQXVDO0FBT3ZDLE1BQU0sUUFBUSxHQUFHLElBQUEsd0NBQW1CLEVBQUMsZ0JBQWdCLEVBQUUsUUFBUSxDQUFDLENBQUE7QUFDaEUsTUFBTSxZQUFZLEdBQUcsSUFBQSx3Q0FBbUIsRUFBQyxvQkFBb0IsRUFBRSxRQUFRLENBQUMsQ0FBQTtBQUN4RSxNQUFNLFdBQVcsR0FBRyxJQUFBLHdDQUFtQixFQUFDLG1CQUFtQixFQUFFLFFBQVEsQ0FBQyxDQUFBO0FBRXpELFFBQUEsVUFBVSxHQUFlO0lBQ3BDLFdBQVc7SUFDWCxNQUFNLEVBQUU7UUFDTixTQUFTLEVBQUUsUUFBUTtRQUNuQixhQUFhLEVBQUUsWUFBWTtRQUMzQixhQUFhLEVBQUUsQ0FBQyxHQUFHLHFCQUFZLENBQUMsU0FBUyx5QkFBeUIsQ0FBQztRQUNuRSxnQkFBZ0IsRUFBRSxLQUFLO1FBQ3ZCLFdBQVcsRUFBRSxDQUFDLG9CQUFvQixDQUFDO1FBQ25DLGNBQWMsRUFBRSxDQUFDLE1BQU0sQ0FBQztRQUN4QiwwQkFBMEIsRUFBRSxtQkFBbUI7UUFDL0MsNEJBQTRCLEVBQUUsT0FBTyxDQUFDLHFEQUFxRDtLQUM1RjtDQUNGLENBQUEifQ==