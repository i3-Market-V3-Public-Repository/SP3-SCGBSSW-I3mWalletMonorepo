"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wellKnownCvsConfiguration = void 0;
const db_1 = require("./db");
const openApi_1 = require("./openApi");
const server_1 = require("./server");
exports.wellKnownCvsConfiguration = {
    name: server_1.serverConfig.id,
    registration_configuration: {
        public_jwk_endpoint: `${server_1.serverConfig.publicUrl}/api/${openApi_1.apiVersion}/registration/public-jwk`,
        registration_endpoint: `${server_1.serverConfig.publicUrl}/api/${openApi_1.apiVersion}/registration/register/{data}`,
        deregistration_endpoint: `${server_1.serverConfig.publicUrl}/api/${openApi_1.apiVersion}/registration/deregister`
    },
    vault_configuration: {
        v2: {
            id: server_1.serverConfig.id,
            version: 'v2',
            vault_size: db_1.dbConfig.storageByteLength,
            vault_endpoint: `${server_1.serverConfig.publicUrl}/api/v2/vault`,
            events_endpoint: `${server_1.serverConfig.publicUrl}/api/v2/vault/events`,
            timestamp_endpoint: `${server_1.serverConfig.publicUrl}/api/v2/vault/timestamp`,
            token_endpoint: `${server_1.serverConfig.publicUrl}/api/v2/vault/token`,
            token_endpoint_auth_methods_supported: [
                'client_secret_post'
            ],
            key_derivation: {
                master: {
                    alg: 'scrypt',
                    derived_key_length: 32,
                    input: 'password',
                    salt_pattern: 'master' + server_1.serverConfig.id + '{username}',
                    salt_hashing_algorithm: 'sha512',
                    alg_options: {
                        N: 2 ** 19,
                        p: 2,
                        r: 8
                    }
                },
                auth: {
                    alg: 'scrypt',
                    derived_key_length: 32,
                    input: 'master-key',
                    salt_pattern: 'auth' + server_1.serverConfig.id + '{username}',
                    salt_hashing_algorithm: 'sha512',
                    alg_options: {
                        N: 2 ** 16,
                        p: 1,
                        r: 8
                    }
                },
                enc: {
                    alg: 'scrypt',
                    derived_key_length: 32,
                    input: 'master-key',
                    salt_pattern: 'enc' + server_1.serverConfig.id + '{username}',
                    salt_hashing_algorithm: 'sha512',
                    alg_options: {
                        N: 2 ** 16,
                        p: 1,
                        r: 8
                    },
                    enc_algorithm: 'aes-256-gcm'
                }
            }
        }
    }
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2VsbC1rbm93bi1jdnMtY29uZmlndXJhdGlvbi5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jb25maWcvd2VsbC1rbm93bi1jdnMtY29uZmlndXJhdGlvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSw2QkFBK0I7QUFDL0IsdUNBQXNDO0FBQ3RDLHFDQUF1QztBQUUxQixRQUFBLHlCQUF5QixHQUErQztJQUNuRixJQUFJLEVBQUUscUJBQVksQ0FBQyxFQUFFO0lBQ3JCLDBCQUEwQixFQUFFO1FBQzFCLG1CQUFtQixFQUFFLEdBQUcscUJBQVksQ0FBQyxTQUFTLFFBQVEsb0JBQVUsMEJBQTBCO1FBQzFGLHFCQUFxQixFQUFFLEdBQUcscUJBQVksQ0FBQyxTQUFTLFFBQVEsb0JBQVUsK0JBQStCO1FBQ2pHLHVCQUF1QixFQUFFLEdBQUcscUJBQVksQ0FBQyxTQUFTLFFBQVEsb0JBQVUsMEJBQTBCO0tBQy9GO0lBQ0QsbUJBQW1CLEVBQUU7UUFDbkIsRUFBRSxFQUFFO1lBQ0YsRUFBRSxFQUFFLHFCQUFZLENBQUMsRUFBRTtZQUNuQixPQUFPLEVBQUUsSUFBSTtZQUNiLFVBQVUsRUFBRSxhQUFRLENBQUMsaUJBQWlCO1lBQ3RDLGNBQWMsRUFBRSxHQUFHLHFCQUFZLENBQUMsU0FBUyxlQUFlO1lBQ3hELGVBQWUsRUFBRSxHQUFHLHFCQUFZLENBQUMsU0FBUyxzQkFBc0I7WUFDaEUsa0JBQWtCLEVBQUUsR0FBRyxxQkFBWSxDQUFDLFNBQVMseUJBQXlCO1lBQ3RFLGNBQWMsRUFBRSxHQUFHLHFCQUFZLENBQUMsU0FBUyxxQkFBcUI7WUFDOUQscUNBQXFDLEVBQUU7Z0JBQ3JDLG9CQUFvQjthQUNyQjtZQUNELGNBQWMsRUFBRTtnQkFDZCxNQUFNLEVBQUU7b0JBQ04sR0FBRyxFQUFFLFFBQVE7b0JBQ2Isa0JBQWtCLEVBQUUsRUFBRTtvQkFDdEIsS0FBSyxFQUFFLFVBQVU7b0JBQ2pCLFlBQVksRUFBRSxRQUFRLEdBQUcscUJBQVksQ0FBQyxFQUFFLEdBQUcsWUFBWTtvQkFDdkQsc0JBQXNCLEVBQUUsUUFBUTtvQkFDaEMsV0FBVyxFQUFFO3dCQUNYLENBQUMsRUFBRSxDQUFDLElBQUksRUFBRTt3QkFDVixDQUFDLEVBQUUsQ0FBQzt3QkFDSixDQUFDLEVBQUUsQ0FBQztxQkFDTDtpQkFDRjtnQkFDRCxJQUFJLEVBQUU7b0JBQ0osR0FBRyxFQUFFLFFBQVE7b0JBQ2Isa0JBQWtCLEVBQUUsRUFBRTtvQkFDdEIsS0FBSyxFQUFFLFlBQVk7b0JBQ25CLFlBQVksRUFBRSxNQUFNLEdBQUcscUJBQVksQ0FBQyxFQUFFLEdBQUcsWUFBWTtvQkFDckQsc0JBQXNCLEVBQUUsUUFBUTtvQkFDaEMsV0FBVyxFQUFFO3dCQUNYLENBQUMsRUFBRSxDQUFDLElBQUksRUFBRTt3QkFDVixDQUFDLEVBQUUsQ0FBQzt3QkFDSixDQUFDLEVBQUUsQ0FBQztxQkFDTDtpQkFDRjtnQkFDRCxHQUFHLEVBQUU7b0JBQ0gsR0FBRyxFQUFFLFFBQVE7b0JBQ2Isa0JBQWtCLEVBQUUsRUFBRTtvQkFDdEIsS0FBSyxFQUFFLFlBQVk7b0JBQ25CLFlBQVksRUFBRSxLQUFLLEdBQUcscUJBQVksQ0FBQyxFQUFFLEdBQUcsWUFBWTtvQkFDcEQsc0JBQXNCLEVBQUUsUUFBUTtvQkFDaEMsV0FBVyxFQUFFO3dCQUNYLENBQUMsRUFBRSxDQUFDLElBQUksRUFBRTt3QkFDVixDQUFDLEVBQUUsQ0FBQzt3QkFDSixDQUFDLEVBQUUsQ0FBQztxQkFDTDtvQkFDRCxhQUFhLEVBQUUsYUFBYTtpQkFDN0I7YUFDRjtTQUNGO0tBQ0Y7Q0FDRixDQUFBIn0=