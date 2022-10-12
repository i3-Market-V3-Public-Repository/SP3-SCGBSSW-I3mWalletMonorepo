/// <reference types="node" />
interface SecretJwk {
    kid: string;
    kty: string;
    k: string;
}
declare const jwkSecret: (secret?: Buffer) => SecretJwk;
export { jwkSecret };
export default jwkSecret;
//# sourceMappingURL=generate-secret.d.ts.map