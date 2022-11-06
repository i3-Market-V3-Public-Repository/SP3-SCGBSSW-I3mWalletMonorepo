"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const base_wallet_1 = require("@i3m/base-wallet");
const debug_1 = __importDefault(require("debug"));
const __1 = __importDefault(require(".."));
const debug = (0, debug_1.default)('i3-market:sw-wallet:test');
describe('@i3m/sw-wallet', () => {
    const dialog = new base_wallet_1.TestDialog();
    const store = new base_wallet_1.TestStore();
    const toast = new base_wallet_1.TestToast();
    let wallet;
    let veramo;
    const identities = {};
    beforeAll(async () => {
        // Build the wallet using a valid mnemonic
        await dialog.setValues({
            text: 'zebra jelly kick pattern depth foam enter alone quote seed alpha road ripple enable wheel'
        }, async () => {
            wallet = await (0, __1.default)({ dialog, store, toast });
            veramo = wallet.veramo; // TODO: Hacky access to veramo. Maybe expose it?
        });
    });
    describe('identities', () => {
        it.each([
            ['alice'],
            ['bob']
        ])('should create identities', async (alias) => {
            const resp = await wallet.identityCreate({
                alias
            });
            expect(resp.did).toBeDefined();
            identities[alias] = resp.did;
            debug(`DID for '${alias}' created: `, resp.did);
        });
        it('should list identities', async () => {
            const ddos = await wallet.identityList({});
            debug('List of DIDs: ', ddos);
            expect(ddos.length).toBe(2);
        });
    });
    describe('resources', () => {
        let credential;
        beforeAll(async () => {
            credential = await veramo.agent.createVerifiableCredential({
                credential: {
                    issuer: { id: identities.bob },
                    credentialSubject: {
                        id: identities.alice,
                        consumer: true
                    }
                },
                proofFormat: 'jwt',
                save: false
            });
        });
        it('should store verifiable credentials', async () => {
            const resource = await wallet.resourceCreate({
                type: 'VerifiableCredential',
                resource: credential
            });
            debug('Resource with id: ', resource.id);
            expect(resource.id).toBeDefined();
        });
        it('should list created resources', async () => {
            const resources = await wallet.resourceList({
                type: 'VerifiableCredential',
                identity: identities.alice
            });
            expect(resources.length).toBe(1);
        });
    });
    describe('selectiveDisclosure', () => {
        let sdrRespJwt;
        let sdr;
        beforeAll(async () => {
            // Generate a sdr generated on the fly
            sdr = await veramo.agent.createSelectiveDisclosureRequest({
                data: {
                    issuer: identities.bob,
                    claims: [{
                            claimType: 'consumer'
                        }]
                }
            });
        });
        it('should resolve selective disclosure requests', async () => {
            await dialog.setValues({
                // Select dispacth claim with the last identity
                // The first one is cancel
                selectMap(values) {
                    return values[values.length - 1];
                }
            }, async () => {
                const sdrResp = await wallet.selectiveDisclosure({ jwt: sdr });
                sdrRespJwt = sdrResp.jwt;
                expect(sdrRespJwt).toBeDefined();
                debug('Selective Disclosure Response:', sdrResp);
            });
        }, 10000);
        it('should respond with a proper signature', async () => {
            await veramo.agent.handleMessage({
                raw: sdrRespJwt
            });
        });
    });
});
//# sourceMappingURL=sw-wallet.spec.js.map