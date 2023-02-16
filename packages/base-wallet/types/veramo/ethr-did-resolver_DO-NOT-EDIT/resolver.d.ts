import { BigNumber } from '@ethersproject/bignumber';
import { BlockTag } from '@ethersproject/providers';
import { ConfigurationOptions } from './configuration';
import { DIDDocument, DIDResolutionOptions, DIDResolutionResult, DIDResolver, ParsedDID, Resolvable } from 'did-resolver';
import { ERC1056Event } from './helpers';
export declare function getResolver(options: ConfigurationOptions): Record<string, DIDResolver>;
export declare class EthrDidResolver {
    private contracts;
    constructor(options: ConfigurationOptions);
    /**
     * returns the current owner of a DID (represented by an address or public key)
     *
     * @param address
     */
    getOwner(address: string, networkId: string, blockTag?: BlockTag): Promise<string>;
    /**
     * returns the previous change
     *
     * @param address
     */
    previousChange(address: string, networkId: string, blockTag?: BlockTag): Promise<BigNumber>;
    getBlockMetadata(blockHeight: number, networkId: string): Promise<{
        height: string;
        isoDate: string;
    }>;
    changeLog(identity: string, networkId: string, blockTag?: BlockTag): Promise<{
        address: string;
        history: ERC1056Event[];
        controllerKey?: string;
        chainId: number;
    }>;
    wrapDidDocument(did: string, address: string, controllerKey: string | undefined, history: ERC1056Event[], chainId: number, blockHeight: string | number, now: BigNumber): {
        didDocument: DIDDocument;
        deactivated: boolean;
        versionId: number;
        nextVersionId: number;
    };
    resolve(did: string, parsed: ParsedDID, _unused: Resolvable, options: DIDResolutionOptions): Promise<DIDResolutionResult>;
    build(): Record<string, DIDResolver>;
}
//# sourceMappingURL=resolver.d.ts.map