import type { BlockTag } from '@ethersproject/abstract-provider';
import type { DIDDocument, DIDResolutionOptions, DIDResolutionResult, DIDResolver, ParsedDID, Resolvable } from 'did-resolver';
import type { BigNumber } from 'ethers';
import type { ERC1056Event } from './ethr-did-resolver_DO-NOT-EDIT/helpers';
import { MultipleExecutionsOptions } from '../utils';
import { EthrDidResolver } from './ethr-did-resolver_DO-NOT-EDIT/resolver';
import type { ProviderData } from './veramo';
export interface ConfigurationOptions {
    networks: ProviderData[];
    multiRpcOptions?: MultipleExecutionsOptions;
}
export declare function getResolver(options: ConfigurationOptions): Record<string, DIDResolver>;
export declare class EthrDidMultipleRpcResolver implements Omit<EthrDidResolver, 'contracts'> {
    protected options: ConfigurationOptions;
    resolvers: EthrDidResolver[];
    networks: ProviderData[];
    multiRpcOptions: MultipleExecutionsOptions;
    constructor(options: ConfigurationOptions);
    getOwner(address: string, networkId: string, blockTag?: BlockTag | undefined): Promise<string>;
    previousChange(address: string, networkId: string, blockTag?: BlockTag | undefined): Promise<BigNumber>;
    getBlockMetadata(blockHeight: number, networkId: string): Promise<{
        height: string;
        isoDate: string;
    }>;
    changeLog(identity: string, networkId: string, blockTag?: BlockTag | undefined): Promise<{
        address: string;
        history: ERC1056Event[];
        controllerKey?: string | undefined;
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
    private multiproviderFnExec;
}
//# sourceMappingURL=ethr-did-multiple-rpc-provider.d.ts.map