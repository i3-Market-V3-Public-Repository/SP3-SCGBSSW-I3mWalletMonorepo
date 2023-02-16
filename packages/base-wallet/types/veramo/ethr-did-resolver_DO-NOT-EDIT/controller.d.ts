import { Signer } from '@ethersproject/abstract-signer';
import { CallOverrides, Contract } from '@ethersproject/contracts';
import { BlockTag, Provider, TransactionReceipt } from '@ethersproject/providers';
import { address } from './helpers';
/**
 * A class that can be used to interact with the ERC1056 contract on behalf of a local controller key-pair
 */
export declare class EthrDidController {
    private contract;
    private signer?;
    private address;
    did: string;
    /**
     * Creates an EthrDidController instance.
     *
     * @param identifier - required - a `did:ethr` string or a publicKeyHex or an ethereum address
     * @param signer - optional - a Signer that represents the current controller key (owner) of the identifier. If a 'signer' is not provided, then a 'contract' with an attached signer can be used.
     * @param contract - optional - a Contract instance representing a ERC1056 contract. At least one of `contract`, `provider`, or `rpcUrl` is required
     * @param chainNameOrId - optional - the network name or chainID, defaults to 'mainnet'
     * @param provider - optional - a web3 Provider. At least one of `contract`, `provider`, or `rpcUrl` is required
     * @param rpcUrl - optional - a JSON-RPC URL that can be used to connect to an ethereum network. At least one of `contract`, `provider`, or `rpcUrl` is required
     * @param registry - optional - The ERC1056 registry address. Defaults to '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'. Only used with 'provider' or 'rpcUrl'
     */
    constructor(identifier: string | address, contract?: Contract, signer?: Signer, chainNameOrId?: string, provider?: Provider, rpcUrl?: string, registry?: string);
    getOwner(address: address, blockTag?: BlockTag): Promise<string>;
    attachContract(controller?: address | Promise<address>): Promise<Contract>;
    changeOwner(newOwner: address, options?: CallOverrides): Promise<TransactionReceipt>;
    addDelegate(delegateType: string, delegateAddress: address, exp: number, options?: CallOverrides): Promise<TransactionReceipt>;
    revokeDelegate(delegateType: string, delegateAddress: address, options?: CallOverrides): Promise<TransactionReceipt>;
    setAttribute(attrName: string, attrValue: string, exp: number, options?: CallOverrides): Promise<TransactionReceipt>;
    revokeAttribute(attrName: string, attrValue: string, options?: CallOverrides): Promise<TransactionReceipt>;
}
//# sourceMappingURL=controller.d.ts.map