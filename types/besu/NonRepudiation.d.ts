declare const _default: {
    address: string;
    abi: ({
        anonymous: boolean;
        inputs: {
            indexed: boolean;
            internalType: string;
            name: string;
            type: string;
        }[];
        name: string;
        type: string;
        outputs?: undefined;
        stateMutability?: undefined;
    } | {
        inputs: {
            internalType: string;
            name: string;
            type: string;
        }[];
        name: string;
        outputs: {
            internalType: string;
            name: string;
            type: string;
        }[];
        stateMutability: string;
        type: string;
        anonymous?: undefined;
    })[];
    transactionHash: string;
    receipt: {
        to: null;
        from: string;
        contractAddress: string;
        transactionIndex: number;
        gasUsed: string;
        logsBloom: string;
        blockHash: string;
        transactionHash: string;
        logs: never[];
        blockNumber: number;
        cumulativeGasUsed: string;
        status: number;
        byzantium: boolean;
    };
    args: never[];
    solcInputHash: string;
    metadata: string;
    bytecode: string;
    deployedBytecode: string;
    devdoc: {
        kind: string;
        methods: {};
        version: number;
    };
    userdoc: {
        kind: string;
        methods: {};
        version: number;
    };
    storageLayout: {
        storage: {
            astId: number;
            contract: string;
            label: string;
            offset: number;
            slot: string;
            type: string;
        }[];
        types: {
            t_address: {
                encoding: string;
                label: string;
                numberOfBytes: string;
            };
            't_mapping(t_address,t_mapping(t_uint256,t_uint256))': {
                encoding: string;
                key: string;
                label: string;
                numberOfBytes: string;
                value: string;
            };
            't_mapping(t_uint256,t_uint256)': {
                encoding: string;
                key: string;
                label: string;
                numberOfBytes: string;
                value: string;
            };
            t_uint256: {
                encoding: string;
                label: string;
                numberOfBytes: string;
            };
        };
    };
};
export default _default;
//# sourceMappingURL=NonRepudiation.d.ts.map