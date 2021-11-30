import types from 'jose';
export interface DataExchange {
    id: number;
    orig?: string;
    dest?: string;
    block_id?: number;
    block_desc?: string;
    hash_alg: string;
    cipherblock_dgst: string;
    block_commitment: string;
    key_commitment: string;
}
export interface PoO {
    iss: string;
    sub: string;
    iat: number;
    exchange: {
        id: number;
        orig: string;
        dest: string;
        block_id: number;
        block_desc: string;
        hash_alg: string;
        cipherblock_dgst: string;
        block_commitment: string;
        key_commitment: string;
    };
}
export interface PoR {
    iss: string;
    sub: string;
    iat: number;
    exchange: {
        poo_dgst: string;
        hash_alg: string;
        exchangeId: number;
    };
}
export interface account {
    privateStorage: {
        availability: string;
        permissions: {
            view: string[];
        };
        type: string;
        id: number;
        content: {
            [block_id: number]: {
                poO: string;
                poR: string;
            };
        };
    };
    blockchain: {
        availability: string;
        type: string;
        content: {
            [kid: string]: types.JWK;
        };
    };
}
//# sourceMappingURL=proofInterfaces.d.ts.map