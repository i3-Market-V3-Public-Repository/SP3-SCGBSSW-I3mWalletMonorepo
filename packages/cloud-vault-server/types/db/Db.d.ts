import { Pool, QueryArrayConfig, QueryArrayResult, QueryConfig, QueryResult, QueryResultRow } from 'pg';
export declare class Db {
    pool: Pool;
    initialized: Promise<void>;
    constructor();
    private init;
    query<R extends any[] = any[], I extends any[] = any[]>(queryConfig: QueryArrayConfig<I>): Promise<QueryArrayResult<R>>;
    query<R extends QueryResultRow = any, I extends any[] = any[]>(queryTextOrConfig: string | QueryConfig<I>, values?: I): Promise<QueryResult<R>>;
    close(): Promise<void>;
}
export declare const db: Db;
