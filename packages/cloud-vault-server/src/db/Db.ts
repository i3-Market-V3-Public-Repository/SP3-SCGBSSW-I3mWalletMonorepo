import { Pool, QueryArrayConfig, QueryArrayResult, QueryConfig, QueryResult, QueryResultRow } from 'pg'
import { dbConfig, general } from '../config/index.js'

const checkDbExistsQuery = 'SELECT version FROM config;'

const tablesSql = `
CREATE TABLE config (
  version VARCHAR(11)
);

CREATE TABLE users (
  did VARCHAR(100) PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE credentials (
  username VARCHAR(100) PRIMARY KEY REFERENCES users(username),
  authkey VARCHAR(100) NOT NULL
);

CREATE TABLE vault (
  username VARCHAR (100) PRIMARY KEY REFERENCES users(username),
  last_uploaded BIGINT, -- milliseconds elapsed from EPOCH
  storage VARCHAR (${dbConfig.storageCharLength})
);

CREATE FUNCTION set_storage(arg_storage VARCHAR, arg_username VARCHAR) RETURNS BIGINT AS $$
  UPDATE vault
  SET storage=arg_storage,
      last_uploaded=TRUNC(1000*EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))
  WHERE username=arg_username AND last_uploaded IS NULL
  RETURNING last_uploaded
$$ LANGUAGE SQL;

CREATE FUNCTION update_storage(arg_storage VARCHAR, arg_username VARCHAR, arg_timestamp BIGINT) RETURNS BIGINT AS $$
  UPDATE vault
  SET storage=arg_storage,
      last_uploaded=TRUNC(1000*EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))
  WHERE username=arg_username
    AND last_uploaded=arg_timestamp
  RETURNING last_uploaded
$$ LANGUAGE SQL;

CREATE FUNCTION register_user(arg_did varchar, arg_username varchar, arg_authkey varchar) RETURNS boolean AS $$
  WITH u AS (
    INSERT INTO users (did, username) VALUES (arg_did, arg_username) RETURNING username
  ),
  c AS (
    INSERT INTO credentials (username, authkey) VALUES (arg_username, arg_authkey) RETURNING username
  ),
  v AS (
    INSERT INTO vault (username) VALUES (arg_username) RETURNING username
  ),
  f AS (
    SELECT count(*) FROM v
    UNION ALL
    SELECT count(*) FROM c
    UNION ALL
    SELECT count(*) FROM u
  )
  SELECT SUM(count) = 3 AS deleted FROM f
$$ LANGUAGE SQL;

CREATE FUNCTION delete_user(arg_username varchar) RETURNS boolean AS $$
  WITH v AS (
    DELETE FROM vault WHERE username=arg_username RETURNING username
  ),
  c AS (
    DELETE FROM credentials WHERE username=arg_username RETURNING username
  ),
  u AS (
    DELETE FROM users WHERE username=arg_username RETURNING username
  ),
  f AS (
    SELECT count(*) FROM v
    UNION ALL
    SELECT count(*) FROM c
    UNION ALL
    SELECT count(*) FROM u
  )
  SELECT SUM(count) = 3 AS deleted FROM f
$$ LANGUAGE SQL;

CREATE FUNCTION delete_did(arg_did varchar) RETURNS boolean AS $$
  WITH u AS (
    SELECT username FROM users WHERE did=arg_did
  )
  SELECT delete_user(username) FROM u
$$ LANGUAGE SQL;
`

const resetDbQuery = `
DROP TABLE IF EXISTS config CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS vault CASCADE;
DROP FUNCTION IF EXISTS set_storage CASCADE;
DROP FUNCTION IF EXISTS update_storage CASCADE;
DROP FUNCTION IF EXISTS register_user CASCADE;
DROP FUNCTION IF EXISTS delete_user CASCADE;
DROP FUNCTION IF EXISTS delete_did CASCADE;

`

export class Db {
  pool: Pool
  initialized: Promise<void>

  constructor () {
    this.pool = new Pool({
      host: dbConfig.host,
      port: dbConfig.port,
      user: dbConfig.user,
      password: dbConfig.password,
      database: dbConfig.database
    })
    this.initialized = this.init()
  }

  private async init (): Promise<void> {
    if (dbConfig.reset) {
      await this.pool.query(resetDbQuery)
    }
    let initialized: boolean = false
    try {
      await this.pool.query(checkDbExistsQuery)
      initialized = true
    } catch (error) {}
    if (!initialized) { // db not initialized
      await this.pool.query(tablesSql)
      await this.pool.query('INSERT INTO config (version) VALUES ($1)', [general.version])
    }
  }

  async query<R extends any[] = any[], I extends any[] = any[]>(
    queryConfig: QueryArrayConfig<I>
  ): Promise<QueryArrayResult<R>>
  async query<R extends QueryResultRow = any, I extends any[] = any[]>(
    queryTextOrConfig: string | QueryConfig<I>,
    values?: I,
  ): Promise<QueryResult<R>>
  async query<R extends QueryResultRow = any, I extends any[] = any[]> (text: string | QueryConfig<I>, values?: I): Promise<QueryResult<R>> {
    await this.initialized
    let start: number
    if (general.nodeEnv === 'development') {
      start = Date.now()
    }
    const res = await this.pool.query(text, values)
    if (general.nodeEnv === 'development') {
      const duration = Date.now() - start! // eslint-disable-line @typescript-eslint/no-non-null-assertion
      console.log('executed query', { text, duration, rows: res.rowCount })
    }
    return res
  }

  async close (): Promise<void> {
    return await this.pool.end()
  }
}

export const db = new Db()
