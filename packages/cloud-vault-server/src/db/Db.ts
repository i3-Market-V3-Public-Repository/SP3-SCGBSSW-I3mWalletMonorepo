import { Pool, QueryArrayConfig, QueryArrayResult, QueryConfig, QueryResult, QueryResultRow } from 'pg'
import { dbConfig, general } from '../config'

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
  passwd VARCHAR(100) NOT NULL
);

CREATE TABLE vault (
  username VARCHAR (100) PRIMARY KEY REFERENCES users(username),
  last_uploaded TIMESTAMP WITH TIME ZONE,
  storage VARCHAR (${dbConfig.storageLimit})
);

CREATE FUNCTION fn_update_last_uploaded()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_uploaded = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_vault_last_uploaded
  BEFORE UPDATE ON vault
  FOR EACH ROW
    EXECUTE PROCEDURE fn_update_last_uploaded();

CREATE FUNCTION register_user(did varchar, username varchar, password varchar) RETURNs void AS $$
BEGIN
  INSERT INTO users (did, username) VALUES (did, username);
  INSERT INTO credentials (username, passwd) VALUES (username, password);
  INSERT INTO vault (username) VALUES (username);
END;
$$ language 'plpgsql';

CREATE FUNCTION delete_user(user_name varchar) RETURNs void AS $$
BEGIN
  DELETE FROM vault WHERE username=user_name;
  DELETE FROM credentials WHERE username=user_name;
  DELETE FROM users WHERE username=user_name;
END;
$$ language 'plpgsql';
`

const resetDbQuery = `
DROP TABLE IF EXISTS config CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS vault CASCADE;
DROP FUNCTION IF EXISTS fn_update_last_uploaded CASCADE;
DROP FUNCTION IF EXISTS register_user CASCADE;
DROP FUNCTION IF EXISTS delete_user CASCADE;

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
