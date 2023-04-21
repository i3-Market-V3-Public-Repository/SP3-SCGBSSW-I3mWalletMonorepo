"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = exports.Db = void 0;
const pg_1 = require("pg");
const config_1 = require("../config");
const checkDbExistsQuery = 'SELECT version FROM config;';
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
  storage VARCHAR (${config_1.dbConfig.storageCharLength})
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
`;
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

`;
class Db {
    pool;
    initialized;
    constructor() {
        this.pool = new pg_1.Pool({
            host: config_1.dbConfig.host,
            port: config_1.dbConfig.port,
            user: config_1.dbConfig.user,
            password: config_1.dbConfig.password,
            database: config_1.dbConfig.database
        });
        this.initialized = this.init();
    }
    async init() {
        if (config_1.dbConfig.reset) {
            await this.pool.query(resetDbQuery);
        }
        let initialized = false;
        try {
            await this.pool.query(checkDbExistsQuery);
            initialized = true;
        }
        catch (error) { }
        if (!initialized) { // db not initialized
            await this.pool.query(tablesSql);
            await this.pool.query('INSERT INTO config (version) VALUES ($1)', [config_1.general.version]);
        }
    }
    async query(text, values) {
        await this.initialized;
        let start;
        if (config_1.general.nodeEnv === 'development') {
            start = Date.now();
        }
        const res = await this.pool.query(text, values);
        if (config_1.general.nodeEnv === 'development') {
            const duration = Date.now() - start; // eslint-disable-line @typescript-eslint/no-non-null-assertion
            console.log('executed query', { text, duration, rows: res.rowCount });
        }
        return res;
    }
    async close() {
        return await this.pool.end();
    }
}
exports.Db = Db;
exports.db = new Db();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRGIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvZGIvRGIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsMkJBQXVHO0FBQ3ZHLHNDQUE2QztBQUU3QyxNQUFNLGtCQUFrQixHQUFHLDZCQUE2QixDQUFBO0FBRXhELE1BQU0sU0FBUyxHQUFHOzs7Ozs7Ozs7Ozs7Ozs7Ozs7cUJBa0JHLGlCQUFRLENBQUMsaUJBQWlCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Q0FrRTlDLENBQUE7QUFFRCxNQUFNLFlBQVksR0FBRzs7Ozs7Ozs7Ozs7Q0FXcEIsQ0FBQTtBQUVELE1BQWEsRUFBRTtJQUNiLElBQUksQ0FBTTtJQUNWLFdBQVcsQ0FBZTtJQUUxQjtRQUNFLElBQUksQ0FBQyxJQUFJLEdBQUcsSUFBSSxTQUFJLENBQUM7WUFDbkIsSUFBSSxFQUFFLGlCQUFRLENBQUMsSUFBSTtZQUNuQixJQUFJLEVBQUUsaUJBQVEsQ0FBQyxJQUFJO1lBQ25CLElBQUksRUFBRSxpQkFBUSxDQUFDLElBQUk7WUFDbkIsUUFBUSxFQUFFLGlCQUFRLENBQUMsUUFBUTtZQUMzQixRQUFRLEVBQUUsaUJBQVEsQ0FBQyxRQUFRO1NBQzVCLENBQUMsQ0FBQTtRQUNGLElBQUksQ0FBQyxXQUFXLEdBQUcsSUFBSSxDQUFDLElBQUksRUFBRSxDQUFBO0lBQ2hDLENBQUM7SUFFTyxLQUFLLENBQUMsSUFBSTtRQUNoQixJQUFJLGlCQUFRLENBQUMsS0FBSyxFQUFFO1lBQ2xCLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsWUFBWSxDQUFDLENBQUE7U0FDcEM7UUFDRCxJQUFJLFdBQVcsR0FBWSxLQUFLLENBQUE7UUFDaEMsSUFBSTtZQUNGLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsa0JBQWtCLENBQUMsQ0FBQTtZQUN6QyxXQUFXLEdBQUcsSUFBSSxDQUFBO1NBQ25CO1FBQUMsT0FBTyxLQUFLLEVBQUUsR0FBRTtRQUNsQixJQUFJLENBQUMsV0FBVyxFQUFFLEVBQUUscUJBQXFCO1lBQ3ZDLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsU0FBUyxDQUFDLENBQUE7WUFDaEMsTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQywwQ0FBMEMsRUFBRSxDQUFDLGdCQUFPLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQTtTQUNyRjtJQUNILENBQUM7SUFTRCxLQUFLLENBQUMsS0FBSyxDQUEyRCxJQUE2QixFQUFFLE1BQVU7UUFDN0csTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFBO1FBQ3RCLElBQUksS0FBYSxDQUFBO1FBQ2pCLElBQUksZ0JBQU8sQ0FBQyxPQUFPLEtBQUssYUFBYSxFQUFFO1lBQ3JDLEtBQUssR0FBRyxJQUFJLENBQUMsR0FBRyxFQUFFLENBQUE7U0FDbkI7UUFDRCxNQUFNLEdBQUcsR0FBRyxNQUFNLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksRUFBRSxNQUFNLENBQUMsQ0FBQTtRQUMvQyxJQUFJLGdCQUFPLENBQUMsT0FBTyxLQUFLLGFBQWEsRUFBRTtZQUNyQyxNQUFNLFFBQVEsR0FBRyxJQUFJLENBQUMsR0FBRyxFQUFFLEdBQUcsS0FBTSxDQUFBLENBQUMsK0RBQStEO1lBQ3BHLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxHQUFHLENBQUMsUUFBUSxFQUFFLENBQUMsQ0FBQTtTQUN0RTtRQUNELE9BQU8sR0FBRyxDQUFBO0lBQ1osQ0FBQztJQUVELEtBQUssQ0FBQyxLQUFLO1FBQ1QsT0FBTyxNQUFNLElBQUksQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLENBQUE7SUFDOUIsQ0FBQztDQUNGO0FBdERELGdCQXNEQztBQUVZLFFBQUEsRUFBRSxHQUFHLElBQUksRUFBRSxFQUFFLENBQUEifQ==