import { db } from './Db'

/**
 * Registers a user in the database
 * @param did
 * @param username
 * @param password
 */
export async function registerUser (did: string, username: string, password: string): Promise<void> {
  const query = 'SELECT register_user($1, $2, $3)'
  await db.query(query, [did, username, password])
}

/**
 * Gets user's stored password
 * @param username
 * @returns
 */
export async function getUserPassword (username: string): Promise<string> {
  const query = 'SELECT passwd FROM credentials WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('DB: failed getting password')
  return rows[0].passwd
}

interface Storage {
  timestamp: Date
  storage: string
}
/**
 * Gets the user storage for a specific username
 * @param username
 * @returns A string in Base64 encoding of the storage
 */
export async function getStorage (username: string): Promise<Storage> {
  const query = 'SELECT last_uploaded, storage FROM vault WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('DB: failed getting storage')
  return {
    timestamp: rows[0].last_uploaded,
    storage: rows[0].storage
  }
}

/**
 * Gets when the storage was last uploaded
 * @param username
 * @returns the timestamp in milliseconds since EPOCH
 */
export async function getTimestamp (username: string): Promise<Date> {
  const query = 'SELECT last_uploaded FROM vault WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('DB: failed getting timestamp')
  return rows[0].last_uploaded
}

/**
 * Set storage for username
 * @param username
 * @param storage - the storage in Base64 encoding
 */
export async function setStorage (username: string, storage: string): Promise<void> {
  const query = 'UPDATE vault SET storage=$1 WHERE username=$2'
  await db.query(query, [storage, username])
}

/**
 * Deletes storage for the specified username
 * @param username
 */
export async function deleteStorage (username: string): Promise<void> {
  const query = 'UPDATE vault SET storage = NULL WHERE username=$1'
  await db.query(query, [username])
}
