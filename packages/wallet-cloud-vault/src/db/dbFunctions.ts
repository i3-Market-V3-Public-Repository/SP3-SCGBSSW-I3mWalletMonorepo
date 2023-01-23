import { db } from './Db'
import { hash, verify } from 'scrypt-mcf'

/**
 * Registers a user in the database
 * @param did
 * @param username
 * @param password
 */
export async function registerUser (did: string, username: string, password: string): Promise<void> {
  const query = 'SELECT register_user($1, $2, $3)'
  await db.query(query, [did, username, await hash(password)])
}

/**
 * Verify provided user credentials
 * @param username
 * @param password
 * @returns
 */
export async function verifyCredentials (username: string, password: string): Promise<boolean> {
  const query = 'SELECT passwd FROM credentials WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('Invalid username or password')
  const mcfString = rows[0].passwd
  const verified = await verify(password, mcfString)
  return verified
}

interface Storage {
  timestamp: number
  storage: string
}
/**
 * Gets the user storage for a specific username
 * @param username
 * @returns A string in Base64 encoding of the storage
 */
export async function getStorage (username: string): Promise<Storage | null> {
  const query = 'SELECT last_uploaded, storage FROM vault WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('DB: failed getting storage')
  if (rows[0].last_uploaded === null) {
    return null
  }
  const storage: Storage = {
    timestamp: (rows[0].last_uploaded as Date).valueOf(),
    storage: rows[0].storage
  }
  return storage
}

/**
 * Gets when the storage was last uploaded
 * @param username
 * @returns the timestamp in milliseconds since EPOCH or null if the storage has not yet been uploaded
 */
export async function getTimestamp (username: string): Promise<number | null> {
  const query = 'SELECT last_uploaded FROM vault WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('failed getting timestamp')
  return (rows[0].last_uploaded !== null) ? (rows[0].last_uploaded as Date).valueOf() : null
}

/**
 * Set storage for username
 * @param username
 * @param storage
 * @param timestamp - The timestamp of the last downloaded storage you are uploading changes of. Undefined for the first upload.
 * @returns the timestamp in milliseconds from EPOCH when the storage
 */
export async function setStorage (username: string, storage: string, timestamp?: number): Promise<number> {
  let query: string, values: any[]
  if (timestamp !== undefined) {
    query = 'UPDATE vault SET storage=$1 WHERE username=$2 AND TRUNC(1000*EXTRACT(EPOCH FROM last_uploaded))=$3::numeric RETURNING last_uploaded'
    values = [storage, username, timestamp]
  } else {
    query = 'UPDATE vault SET storage=$1 WHERE username=$2 AND last_uploaded IS NULL RETURNING last_uploaded'
    values = [storage, username]
  }
  const res = await db.query(query, values)
  if (res.rowCount !== 1) throw new Error('failed updating storage')
  return (res.rows[0].last_uploaded as Date).valueOf()
}

/**
 * Deletes storage for the specified username
 * @param username
 */
export async function deleteStorage (username: string): Promise<void> {
  const query = 'UPDATE vault SET storage=NULL WHERE username=$1'
  await db.query(query, [username])
}
