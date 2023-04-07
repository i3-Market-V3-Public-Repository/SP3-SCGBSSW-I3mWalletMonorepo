import { hash, verify } from 'scrypt-mcf'
import { OpenApiComponents } from '../../types/openapi.js'
import { db } from './Db.js'

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
 * @param authkey
 * @returns
 */
export async function verifyCredentials (username: string, authkey: string): Promise<boolean> {
  const query = 'SELECT authkey FROM credentials WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) return false
  const mcfString = rows[0].authkey
  const verified = await verify(authkey, mcfString)
  return verified
}

/**
 * Gets the user storage for a specific username
 * @param username
 * @returns an object with the encrypted storage and the timestamp (milliseconds since epoch) when it was uploaded
 */
export async function getStorage (username: string): Promise<Required<OpenApiComponents.Schemas.EncryptedStorage> | null> {
  const query = 'SELECT last_uploaded, storage FROM vault WHERE username=$1'
  const { rows } = await db.query(query, [username])
  if (rows.length !== 1) throw new Error('not-registered')
  if (rows[0].last_uploaded === null) {
    return null
  }
  const storage = {
    timestamp: Number(rows[0].last_uploaded),
    ciphertext: rows[0].storage
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
  const { rows, rowCount } = await db.query(query, [username])
  if (rowCount !== 1) throw new Error('not-registered')
  return (rows[0].last_uploaded !== null) ? Number(rows[0].last_uploaded) : null
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
    query = 'SELECT update_storage($1, $2, $3) AS last_uploaded'
    values = [storage, username, timestamp]
  } else {
    query = 'SELECT set_storage($1, $2) AS last_uploaded'
    values = [storage, username]
  }
  const res = await db.query(query, values)
  if (res.rows[0].last_uploaded === null) {
    if (timestamp !== undefined) {
      throw new Error('invalid-timestamp') // it could also be that it is an invalid user, but let us assume that this function is only called for registered users
    } else {
      throw new Error('not-registered')
    }
  }
  return Number(res.rows[0].last_uploaded)
}

/**
 * Deletes storage (and user) data for the specified username
 * @param username
 */
export async function deleteStorageByUsername (username: string): Promise<void> {
  const query = 'SELECT delete_user($1) AS deleted'
  const res = await db.query(query, [username])
  const deleted = res.rows[0].deleted as boolean
  if (!deleted) {
    throw new Error('not-registered')
  }
}

/**
 * Deletes storage (and user) data for the specified username
 * @param username
 */
export async function deleteStorageByDid (did: string): Promise<void> {
  const query = 'SELECT delete_did($1) AS deleted'
  const res = await db.query(query, [did])
  const deleted = res.rows[0].deleted as boolean
  if (!deleted) {
    throw new Error('not-registered')
  }
}
