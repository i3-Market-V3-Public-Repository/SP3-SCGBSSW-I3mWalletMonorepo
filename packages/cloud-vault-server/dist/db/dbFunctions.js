"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteStorageByDid = exports.deleteStorageByUsername = exports.setStorage = exports.getTimestamp = exports.getStorage = exports.verifyCredentials = exports.registerUser = void 0;
const scrypt_mcf_1 = require("scrypt-mcf");
const Db_1 = require("./Db");
/**
 * Registers a user in the database
 * @param did
 * @param username
 * @param password
 */
async function registerUser(did, username, password) {
    const query = 'SELECT register_user($1, $2, $3)';
    await Db_1.db.query(query, [did, username, await (0, scrypt_mcf_1.hash)(password)]);
}
exports.registerUser = registerUser;
/**
 * Verify provided user credentials
 * @param username
 * @param authkey
 * @returns
 */
async function verifyCredentials(username, authkey) {
    const query = 'SELECT authkey FROM credentials WHERE username=$1';
    const { rows } = await Db_1.db.query(query, [username]);
    if (rows.length !== 1)
        return false;
    const mcfString = rows[0].authkey;
    const verified = await (0, scrypt_mcf_1.verify)(authkey, mcfString);
    return verified;
}
exports.verifyCredentials = verifyCredentials;
/**
 * Gets the user storage for a specific username
 * @param username
 * @returns an object with the encrypted storage and the timestamp (milliseconds since epoch) when it was uploaded
 */
async function getStorage(username) {
    const query = 'SELECT last_uploaded, storage FROM vault WHERE username=$1';
    const { rows } = await Db_1.db.query(query, [username]);
    if (rows.length !== 1)
        throw new Error('not-registered');
    if (rows[0].last_uploaded === null) {
        return null;
    }
    const storage = {
        timestamp: Number(rows[0].last_uploaded),
        ciphertext: rows[0].storage
    };
    return storage;
}
exports.getStorage = getStorage;
/**
 * Gets when the storage was last uploaded
 * @param username
 * @returns the timestamp in milliseconds since EPOCH or null if the storage has not yet been uploaded
 */
async function getTimestamp(username) {
    const query = 'SELECT last_uploaded FROM vault WHERE username=$1';
    const { rows, rowCount } = await Db_1.db.query(query, [username]);
    if (rowCount !== 1)
        throw new Error('not-registered');
    return (rows[0].last_uploaded !== null) ? Number(rows[0].last_uploaded) : null;
}
exports.getTimestamp = getTimestamp;
/**
 * Set storage for username
 * @param username
 * @param storage
 * @param timestamp - The timestamp of the last downloaded storage you are uploading changes of. Undefined for the first upload.
 * @returns the timestamp in milliseconds from EPOCH when the storage
 */
async function setStorage(username, storage, timestamp) {
    let query, values;
    if (timestamp !== undefined) {
        query = 'SELECT update_storage($1, $2, $3) AS last_uploaded';
        values = [storage, username, timestamp];
    }
    else {
        query = 'SELECT set_storage($1, $2) AS last_uploaded';
        values = [storage, username];
    }
    const res = await Db_1.db.query(query, values);
    if (res.rows[0].last_uploaded === null) {
        if (timestamp !== undefined) {
            throw new Error('invalid-timestamp'); // it could also be that it is an invalid user, but let us assume that this function is only called for registered users
        }
        else {
            throw new Error('not-registered');
        }
    }
    return Number(res.rows[0].last_uploaded);
}
exports.setStorage = setStorage;
/**
 * Deletes storage (and user) data for the specified username
 * @param username
 */
async function deleteStorageByUsername(username) {
    const query = 'SELECT delete_user($1) AS deleted';
    const res = await Db_1.db.query(query, [username]);
    const deleted = res.rows[0].deleted;
    if (!deleted) {
        throw new Error('not-registered');
    }
}
exports.deleteStorageByUsername = deleteStorageByUsername;
/**
 * Deletes storage (and user) data for the specified username
 * @param username
 */
async function deleteStorageByDid(did) {
    const query = 'SELECT delete_did($1) AS deleted';
    const res = await Db_1.db.query(query, [did]);
    const deleted = res.rows[0].deleted;
    if (!deleted) {
        throw new Error('not-registered');
    }
}
exports.deleteStorageByDid = deleteStorageByDid;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGJGdW5jdGlvbnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvZGIvZGJGdW5jdGlvbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsMkNBQXlDO0FBRXpDLDZCQUF5QjtBQUV6Qjs7Ozs7R0FLRztBQUNJLEtBQUssVUFBVSxZQUFZLENBQUUsR0FBVyxFQUFFLFFBQWdCLEVBQUUsUUFBZ0I7SUFDakYsTUFBTSxLQUFLLEdBQUcsa0NBQWtDLENBQUE7SUFDaEQsTUFBTSxPQUFFLENBQUMsS0FBSyxDQUFDLEtBQUssRUFBRSxDQUFDLEdBQUcsRUFBRSxRQUFRLEVBQUUsTUFBTSxJQUFBLGlCQUFJLEVBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFBO0FBQzlELENBQUM7QUFIRCxvQ0FHQztBQUVEOzs7OztHQUtHO0FBQ0ksS0FBSyxVQUFVLGlCQUFpQixDQUFFLFFBQWdCLEVBQUUsT0FBZTtJQUN4RSxNQUFNLEtBQUssR0FBRyxtREFBbUQsQ0FBQTtJQUNqRSxNQUFNLEVBQUUsSUFBSSxFQUFFLEdBQUcsTUFBTSxPQUFFLENBQUMsS0FBSyxDQUFDLEtBQUssRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUE7SUFDbEQsSUFBSSxJQUFJLENBQUMsTUFBTSxLQUFLLENBQUM7UUFBRSxPQUFPLEtBQUssQ0FBQTtJQUNuQyxNQUFNLFNBQVMsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFBO0lBQ2pDLE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBQSxtQkFBTSxFQUFDLE9BQU8sRUFBRSxTQUFTLENBQUMsQ0FBQTtJQUNqRCxPQUFPLFFBQVEsQ0FBQTtBQUNqQixDQUFDO0FBUEQsOENBT0M7QUFFRDs7OztHQUlHO0FBQ0ksS0FBSyxVQUFVLFVBQVUsQ0FBRSxRQUFnQjtJQUNoRCxNQUFNLEtBQUssR0FBRyw0REFBNEQsQ0FBQTtJQUMxRSxNQUFNLEVBQUUsSUFBSSxFQUFFLEdBQUcsTUFBTSxPQUFF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