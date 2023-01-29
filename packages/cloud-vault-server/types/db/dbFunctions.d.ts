/**
 * Registers a user in the database
 * @param did
 * @param username
 * @param password
 */
export declare function registerUser(did: string, username: string, password: string): Promise<void>;
/**
 * Verify provided user credentials
 * @param username
 * @param password
 * @returns
 */
export declare function verifyCredentials(username: string, password: string): Promise<boolean>;
interface Storage {
    timestamp: number;
    storage: string;
}
/**
 * Gets the user storage for a specific username
 * @param username
 * @returns A string in Base64 encoding of the storage
 */
export declare function getStorage(username: string): Promise<Storage | null>;
/**
 * Gets when the storage was last uploaded
 * @param username
 * @returns the timestamp in milliseconds since EPOCH or null if the storage has not yet been uploaded
 */
export declare function getTimestamp(username: string): Promise<number | null>;
/**
 * Set storage for username
 * @param username
 * @param storage
 * @param timestamp - The timestamp of the last downloaded storage you are uploading changes of. Undefined for the first upload.
 * @returns the timestamp in milliseconds from EPOCH when the storage
 */
export declare function setStorage(username: string, storage: string, timestamp?: number): Promise<number>;
/**
 * Deletes storage (and user) data for the specified username
 * @param username
 */
export declare function deleteStorage(username: string): Promise<void>;
export {};
