import { OpenApiComponents } from '../../types/openapi';
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
 * @param authkey
 * @returns
 */
export declare function verifyCredentials(username: string, authkey: string): Promise<boolean>;
/**
 * Gets the user storage for a specific username
 * @param username
 * @returns an object with the encrypted storage and the timestamp (milliseconds since epoch) when it was uploaded
 */
export declare function getStorage(username: string): Promise<Required<OpenApiComponents.Schemas.EncryptedStorage> | null>;
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
export declare function deleteStorage(username: string): Promise<boolean>;
