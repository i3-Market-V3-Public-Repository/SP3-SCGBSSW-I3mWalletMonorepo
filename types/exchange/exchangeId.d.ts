import { DataExchange } from '../types';
/**
 * Returns the exchangeId of the data exchange. The id is computed hashing an object with
 * all the properties of the data exchange but the id.
 *   id = BASE64URL(SHA256(hashable(dataExchangeButId)))
 * @param exchange - a complete data exchange without an id
 * @returns the exchange id in hexadecimal
 */
export declare function exchangeId(exchange: Omit<DataExchange, 'id'>): Promise<string>;
//# sourceMappingURL=exchangeId.d.ts.map