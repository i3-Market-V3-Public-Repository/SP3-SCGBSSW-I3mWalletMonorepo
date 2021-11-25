
declare module 'base58-js' {
  export function base58_to_binary (base58String: string): Uint8Array
  export function binary_to_base58 (array: Uint8Array): string
}
