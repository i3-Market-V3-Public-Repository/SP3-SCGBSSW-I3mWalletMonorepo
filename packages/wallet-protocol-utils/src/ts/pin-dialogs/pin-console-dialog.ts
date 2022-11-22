import * as readline from 'node:readline/promises'
import { PinConsoleDialogOptions } from '../types'
/**
 * A PIN input dialog for Node.js. The PIN is requested through the terminal/console.
 *
 * @returns a promise that resolves to the PIN
 */
export const pinConsoleDialog = async (options?: PinConsoleDialogOptions): Promise<string> => {
  const query = options?.message ?? 'Introduce the PIN:'
  // Creates a readline interface and retrieves a string.
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  const pin = await rl.question(query)
  console.log(pin)
  rl.close()

  return pin
}
