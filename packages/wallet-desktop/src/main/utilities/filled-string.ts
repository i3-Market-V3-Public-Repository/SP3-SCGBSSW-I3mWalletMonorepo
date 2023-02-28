
export function filledString (...args: Array<string | undefined>): string {
  for (const str of args) {
    if (str !== undefined && str !== '') {
      return str
    }
  }
  throw new Error('No filled string passed...')
}
