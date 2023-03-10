
export function getVersionDate (timestamp?: number): string | 'never' {
  if (timestamp === undefined) {
    return 'never'
  }
  return new Date(timestamp).toString()
}
