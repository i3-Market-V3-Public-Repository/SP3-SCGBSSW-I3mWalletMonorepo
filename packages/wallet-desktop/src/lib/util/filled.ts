
export function filled (text?: string): text is string {
  return text !== undefined && text !== ''
}

export function firstFilled (...texts: Array<string | undefined>): string {
  for (const text of texts) {
    if (filled(text)) return text
  }

  throw new Error('Unfilled text!')
}
