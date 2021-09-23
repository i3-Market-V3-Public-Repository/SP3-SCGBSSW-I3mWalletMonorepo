
export function joinClassNames (...classNames: Array<string | undefined>): string {
  return classNames
    .filter((className) => className !== undefined)
    .join(' ')
}
