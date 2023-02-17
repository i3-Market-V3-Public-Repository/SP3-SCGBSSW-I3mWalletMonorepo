import { randomInt } from 'crypto'

export function shuffleArray<T> (arr: T[]): T[] {
  const arr2: T[] = [...arr]
  const ret: T[] = []
  for (let i = 0; i < arr.length; i++) {
    const randomIndex = randomInt(arr.length - i)
    ret.push(arr2[randomIndex])
    arr2.splice(randomIndex, 1)
  }
  return ret
}
