interface MyObject {
  [key: string]: any
}

export function getUndefinedKeys (obj: MyObject): string[] {
  const keys: string[] = []
  for (const key in obj) {
    if (typeof obj[key] === 'undefined') {
      keys.push(key)
    } else if (Array.isArray(obj[key])) {
      obj[key].forEach((el: any, index: number) => {
        const subKey = `${key}[${index}]`
        keys.push(...getUndefinedKeys(el).map(subSubKey => `${subKey}.${subSubKey}`))
      })
    } else if (typeof obj[key] === 'object') {
      keys.push(...getUndefinedKeys(obj[key]).map(subKey => `${key}.${subKey}`))
    }
  }
  return keys
}
