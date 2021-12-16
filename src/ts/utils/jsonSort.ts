function isObject (v: any): boolean {
  return Object.prototype.toString.call(v) === '[object Object]'
}

export function jsonSort (obj: any): any {
  if (Array.isArray(obj)) {
    return obj.sort().map(jsonSort) // eslint-disable-line
  } else if (isObject(obj)) {
    return Object
      .keys(obj)
      .sort()
      .reduce(function (a: any, k) {
        a[k] = jsonSort(obj[k])
        return a
      }, {})
  }

  return obj
}
