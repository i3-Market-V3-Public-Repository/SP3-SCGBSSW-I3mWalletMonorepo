
export function filterUndefined <T extends object> (obj: T): T {
  const objBackup = { ...obj }
  for (const key of Object.keys(objBackup) as Array<keyof T>) {
    if (objBackup[key] === undefined) {
      delete objBackup[key] // eslint-disable-line @typescript-eslint/no-dynamic-delete
    }
  }

  return objBackup
}
