
export function filterUndefined <T extends object>(obj: T): T {
  const objBackup = { ...obj }
  for (const key of Object.keys(objBackup) as (keyof T)[]) {
    if (objBackup[key] === undefined) {
      delete objBackup[key]
    }
  }

  return objBackup
}

