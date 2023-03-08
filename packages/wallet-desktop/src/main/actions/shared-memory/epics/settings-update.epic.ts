import { syncCloudAction } from '@wallet/lib'
import { Epic, filterAction } from '@wallet/main/internal'

export const settingsUpdateEpic: Epic = (action$, locals, next) =>
  action$
    .pipe(filterAction(syncCloudAction))
    .subscribe((action) => {
      console.log(action)
    })
