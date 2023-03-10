import { syncCloudAction } from '@wallet/lib'
import { Epic, filterAction } from '@wallet/main/internal'
import { debounceTime } from 'rxjs/operators'

export const settingsUpdateEpic: Epic = (action$, locals, next) =>
  action$
    .pipe(filterAction(syncCloudAction), debounceTime(2000))
    .subscribe((action) => {
      console.log(action)
    })
