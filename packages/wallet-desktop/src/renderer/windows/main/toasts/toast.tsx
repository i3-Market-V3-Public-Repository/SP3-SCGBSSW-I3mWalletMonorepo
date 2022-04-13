import { IconDefinition } from '@fortawesome/fontawesome-svg-core'
import { faTimes, faInfo, faCheck, faExclamation } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'

import { ToastData, ToastType, closeToastAction } from '@wallet/lib'
import { joinClassNames } from '@wallet/renderer/util'
import { useAction } from '@wallet/renderer/communication'

interface ToastProps {
  toast: ToastData
}

const TOAST_ICON_MAP: Map<ToastType, IconDefinition> = new Map([
  ['info', faInfo],
  ['success', faCheck],
  ['warning', faExclamation],
  ['error', faTimes]
])

export function Toast (props: ToastProps): JSX.Element {
  const dispatch = useAction()
  const { toast } = props
  const toastType = toast.type ?? 'info'
  const toastIcon = TOAST_ICON_MAP.get(toastType) ?? faInfo

  const closeToast = (): void => {
    dispatch(closeToastAction.create(toast.id))
  }

  return (
    <div className={joinClassNames('toast', toastType)}>
      <FontAwesomeIcon className='icon type' icon={toastIcon} />
      <div className='toast-content'>
        <span className='message'>{toast.message}</span>
        <span className='details'>{toast.details}</span>
      </div>
      <FontAwesomeIcon
        className='icon close' icon={faTimes}
        onClick={closeToast}
      />
    </div>
  )
}
