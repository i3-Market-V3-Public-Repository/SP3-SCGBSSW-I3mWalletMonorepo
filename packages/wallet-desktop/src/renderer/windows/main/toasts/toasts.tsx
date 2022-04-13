import { ToastData } from '@wallet/lib'

import { Toast } from './toast'

import './toasts.scss'

interface ToastsProps {
  toasts: ToastData[]
}

export function Toasts (props: ToastsProps): JSX.Element {
  const { toasts } = props
  return (
    <div className='toasts'>
      {toasts.map((toast, i) => <Toast key={i} toast={toast} />)}
    </div>
  )
}
