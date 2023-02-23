import { TransitionGroup, CSSTransition } from 'react-transition-group'
import { ToastData } from '@wallet/lib'

import { Toast } from './toast'

import './toasts.scss'

interface ToastsProps {
  toasts: ToastData[]
}

export function Toasts (props: ToastsProps): JSX.Element {
  const { toasts } = props

  return (
    <TransitionGroup component='div' className='toasts'>
      {toasts.reverse().map((toast, i) => (
        <CSSTransition key={i} classNames='toast-transition' timeout={500}>
          <Toast toast={toast} />
        </CSSTransition>
      ))}
      {/* {transition((style, toast) => toast !== undefined ? (
        <Animated.div style={style}>
        </Animated.div>
      ) : '')} */}
    </TransitionGroup>
  )
}
