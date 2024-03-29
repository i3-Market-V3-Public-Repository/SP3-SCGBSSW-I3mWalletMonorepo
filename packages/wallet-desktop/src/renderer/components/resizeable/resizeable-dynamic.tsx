import * as React from 'react'

import { usePresistentState } from '@wallet/renderer/hooks'
import { joinClassNames } from '@wallet/renderer/util'

import './resizeable.scss'

type Props = React.PropsWithChildren<{
  stateId: string
  disabled?: boolean
  resizeHeight?: boolean
  resizeWidth?: boolean
}> & React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>

interface Size {
  width: number
  height: number
}

type ResizeHandler = (start: Size, end: Size) => Partial<Size>

export function ResizeableDynamic (props: Props): JSX.Element {
  const { stateId, children, disabled, className, resizeHeight: inResizeHeight, resizeWidth: inResizeWidth, ...extraProps } = props

  const resizeWidth = inResizeWidth ?? false
  const resizeHeight = inResizeHeight ?? false
  const style: React.CSSProperties = {}
  const classNames = [className]

  const [active, setActive] = React.useState(false)
  const [size, setSize] = usePresistentState<Size>(stateId, { width: 400, height: 300 })
  const element = React.useRef<HTMLDivElement>(null)

  if (disabled !== true) {
    if (resizeWidth) {
      style.width = size.width
      classNames.push('horizontal')
    }

    if (resizeHeight) {
      style.height = size.height
      classNames.push('vertical')
    }
  }

  const horizontalHandler: ResizeHandler = (start, end) => ({
    width: end.width - start.width
  })

  const verticalHandler: ResizeHandler = (start, end) => ({
    // height: curr.height - start.pageY + end.pageY
  })

  const vhHandler: ResizeHandler = (start, end) => ({
    // width: curr.width - start.pageX + end.pageX,
    // height: curr.height - start.pageY + end.pageY
  })

  const handlerBuilder = (handler: ResizeHandler): React.MouseEventHandler => {
    return (mouseDownEvent) => {
      function onMouseMove (mouseMoveEvent: MouseEvent): void {
        if (element.current !== null) {
          const start: Size = {
            height: element.current.offsetTop,
            width: element.current.offsetLeft
          }
          const end: Size = {
            height: mouseMoveEvent.pageY,
            width: mouseMoveEvent.pageX
          }

          setSize((state) => {
            return Object.assign({}, state, handler(start, end))
          })
        }
      }
      function onMouseUp (): void {
        setActive(false)
        document.body.removeEventListener('mousemove', onMouseMove)
        // uncomment the following line if not using `{ once: true }`
        // document.body.removeEventListener("mouseup", onMouseUp);
      }

      setActive(true)
      document.body.addEventListener('mousemove', onMouseMove)
      document.body.addEventListener('mouseup', onMouseUp, { once: true })
    }
  }

  return (
    <div className={joinClassNames('resizeable-dynamic', active ? 'active' : undefined, ...classNames)} ref={element} style={style} {...extraProps}>
      {children}
      {resizeWidth ? <span className='draghandle horizontal' onMouseDown={handlerBuilder(horizontalHandler)} /> : null}
      {resizeHeight ? <span className='draghandle vertical' onMouseDown={handlerBuilder(verticalHandler)} /> : null}
      {resizeWidth && resizeHeight ? <span className='draghandle' onMouseDown={handlerBuilder(vhHandler)} /> : null}
    </div>
  )
}
