import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

import './list-selector.scss'

interface Props<T> {
  selected: T | undefined
  items: T[]
  getText?: (item: T) => string
  onSelect?: (item: T) => void
}

export function ListSelector<T = string> (props: Props<T>): JSX.Element {
  const { items, selected } = props

  const [cursorIndex, setCursorIndex] = React.useState<number>(0)
  const listRef = React.useRef<HTMLDivElement>(null)
  const cursorRef = React.useRef<HTMLDivElement>(null)

  const onSelect = props.onSelect ?? (() => {})
  const getText = props.getText ?? ((i: T) => i as any)

  if (selected !== undefined && cursorIndex === undefined) {
    for (let i = 0; i < items.length; i++) {
      if (selected === items[i]) {
        setCursorIndex(i)
        break
      }
    }
  }

  const selectCursor = (): void => {
    if (cursorIndex !== undefined) {
      onSelect(items[cursorIndex])
    }
  }

  const fixScroll = (): void => {
    if (listRef.current === null || cursorRef.current === null) {
      return
    }
    const list = listRef.current
    const cursor = cursorRef.current
    const normalizedCursorTop = cursor.offsetTop - list.offsetTop - list.scrollTop

    if (normalizedCursorTop < 0) {
      list.scrollTop = cursor.offsetTop - list.offsetTop
    } else if (normalizedCursorTop + cursor.offsetHeight > list.offsetHeight) {
      list.scrollTop = cursor.offsetTop - list.offsetTop + cursor.offsetHeight - list.offsetHeight
    }
  }

  const keyDown: React.KeyboardEventHandler = (ev) => {
    switch (ev.key) {
      case 'ArrowUp':
        ev.preventDefault()
        if (cursorIndex !== undefined && cursorIndex > 0) {
          setCursorIndex(cursorIndex - 1)
        }
        break

      case 'ArrowDown':
        ev.preventDefault()
        if (cursorIndex !== undefined && cursorIndex < items.length - 1) {
          setCursorIndex(cursorIndex + 1)
        }
        break

      case 'Enter':
        selectCursor()
        break
    }
  }

  const selectItem = (index: number, item: T): void => {
    setCursorIndex(index)
    onSelect(item)
  }

  React.useLayoutEffect(fixScroll)
  return (
    <div
      tabIndex={0} className={joinClassNames('list-selector')}
      onKeyDown={keyDown} ref={listRef}
    >
      {items.map((item, i) => {
        const extraParams: React.DetailedHTMLProps<React.HTMLAttributes<HTMLSpanElement>, HTMLSpanElement> = {}
        const isSelected = item === selected
        const hasCursor = i === cursorIndex

        if (hasCursor) {
          extraParams.ref = cursorRef
        }

        return (
          <span
            className={joinClassNames(
              'list-selector-item',
              isSelected ? 'selected' : undefined,
              hasCursor ? 'cursor' : undefined
            )}
            onClick={() => selectItem(i, item)} key={i}
            {...extraParams}
          >
            {getText(item)}
          </span>
        )
      })}
    </div>
  )
}
