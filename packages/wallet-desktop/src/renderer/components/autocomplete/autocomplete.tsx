import * as React from 'react'
import { Form, FormControlProps } from 'react-bootstrap'

// import { joinClassNames } from '@wallet/renderer/util'

import './autocomplete.scss'

export type AnyElement = React.DetailedHTMLProps<React.HTMLAttributes<any>, any>
export type ItemRenderer<T> = (label: string, option: T) => JSX.Element
interface AutocompleteProps<T> {
  id?: string
  placeholder?: string
  onChange?: (label: string) => void
  value: string

  renderItem?: ItemRenderer<T>

  options: T[]
  getLabel: (value: T) => string
}

type Props<T> = AutocompleteProps<T>

function escapeRegExp (str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') // $& means the whole matched string
}

export function Autocomplete<T> (props: Props<T>): JSX.Element {
  const { onChange, options, getLabel, renderItem, value, ...inputProps } = props

  let disableBlur = false
  const propOnChange = onChange ?? (() => {})
  const parsedText = value
    // Remove initial and final spaces
    .trim()
    // Split the string in characters
    .split('')
    // Espace each regex character
    .map(escapeRegExp)
    // Join all the characters again.
    // We want to create regex groups for each character that the user typed.
    // Then we use the matches of the selected options to highligth the matched
    // letters.
    .join(')(.*?)(')
  const regex = new RegExp(`^(.*?)(${parsedText})(.*?)$`, 'gi')

  const defaultRenderItem: ItemRenderer<any> = (label) => {
    return (
      <span
        dangerouslySetInnerHTML={{
          __html: label.replace(regex, (str, ...args: string[]) => {
            args.pop() // discard all text
            args.pop() // discard first match index

            const text = args.map((v, i) => i % 2 === 0 ? v : `<b>${v}</b>`).join('')
            return text
          })
        }}
      />
    )
  }
  const propRenderItem = renderItem ?? defaultRenderItem

  const suggestions = options.filter((v) => getLabel(v).match(regex))
  const [visible, setVisible] = React.useState(false)
  const inputRef = React.useRef<HTMLInputElement | null>(null)

  const changeValue = (label: string): void => {
    propOnChange(label)
  }

  const onInputChange: FormControlProps['onChange'] = (ev) => {
    changeValue(ev.target.value)
  }

  const onBlur: FormControlProps['onBlur'] = (ev) => {
    if (!disableBlur) {
      setVisible(false)
    }
  }

  const onFocus: FormControlProps['onFocus'] = (ev) => {
    setVisible(true)
  }

  const renderMenu = (): JSX.Element | null => {
    if (!visible) {
      return null
    }

    if (suggestions.length > 0) {
      const items = suggestions.map((option, i) => {
        const label = getLabel(option)
        const item = propRenderItem(label, option)
        return React.cloneElement<AnyElement>(item, {
          key: i,
          onMouseDown (ev) {
            disableBlur = true
          },
          onMouseLeave (ev) {
            disableBlur = false
            inputRef.current?.focus()
          },
          onMouseUp (ev) {
            disableBlur = false
            inputRef.current?.focus()
          },
          onClick () {
            changeValue(label)
          }
        })
      })
      return (
        <div className='suggestions'>
          {items}
        </div>
      )
    }

    return <div className='no-suggestions' />
  }

  return (
    <div className='autocomplete'>
      <Form.Control ref={inputRef} {...inputProps} type='text' size='sm' onFocus={onFocus} onBlur={onBlur} onChange={onInputChange} value={value} />
      {renderMenu()}
    </div>
  )
}
