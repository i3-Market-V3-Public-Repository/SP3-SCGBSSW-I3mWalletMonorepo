import { faChevronLeft, faChevronRight } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { joinClassNames } from '@wallet/renderer/util'
import { useFocus } from '@wallet/renderer/hooks'
import { DialogOption as MessageDialogOption, DialogData } from '@wallet/lib'

import './dialog.scss'

export type DialogOption<T> = MessageDialogOption<T>

export type DialogClose<T> = (option: DialogOption<T> | undefined) => void

export type DialogProps = React.PropsWithChildren<DialogData & {
  onClose?: DialogClose<DialogProps['response']>
}>

interface FormIndicatorProps {
  order: any[]
  tabIndex: number
  formValues: Array<DialogOption<any> | undefined>
}

function FormIndicator (props: FormIndicatorProps): JSX.Element {
  const { order, tabIndex } = props

  return (
    <div className='form-indicator'>
      {/* {order.map((key, i) => (
        <div className={joinClassNames('form-item', tabIndex === i ? 'selected' : undefined)} key={i}>
          <span className='form-key'>{key}</span>
          {(() => {
            if (tabIndex === i) {
              return null
            }

            const formValue = formValues[i]
            if (formValue !== undefined) {
              return <span className='form-value'>: {formValue.text}</span>
            }
            return null
          })()}
        </div>
      ))} */}
      Step {tabIndex + 1} of {order.length}
    </div>
  )
}

export function Dialog (props: DialogProps): JSX.Element {
  // Setup state
  const [text, setText] = React.useState('')
  const [highlight, setHighlight] = React.useState(false)
  const [selectedOption, setSelectedOption] = React.useState(0)
  const [tabIndex, setTabIndex] = React.useState(0)
  const [formValues, setFormValues] = React.useState<Array<DialogOption<any> | undefined>>([])

  // Setup extra hooks
  const [inputRef, focusInput] = useFocus<HTMLInputElement>()
  const [dialogRef, focusDialog] = useFocus<HTMLDivElement>()

  // Focus dialog on render
  React.useLayoutEffect(focusDialog)

  // Setup options
  const title = props.title
  const allowCancel = props.allowCancel ?? true
  const onClose = props.onClose ?? (() => {})
  const regex = new RegExp(`^(.*?)(${text.trim().split('').join(')(.*?)(')})(.*?)$`, 'gi')

  let message = props.message
  let options: Array<DialogOption<{}>> = []
  let hiddenText = false
  let dialogData: DialogData
  let maxTabIndex = 0
  let order: any[] = []

  if (props.type === 'form') {
    maxTabIndex = props.order.length
    if (tabIndex > maxTabIndex) {
      setTabIndex(maxTabIndex)
      return <div />
    }
    order = props.order

    const currentProps = props.order[tabIndex]
    dialogData = props.descriptors[currentProps as string]

    if (dialogData.message !== undefined) {
      if (message !== undefined) {
        message += `\n${dialogData.message}`
      } else {
        message = dialogData.message
      }
    }
  } else {
    dialogData = props
  }

  switch (dialogData.type) {
    case 'text':
      hiddenText = dialogData.hiddenText === true
      break

    case 'confirmation':
      message = dialogData.message !== undefined ? dialogData.message : 'Are you sure?'
      options = [
        { text: dialogData.acceptMsg ?? 'Yes', value: true, context: 'success' },
        { text: dialogData.rejectMsg ?? 'No', value: false, context: 'danger' }
      ]
      options = options.filter((option) => option.text !== '')
      break

    case 'select':
      options = (dialogData.options ?? [])
      break
  }

  const filteredOptions = options.filter(option => option.text.match(regex))

  const showInput = props.type !== 'confirmation'
  const showOptions = filteredOptions.length > 0
  const showTitle = title !== undefined
  const showMessage = message !== undefined
  const showSteps = props.type === 'form'
  const showPrevious = tabIndex > 0

  // Utilities
  const closeDialog = (selectedOption?: DialogOption<any>, exit = false): void => {
    if (!allowCancel && selectedOption === undefined) {
      setHighlight(true)
    } else {
      if (exit) {
        onClose(undefined)
      } else if (props.type === 'form') {
        buildFormValue(onClose, selectedOption)
      } else if (selectedOption === undefined) {
        onClose(undefined)
      } else {
        onClose(selectedOption.value)
      }
    }
  }

  const getSelectedOption = (): DialogOption<any> | undefined => {
    if (filteredOptions.length > 0) {
      return filteredOptions[selectedOption]
    } else if (text !== '') {
      return { text, value: text, context: 'success' }
    } else {
      return undefined
    }
  }

  const buildFormValue = (getValues: (value: any) => void, option?: DialogOption<any>): void => {
    updateFormValues((formValues) => {
      getValues(order.reduce((prev, curr, i) => {
        const formValue = formValues[i]
        if (formValue !== undefined) {
          prev[curr] = formValue.value
        }
        return prev
      }, {}))
    }, option)
  }

  const updateFormValues = (onUpdate: (value: Array<DialogOption<any> | undefined>) => void, option?: DialogOption<any>): void => {
    const newFormValues = [...formValues]
    const selectedOption = option ?? getSelectedOption()
    if (dialogData.allowCancel === false && selectedOption === undefined) {
      setHighlight(true)
    } else {
      newFormValues[tabIndex] = selectedOption
      setFormValues(newFormValues)
      onUpdate(newFormValues)
    }
  }

  const moveFormIndex = (newTabIndex: number, option?: DialogOption<any>): void => {
    updateFormValues((newFormValues) => {
      const formValue = newFormValues[newTabIndex]
      if (formValue !== undefined) {
        setText(formValue.text)
      } else {
        setText('')
      }
      setSelectedOption(0)
      setTabIndex(newTabIndex)
    }, option)
  }

  const next = (option?: DialogOption<any>): void => {
    moveFormIndex((tabIndex + 1) % maxTabIndex, option)
  }

  const previous = (): void => {
    moveFormIndex((tabIndex - 1 + maxTabIndex) % maxTabIndex)
  }

  const enter = (option?: DialogOption<any>): void => {
    if (tabIndex < maxTabIndex - 1) {
      return next(option)
    }

    closeDialog(option ?? getSelectedOption())
  }

  // Events
  const updateText: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    setText(ev.target.value)
    setSelectedOption(0)
  }

  const dialogClick: React.MouseEventHandler<HTMLInputElement> = (ev) => {
    ev.stopPropagation()
    const target = ev.target as HTMLInputElement
    if (target.tagName === 'INPUT' && target !== inputRef.current) {
      navigator.clipboard.writeText(target.value).catch(() => {
        alert('Cannot copy to clipboard')
      })
    }
  }

  const dialogFocus: React.FocusEventHandler<HTMLDivElement> = (ev) => {
    if (ev.target.tagName !== 'input') {
      focusInput()
    }
  }

  const highlightEnd: React.AnimationEventHandler = () => {
    focusInput()
    setHighlight(false)
  }

  const keyDown: React.KeyboardEventHandler = (ev) => {
    switch (ev.key) {
      case 'ArrowUp':
        setSelectedOption((selectedOption - 1 + filteredOptions.length) % filteredOptions.length)
        break

      case 'ArrowDown':
        setSelectedOption((selectedOption + 1) % filteredOptions.length)
        break

      case 'Enter':
        enter()
        break

      case 'Tab':
        ev.preventDefault()
        if (ev.shiftKey) {
          previous()
        } else {
          next()
        }
        break

      case 'Escape':
        closeDialog(undefined, true)
        break
    }
  }

  return (
    <div className='dialog-overlay' onClick={() => closeDialog(undefined, true)} onAnimationEnd={highlightEnd}>
      <div
        className={joinClassNames('dialog', highlight ? 'highlight' : undefined)}
        tabIndex={0} ref={dialogRef}
        onClick={dialogClick} onKeyDown={keyDown} onFocus={dialogFocus}
      >
        {showTitle ? (
          <div className='title'>{title}</div>
        ) : null}
        {showMessage ? (
          <div className='message-container'>
            {message?.split('\n').map((line, i) => (
              <span className='message' key={i} dangerouslySetInnerHTML={{ __html: line }} />
            ))}
          </div>
        ) : null}
        {showSteps ? <FormIndicator order={order} tabIndex={tabIndex} formValues={formValues} /> : null}
        {showSteps || showMessage ? <span className='separator' /> : null}
        {showInput ? (

          <div className='input-box'>
            {showPrevious ? (
              <span className='button' onClick={previous}>
                <FontAwesomeIcon className='icon' icon={faChevronLeft} />
              </span>
            ) : null}
            <input
              className='modern'
              ref={inputRef}
              type={hiddenText ? 'password' : 'text'}
              placeholder='Write here to search an option...' value={text}
              onChange={updateText}
            />
            <span className='button' onClick={() => enter()}>
              <FontAwesomeIcon className='icon' icon={faChevronRight} />
            </span>
          </div>
        ) : null}
        {showInput && showOptions ? <span className='separator' /> : null}
        <div className='options'>
          {filteredOptions.map((option, i) => (
            <span
              key={i}
              className={joinClassNames(
                'option',
                option.context,
                i === selectedOption ? 'selected' : undefined
              )}
              onClick={() => enter(option)}
              dangerouslySetInnerHTML={{
                __html: option.text.replace(regex, (str, ...args: string[]) => {
                  args.pop() // discard all text
                  args.pop() // discard first match index

                  const text = args.map((v, i) => i % 2 === 0 ? v : `<b>${v}</b>`).join('')
                  return text
                })
              }}
            />
          ))}
        </div>
      </div>
    </div>
  )
}
