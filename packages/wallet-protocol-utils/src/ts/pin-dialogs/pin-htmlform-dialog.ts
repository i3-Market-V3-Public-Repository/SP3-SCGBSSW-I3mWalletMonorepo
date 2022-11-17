// @ts-expect-error
import styleCss from '../../pin-dialog.css'

import { PinHtmlFormDialogOptions } from '../types'

const defaultHtmlOptions: Required<PinHtmlFormDialogOptions> = {
  overlayClass: 'wallet-protocol-overlay',
  modalClass: 'wallet-modal',
  titleClass: 'wallet-title',
  messageClass: 'wallet-message',
  inputBoxClass: 'wallet-input-box',
  inputClass: 'wallet-input',
  buttonClass: 'wallet-button'
}

/**
 * A PIN input dialog for browsers. It shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.
 * @param opts - HTML/CSS class names for styling the dialog
 * @returns a promise that resolves to the PIN
 */
export const pinHtmlFormDialog = async (opts: PinHtmlFormDialogOptions = defaultHtmlOptions): Promise<string> => {
  const options: Required<PinHtmlFormDialogOptions> = Object.assign({}, opts, defaultHtmlOptions)

  const overlay = document.createElement('div')
  document.body.appendChild(overlay)
  overlay.className = options.overlayClass

  const style = document.createElement('style')
  overlay.appendChild(style)
  style.innerText = styleCss
    .replace(/__WALLET_PROTOCOL_OVERLAY__/g, options.overlayClass)
    .replace(/__WALLET_MODAL__/g, options.modalClass)
    .replace(/__WALLET_TITLE__/g, options.titleClass)
    .replace(/__WALLET_MESSAGE__/g, options.messageClass)
    .replace(/__WALLET_INPUT_BOX__/g, options.inputBoxClass)
    .replace(/__WALLET_INPUT__/g, options.inputClass)
    .replace(/__WALLET_BUTTON__/g, options.buttonClass)

  const modal = document.createElement('div')
  overlay.appendChild(modal)
  modal.className = options.modalClass

  const title = document.createElement('span')
  modal.appendChild(title)
  title.className = options.titleClass
  title.innerText = 'Connecting to your wallet...'

  const message = document.createElement('span')
  modal.appendChild(message)
  message.className = options.messageClass
  message.innerText = 'Set up your wallet on pairing mode and put the PIN here'

  const inputBox = document.createElement('div')
  modal.appendChild(inputBox)
  inputBox.className = options.inputBoxClass

  const pinInput = document.createElement('input')
  inputBox.appendChild(pinInput)
  pinInput.className = options.inputClass
  pinInput.setAttribute('placeholder', 'pin...')

  const pairButton = document.createElement('button')
  inputBox.appendChild(pairButton)
  pairButton.className = options.buttonClass
  pairButton.innerText = 'Syncronize'

  return await new Promise((resolve, reject) => {
    const close = (value?: string): void => {
      document.body.removeChild(overlay)
      resolve(value ?? '')
    }
    pairButton.addEventListener('click', () => close(pinInput.value))
    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) {
        close()
      }
    })
  })
}
