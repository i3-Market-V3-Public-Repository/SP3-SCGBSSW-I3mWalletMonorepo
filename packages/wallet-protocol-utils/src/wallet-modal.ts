
import styleCss from './style.css'

export const openModal = (): Promise<string> => {
  return new Promise(resolve => {
    const overlay = document.createElement('div')
    document.body.appendChild(overlay)
    overlay.className = 'wallet-protocol-overlay'

    const style = document.createElement('style')
    overlay.appendChild(style)
    style.innerText = styleCss

    const modal = document.createElement('div')
    overlay.appendChild(modal)
    modal.className = 'modal'

    const title = document.createElement('span')
    modal.appendChild(title)
    title.className = 'title'
    title.innerText = 'Connecting to your wallet...'

    const message = document.createElement('span')
    modal.appendChild(message)
    message.className = 'message'
    message.innerText = 'Set up your wallet on pairing mode and put the PIN here'

    const inputBox = document.createElement('div')
    modal.appendChild(inputBox)
    inputBox.className = 'input-box'

    const pinInput = document.createElement('input')
    inputBox.appendChild(pinInput)
    pinInput.setAttribute('placeholder', 'pin...')

    const pairButton = document.createElement('button')
    inputBox.appendChild(pairButton)
    pairButton.innerText = 'Syncronize'

    const close = (value?: string) => {
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
