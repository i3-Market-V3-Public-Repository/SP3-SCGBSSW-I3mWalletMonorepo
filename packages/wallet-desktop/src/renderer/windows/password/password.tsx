import { PasswordArgs } from '@wallet/lib'

import './password.scss'

interface DialogState {
  password: string
}

export default class Password extends React.Component<PasswordArgs, DialogState> {
  state = {
    password: ''
  }

  handleChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    this.setState({ password: ev.target.value })
  }

  handleSubmit: React.MouseEventHandler = (ev): void => {
    ev.preventDefault()
    const id = electron.remote.getCurrentWindow().id
    electron.ipcRenderer.send(`${id}:response`, this.state.password)
  }

  render (): JSX.Element {
    return (
      <form>
        <input type='password' autoFocus value={this.state.password} onChange={this.handleChange} />
        <button type='submit' onClick={this.handleSubmit}>
          Send password
        </button>
      </form>
    )
  }
}
