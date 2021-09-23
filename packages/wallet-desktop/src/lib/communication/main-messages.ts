import { WindowInput, WindowOutput } from './window-messages'

interface PasswordOutput {
  type: 'password'
  value: string
}

export type MainOutput = PasswordOutput | WindowOutput

interface NavigateInput {
  type: 'navigate'
  path: string
}

export type MainInput = NavigateInput | WindowInput
