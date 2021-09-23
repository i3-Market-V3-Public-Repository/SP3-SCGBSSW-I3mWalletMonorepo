import { MainOutput, MainInput } from '@wallet/lib'
import { CustomWindow } from './custom-window'

export type MainWindow = CustomWindow<MainInput, MainOutput>
