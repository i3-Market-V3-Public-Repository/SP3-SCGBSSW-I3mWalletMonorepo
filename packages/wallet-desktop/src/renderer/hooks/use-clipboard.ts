import { showToastAction } from '@wallet/lib'
import { ActionDispatcher } from '../communication'

type WriteClipboard = (text: string) => void
type ReadClipboard = () => string

export const useClipboard = (dispatch: ActionDispatcher): [WriteClipboard, ReadClipboard] => {
  const writeClipboard = (text: string): void => {
    electron.clipboard.writeText(text)
    dispatch(showToastAction.create({
      message: 'Copied to clipboard!',
      type: 'info'
    }))
  }
  const readClipboard = electron.clipboard.readText

  return [writeClipboard, readClipboard]
}
