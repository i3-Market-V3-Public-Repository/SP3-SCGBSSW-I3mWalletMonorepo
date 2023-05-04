
import { v4 as uuid } from 'uuid'
import { DialogOptionContext } from '@i3m/base-wallet'

export interface DialogOption<T> {
  text: string
  context: DialogOptionContext
  value: T
  index?: number
}

export interface BaseDialogData<T> {
  id: string
  title?: string
  allowCancel?: boolean
  freeAnswer?: boolean
  message?: string
  response?: T | undefined
}
export interface TextDialogData extends BaseDialogData<string> {
  type: 'text'
  hiddenText?: boolean
}

export interface ConfirmationDialogData extends BaseDialogData<boolean> {
  type: 'confirmation'
  acceptMsg?: string
  rejectMsg?: string
}

export interface SelectDialogData<T> extends BaseDialogData<T> {
  type: 'select'
  showInput?: boolean
  options?: Array<DialogOption<T>>
}

export type DialogDescriptors<T> = TextDialogData | ConfirmationDialogData | SelectDialogData<T>

export interface FormDialogData<T> extends BaseDialogData<T> {
  type: 'form'
  descriptors: {
    [K in keyof T]: DialogDescriptors<T[K]>
  }
  order: Array<keyof T>
}

export type DialogData = (
  TextDialogData |
  ConfirmationDialogData |
  SelectDialogData<any> |
  FormDialogData<any>
)

export function createDialogId (): string {
  return uuid()
}
