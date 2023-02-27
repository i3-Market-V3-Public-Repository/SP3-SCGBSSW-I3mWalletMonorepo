
import { Dialog, ConfirmationOptions, SelectOptions, DialogResponse, TextOptions, FormOptions, Descriptors, DialogOptionContext } from '@i3m/base-wallet'

import { DialogData, DialogDescriptors, createDialogId } from '@wallet/lib'
import { Locals, MainContext } from '@wallet/main/internal'
import { SelectBuilder } from './select-builder'

interface BasicOption {
  id: number
  text: string
  context: DialogOptionContext
}

export class ElectronDialog implements Dialog {
  public resolvers: Map<string, (values: {} | undefined) => void>
  public dialogQueue: string[]

  static async initialize (ctx: MainContext, locals: Locals): Promise<ElectronDialog> {
    return new ElectronDialog(locals)
  }

  constructor (protected locals: Locals) {
    this.resolvers = new Map()
    this.dialogQueue = []
  }

  useOptionsBuilder (): SelectBuilder<BasicOption, [text: string, context?: DialogOptionContext]> {
    let id = 0
    return new SelectBuilder(
      (text, context) => ({ id: id++, text, context: context ?? 'success' }),
      (a, b) => a?.id === b?.id,
      (opt) => opt.text,
      (opt) => opt.context
    )
  }

  async launchDialog<T>(dialogData: DialogData): Promise<T | undefined> {
    const { windowManager, sharedMemoryManager } = this.locals
    const mainWindow = windowManager.openMainWindow()
    if (mainWindow === undefined) {
      throw new Error('No main window')
    }

    let current = sharedMemoryManager.memory.dialogs.current
    if (current === undefined) {
      current = dialogData.id
    } else {
      this.dialogQueue.push(dialogData.id)
    }

    sharedMemoryManager.update((mem) => ({
      ...mem,
      dialogs: {
        ...mem.dialogs,
        current: current,
        data: {
          ...mem.dialogs.data,
          [dialogData.id]: dialogData
        }
      }
    }))

    mainWindow.flashFrame(false)
    mainWindow.flashFrame(true)

    const option = await new Promise<T | undefined>(resolve => {
      this.resolvers.set(dialogData.id, resolve as any)
    })

    return option
  }

  buildArguments<T = {}>(options: Descriptors<T>): DialogDescriptors<T> {
    switch (options.type) {
      case 'text':
      {
        const { title, message, hiddenText, allowCancel } = options
        return {
          id: createDialogId(),
          title,
          message,
          allowCancel,
          freeAnswer: true,

          type: 'text',
          hiddenText
        }
      }
      case 'confirmation':
      {
        const { title, message, acceptMsg, rejectMsg, allowCancel } = options
        return {
          id: createDialogId(),
          title,
          message: message,
          allowCancel: allowCancel,
          type: 'confirmation',
          acceptMsg: acceptMsg,
          rejectMsg: rejectMsg
        }
      }
      case 'select':
      {
        const { title, message, values, allowCancel } = options
        const getText = options.getText ?? ((v: string): string => v)
        const getContext = options.getContext ?? ((v): DialogOptionContext => 'success')

        return {
          id: createDialogId(),
          title,
          message,
          allowCancel,
          type: 'select',
          options: values.map((value: any, i) => ({
            index: i,
            value,
            text: getText(value),
            context: getContext(value)
          }))
        }
      }
    }

    throw new Error('Unknown type for dialog')
  }

  async text (options: TextOptions): DialogResponse<string> {
    const dialogData = this.buildArguments({
      ...options,
      type: 'text'
    })

    return await this.launchDialog<string>(dialogData)
  }

  async confirmation (options: ConfirmationOptions): DialogResponse<boolean> {
    const dialogData = this.buildArguments({
      ...options,
      type: 'confirmation'
    })

    return await this.launchDialog(dialogData)
  }

  async select<T> (options: SelectOptions<T>): DialogResponse<T> {
    const dialogInput = this.buildArguments({
      ...options,
      type: 'select'
    })

    return await this.launchDialog(dialogInput)
  }

  async form<T>(options: FormOptions<T>): DialogResponse<T> {
    const { title, message, allowCancel, descriptors, order } = options

    const dialogDescriptors: { [k: string]: DialogDescriptors<any> } = {}

    for (const [key, descriptor] of Object.entries<Descriptors<any>>(descriptors)) {
      dialogDescriptors[key] = this.buildArguments(descriptor)
    }

    const dialogData: DialogData = {
      id: createDialogId(),
      title,
      message,
      allowCancel,
      freeAnswer: true,
      type: 'form',
      descriptors: dialogDescriptors,
      order
    }

    return await this.launchDialog(dialogData)
  }

  async authenticate (): DialogResponse<any> {
    throw new Error('NOT IMPLEMENTED')
  }
}
