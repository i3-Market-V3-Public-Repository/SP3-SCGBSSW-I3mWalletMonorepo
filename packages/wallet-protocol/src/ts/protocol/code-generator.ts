import { format } from '../internal'
import { MasterKey } from './master-key'

export interface CodeGenerator {
  generate: (masterKey: MasterKey) => Promise<Uint8Array>
  getMasterKey: (code: Uint8Array) => Promise<MasterKey>
}

export const defaultCodeGenerator: CodeGenerator = {
  async generate (masterKey) {
    console.warn('Using the default code verifier. Note that it is not secure for production.')
    const keyCode = await masterKey.toJSON()
    return format.utf2U8Arr(keyCode)
  },
  async getMasterKey (code) {
    const keyCode = format.u8Arr2Utf(code)
    return await MasterKey.fromJSON(keyCode)
  }
}
