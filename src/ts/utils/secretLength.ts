import { NrError } from '../errors'
import { EncryptionAlg } from '../types'

export function secretLength (encAlg: EncryptionAlg): number {
  if (encAlg === 'A128GCM') {
    return 16
  } else if (encAlg === 'A256GCM') {
    return 32
  }
  throw new NrError('unsupported algorithm', ['invalid algorithm'])
}
