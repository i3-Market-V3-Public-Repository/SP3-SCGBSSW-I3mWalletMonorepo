import { NrError } from '../errors'

export function checkTimestamp (timestamp: number, notBefore: number, notAfter: number, tolerance: number = 2000): void {
  if (timestamp < notBefore - tolerance) {
    throw new NrError(new Error(`timestamp ${(new Date(timestamp).toTimeString())} before 'notBefore' ${(new Date(notBefore).toTimeString())} with tolerance of ${tolerance / 1000}s`), ['invalid timestamp'])
  } else if (timestamp > notAfter + tolerance) {
    throw new NrError(new Error(`timestamp ${(new Date(timestamp).toTimeString())} after 'notAfter' ${(new Date(notAfter).toTimeString())} with tolerance of ${tolerance / 1000}s`), ['invalid timestamp'])
  }
}
