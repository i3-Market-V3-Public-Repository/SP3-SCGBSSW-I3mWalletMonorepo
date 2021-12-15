import { NrError } from '../errors'
import { TimestampVerifyOptions } from '../types'

export function checkIssuedAt (iat: number, timestampVerifyOptions?: TimestampVerifyOptions): void {
  const parsedOptions: TimestampVerifyOptions = timestampVerifyOptions ?? {}

  iat = iat * 1000 // iat is in seconds

  if (parsedOptions.clockToleranceMs === undefined) delete parsedOptions.clockToleranceMs
  if (parsedOptions.currentTimestamp === undefined) delete parsedOptions.currentTimestamp
  if (parsedOptions.expectedTimestampInterval === undefined) delete parsedOptions.expectedTimestampInterval

  const currentTimestamp = Date.now()
  const options: Required<TimestampVerifyOptions> = {
    currentTimestamp,
    expectedTimestampInterval: {
      min: currentTimestamp,
      max: currentTimestamp
    },
    clockToleranceMs: 10000,
    ...parsedOptions
  }

  if (options.currentTimestamp < iat - options.clockToleranceMs) {
    throw new NrError(new Error('current date is before the proof\'s "iat"'), ['invalid iat'])
  }
  if (options.currentTimestamp < options.expectedTimestampInterval.min - options.clockToleranceMs) {
    throw new NrError(new Error('iat < expected minimum reception time'), ['invalid iat'])
  }
  if (options.currentTimestamp > options.expectedTimestampInterval.max + options.clockToleranceMs) {
    throw new NrError(new Error('iat < expected maximum reeption Time'), ['invalid iat'])
  }
}
