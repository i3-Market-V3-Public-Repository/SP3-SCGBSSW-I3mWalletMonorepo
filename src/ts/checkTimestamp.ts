import { TimestampVerifyOptions } from './types'

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
    throw new Error('Current date is before the proof\'s "iat"')
  }
  if (options.currentTimestamp < options.expectedTimestampInterval.min - options.clockToleranceMs) {
    throw new Error('iat < expected minimum reception time')
  }
  if (options.currentTimestamp > options.expectedTimestampInterval.max + options.clockToleranceMs) {
    throw new Error('iat < expected maximum reeption Time')
  }
}
