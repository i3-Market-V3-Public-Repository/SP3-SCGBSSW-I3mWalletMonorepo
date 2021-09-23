
import { Locals, logger } from '@wallet/main/internal'
import { FeatureHandler } from './feature-handler'

export interface Feature<T> {
  handler: FeatureHandler<T>
  opts?: T
}

export class FeatureManager {
  features: Map<string, Feature<any>>
  constructor () {
    this.features = new Map()
  }

  static CreateFeature<T> (handler: FeatureHandler<T>, opts?: T): Feature<T> {
    return { handler, opts }
  }

  addFeature<T> (feature: Feature<T>): void {
    const name = feature.handler.name
    if (this.features.has(name)) {
      logger.error(`Feature with name '${name}' already set`)
      return
    }

    this.features.set(name, feature)
  }

  async clearFeatures (locals: Locals): Promise<void> {
    for (const [, feature] of this.features) {
      if (feature.handler.stop !== undefined) {
        await feature.handler.stop(feature.opts, locals)
      }
    }
    this.features.clear()
  }

  async start (locals: Locals): Promise<void> {
    for (const [, feature] of this.features) {
      if (feature.handler.start !== undefined) {
        await feature.handler.start(feature.opts, locals)
      }
    }
  }
}
