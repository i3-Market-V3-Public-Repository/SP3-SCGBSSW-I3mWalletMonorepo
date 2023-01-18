import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../types/openapi'
import { jwksPromise } from '../config'
import { parseJwk } from '@i3m/non-repudiation-library'

export default function publicKey (router: Router): void {
  router.get('/publicJwk',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.PublicJwk.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const jwkPair = await jwksPromise
        res.json({
          publicJwk: await parseJwk(jwkPair.publicJwk, true)
        })
      } catch (error) {
        next(error)
      }
    }
  )
}
