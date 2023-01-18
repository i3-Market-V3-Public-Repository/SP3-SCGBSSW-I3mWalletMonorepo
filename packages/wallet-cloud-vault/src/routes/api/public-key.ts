import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { jwksPromise } from '../../config'

export default function publicKey (router: Router): void {
  router.get('/publicJwk',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2PublicJwk.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const jwkPair = await jwksPromise
        // const publicJwk = { ...jwkPair.publicJwk, x: 'hello&/%·' }
        // res.json(publicJwk as OpenApiComponents.Schemas.JwkEcPublicKey)
        res.json(jwkPair.publicJwk)
      } catch (error) {
        next(error)
      }
    }
  )
}
