import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { jwksPromise } from '../../config'

export default function (router: Router): void {
  router.get('/publicJwk',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const jwkPair = await jwksPromise
        // const publicJwk = { ...jwkPair.publicJwk, x: 'hello&/%·' }
        // res.json(publicJwk as OpenApiComponents.Schemas.JwkEcPublicKey)
        res.json({ jwk: jwkPair.publicJwk })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/:data',
    async (req: Request<OpenApiPaths.ApiV2Registration$Data.Get.PathParameters, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Registration$Data.Get.Responses.$201>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        // TO-DO
        console.log(req.params.data)
        res.status(201).json({
          status: 'created',
          username: 'username',
          auth_endpoint: '/api/v2/vault/auth'
        })
      } catch (error) {
        return next(error)
      }
    }
  )
}
