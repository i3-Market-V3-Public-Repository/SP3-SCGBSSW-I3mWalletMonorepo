import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { wellKnownCvsConfiguration } from '../../config'

export default async (): Promise<Router> => {
  const router = Router()

  router.get('/.well-known/cvs-configuration',
    (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.WellKnownCvsConfiguration.Get.Responses.$200>) => {
      res.json(wellKnownCvsConfiguration)
    }
  )
  return router
}
