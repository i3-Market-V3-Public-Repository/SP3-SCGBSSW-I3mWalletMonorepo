import { Request, Response, Router } from 'express'
import { readFileSync } from 'fs'
import { join as pathJoin } from 'path'
import * as swaggerUi from 'swagger-ui-express'

function openApiSpecRoute (router: Router): void {
  const oas = JSON.parse(readFileSync(pathJoin(__dirname, '..', '..', 'spec', 'cvs.json'), 'utf8'))
  router.get('/spec',
    (req: Request, res: Response) => {
      res.json(oas)
    }
  )
  router.use('/spec-ui', swaggerUi.serve)
  router.get('/spec-ui', swaggerUi.setup(oas))
}

const router = Router()

export default async (): Promise<Router> => {
  openApiSpecRoute(router)

  return router
}
