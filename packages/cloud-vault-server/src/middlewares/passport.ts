import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { Passport } from 'passport'
import { Strategy, ExtractJwt } from 'passport-jwt'
import { jwt } from '../config'

export interface User {
  username: string
}

export const passport = new Passport()
passport.use('jwtBearer', new Strategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: jwt.secret
  },
  (jwtPayload, done) => {
    try {
      // const user: User = {
      //   username: jwtPayload.username
      // }
      // return done(null, user)
      return done(new HttpError({
        status: 401,
        name: 'unauthorized',
        path: ''
      }))
    } catch (error) {
      return done(error)
    }
  }
))
