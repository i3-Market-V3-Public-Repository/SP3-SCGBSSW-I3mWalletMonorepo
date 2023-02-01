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
      const user: User = {
        username: jwtPayload.username
      }
      // console.log(JSON.stringify(user));
      return done(null, user)
    } catch (error) {
      return done(error)
    }
  }
))
