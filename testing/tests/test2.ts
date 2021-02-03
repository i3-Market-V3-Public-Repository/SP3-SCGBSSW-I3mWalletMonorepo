// variable _pkg cannot be changed and chai should be removed (and loaded in the browser).
// Please, do NOT touch the following 2 requires!
import * as _pkg from '../..'
import * as chai from 'chai'

describe('testing function sign()', function () {
  it('should return a JWS string in node', async function () { // This will be run in node
    const ret = await _pkg.sign('hello')
    chai.expect(ret).to.be.a('string')
  })
})
