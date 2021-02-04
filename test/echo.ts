// variable _pkg cannot be changed and chai should be removed (and loaded in the browser).
// Please, do NOT touch the following 2 requires!
import * as _pkg from '~root'
import * as chai from 'chai'

describe('testing function echo()', function () {
  const inputs = ['Hello!', 'Goodbye!']
  for (const input of inputs) {
    describe(`echo(${input})`, function () {
      it(`should return ${input}`, function () {
        const ret = _pkg.echo(input)
        chai.expect(ret).to.equal(input)
      })
    })
  }
})
