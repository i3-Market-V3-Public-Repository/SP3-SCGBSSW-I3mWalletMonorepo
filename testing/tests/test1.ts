// variable _pkg cannot be changed and chai should be removed (and loaded in the browser).
// Please, do NOT touch the following 2 requires!
import * as _pkg from '../..'
import * as chai from 'chai'

describe('testing function echo()', function () {
  const inputs = ['Hello!', 'Goodbye!']
  for (const input of inputs) {
    describe(`echo(${input})`, function () {
      it(`should return ${input}`, async function () { // This will be run in node
        const ret = _pkg.echo(input)
        chai.expect(ret).to.equal(input)
      })
    })
  }
})
