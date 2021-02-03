// variable _pkg cannot be changed. Please, do NOT touch the following require!
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

describe('testing function sign()', function () {
  const testFn = async (): Promise<string> => await _pkg.sign('hello') // add here the function you want to test in the next it
  it('should return a JWS string in node', async function () { // This will be run in node
    const ret = await testFn()
    chai.expect(ret).to.be.a('string')
  })
})
