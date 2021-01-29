// variable _pkg cannot be change. Please, do NOT touch the following two requires (since they have been done in a similar way for the browser)
const _pkg = require('../../dist/index.node.cjs')
const chai = require('chai')

const inputs = ['Hello!', 'Goodbye!']

describe('testing function echo()', function () {
  for (const input of inputs) {
    describe(`echo(${input})`, function () {
      const testFn = (val) => _pkg.echo(val) // add here the function you want to test in the next it
      it(`should return ${input} in Node`, async function () { // This will be run in node
        const ret = await testFn(input)
        chai.expect(ret).to.equal(input)
      })
      it(`should return ${input} in Browser`, async function () { // This will be run in browser
        const ret = await page.evaluate(testFn, input) // first param is the function to test, the next ones are the parameters of the function.
        chai.expect(ret).to.equal(input)
      })
    })
  }
})
