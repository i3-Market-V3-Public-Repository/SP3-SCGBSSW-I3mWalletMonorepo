import { helloWorld } from '#pkg'

describe('testing function helloWorld() with ts file in the test directory', function () {
  const inputs = ['Alice', 'Bob']
  for (const input of inputs) {
    describe(`helloWorld(${input})`, function () {
      it(`should return "Hello ${input}!"`, async function () {
        const ret = await helloWorld(input)
        chai.expect(ret).to.equal(`Hello ${input}!`)
      })
      it('should print \'node\' in node and \'browser\' in a browser', function () {
        const output = IS_BROWSER ? 'browser' : 'node'
        if (IS_BROWSER) {
          console.log(output)
          chai.expect(output).to.equal('browser')
        } else {
          console.log(output)
          chai.expect(output).to.equal('node')
        }
      })
    })
  }
})
