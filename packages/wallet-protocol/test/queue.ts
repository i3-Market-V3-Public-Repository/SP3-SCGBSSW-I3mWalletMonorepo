
import * as _pkg from '#pkg'

const { Queue } = _pkg

describe('Testing queue Object', () => {
  const singleQueue = new Queue<String>(1)
  const item = 'last'

  it('shoud add items into the queue', () => {
    singleQueue.push('First')
    chai.expect(singleQueue.length).to.be.equal(1)
  })

  it('shoud replace the first item if we exeed the max length', () => {
    singleQueue.push('foo')
    singleQueue.push('der')
    singleQueue.push('bar')

    singleQueue.push(item)
    chai.expect(singleQueue.last).to.be.equal(item)
  })

  it('shoud be able to pop last item', () => {
    const popped = singleQueue.pop()
    chai.expect(popped).to.be.equal(item)

    chai.expect(singleQueue.length).to.be.equal(0)
  })
})
