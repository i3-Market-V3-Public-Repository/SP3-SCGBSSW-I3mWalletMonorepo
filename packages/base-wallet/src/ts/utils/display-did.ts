
export const displayDid = (did: string): string => {
  const splittedDid = did.split(':')
  if (splittedDid.length === 1) {
    throw new Error('Wrong did format')
  } else if (splittedDid[1] === 'ethr') {
    const address = splittedDid.pop() as string
    splittedDid.push(`${address.slice(0, 6)}...${address.slice(address.length - 6)}`)
    return splittedDid.join(':')
  } else {
    return did
  }
}
