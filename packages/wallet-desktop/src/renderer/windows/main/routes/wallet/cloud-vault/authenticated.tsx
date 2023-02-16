
export function Authenticated (): JSX.Element {
  return (
    <>
      <div className='authenticated'>
        You are already authenticated
      </div>
      <div className='authenticated'>
        You are connected to the vault __URL__
      </div>
      <div className='authenticated'>
        With the username __USER__
      </div>
      <button>Delete cloud storage</button>
      <button>Logout</button>
    </>
  )
}
