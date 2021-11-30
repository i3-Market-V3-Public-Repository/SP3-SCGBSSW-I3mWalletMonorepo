
// export const Wave = (): JSX.Element => {
//   return (
//     <svg
//       width='75mm'
//       height='75mm'
//       viewBox='0 0 75 75'
//       version='1.1'
//       id='svg5'
//       className='wave'
//       xmlns='http://www.w3.org/2000/svg'
//     >
//       <defs id='defs2'>
//         <linearGradient id='linearGradient5663'>
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0 }}
//             offset='0'
//             id='stop5661'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0 }}
//             offset='0.32737753'
//             id='stop14504'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0.11561003 }}
//             offset='0.7305395'
//             id='stop14634'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0.20392157 }}
//             offset='0.91096359'
//             id='stop15020'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0.43364254 }}
//             offset='1'
//             id='stop5659'
//           />
//         </linearGradient>
//         <radialGradient id='radialGradient6315' cx='37.5' cy='37.5' fx='37.5' fy='37.5' r='37.5' gradientUnits='userSpaceOnUse' />
//       </defs>
//       <g id='layer1'>
//         <circle
//         // "opacity:1;mix-blend-mode:normal;fill:url(#radialGradient6315);fill-opacity:1;stroke:none;stroke-width:0.269557;stroke-opacity:1"
//           style={{
//             opacity: 1,
//             mixBlendMode: 'normal',
//             fill: 'url(#radialGradient6315)',
//             fillOpacity: 1,
//             stroke: 'none'
//           }}
//           id='path1908'
//           cx='37.5'
//           cy='37.5'
//           r='37.5'
//         />
//       </g>
//     </svg>
//   )
// }const Wave = (): JSX.Element => {
//   return (
//     <svg
//       width='75mm'
//       height='75mm'
//       viewBox='0 0 75 75'
//       version='1.1'
//       id='svg5'
//       className='wave'
//       xmlns='http://www.w3.org/2000/svg'
//     >
//       <defs id='defs2'>
//         <linearGradient id='linearGradient5663'>
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0 }}
//             offset='0'
//             id='stop5661'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0 }}
//             offset='0.32737753'
//             id='stop14504'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0.11561003 }}
//             offset='0.7305395'
//             id='stop14634'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0.20392157 }}
//             offset='0.91096359'
//             id='stop15020'
//           />
//           <stop
//             style={{ stopColor: '#d2d6e1', stopOpacity: 0.43364254 }}
//             offset='1'
//             id='stop5659'
//           />
//         </linearGradient>
//         <radialGradient id='radialGradient6315' cx='37.5' cy='37.5' fx='37.5' fy='37.5' r='37.5' gradientUnits='userSpaceOnUse' />
//       </defs>
//       <g id='layer1'>
//         <circle
//         // "opacity:1;mix-blend-mode:normal;fill:url(#radialGradient6315);fill-opacity:1;stroke:none;stroke-width:0.269557;stroke-opacity:1"
//           style={{
//             opacity: 1,
//             mixBlendMode: 'normal',
//             fill: 'url(#radialGradient6315)',
//             fillOpacity: 1,
//             stroke: 'none'
//           }}
//           id='path1908'
//           cx='37.5'
//           cy='37.5'
//           r='37.5'
//         />
//       </g>
//     </svg>
//   )
// }

export const Wave = (): JSX.Element => {
  return (
    <>
      <div className='wave' />
      <div className='wave' style={{ animationDelay: '0.5s' }} />
    </>
  )
}
