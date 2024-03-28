import { Elysia } from 'elysia'
import { getLatestDIDDoc } from './routes/did';

const getMaxVersionId = (max: number, name: string) => {
  const pattern = /\d+(?=.json)/;
  const match = name.match(pattern);
  if (match) {
    const num = parseInt(match[0], 10);
    return Math.max(max, num);
  }
  return max;
}

const app = new Elysia()
	.get('/:id', ({params, set}) => getLatestDIDDoc({params, set}))
  .get('/:id/:version', ({params: {id, version}}) => {
    console.log(version)
  })
  .get('/:id/versions', ({params: {id}}) => {
    console.log('versions')
  })
	.listen(8000)

console.log(`🔍 Resolver is running at on port ${app.server?.port}...`)
