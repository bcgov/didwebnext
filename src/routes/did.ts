import { resolveDID } from '../method';

export const getLatestDIDDoc = async ({params: {id}, set}: {params: {id: string;}; set: any;}) => {
  console.log(`Resolving ${id}...`);
  try {
    const didLog = await Bun.file(`./out/${id}/log.txt`).text();
    // console.log(didLog)
    // const logLine: string = '[{"op":"replace","path":"/proof/proofValue","value":"z128ss1..."}]';
    const logEntries: DIDLog = didLog.trim().split('\n').map(l => JSON.parse(l));
    const {did, doc, meta} = await resolveDID(logEntries);
    return {doc, meta};
  } catch (e) {
    console.error(e)
    throw new Error(`Failed to resolve DID`);
  }
}