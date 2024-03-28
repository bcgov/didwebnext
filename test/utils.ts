import fs from 'node:fs';

export const readKeysFromDisk = () => {
  return {keys: fs.readFileSync('./in/keys.json', 'utf8')}
}

export const readLogFromDisk = (path: string): DIDLog => {
  return fs.readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
}

export const writeLogToDisk = (path: string, log: DIDLog) => {
  fs.writeFileSync(path, JSON.stringify(log.shift()) + '\n');
  for (const entry of log) {
    fs.appendFileSync(path, JSON.stringify(entry) + '\n');
  }
}