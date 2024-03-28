import fs from 'node:fs';
import {generate as generateEd25519} from '@digitalbazaar/ed25519-multikey';
import {X25519KeyAgreementKey2020} from '@digitalbazaar/x25519-key-agreement-key-2020';

export const genKeys = async (count) => {
  let i = 0;
  const keys = [];
  while(i < count) {
    // const {publicKeyMultibase, secretKeyMultibase} = await generateEd25519();
    const {publicKeyMultibase, privateKeyMultibase} = await X25519KeyAgreementKey2020.generate();
    keys.push({publicKeyMultibase, secretKeyMultibase: privateKeyMultibase});
    i++;
  }
  console.log(keys);
  // fs.writeFileSync('./in/keys.json', JSON.stringify(keys, null, 2))
}

await genKeys(100);