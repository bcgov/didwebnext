import { test, expect, beforeAll } from "bun:test";
import { createDID, LOG_FORMAT, PROTOCOL, resolveDID, updateDID } from "../src/method";
import fs from 'node:fs';

let docFile: string, logFile: string;
let did: string;
let availableKeys: { ed25519: (VerificationMethod | null)[]; x25519: (VerificationMethod | null)[]};

const verboseMode = Bun.env['LOG_RESOLVES'] === 'true';

const writeFilesToDisk = (_log: DIDLog, _doc: any, version: number) => {
  let id = _doc.id.split(':').at(-1);
  if (verboseMode) {
    id = 'test-run';
  }
  docFile = `./test/logs/${id}/did${verboseMode ? '.' + version : ''}.json`;
  logFile = `./test/logs/${id}/did${verboseMode ? '.' + version : ''}.log`;
  fs.mkdirSync(`./test/logs/${id}`, {recursive: true});
  fs.writeFileSync(docFile, JSON.stringify(_doc, null, 2));
  fs.writeFileSync(logFile, JSON.stringify(_log.shift()) + '\n');
  for (const entry of _log) {
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  }
}

const readFilesFromDisk = () => {
  return {
    log: fs.readFileSync(logFile, 'utf8').trim().split('\n').map(l => JSON.parse(l))
  }
}

const readKeysFromDisk = () => {
  return {keys: fs.readFileSync('./in/keys.json', 'utf8')}
}

const testResolveVersion = async (versionId: number) => {
  const {log: didLog} = readFilesFromDisk();
  const {did: resolvedDID, doc: resolvedDoc, meta} = await resolveDID(didLog);
  
  if(verboseMode) {
    console.log(`Resolved DID Document: ${versionId}`, resolvedDoc);
  }
  
  expect(resolvedDID).toBe(resolvedDoc.id);
  expect(resolvedDoc.id).toBe(did);
  expect(meta.versionId).toBe(versionId);
  expect(resolvedDoc.proof).toBeUndefined();
}

let currentAuthKey: VerificationMethod | null = null;

beforeAll(async () => {
  const {keys} = readKeysFromDisk();
  availableKeys = JSON.parse(keys);
  currentAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
});

test("Create DID (2 keys)", async () => {
  const {did: newDID, doc: newDoc, meta, log: newLog} = await createDID({VMs: [
    currentAuthKey!,
    {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
  ]});
  did = newDID;

  expect(newDID.split(':').length).toBe(3);
  expect(newDID.split(':').at(-1)?.length).toBe(24);
  expect(newDoc.verificationMethod.length).toBe(2);
  expect(newDoc.id).toBe(newDID);
  expect(newLog.length).toBe(2);
  
  // header
  expect(newLog[0][0]).toBe(LOG_FORMAT as any);
  expect(newLog[0][1]).toBe(PROTOCOL as any);
  expect(newLog[0][2]).toBe(newDID.split(':').at(-1) as any);

  // entry
  expect(newLog[1][1]).toBe(meta.versionId);
  expect(newLog[1][2]).toBe(meta.created);
  expect(Object.entries(newLog[1][3]).length).toBe(5);

  writeFilesToDisk(newLog, newDoc, 1);
});

test("Resolve DID", async () => {
  testResolveVersion(1);
});

test("Update DID (2 keys, 1 service)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const {log: didLog} = readFilesFromDisk();
  const context = ["https://identity.foundation/linked-vp/contexts/v1"];

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      authKey: currentAuthKey!,
      context,
      vms: [
        nextAuthKey,
        {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
      ],
      services: [
        {
          "id": `${did}#whois`,
          "type": "LinkedVerifiablePresentation",
          "serviceEndpoint": [`https://example.com/docs/${did}/whois.json`]
        }
      ]
    });
  expect(updatedDID).toBe(did);
  expect(updatedDoc.service.length).toBe(1);
  expect(updatedDoc.service[0].id).toBe(`${did}#whois`);
  expect(updatedDoc.service[0].type).toBe('LinkedVerifiablePresentation');
  expect(updatedDoc.service[0].serviceEndpoint).toContain(`https://example.com/docs/${did}/whois.json`);
  expect(meta.versionId).toBe(2);

  writeFilesToDisk(updatedLog, updatedDoc, 2);
  currentAuthKey = nextAuthKey;
});

test("Resolve DID", async () => {
  testResolveVersion(2);
});

test("Update DID (3 keys, 2 services)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const {log: didLog} = readFilesFromDisk();
  const {doc} = await resolveDID(didLog);

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      authKey: currentAuthKey!,
      context: [...doc['@context'], 'https://didcomm.org/messaging/v2'],
      vms: [
        nextAuthKey,
        {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
        {type: 'keyAgreement', ...availableKeys.x25519.shift()}
      ],
      services: [
        ...doc.service,
        {
          id: `${did}#didcomm`,
          type: 'DIDCommMessaging',
          serviceEndpoint: {
            "uri": "https://example.com/didcomm",
            "accept": [
                "didcomm/v2",
                "didcomm/aip2;env=rfc587"
            ],
            "routingKeys": ["did:example:somemediator#somekey"]
          }
        }
      ]});
  expect(updatedDID).toBe(did);
  expect(updatedDoc.keyAgreement.length).toBe(1)
  expect(updatedDoc.service.length).toBe(2);
  expect(updatedDoc.service[1].id).toBe(`${did}#didcomm`);
  expect(updatedDoc.service[1].type).toBe('DIDCommMessaging');
  expect(updatedDoc.service[1].serviceEndpoint.uri).toContain(`https://example.com/didcomm`);
  expect(meta.versionId).toBe(3);

  writeFilesToDisk(updatedLog, updatedDoc, 3);
  currentAuthKey = nextAuthKey;
});

test("Resolve DID", async () => {
  testResolveVersion(3);
});

test("Update DID (add alsoKnownAs)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const {log: didLog} = readFilesFromDisk();
  const {doc} = await resolveDID(didLog);

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      authKey: currentAuthKey!,
      context: doc['@context'],
      vms: [
        nextAuthKey,
        {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
        {type: 'keyAgreement', ...availableKeys.x25519.shift()},
      ],
      services: doc.service,
      alsoKnownAs: ['did:web:example.com']
    });
  expect(updatedDID).toBe(did);
  expect(updatedDoc.alsoKnownAs).toContain('did:web:example.com')
  expect(meta.versionId).toBe(4);

  writeFilesToDisk(updatedLog, updatedDoc, 4);
  currentAuthKey = nextAuthKey;
});

test("Resolve DID", async () => {
  testResolveVersion(4);
});