import { test, expect, beforeAll, afterEach } from "bun:test";
import { createDID, createVMID, METHOD, PROTOCOL, resolveDID, updateDID } from "../src/method";
import fs from 'node:fs';
import { readLogFromDisk, readKeysFromDisk } from "./utils";

let docFile: string, logFile: string;
let did: string;
let availableKeys: { ed25519: (VerificationMethod | null)[]; x25519: (VerificationMethod | null)[]};
let currentAuthKey: VerificationMethod | null = null;

const verboseMode = Bun.env['LOG_RESOLVES'] === 'true';

const logFilePath =
  (id: string, version?: number) =>
    `./test/logs/${id}/did${verboseMode && version ? '.' + version : ''}.log`;

const writeFilesToDisk = (_log: DIDLog, _doc: any, version: number) => {
  let id = _doc.id.split(':').at(-1);
  if (verboseMode) {
    id = 'test-run';
  }
  docFile = `./test/logs/${id}/did${verboseMode ? '.' + version : ''}.json`;
  logFile = logFilePath(id, version);
  fs.mkdirSync(`./test/logs/${id}`, {recursive: true});
  fs.writeFileSync(docFile, JSON.stringify(_doc, null, 2));
  fs.writeFileSync(logFile, JSON.stringify(_log.shift()) + '\n');
  for (const entry of _log) {
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  }
}


const testResolveVersion = async (versionId: number) => {
  const log = readLogFromDisk(logFile);
  const {did: resolvedDID, doc: resolvedDoc, meta} = await resolveDID(log);

  if(verboseMode) {
    console.log(`Resolved DID Document: ${versionId}`, resolvedDID, resolvedDoc);
  }

  expect(resolvedDoc.id).toBe(resolvedDID);
  expect(meta.versionId).toBe(versionId);
  expect(resolvedDoc.proof).toBeUndefined();
}

beforeAll(async () => {
  const {keys} = readKeysFromDisk();
  availableKeys = JSON.parse(keys);
  currentAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
});

test("Create DID (2 keys + domain)", async () => {
  const {did: newDID, doc: newDoc, meta, log: newLog} = await createDID({
    domain: 'example.com',
    VMs: [
      currentAuthKey!,
      {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
    ]});
  did = newDID;
  currentAuthKey!.controller = did;
  currentAuthKey!.id = createVMID(currentAuthKey!, did);

  expect(newDID).toContain('example.com');
  expect(newDID.split(':').length).toBe(4);
  expect(newDID.split(':').at(-1)?.length).toBe(24);
  expect(newDoc.verificationMethod.length).toBe(2);
  expect(newDoc.id).toBe(newDID);
  expect(newLog.length).toBe(1);
  
  expect(newLog[0][1]).toBe(meta.versionId);
  expect(newLog[0][2]).toBe(meta.created);
  expect(newLog[0][3].method).toBe(`did:${METHOD}:1`);

  writeFilesToDisk(newLog, newDoc, 1);
});

test("Resolve DID", async () => {
  await testResolveVersion(1);
});

test("Update DID (2 keys, 1 service, change domain)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const didLog = readLogFromDisk(logFile);
  const context = ["https://identity.foundation/linked-vp/contexts/v1"];

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      authKey: currentAuthKey!,
      context,
      domain: 'migrated.example.com',
      vms: [
        nextAuthKey,
        {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
      ],
      services: [
        {
          "id": `${did}#whois`,
          "type": "LinkedVerifiablePresentation",
          "serviceEndpoint": [`https://example.com/docs/${did.split(':').at(-1)}/whois.json`]
        }
      ]
    });

  expect(updatedDID).toContain('migrated.example.com');
  expect(updatedDoc.service.length).toBe(1);
  expect(updatedDoc.service[0].id).toBe(`${did}#whois`);
  expect(updatedDoc.service[0].type).toBe('LinkedVerifiablePresentation');
  expect(updatedDoc.service[0].serviceEndpoint).toContain(`https://example.com/docs/${did.split(':').at(-1)}/whois.json`);
  expect(meta.versionId).toBe(2);

  writeFilesToDisk(updatedLog, updatedDoc, 2);
  did = updatedDID;
  currentAuthKey = nextAuthKey;
});

test("Resolve DID", async () => {
  await testResolveVersion(2);
});

test("Update DID (3 keys, 2 services)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const didLog = readLogFromDisk(logFile);
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
  await testResolveVersion(3);
});

test("Update DID (add alsoKnownAs)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const didLog = readLogFromDisk(logFile);
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
  await testResolveVersion(4);
});

test("Update DID (add external controller)", async () => {
  const nextAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const didLog = readLogFromDisk(logFile);
  const {doc} = await resolveDID(didLog);
  const externalAuthKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  externalAuthKey.controller = `did:key:${externalAuthKey.publicKeyMultibase}`;

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      authKey: currentAuthKey!,
      context: doc['@context'],
      controller: [externalAuthKey.controller],
      vms: [
        nextAuthKey,
        externalAuthKey,
        {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
        {type: 'keyAgreement', ...availableKeys.x25519.shift()},
      ],
      services: doc.service,
      alsoKnownAs: ['did:web:example.com']
    });

  expect(updatedDID).toBe(did);
  expect(updatedDoc.controller).toContain(externalAuthKey.controller);
  expect(updatedDoc.authentication[1].slice(-6)).toBe(externalAuthKey.controller.slice(-6));
  expect(updatedDoc.verificationMethod[1].controller).toBe(externalAuthKey.controller);

  expect(meta.versionId).toBe(5);

  writeFilesToDisk(updatedLog, updatedDoc, 5);
  currentAuthKey = nextAuthKey;
});

test("Resolve DID", async () => {
  await testResolveVersion(5);
});