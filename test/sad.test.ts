import { beforeAll, expect, test } from "bun:test";
import { readKeysFromDisk, readLogFromDisk, writeLogToDisk } from "./utils";
import { createDID, resolveDID, updateDID } from "../src/method";

let availableKeys: { ed25519: (VerificationMethod | null)[]; x25519: (VerificationMethod | null)[]};

beforeAll(async () => {
  const {keys} = readKeysFromDisk();
  availableKeys = JSON.parse(keys);
});

test("Update with wrong key fails resolution", async () => {
  const authKey = {type: 'authentication', ...availableKeys.ed25519.shift()};
  const assertionKey = {type: 'assertionMethod', ...availableKeys.ed25519.shift()};
  const {did: newDID, doc: newDoc, meta: createMeta, log: newLog} = await createDID({VMs: [
    authKey,
    assertionKey,
  ]});

  let err;
  try {
    const result =
      await updateDID({
        log: newLog,
        authKey: assertionKey!,
        context: newDoc['@context'],
        vms: [
          {type: 'aauthentication', ...availableKeys.ed25519.shift()},
          {type: 'assertionMethod', ...availableKeys.ed25519.shift()},
        ]
      });

      // TODO
      // DONT LET BAD KEYS SIGN
      writeLogToDisk('./test/fixtures/not-authorized.log', result.log);
  } catch(e) {
    err = e;
  }
  
  const badLog = readLogFromDisk('./test/fixtures/not-authorized.log');
  let result;
  try {
    result = await resolveDID(badLog);
  } catch(e: any) {
    err = e;
  }

  expect(result).toBeUndefined();
  expect(err.message).toContain('is not authorized to update.')
});