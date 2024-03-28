import { documentLoader, jdl } from "./data-integrity";

import { nanoid } from 'nanoid';
import { sha256 } from 'multiformats/hashes/sha2';
import { base32 } from 'multiformats/bases/base32';
import { CID } from 'multiformats/cid';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import { canonicalize } from 'json-canonicalize';
import * as jsonpatch from 'fast-json-patch/index.mjs';
import {cryptosuite as eddsa2022CryptoSuite} from
  '@digitalbazaar/eddsa-2022-cryptosuite';
import jsigs from 'jsonld-signatures';
import chalk from "chalk";
import { base58btc } from "multiformats/bases/base58";
import fs from 'node:fs';
import { clone } from "./utils";
import { error } from "elysia";

export const PLACEHOLDER = "{{SCID}}";
export const METHOD = "tdw";
export const PROTOCOL = `did:${METHOD}:1`;

const CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"];
const {purposes: {AuthenticationProofPurpose}} = jsigs;

export const createSCID = async (logEntryHash: string): Promise<{scid: string}> => {
  return {scid: `${logEntryHash.slice(-24)}`};
}

export const deriveHash = async (input: any): Promise<{logEntryHash: string}> => {
  const data = canonicalize(input);
  const hash = await sha256.digest(Buffer.from(data));
  return {logEntryHash: base58btc.encode(hash.digest)};
}

export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const controller = `did:${METHOD}:${options.domain}:${PLACEHOLDER}`
  let {doc} = await createDIDDoc({...options, controller});
  const {logEntryHash: genesisDocHash} = await deriveHash(doc);
  const {scid} = await createSCID(genesisDocHash);
  doc = JSON.parse(JSON.stringify(doc).replaceAll(PLACEHOLDER, scid));
  const logEntry: DIDLogEntry = [
    genesisDocHash,
    1,
    (new Date).toISOString().slice(0,-5)+'Z',
    {method: PROTOCOL, scid},
    {value: doc}
  ]
  const {logEntryHash} = await deriveHash(logEntry);
  logEntry[0] = logEntryHash;
  let authKey = {...options.VMs?.find(vm => vm.type === 'authentication')};
  if (!authKey) {
    throw new Error('Auth key not supplied')
  }
  authKey.id = createVMID({...authKey, type: 'authentication'}, doc.id!);
  const signedDoc = await signDocument(doc, {...authKey, type: 'authentication'}, logEntryHash);
  logEntry.push(signedDoc.proof);
  return {
    did: doc.id!,
    doc,
    meta: {
      versionId: 1,
      created: logEntry[2],
      updated: logEntry[2]
    },
    log: [
      logEntry
    ]
  }
}

export const createDIDDoc = async (options: CreateDIDInterface): Promise<{doc: DIDDoc}> => {
  const {controller} = options;
  const {all} = normalizeVMs(options.VMs, controller);
  return {
    doc: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      id: controller,
      controller,
      ...all
    }
  };
}

export const resolveDID = async (log: DIDLog): Promise<{did: string, doc: any, meta: any}> => {
  const resolutionLog = clone(log);
  const protocol = resolutionLog[0][3].method;
  if(protocol !== PROTOCOL) {
    throw new Error(`'${protocol}' protocol unknown.`);
  }
  let versionId = 0;
  let doc: any = {};
  let did = '';
  let created = '';
  let updated = '';
  let previousLogEntryHash = '';
  for (const entry of resolutionLog) {
    if (entry[1] !== versionId + 1) {
      throw new Error(`versionId '${entry[1]}' in log doesn't match expected '${versionId}'.`);
    }
    versionId = entry[1];
    if (entry[2]) {
      // TODO check timestamps make sense
    }
    updated = entry[2];

    // doc patches & proof
    let newDoc;
    if (versionId === 1) {
      created = entry[2];
      newDoc = entry[4].value;
      const {scid} = entry[3];
      const {logEntryHash} = await deriveHash(
        JSON.parse(JSON.stringify(newDoc).replaceAll(scid, PLACEHOLDER))
      );
      const {scid: derivedScid} = await createSCID(logEntryHash);
      previousLogEntryHash = logEntryHash;
      if (scid !== derivedScid) {
        throw new Error(`SCID '${scid}' not derived from logEntryHash '${logEntryHash}' (scid ${derivedScid})`);
      }
      const authKey = newDoc.verificationMethod.find((vm: VerificationMethod) => vm.id === entry[5].verificationMethod);
      const result = await isDocumentStateValid(authKey, {...newDoc, proof: entry[5]}, newDoc);
      if (!result.verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`, {cause: result})
      }
    } else {
      // versionId > 1
      if (Object.keys(entry[4]).some((k: string) => k === 'value')) {
        newDoc = entry[4].value;
      } else {
        newDoc = jsonpatch.applyPatch(doc, entry[4].patch, false, false).newDocument;
      }
      const {logEntryHash} = await deriveHash([previousLogEntryHash, entry[1], entry[2], entry[3], entry[4]]);
      previousLogEntryHash = logEntryHash;
      if (logEntryHash !== entry[0]) {
        throw new Error(`Hash chain broken at '${versionId}'`);
      }
      const authKey = doc.verificationMethod.find((vm: VerificationMethod) => vm.id === entry[5].verificationMethod);
      if (!authKey) {
        throw new Error(`Auth key '${entry[5].verificationMethod}' not found in previous document`);
      }
      const result = await isDocumentStateValid(authKey, {...newDoc, proof: entry[5]}, doc);
      if (!result.verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`, {cause: {result, currentDoc: doc}})
      }
    }
    doc = clone(newDoc);
    did = doc.id;
  }
  return {did, doc, meta: {versionId, created, updated, previousLogEntryHash}}
}

export const updateDID = async (options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const {log, authKey, context, vms, services, alsoKnownAs, controller, domain} = options;
  let {did, doc, meta} = await resolveDID(log);
  if (domain) {
    did = `did:${METHOD}:${domain}:${log[0][3].scid}`;
  }
  const {all} = normalizeVMs(vms, did);
  const newDoc = {
    ...(context ? {'@context': Array.from(new Set([...CONTEXT, ...context]))} : {'@context': CONTEXT}),
    id: did,
    ...(controller ? {controller: Array.from(new Set([did, ...controller]))} : {controller:[did]}),
    ...all,
    ...(services ? {service: services} : {}),
    ...(alsoKnownAs ? {alsoKnownAs} : {})
  }
  meta.versionId++;
  meta.updated = (new Date).toISOString().slice(0,-5)+'Z';
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [meta.previousLogEntryHash, meta.versionId, meta.updated, {}, {patch: clone(patch)}];
  const {logEntryHash} = await deriveHash(logEntry);
  if(!authKey) {
    throw new Error(`No auth key`);
  }
  authKey.id = authKey.id ?? createVMID({...authKey, type: 'authentication'}, doc.id);
  const signedDoc = await signDocument(newDoc, authKey, logEntryHash);
  return {
    did,
    doc: newDoc,
    meta: {
      versionId: meta.versionId,
      created: meta.created,
      updated: meta.updated,
      previousLogEntryHash: meta.previousLogEntryHash
    },
    log: [
      ...clone(log),
      [logEntryHash, meta.versionId, meta.updated, {}, {patch: clone(patch)}, signedDoc.proof]
    ]
  };
}

export const normalizeVMs = (verificationMethod: VerificationMethod[] | undefined, did: string | null = null) => {
  if (!verificationMethod) {
    return {};
  }
  const all: any = {};
  const authentication = verificationMethod
    ?.filter(vm => vm.type === 'authentication').map(vm => createVMID(vm, did))
  if (authentication && authentication?.length > 0) {
    all.authentication = authentication;
  }
  const assertionMethod = verificationMethod
    ?.filter(vm => vm.type === 'assertionMethod').map(vm => createVMID(vm, did))
  if (assertionMethod && assertionMethod?.length > 0) {
    all.assertionMethod = assertionMethod;
  }
  const keyAgreement = verificationMethod
    ?.filter(vm => vm.type === 'keyAgreement').map(vm => createVMID(vm, did));
  if (keyAgreement && keyAgreement?.length > 0) {
    all.keyAgreement = keyAgreement;
  }
  const capabilityDelegation = verificationMethod
    ?.filter(vm => vm.type === 'capabilityDelegation').map(vm => createVMID(vm, did));
  if (capabilityDelegation && capabilityDelegation?.length > 0) {
    all.capabilityDelegation = capabilityDelegation;
  }
  const capabilityInvocation = verificationMethod
  ?.filter(vm => vm.type === 'capabilityInvocation').map(vm => createVMID(vm, did));
  if (capabilityInvocation && capabilityInvocation?.length > 0) {
    all.capabilityInvocation = capabilityInvocation;
  }
  if(verificationMethod && verificationMethod.length > 0) {
    all.verificationMethod = verificationMethod?.map(vm => ({
      id: createVMID(vm, did),
      ...(did ? {controller: vm.controller ?? did} : {}),
      type: 'Multikey',
      publicKeyMultibase: vm.publicKeyMultibase
    }))
  }
  return {all};
}

export const createVMID = (vm: VerificationMethod, did: string | null) => {
  return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || nanoid(8)}`
}

export const signDocument = async (doc: any, vm: VerificationMethod, challenge: string) => {
  try {
    const keyPair = await Ed25519Multikey.from({
      '@context': 'https://w3id.org/security/multikey/v1',
      type: 'Multikey',
      controller: doc.id,
      id: vm.id,
      publicKeyMultibase: vm.publicKeyMultibase,
      secretKeyMultibase: vm.secretKeyMultibase
    });
    const suite = new DataIntegrityProof({
      signer: keyPair.signer(), cryptosuite: eddsa2022CryptoSuite
    });
    
    const signedDoc = await jsigs.sign(clone(doc), {
      suite,
      purpose: new AuthenticationProofPurpose({challenge}),
      documentLoader
    });
    return signedDoc;
  } catch (e: any) {
    console.error(e)
    throw new Error(`Document signing failure: ${e.details}`)
  }
}

export const isDocumentStateValid = async (authKey: VerificationMethod, doc: any, prevDoc: any) => {
  if (!isKeyAuthorized(authKey, prevDoc)) {
    throw new Error(`key ${authKey.id} is not authorized to update.`)
  }
  jdl.addStatic(prevDoc.id, prevDoc);
  jdl.addStatic(doc.proof.verificationMethod, authKey);
  const docLoader = jdl.build();
  const {document: keyPairDoc} = await docLoader(authKey.id);
  const keyPair = await Ed25519Multikey.from(keyPairDoc);
  
  const suite = new DataIntegrityProof({
    verifier: keyPair.verifier(), cryptosuite: eddsa2022CryptoSuite
  });
  const verification = await jsigs.verify(doc, {
    suite,
    purpose: new AuthenticationProofPurpose({challenge: doc.proof.challenge}),
    documentLoader: docLoader
  });
  return verification;
}


export const isKeyAuthorized = (authKey: VerificationMethod, prevDoc: any) => {
  return prevDoc.authentication.some((kId: string) => kId === authKey.id);
}
