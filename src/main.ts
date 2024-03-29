import {
  Field,
  SmartContract,
  state,
  State,
  method,
  Signature,
  PublicKey,
  PrivateKey,
  Mina,
  AccountUpdate
} from 'o1js';
import { TlsnVerifier } from './TlsnVerifier.js';
import fs from 'fs';
import { z } from 'zod';
import { RootSchema } from './schemas.js';
import { p } from 'o1js/dist/node/bindings/crypto/finite-field.js';
import { createSign } from 'crypto';
import stableStringify from 'json-stable-stringify';

// Read the JSON file
const jsonData = fs.readFileSync('src/simple_proof.json', 'utf-8');

// Parse the JSON data
const parsedData = JSON.parse(jsonData);

// Validate the parsed data using Zod
const result = RootSchema.safeParse(parsedData);

if (result.success) {
  // Data is valid
  const tlsnProof = result.data;
  console.log('Valid data:', tlsnProof);

  const Local = Mina.LocalBlockchain({ proofsEnabled: false });
  Mina.setActiveInstance(Local);
  const { privateKey: deployerKey, publicKey: deployerAccount } = Local.testAccounts[0];
  const { privateKey: senderKey, publicKey: senderAccount } = Local.testAccounts[1];
  // ----------------------------------------------------
  
  // Create a public/private key pair. The public key is your address and where you deploy the zkApp to
  const zkAppPrivateKey = PrivateKey.random();
  const zkAppAddress = zkAppPrivateKey.toPublicKey();
  
  // create an instance of Square - and deploy it to zkAppAddress
  const zkAppInstance = new TlsnVerifier(zkAppAddress);
  const deployTxn = await Mina.transaction(deployerAccount, () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  zkAppInstance.deploy();
  });
  await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
  // get the initial state of Square after deployment
  const notaryPublicKey = zkAppInstance.notaryPublicKey.get();
  console.log('state after init:', notaryPublicKey.toString());
  
  // ----------------------------------------------------
  // Serialize the header object in a deterministic manner
  const serializedHeader = stableStringify(tlsnProof.session.header);
  // Step 2: Convert the serialized string to a byte array
  const encoder = new TextEncoder();
  const dataToSign = encoder.encode(serializedHeader);

  const headerBytes: Field[] = [];
  for (let i = 0; i < dataToSign.length; i++) {
    headerBytes.push(Field(dataToSign[i]));
  }
  const signatureBytes = tlsnProof.session.signature.map((byte: number) => Field(byte));
  
  const signature = Signature.fromFields(signatureBytes);
  
  const txn1 = await Mina.transaction(senderAccount, () => {
  zkAppInstance.verify(headerBytes, signature);
  });
  await txn1.prove();
  
  await txn1.sign([senderKey]).send();
  
  
} else {
  // Data is invalid
  console.error('Invalid data:', result.error);
}


