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
  AccountUpdate,
} from 'o1js';
import { TlsnVerifier } from './TlsnVerifier.js';
import fs from 'fs';
import { z } from 'zod';
import { RootSchema } from './schemas.js';
import { SessionHeader } from './SessionHeader.js';

// Convert a number to a byte array
function numberToBytes(num: number) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setInt32(0, num, true);
  return new Uint8Array(buffer);
}

function bytesToFields(bytes: Uint8Array): Field[] {
  const fields: Field[] = [];
  bytes.forEach((byte: number) => fields.push(Field(byte)));
  return fields;
}

// Read the JSON file
const jsonData = fs.readFileSync('src/simple_proof.json', 'utf-8');

// Parse the JSON data
const parsedData = JSON.parse(jsonData);
// Replace the string "secp256r1" for its corresponding byte representation.
parsedData.session.header.handshake_summary.server_public_key.group = [0, 65];

// Validate the parsed data using Zod
const result = RootSchema.safeParse(parsedData);

if (result.success) {
  const tlsnProof = result.data;
  const signature = Signature.fromBase58(tlsnProof.session.signature.MinaSchnorr);

  const encoder_seed = tlsnProof.session.header.encoder_seed;
  const merkle_root = tlsnProof.session.header.merkle_root;
  const sent_len = numberToBytes(tlsnProof.session.header.sent_len);
  const recv_len = numberToBytes(tlsnProof.session.header.recv_len);
  const time = numberToBytes(tlsnProof.session.header.handshake_summary.time);
  const group = tlsnProof.session.header.handshake_summary.server_public_key.group;
  const key = tlsnProof.session.header.handshake_summary.server_public_key.key;
  const handshake_commitment = tlsnProof.session.header.handshake_summary.handshake_commitment;

  const sessionHeader = new SessionHeader({
    encoderSeed: bytesToFields(new Uint8Array(encoder_seed)),
    merkleRoot: bytesToFields(new Uint8Array(merkle_root)),
    sentLen: bytesToFields(new Uint8Array(sent_len)),
    recvLen: bytesToFields(new Uint8Array(recv_len)),
    handshakeSummary: {
      time: bytesToFields(new Uint8Array(time)),
      serverPublicKey: {
        group: bytesToFields(new Uint8Array(group)),
        key: bytesToFields(new Uint8Array(key)),
      },
      handshakeCommitment: bytesToFields(new Uint8Array(handshake_commitment)),
    },
  });

  // ----------------------------------------------------
  // Create a local blockchain instance
  const Local = Mina.LocalBlockchain({ proofsEnabled: false });
  Mina.setActiveInstance(Local);
  const { privateKey: deployerKey, publicKey: deployerAccount } =
    Local.testAccounts[0];
  const { privateKey: senderKey, publicKey: senderAccount } =
    Local.testAccounts[1];

  // Create a public/private key pair. The public key is your address and where you deploy the zkApp to
  const zkAppPrivateKey = PrivateKey.random();
  const zkAppAddress = zkAppPrivateKey.toPublicKey();

  // create an instance of TlsnVerifier - and deploy it to zkAppAddress
  const zkAppInstance = new TlsnVerifier(zkAppAddress);
  const deployTxn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    zkAppInstance.deploy();
    zkAppInstance.notaryPublicKey.set(PublicKey.fromBase58("B62qowWuY2PsBZsm64j4Uu2AB3y4L6BbHSvtJcSLcsVRXdiuycbi8Ws"));
  });
  await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();

  const txn1 = await Mina.transaction(senderAccount, () => {
      zkAppInstance.verify(sessionHeader, signature);
    });
    await txn1.prove();
    await txn1.sign([senderKey]).send();

} else {
  // Data is invalid
  console.error('Invalid data:', result.error);
}
