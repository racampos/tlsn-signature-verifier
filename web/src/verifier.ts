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
  Provable,
  Struct,
} from 'o1js';
import fs from 'fs';
import { z } from 'zod';
import { RootSchema } from '../../src/schemas';
import { SessionHeader } from '../../src/SessionHeader';

export async function verifier(jsonData: string) {
  // Parse the JSON data
  const parsedData = JSON.parse(jsonData);

  console.log('parsedData:', parsedData);

  parsedData.session.header.handshake_summary.server_public_key.group = [0, 65];

  // Validate the parsed data using Zod
  const result = RootSchema.safeParse(parsedData); // works

  function numberToBytes(num) {
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

  if (result.success) {
    // Data is valid
    const tlsnProof = result.data;
    console.log('Valid data:', tlsnProof);

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

    const pubKey = PublicKey.fromBase58("B62qowWuY2PsBZsm64j4Uu2AB3y4L6BbHSvtJcSLcsVRXdiuycbi8Ws");
    const rustSignature = Signature.fromBase58(tlsnProof.session.signature.MinaSchnorr);
    const isValid = rustSignature.verify(pubKey, sessionHeader.toFields());
    console.log('isValid:', isValid.toBoolean());


    // const Local = Mina.LocalBlockchain({ proofsEnabled: false });
    // Mina.setActiveInstance(Local);
    // const { privateKey: deployerKey, publicKey: deployerAccount } =
    //   Local.testAccounts[0];
    // const { privateKey: senderKey, publicKey: senderAccount } =
    //   Local.testAccounts[1];
    // // ----------------------------------------------------

    // // Create a public/private key pair. The public key is your address and where you deploy the zkApp to
    // const zkAppPrivateKey = PrivateKey.random();
    // const zkAppAddress = zkAppPrivateKey.toPublicKey();

    // create an instance of Square - and deploy it to zkAppAddress
    // const zkAppInstance = new TlsnVerifier(zkAppAddress);
    // const deployTxn = await Mina.transaction(deployerAccount, () => {
    //   AccountUpdate.fundNewAccount(deployerAccount);
    //   zkAppInstance.deploy();
    // });
    // await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();

    // const notaryPublicKey = zkAppInstance.notaryPublicKey.get();
    // console.log('state after init:', notaryPublicKey.toString());


    // const txn1 = await Mina.transaction(senderAccount, () => {
    //   zkAppInstance.verify(headerFields, rustSignature);
    // });
    // await txn1.prove();
    // await txn1.sign([senderKey]).send();

    return {
      signature: rustSignature,
      headerFields: sessionHeader,
    };

  } else {
    // Data is invalid
    console.error('Invalid data:', result.error);
  }
}
