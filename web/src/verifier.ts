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
import fs from 'fs';
import { z } from 'zod';
import { RootSchema } from '../../src/schemas';
import { TlsnVerifier } from '../../src/TlsnVerifier';

import { bcs } from '@mysten/bcs';

import stableStringify from 'json-stable-stringify';

export async function verifier(jsonData: string) {
  // Parse the JSON data
  const parsedData = JSON.parse(jsonData);

  // Validate the parsed data using Zod
  const result = RootSchema.safeParse(parsedData); // works

  if (result.success) {
    // Data is valid
    const tlsnProof = result.data;
    console.log('Valid data:', tlsnProof);

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

    // // create an instance of Square - and deploy it to zkAppAddress
    // const zkAppInstance = new TlsnVerifier(zkAppAddress);
    // const deployTxn = await Mina.transaction(deployerAccount, () => {
    //   AccountUpdate.fundNewAccount(deployerAccount);
    //   zkAppInstance.deploy();
    // });
    // await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
    // // get the initial state of Square after deployment
    // const notaryPublicKey = zkAppInstance.notaryPublicKey.get();
    // console.log('state after init:', notaryPublicKey.toString());

    // ----------------------------------------------------
    // Serialize the header object in a deterministic manner

    const Header = bcs.struct('Header', {
      encoder_seed: bcs.fixedArray(32, bcs.u8()),
      merkle_root: bcs.fixedArray(32, bcs.u8()),
      sent_len: bcs.u64(),
      recv_len: bcs.u64(),
      handshake_summary: bcs.struct('HandshakeSummary', {
        time: bcs.u64(),
        server_public_key: bcs.struct('ServerPublicKey', {
          group: bcs.string(),
          key: bcs.fixedArray(65, bcs.u8()),
        }),
        handshake_commitment: bcs.fixedArray(32, bcs.u8()),
      }),
    });

    const header = Header.serialize(tlsnProof.session.header);
    const headerBytes = header.toBytes();
    // const headerBytes = [97, 180, 179, 127, 143, 171, 102, 152, 12, 59, 30, 146, 214, 137, 234, 111, 0, 180, 236, 192, 40, 87, 95, 255, 249, 138, 80, 210, 9, 6, 34, 2, 97, 139, 99, 106, 123, 249, 206, 146, 169, 198, 0, 174, 41, 126, 8, 238, 130, 46, 92, 151, 46, 11, 233, 54, 185, 122, 67, 82, 197, 205, 229, 10, 211, 0, 0, 0, 0, 0, 0, 0, 90, 6, 0, 0, 0, 0, 0, 0, 151, 117, 8, 102, 0, 0, 0, 0, 0, 65, 4, 231, 210, 182, 148, 213, 174, 89, 198, 143, 22, 197, 201, 169, 156, 123, 94, 113, 18, 56, 63, 125, 7, 3, 118, 89, 66, 71, 211, 155, 64, 160, 39, 38, 113, 147, 132, 89, 110, 91, 76, 24, 155, 200, 79, 46, 189, 161, 201, 177, 204, 234, 177, 51, 187, 189, 213, 22, 120, 205, 214, 122, 210, 73, 141, 161, 24, 170, 137, 111, 237, 52, 38, 249, 233, 16, 140, 202, 239, 240, 109, 32, 231, 22, 13, 10, 64, 67, 130, 27, 165, 166, 160, 167, 209, 206, 67];

    console.log('headerBytes:', headerBytes);

    const headerFields: Field[] = [];
    headerBytes.forEach((byte: number) => headerFields.push(Field(byte)));

    const headerFieldsStr = headerFields.map((field) => field.toString());

    console.log('headerFields:', headerFieldsStr);

    const privKey = PrivateKey.fromBase58(
      'EKFSmntAEAPm5CnYMsVpfSEuyNfbXfxy2vHW8HPxGyPPgm5xyRtN'
    );

    const pubKey = PublicKey.fromPrivateKey(privKey);

    console.log('pubKey:', pubKey.toBase58());

    const rustSignature = Signature.fromBase58(tlsnProof.session.signature);
    const isValid = rustSignature.verify(pubKey, headerFields);
    isValid.assertTrue();

    console.log('signature - r: ', rustSignature.r.toBigInt());
    console.log('signature - s: ', rustSignature.s.toBigInt());

    const o1jsSignature = Signature.create(privKey, headerFields);
    console.log('o1jsSignature - r: ', o1jsSignature.r.toBigInt());
    console.log('o1jsSignature - s: ', o1jsSignature.s.toBigInt());
    console.log('o1jsSignature - toBase58: ', o1jsSignature.toBase58());

    return {
      signature: rustSignature,
      headerFields: headerFields,
    };

    // const txn1 = await Mina.transaction(senderAccount, () => {
    //   zkAppInstance.verify(headerFields, signature);
    // });
    // await txn1.prove();

    // await txn1.sign([senderKey]).send();
  } else {
    // Data is invalid
    console.error('Invalid data:', result.error);
  }
}
