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

    // console.log('tlsnProof.session.header:', tlsnProof.session.header);
    const header = Header.serialize(tlsnProof.session.header);
    // console.log('header:', header);
    const headerBytes = header.toBytes();

    console.log('headerBytes:', headerBytes);

    const headerFields: Field[] = [];
    headerBytes.forEach((byte: number) => headerFields.push(Field(byte)));

    // headerFields.fill(Field(0), headerFields.length, 256);

    while (headerFields.length < 256) {
      headerFields.push(Field(0));
    }

    console.log('headerFields:', headerFields);

    // const headerFieldsSig = 2;
    const headerFieldsSig = Signature.fromFields(headerFields);

    const privKey = PrivateKey.fromBase58(
      'EKFSmntAEAPm5CnYMsVpfSEuyNfbXfxy2vHW8HPxGyPPgm5xyRtN'
    );

    // console.log('headerFieldsSig - r: ', headerFieldsSig.r.toBigInt());
    // console.log('headerFieldsSig - s: ', headerFieldsSig.s.toBigInt());

    const pubKey = PublicKey.fromPrivateKey(privKey);

    console.log('pubKey:', pubKey.toBase58());

    const isValid = headerFieldsSig.verify(pubKey, headerFields);

    isValid.assertTrue();

    const signatureBytes = tlsnProof.session.signature.map((byte: number) =>
      Field(byte)
    );

    // while (signatureBytes.length < 256) {
    //   signatureBytes.push(Field(0));
    // }

    // signatureBytes.fill(Field(0), headerFields.length, 256);

    const signatureSig = Signature.fromFields(signatureBytes);

    console.log('signatureSig - r: ', signatureSig.r.toBigInt());
    console.log('signatureSig - s: ', signatureSig.s.toBigInt());

    return {
      signature: signatureSig,
      headerFieldsSig: headerFieldsSig,
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
