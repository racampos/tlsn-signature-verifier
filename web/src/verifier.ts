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

interface BytesArrDiff {
  index: number;
  header: number;
  headerCopy: number;
}

interface Base58ArrDiff {
  index: number;
  header: string;
  headerCopy: string;
}

export async function verifier(jsonData: string) {
  // Parse the JSON data
  const parsedData = JSON.parse(jsonData);

  console.log('parsedData:', parsedData);

  parsedData.session.header.handshake_summary.server_public_key.group = [0, 65];

  // Validate the parsed data using Zod
  const result = RootSchema.safeParse(parsedData); // works

  if (result.success) {
    // Data is valid
    const tlsnProof = result.data;
    console.log('Valid data:', tlsnProof);

    const Header = bcs.struct('Header', {
      encoder_seed: bcs.fixedArray(32, bcs.u8()),
      merkle_root: bcs.fixedArray(32, bcs.u8()),
      sent_len: bcs.u64(),
      recv_len: bcs.u64(),
      handshake_summary: bcs.struct('handshake_summary', {
        time: bcs.u64(),
        server_public_key: bcs.struct('server_public_key', {
          group: bcs.fixedArray(2, bcs.u8()),
          key: bcs.fixedArray(65, bcs.u8()),
        }),
        handshake_commitment: bcs.fixedArray(32, bcs.u8()),
      }),
    });

    const header = Header.serialize(tlsnProof.session.header);

    const headerBytes = header.toBytes();

    const headerFields: Field[] = [];
    headerBytes.forEach((byte: number) => headerFields.push(Field(byte)));

    const privKey = PrivateKey.fromBase58(
      'EKFSmntAEAPm5CnYMsVpfSEuyNfbXfxy2vHW8HPxGyPPgm5xyRtN'
    );

    const pubKey = PublicKey.fromPrivateKey(privKey);

    const rustSignature = Signature.fromBase58(tlsnProof.session.signature);
    const isValid = rustSignature.verify(pubKey, headerFields);
    console.log('isValid:', isValid.toBoolean());

    // console.log('signature - r: ', rustSignature.r.toBigInt());
    // console.log('signature - s: ', rustSignature.s.toBigInt());
    // console.log('rustSignature - toBase58: ', rustSignature.toBase58());

    // const o1jsSignature = Signature.create(privKey, headerFields);

    // console.log('o1jsSignature:', o1jsSignature);
    // console.log('o1jsSignature - r: ', o1jsSignature.r.toBigInt());
    // console.log('o1jsSignature - s: ', o1jsSignature.s.toBigInt());
    // console.log('o1jsSignature - toBase58: ', o1jsSignature.toBase58());

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
