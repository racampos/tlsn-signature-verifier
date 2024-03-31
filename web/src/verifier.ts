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

  console.log(
    'parsedData.session.header.handshake_summary.server_public_key.group:',
    parsedData.session.header.handshake_summary.server_public_key.group
  );

  parsedData.session.header.handshake_summary.server_public_key.group = [0, 65];

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

    // const headerBytes = [97, 180, 179, 127, 143, 171, 102, 152, 12, 59, 30, 146, 214, 137, 234, 111, 0, 180, 236, 192, 40, 87, 95, 255, 249, 138, 80, 210, 9, 6, 34, 2, 97, 139, 99, 106, 123, 249, 206, 146, 169, 198, 0, 174, 41, 126, 8, 238, 130, 46, 92, 151, 46, 11, 233, 54, 185, 122, 67, 82, 197, 205, 229, 10, 211, 0, 0, 0, 0, 0, 0, 0, 90, 6, 0, 0, 0, 0, 0, 0, 151, 117, 8, 102, 0, 0, 0, 0, 0, 65, 4, 231, 210, 182, 148, 213, 174, 89, 198, 143, 22, 197, 201, 169, 156, 123, 94, 113, 18, 56, 63, 125, 7, 3, 118, 89, 66, 71, 211, 155, 64, 160, 39, 38, 113, 147, 132, 89, 110, 91, 76, 24, 155, 200, 79, 46, 189, 161, 201, 177, 204, 234, 177, 51, 187, 189, 213, 22, 120, 205, 214, 122, 210, 73, 141, 161, 24, 170, 137, 111, 237, 52, 38, 249, 233, 16, 140, 202, 239, 240, 109, 32, 231, 22, 13, 10, 64, 67, 130, 27, 165, 166, 160, 167, 209, 206, 67];

    const headerBytesCopy = [
      247, 249, 197, 68, 116, 126, 246, 208, 99, 167, 35, 37, 239, 47, 240, 171,
      234, 150, 169, 89, 179, 211, 149, 146, 4, 30, 50, 248, 221, 78, 0, 187,
      136, 218, 206, 215, 174, 228, 230, 205, 168, 97, 80, 105, 71, 244, 70, 41,
      101, 76, 156, 170, 130, 243, 41, 244, 212, 150, 48, 158, 184, 94, 236,
      152, 211, 0, 0, 0, 0, 0, 0, 0, 79, 6, 0, 0, 0, 0, 0, 0, 96, 206, 8, 102,
      0, 0, 0, 0, 0, 65, 4, 237, 73, 139, 95, 205, 99, 70, 184, 43, 85, 187,
      207, 54, 115, 71, 60, 38, 168, 23, 56, 10, 237, 18, 153, 47, 106, 106,
      127, 24, 179, 75, 98, 163, 14, 178, 238, 18, 217, 40, 204, 23, 24, 184,
      186, 234, 19, 254, 235, 64, 158, 2, 129, 252, 105, 131, 26, 63, 126, 114,
      137, 237, 37, 173, 136, 139, 245, 59, 254, 42, 246, 128, 93, 216, 66, 248,
      191, 174, 91, 109, 37, 32, 232, 106, 67, 151, 53, 237, 245, 179, 70, 99,
      123, 249, 18, 92, 119,
    ];

    const headerBase58Copy =
      '5VpG2FTksdhzZifDhL2aVZPSjHLeaCzwU4yHbcwx4UkB5mrco65iR1TtjH4FvrsTmUfnaQjVNnEyL39ezoCxiJyPGsLaSReKKMaBNDNi9pLLGYmiKDwtURYcXgfUN719K761PUMKkkARopMEVvzbXQ4ryU2TQEoJ2FNyfhtFWRwp63hJusbGu62csCC3qzorZxoZYRzvx9Ns7sDduW7Vv4CjfBx6oaV4bkRWGCraDxyJkgED3DvkY3AosW9AkGSi';

    const headerBytes = header.toBytes();
    const headerBase58 = header.toBase58();

    const uint8ArrBytes = Uint8Array.from(headerBytes);
    const uint8ArrBytesCopy = Uint8Array.from(headerBytesCopy);

    console.log('headerBase58', headerBase58);
    console.log('headerBase58.length', headerBase58.length);
    console.log('headerBase58Copy', headerBase58Copy);
    console.log('headerBase58Copy.length', headerBase58Copy.length);
    console.log('--------------------');
    console.log('uint8ArrBytes: ', uint8ArrBytes);
    console.log('uint8ArrBytes.length: ', uint8ArrBytes.length);
    console.log('uint8ArrBytesCopy: ', uint8ArrBytesCopy);
    console.log('uint8ArrBytesCopy.length: ', uint8ArrBytesCopy.length);

    let bytesArrOff: BytesArrDiff[] = [];
    let base58ArrOff: Base58ArrDiff[] = [];

    headerBytes.forEach((byte: number, i) => {
      if (byte !== headerBytesCopy[i]) {
        bytesArrOff.push({
          index: i,
          header: byte,
          headerCopy: uint8ArrBytesCopy[i],
        });
      }
    });

    headerBase58.split('').forEach((char: string, i) => {
      if (char !== headerBase58Copy[i]) {
        base58ArrOff.push({
          index: i,
          header: char,
          headerCopy: headerBase58Copy[i],
        });
      }
    });

    console.log('--------------------');
    console.log('bytesArrOff: ', bytesArrOff);
    console.log('base58ArrOff: ', base58ArrOff);
    console.log('--------------------');

    // console.log('header58: ', headerBase58);
    // console.log('headerBytes:', headerBytes);

    const headerFields: Field[] = [];
    headerBytes.forEach((byte: number) => headerFields.push(Field(byte)));

    const headerFieldsStr = headerFields.map((field) => field.toString());

    // console.log('headerFields:', headerFieldsStr);

    const privKey = PrivateKey.fromBase58(
      'EKFSmntAEAPm5CnYMsVpfSEuyNfbXfxy2vHW8HPxGyPPgm5xyRtN'
    );

    const pubKey = PublicKey.fromPrivateKey(privKey);

    // console.log('pubKey:', pubKey.toBase58());

    const rustSignature = Signature.fromBase58(tlsnProof.session.signature);
    const isValid = rustSignature.verify(pubKey, headerFields);
    // isValid.assertTrue();

    console.log('signature - r: ', rustSignature.r.toBigInt());
    console.log('signature - s: ', rustSignature.s.toBigInt());
    console.log('rustSignature - toBase58: ', rustSignature.toBase58());

    const o1jsSignature = Signature.create(privKey, headerFields);

    console.log('o1jsSignature:', o1jsSignature);
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
