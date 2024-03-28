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

const useProof = false;
const Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
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

// Your JSON string would typically come from somewhere; assuming it's loaded as a constant here:
const sessionHeaderJson = `
{
  "header": {
    "encoder_seed": [100, 125, 53, 53, 52, 70, 100, 124, 143, 252, 168, 128, 196, 148, 157, 181, 206, 27, 18, 128, 44, 57, 32, 206, 159, 47, 190, 174, 92, 198, 97, 117],
    "merkle_root": [121, 176, 177, 165, 167, 203, 209, 250, 148, 247, 24, 196, 131, 197, 99, 77, 140, 141, 143, 89, 177, 113, 226, 87, 174, 187, 165, 92, 8, 127, 123, 34],
    "sent_len": 211,
    "recv_len": 1615,
    "handshake_summary": {
      "time": 1711578768,
      "server_public_key": {
        "group": "secp256r1",
        "key": [4, 151, 64, 35, 141, 208, 77, 198, 22, 76, 58, 99, 133, 238, 84, 87, 211, 93, 184, 18, 138, 115, 179, 4, 103, 48, 52, 208, 185, 34, 132, 128, 152, 200, 58, 163, 139, 142, 24, 91, 234, 19, 201, 224, 84, 184, 215, 203, 200, 233, 136, 254, 180, 241, 247, 209, 83, 156, 169, 102, 116, 200, 61, 29, 87]
      },
      "handshake_commitment": [190, 147, 90, 4, 97, 100, 176, 7, 169, 50, 189, 253, 171, 67, 220, 186, 52, 193, 7, 186, 253, 169, 145, 217, 37, 81, 224, 97, 87, 27, 232, 189]
    }
  }
}`;

// Parse the JSON string
const parsedHeaderJson = JSON.parse(sessionHeaderJson);

// Accessing the header object
const header = parsedHeaderJson.header;

// Concatenating all the byte arrays into one
const serializedHeader = [
  ...header.encoder_seed,
  ...header.merkle_root,
  ...header.handshake_summary.server_public_key.key,
  ...header.handshake_summary.handshake_commitment,
];

console.log(serializedHeader);

const serializedHeaderField = serializedHeader.map((byte: number) => Field(byte));

// The JSON string containing the signature
const signatureJson = `
{
  "signature": [
    35, 241, 217, 221, 152, 91, 147, 121, 153, 135, 8, 83, 177, 72, 21, 241, 67, 127, 50, 250,
    185, 210, 102, 136, 107, 0, 193, 4, 155, 84, 208, 17, 189, 191, 79, 11, 139, 235, 228, 26,
    109, 232, 84, 188, 73, 79, 217, 37, 66, 67, 73, 85, 98, 143, 153, 119, 148, 20, 110, 54,
    100, 127, 113, 47
  ]
}`;

// Parse the JSON string
const parsedSignatureJson = JSON.parse(signatureJson);

// Accessing the signature array directly
const serializedSignature = parsedSignatureJson.signature;

console.log(serializedSignature);

const serializedSignatureField = serializedSignature.map((byte: number) => Field(byte));


const signature = Signature.fromFields(serializedSignatureField);

const txn1 = await Mina.transaction(senderAccount, () => {
zkAppInstance.verify(serializedHeaderField, signature);
});
await txn1.prove();

await txn1.sign([senderKey]).send();
