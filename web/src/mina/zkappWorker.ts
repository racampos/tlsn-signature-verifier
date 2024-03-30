import { Field, Mina, PublicKey, Signature, fetchAccount } from 'o1js';

type Transaction = Awaited<ReturnType<typeof Mina.transaction>>;

// ---------------------------------------------------------------------------------------

import type { TlsnVerifier } from '../../../src/TlsnVerifier.js';

const state = {
  TlsnVerifier: null as null | typeof TlsnVerifier,
  zkapp: null as null | TlsnVerifier,
  transaction: null as null | Transaction,
};

interface VerifySessionHeaderArgs {
  sessionHeader: Field[];
  signature: Signature;
}

// ---------------------------------------------------------------------------------------

const functions = {
  setActiveInstanceToBerkeley: async () => {
    const Berkeley = Mina.Network(
      'https://api.minascan.io/node/berkeley/v1/graphql'
    );
    console.log('Berkeley Instance Created');
    Mina.setActiveInstance(Berkeley);
  },
  loadContract: async () => {
    const { TlsnVerifier } = await import('../../../src/TlsnVerifier.js');
    state.TlsnVerifier = TlsnVerifier;
  },
  compileContract: async () => {
    if (!state.TlsnVerifier) {
      throw new Error('Contract not loaded.');
    }

    await state.TlsnVerifier.compile();
  },
  fetchAccount: async (args: { publicKey58: string }) => {
    const publicKey = PublicKey.fromBase58(args.publicKey58);
    return await fetchAccount({ publicKey });
  },
  initZkappInstance: async (args: { publicKey58: string }) => {
    const publicKey = PublicKey.fromBase58(args.publicKey58);

    if (!state.TlsnVerifier) {
      throw new Error('Contract not loaded.');
    }

    state.zkapp = new state.TlsnVerifier(publicKey);
  },
  getNotaryPublicKey: async () => {
    if (!state.zkapp) {
      throw new Error('Contract not initialized.');
    }

    const notaryPublicKey = await state.zkapp.notaryPublicKey.get();
    return JSON.stringify(notaryPublicKey.toJSON());
  },
  verifySessionHeader: async (args: VerifySessionHeaderArgs) => {
    const transaction = await Mina.transaction(() => {
      if (!state.zkapp) {
        throw new Error('Contract not initialized.');
      }

      state.zkapp.verify(args.sessionHeader, args.signature);
    });
    state.transaction = transaction;
  },
  proveSessionHeader: async () => {
    if (!state.transaction) {
      throw new Error('Transaction not initialized.');
    }

    await state.transaction.prove();
  },
  getTransactionJSON: async () => {
    if (!state.transaction) {
      throw new Error('Transaction not initialized.');
    }

    return state.transaction.toJSON();
  },
};

// ---------------------------------------------------------------------------------------

export type WorkerFunctions = keyof typeof functions;

export type ZkappWorkerRequest = {
  id: number;
  fn: WorkerFunctions;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  args: any;
};

export type ZkappWorkerReponse = {
  id: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any;
};

if (typeof window !== 'undefined') {
  addEventListener(
    'message',
    async (event: MessageEvent<ZkappWorkerRequest>) => {
      const returnData = await functions[event.data.fn](event.data.args);

      const message: ZkappWorkerReponse = {
        id: event.data.id,
        data: returnData,
      };
      postMessage(message);
    }
  );
}

console.log('Web Worker Successfully Initialized.');
