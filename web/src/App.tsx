import React, { useEffect, useState } from 'react';
import { bcs } from '@mysten/bcs';
import { z } from 'zod';

import { verifier } from './verifier';
import ZkappWorkerClient from './mina/zkappWorkerClient';
import { Field, PublicKey } from 'o1js';

function App() {
  // Use the BCS package here to test its functionality
  const [jsonData, setJsonData] = useState<string | null>(null);
  const [state, setState] = useState({
    zkappWorkerClient: null as null | ZkappWorkerClient,
    hasWallet: null as null | boolean,
    hasBeenSetup: false,
    accountExists: false,
    currentNum: null as null | Field,
    publicKey: null as null | PublicKey,
    zkappPublicKey: null as null | PublicKey,
    creatingTransaction: false,
  });

  useEffect(() => {
    (async () => {
      try {
        const response = await fetch('../simple_proof.json');
        const data = await response.text();
        setJsonData(data);

        const sig = await verifier(data);
        console.log('sig: ', sig);
      } catch (error) {
        console.error('Error fetching JSON data:', error);
      }
    })();
  }, []);

  return (
    <div>
      <h1>BCS Test</h1>
      {jsonData ? <pre>{jsonData}</pre> : <p>Loading JSON data...</p>}
    </div>
  );
}

export default App;
