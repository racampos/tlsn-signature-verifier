import {
    Field,
    SmartContract,
    state,
    State,
    method,
    Signature,
    PublicKey
} from 'o1js';

export class TlsnVerifier extends SmartContract {
    @state(PublicKey) notaryPublicKey = State<PublicKey>();

    @method verify(
        sessionHeader: Field[],
        signature: Signature
    ) {
    // Get the notary public key from the contract state
    const notaryPublicKey = this.notaryPublicKey.getAndRequireEquals();

    // Evaluate whether the signature is valid for the provided data
    const validSignature = signature.verify(notaryPublicKey, sessionHeader);
    validSignature.assertTrue();
    }
}