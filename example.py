from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine


if __name__ == '__main__':

    tree = MerkleTree()

    # Populate tree with some records
    for data in [b'apple', b'banana', b'pear', b'mango', b'lime']:
        tree.encrypt(data)

    print(tree)

    # Prove and verify encryption of `banana`
    challenge = b'113b1cd81fbaf46c16cfa07e7ac8eb414cf2a5ac25c133dbe64be9499020de4f'
    proof = tree.generate_audit_proof(challenge)
    print("The proof value is: " + str(proof.verify()))

    # Prove and verify encryption of `lime`
    # Your code goes here
    challenge1=b'c6eaba71aa0235d9882df6b665dc8da39cc1a9773e1ebadbefe55a7fafeee1f7'
    #challenge = HashEngine(**tree.get_config()).hash(b'lime')
    proof1=tree.generate_audit_proof(challenge1)
    print("The proof value is:" +str(proof1.verify()))
    #if(challenge1==challenge):
    #		print('True')

    

    # Save current tree state
    state = tree.get_root_hash()

    # Append further leaves
    for data in [b'watermelon', b'kiwi', b'strawberry']:
        tree.encrypt(data)

    # Prove and verify saved state
    # Your code goes here
    proof2 = tree.generate_consistency_proof(challenge=state)
    print(proof2)
    print(proof2.verify())
    serialized = proof2.serialize()
    print(serialized)


