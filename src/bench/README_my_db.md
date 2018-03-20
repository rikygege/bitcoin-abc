
Leveldb in /Optane/chainstate, which is mounted on Optane SSD 9 (280GB)
    1. 1G UTXOs use feed uint256S("8e8b4cf3e4df8b332057e3e23af42ebc663b61e0495d5e7e32d85"), and the txout.scriptPubKey uses the RandomScript();
    2. 1G UTXOs use feed1 uint256S("8d75a32e8858f12307c362bcb3f76c0e645d360b0587569a49c5068efccf83fc"), and the txout.scriptPubKey uses the P2PKSH :OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;
    3. We use the entry.n to differentiate the fake UTXOs. The entry.n increase from 0 to 1G;
    4. We use multi-thread to random read the database.
    5. bench WriteMyDb() construct the database
    6. bench ReadMyDb() read the database
