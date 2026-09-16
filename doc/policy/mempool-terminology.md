## Fee and Size Terminology in Mempool Policy

 * Each transaction has a **weight** and virtual size as defined in BIP 141 (different from serialized size for witness transactions, as witness data is discounted and the value is rounded up to the nearest integer).

   * In the RPCs, "weight", refers to the weight as defined in BIP 141.

 * A transaction's **virtual size (vsize)** is its BIP 141 weight divided by four and rounded up.

   * Mempool entry data with the suffix "-size" (eg "ancestorsize") refer to the cumulative virtual size of the transactions in the associated set.

 * Mempool entry data with the suffix "-weight" (eg "chunkweight", "clusterweight") refer to BIP 141 transaction weight.

 * A transaction's **base fee** is the difference between its input and output values.

 * A transaction's **modified fee** is its base fee added to any **fee delta** introduced by using the `prioritisetransaction` RPC. Modified fee is used internally for all fee-related mempool policies and block building.
