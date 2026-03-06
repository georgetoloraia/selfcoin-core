## Consensus History

Earlier SelfCoin development included multiple consensus generations and runtime activation/version-routing experiments.

The active runtime no longer treats consensus as a version-switched protocol. The shipped implementation preserves the previously characterized mainnet behavior as one fixed runtime:

- deterministic proposer selection
- deterministic committee selection
- committee-membership voting
- quorum from committee size
- current validator/bond validation semantics in transaction and block validation

Weighted/VRF routing is not the active shipped mainnet path in this cleaned runtime. Historical activation/signaling code and historical sortition modules have been removed from the runtime tree.
