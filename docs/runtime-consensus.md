## Runtime Consensus

The active SelfCoin runtime follows one fixed consensus path.

- Proposer path: deterministic leader selection from finalized chain state.
- Committee path: deterministic committee selection from finalized chain state.
- Vote rule: only committee members vote; votes are tracked per `(height, round, block_id)`.
- Quorum rule: `quorum_threshold(committee.size())`.
- Validation semantics: transaction and block validation use the current validator/bond rules, including variable validator bond bounds.

This document describes the shipped runtime behavior, not older development-era consensus experiments.
