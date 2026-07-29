# Echo clean-room and self-developed boundary

Echo's implementation, names, state transitions, runtime contract, tests, and
documentation are maintained in this repository. Public research and projects
may inform high-level principles such as event logging, least privilege,
capability authorization, bounded execution, and human review, but their code,
prompts, examples, API shapes, class names, and test fixtures are not copied.

Repository contributors must:

- record relevant research and dependency provenance in `ORIGIN_LEDGER.md`;
- keep third-party notices and generated SBOM/license evidence current;
- avoid adding source with unknown provenance or an incompatible license;
- add new behavior through Echo's runtime/effect/ledger contracts instead of
  importing another agent runtime;
- keep claims limited to evidence that can be reproduced from this checkout.

This document is an engineering clean-room control, not a legal opinion. A
claim of legal clearance or GitHub stable readiness still requires independent
FTO and clean-room review. External security audit and red-team sign-off also
remain separate release gates.

