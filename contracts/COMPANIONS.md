# Companions

Experimental companion contracts — not part of the ERC-8414 reference implementation — live in [`/companions`](../companions). First entry: [`InvinoveritasVerdictAuthority.sol`](../companions/InvinoveritasVerdictAuthority.sol), an acceptance-authority relay reviewed and merged in [PR #1](https://github.com/garyyang-finchip/task-token-standard/pull/1).

Second entry: [`InvinoveritasVerdictAuthoritySigned.sol`](../companions/InvinoveritasVerdictAuthoritySigned.sol) with [`Bip340.sol`](../companions/Bip340.sol) — the on-chain BIP-340 follow-up named in PR #1's review. The verdict signature is checked on-chain over a digest built from the kernel's own submission values plus chain, authority and task-contract binding, so anyone may submit and there is no designated relayer. Reviewed and merged in [PR #2](https://github.com/garyyang-finchip/task-token-standard/pull/2).
