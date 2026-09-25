// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {ITaskTender} from "../interfaces/ITaskTender.sol";

/// @title  Invinoveritas verdict acceptance authority — a judgment-execution attestation
///         companion for ERC-9999 (TASK-KERNEL v3.0).
/// @notice Occupies the acceptanceAuthorityOf slot for a task token. Does not itself decide
///         whether work is good — it relays a signed, independently-recomputable verdict from
///         invinoveritas's /review verification layer into a kernel ruling, binding that
///         verdict cryptographically to the exact submission (taskVersion + resultHash) it
///         answers, and enforcing an internal decision deadline strictly shorter than the
///         tender's own `judgmentWindow`, per this ERC's "Composing an external judging
///         contract's own timeout" rule in Security Considerations.
///
///         The kernel-side composition this relies on, unchanged: this contract IS the
///         acceptance authority (calls acceptFulfillment/rejectFulfillment only when its own
///         checks pass, so the kernel needs no modification and an indexer sees ordinary judged
///         settlement); it reads `submissionOf(...).taskVersion` off the kernel itself, so it
///         always knows exactly which committed criteria bytes a verdict answers to without
///         being told twice; and it holds its own deadline strictly inside `judgmentWindow`, so
///         a verdict that never arrives resolves the same way any other judge's silence does —
///         the fulfiller claims via `claimUnjudged` on the kernel, not through this contract.
///         Precision, not overclaim (real gap named on t/29597#14, confirmed against the kernel
///         source directly before writing this): under epoch pacing, "resolves" can mean
///         "resolves once `claimUnjudged`'s own epoch-exhaustion check next clears," not
///         instantly the moment `judgmentWindow` closes — this contract inherits that timing
///         exactly as any other silent judge would, it does not add or remove delay of its own.
///
/// @dev HONEST TWO-LAYER TRUST MODEL — stated explicitly rather than overclaimed, matching the
///      account's own REPRODUCED-vs-VERIFIED discipline (WYRIWE):
///
///      LAYER 1, fully trustless, enforced HERE on-chain, no trust in the relayer for either
///      check:
///        (a) BINDING — a relayed verdict must cite the exact `taskVersion` and `resultHash`
///            `submissionOf` currently returns for that submission. A verdict computed against
///            a different version or a different deliverable is refused, not silently accepted.
///        (b) DEADLINE — a verdict arriving after `internalWindow` (configured strictly shorter
///            than the tender's `judgmentWindow` at deployment) is refused, never accepted late.
///            The fulfiller's protection is the kernel's own `claimUnjudged`, exactly as if no
///            acceptance authority existed at all, so this contract failing into silence never
///            strands the FULFILLER. It is not free for the DEMANDER: under the deadline default a
///            judge's lapse pays the submitter, junk included (ERC-8414 Security Considerations,
///            "the only unpaid exit from a reservation is a rejection in time"). This relay's
///            liveness is therefore load-bearing for `internalWindow` per submission, like any
///            judge's: a publisher using it MUST size `judgmentWindow` to the relayer's real
///            availability, and an outage here is paid for in rejections that never land. Under
///            epoch pacing the claim itself can be queued to the next epoch (the kernel's own
///            documented behavior, which also caps extraction at maxCompletionsPerEpoch x
///            rewardPerCompletion per epoch) -- worth knowing, not changed by this contract.
///
///      LAYER 2, off-chain-verified today, on-chain-recomputable by anyone: the verdict's own
///      AUTHENTICITY — that invinoveritas actually signed this exact
///      (decisionRef, policyCommitment, artifactHash) triple — is a BIP-340 schnorr signature
///      over a Nostr kind-30078 event, verified off-chain (by the relayer, and independently by
///      anyone else) against invinoveritas's published pubkey via the free, no-auth
///      /verify-proof endpoint, NOT verified inside this contract. Full on-chain BIP-340
///      verification against that exact curve is real, disclosed future work — not silently
///      assumed done. What this contract guarantees on-chain regardless: the complete verdict
///      payload (decisionRef, policyCommitment, artifactHash, and the raw signature bytes) is
///      emitted verbatim in `VerdictRelayed`, immutably, before the ruling call — so the
///      authenticity check layer 2 depends on is never something only the relayer could ever
///      redo. "The judge said yes, and anyone can recompute why" holds without trusting this
///      contract's relayer or invinoveritas itself for the recompute step — only for the initial
///      relay. Removing that remaining trust step (relayer-submits) is exactly the natural
///      companion work this contract's own docstring names as a v2 direction: on-chain BIP-340
///      verification would let `relayVerdict` become fully permissionless.
contract InvinoveritasVerdictAuthority {
    error NotRelayer();
    error NotAdmin();
    error SubmissionMismatch();
    error WindowExpired();
    error AlreadyRuled();

    /// @notice The full verdict payload, emitted before the kernel call — this is the
    ///         recompute surface. Any observer can take these four fields to
    ///         invinoveritas's public /verify-proof endpoint (or verify the BIP-340 schnorr
    ///         signature directly against the published pubkey with any Nostr library) and
    ///         confirm authenticity themselves, independent of this contract or its relayer.
    event VerdictRelayed(
        address indexed taskContract,
        uint256 indexed tokenId,
        uint256 indexed submissionId,
        bytes32 decisionRef,
        bytes32 policyCommitment,
        bytes32 artifactHash,
        bool approved,
        bytes signature
    );

    event RelayerChanged(address indexed previousRelayer, address indexed newRelayer);

    /// @notice MUST be configured strictly less than the target tender's own `judgmentWindow`,
    ///         with enough margin that this contract's own off-chain verdict pipeline
    ///         (running /review, then relaying) can realistically finish inside it — the same
    ///         margin obligation this ERC places on any external judging contract's internal
    ///         timeout. A window configured too close to `judgmentWindow` risks the kernel's own
    ///         default-to-acceptance firing before a genuine REJECT verdict can land, which
    ///         silently converts a real rejection into a paid claim.
    uint64 public immutable internalWindow;
    address public relayer;
    address public admin;

    /// @dev keccak256(taskContract, tokenId, submissionId) => already ruled. One relay per
    ///      submission — a second verdict on an already-ruled submission is refused rather than
    ///      silently ignored, since the kernel itself would revert on a double-settlement
    ///      attempt anyway; this just fails earlier and more legibly.
    mapping(bytes32 => bool) public ruled;

    constructor(uint64 _internalWindow, address _relayer) {
        internalWindow = _internalWindow;
        relayer = _relayer;
        admin = msg.sender;
    }

    modifier onlyRelayer() {
        if (msg.sender != relayer) revert NotRelayer();
        _;
    }

    /// @notice Rotate the trusted relayer address. Layer-2 trust (verdict authenticity) is
    ///         currently anchored here, not in this contract's own logic — rotating it is an
    ///         operational key-management act, not a protocol upgrade.
    function setRelayer(address newRelayer) external {
        if (msg.sender != admin) revert NotAdmin();
        emit RelayerChanged(relayer, newRelayer);
        relayer = newRelayer;
    }

    /// @notice Relay one invinoveritas /review verdict into a kernel ruling.
    /// @param taskContract The ERC-9999 deployment (ITaskTender) this task token lives on.
    /// @param tokenId The task token id whose acceptance authority this contract occupies.
    /// @param submissionId The submission this verdict rules on.
    /// @param expectedTaskVersion MUST equal `submissionOf(tokenId, submissionId).taskVersion`
    ///        at call time — binds the verdict to the exact committed criteria bytes it was
    ///        actually run against, not whatever the binding has since moved to.
    /// @param expectedResultHash MUST equal `submissionOf(tokenId, submissionId).resultHash` —
    ///        binds the verdict to the exact deliverable it actually reviewed.
    /// @param decisionRef / policyCommitment / artifactHash / signature: the raw invinoveritas
    ///        /review verdict fields, emitted verbatim (see VerdictRelayed) so authenticity is
    ///        independently recomputable by anyone via /verify-proof, not just assertable by
    ///        this contract.
    /// @param approved true relays as acceptFulfillment, false as rejectFulfillment.
    function relayVerdict(
        ITaskTender taskContract,
        uint256 tokenId,
        uint256 submissionId,
        uint64 expectedTaskVersion,
        bytes32 expectedResultHash,
        bytes32 decisionRef,
        bytes32 policyCommitment,
        bytes32 artifactHash,
        bool approved,
        bytes calldata signature
    ) external onlyRelayer {
        bytes32 key = keccak256(abi.encode(address(taskContract), tokenId, submissionId));
        if (ruled[key]) revert AlreadyRuled();

        ITaskTender.Submission memory sub = taskContract.submissionOf(tokenId, submissionId);
        if (sub.taskVersion != expectedTaskVersion || sub.resultHash != expectedResultHash) {
            revert SubmissionMismatch();
        }
        if (block.timestamp > sub.submittedAt + internalWindow) revert WindowExpired();

        ruled[key] = true;

        emit VerdictRelayed(
            address(taskContract), tokenId, submissionId,
            decisionRef, policyCommitment, artifactHash, approved, signature
        );

        if (approved) {
            taskContract.acceptFulfillment(tokenId, submissionId);
        } else {
            taskContract.rejectFulfillment(tokenId, submissionId);
        }
    }
}
