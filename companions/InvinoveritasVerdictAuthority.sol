// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

// EXPERIMENTAL — not part of the ERC's reference implementation.
// A companion sketch that composes with the ERC-8414 kernel unchanged. It is not normative,
// and nothing in ERC-8414 depends on it.

import {ITaskTender} from "../contracts/interfaces/ITaskTender.sol";

/// @title  Invinoveritas verdict acceptance authority (experimental ERC-8414 companion)
/// @notice Occupies a task token's acceptance-authority slot and turns a relayed invinoveritas
///         /review verdict into an ordinary judged ruling (acceptFulfillment / rejectFulfillment).
///         It does not decide whether work is good, and it needs no kernel change: an indexer
///         sees normal judged settlement.
///
/// @dev TRUST BOUNDARY, stated exactly.
///
///      Checked on-chain, per call:
///        (a) Parameter consistency. The caller's `expectedTaskVersion` and `expectedResultHash`
///            must equal what `submissionOf` returns for that submission now. This proves the
///            relayer named the right submission. It does NOT authenticate the signed verdict,
///            and it does not prove that the signed payload says `approved`.
///        (b) Window compatibility. `internalWindow` must be strictly shorter than THIS tender's
///            `judgmentWindow`, read from `tenderTermsOf` at relay time, so one instance can serve
///            several tenders and refuses any it does not fit.
///        (c) Relay deadline. No relay after `submittedAt + internalWindow` (widened to uint256).
///            This bars late APPROVALs as well as late REJECTs. It is this contract's own SLA; the
///            kernel itself would still take a late acceptance.
///        (d) One ruling per submission (`ruled`).
///
///      Trusted to the designated relayer:
///        - Authenticity. The verdict is a BIP-340 Schnorr signature over a Nostr kind-30078 event.
///          The relayer verifies it off-chain, and so can anyone else, against invinoveritas's
///          published key (free /verify-proof endpoint). It is not verified here.
///        - Correspondence. That the signed verdict is about this submission's deliverable and that
///          its outcome is `approved`.
///        - Availability. That a verdict is delivered before the relay deadline.
///      On-chain BIP-340 verification, together with complete action/domain binding and
///      permissionless submission, is the proposed next step. It would remove the need for a
///      designated relayer to submit an available valid verdict. It would NOT guarantee that a
///      verdict is produced, published, or included before the deadline; availability stays an
///      operational assumption either way.
///
///      Events. `VerdictRelayed` is emitted in the same transaction as the kernel call and is
///      atomic with it. If the kernel call reverts, the event and `ruled[key]` are rolled back too,
///      and a later valid relay is not blocked. The event is an audit record of committed rulings,
///      not evidence that survives a failed one.
///
///      Liveness and defaults. On the judged path, a missed relay leaves the kernel's default
///      claim (`claimUnjudged`) available once `judgmentWindow` closes, subject to the kernel's own
///      conditions, including epoch pacing (a claim can wait for the next epoch). That is not
///      costless: it can delay settlement, it produces a different record (a default, not an
///      acceptance), and it pays the submitter whether or not the work was good. Silence here never
///      strands the fulfiller, but it costs the demander, so a publisher using this contract MUST
///      size `judgmentWindow` to the relayer's real availability, with operational margin. The
///      window check in (b) is a guard, not a liveness guarantee. It does not block funding or
///      installation of this authority, and it does not disable `claimUnjudged`.
///      All of this applies only to submissions whose `machineSettled` snapshot is false. The
///      kernel routes deadlines off the snapshot taken at delivery, so installing this companion
///      does not turn earlier machine-path submissions into judged-path defaults.
///
///      Authority lifecycle. The kernel lets only the current acceptance authority hand the slot
///      on. This contract exposes no forwarding call for `setAcceptanceAuthority`, so once it is
///      installed for a token the slot cannot be moved to another authority. That is a known
///      limitation of this experimental version. `setRelayer` rotates the relayer key only; it does
///      not replace this contract as the authority. A migration function would need its own
///      authorization design and is out of scope here.
contract InvinoveritasVerdictAuthority {
    error NotRelayer();
    error NotAdmin();
    error SubmissionMismatch();
    error WindowNotInside();
    error WindowExpired();
    error AlreadyRuled();

    /// @notice Audit payload of a committed ruling (see "Events" above). The four verdict fields
    ///         let anyone re-check authenticity against invinoveritas's published key.
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

    /// @notice This contract's relay deadline, per submission. It must be strictly shorter than
    ///         the `judgmentWindow` of every tender it serves (checked per relay), with enough margin
    ///         for the verdict pipeline to finish inside it.
    uint64 public immutable internalWindow;
    address public relayer;
    address public admin;

    /// @dev keccak256(taskContract, tokenId, submissionId) => ruled.
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

    /// @notice Rotate the relayer key. Does not transfer the acceptance-authority slot.
    function setRelayer(address newRelayer) external {
        if (msg.sender != admin) revert NotAdmin();
        emit RelayerChanged(relayer, newRelayer);
        relayer = newRelayer;
    }

    /// @dev Checks (a)-(c) from the contract docs. Split out to keep relayVerdict's stack shallow.
    function _checkRelay(
        ITaskTender taskContract,
        uint256 tokenId,
        uint256 submissionId,
        uint64 expectedTaskVersion,
        bytes32 expectedResultHash
    ) internal view {
        ITaskTender.Submission memory sub = taskContract.submissionOf(tokenId, submissionId);
        if (sub.taskVersion != expectedTaskVersion || sub.resultHash != expectedResultHash) {
            revert SubmissionMismatch();
        }

        uint64 jw = taskContract.tenderTermsOf(tokenId).judgmentWindow;
        if (internalWindow >= jw) revert WindowNotInside();

        uint256 relayDeadline = uint256(sub.submittedAt) + uint256(internalWindow);
        if (block.timestamp > relayDeadline) revert WindowExpired();
    }

    /// @notice Relay one invinoveritas /review verdict into a kernel ruling.
    /// @param taskContract The ERC-8414 deployment (ITaskTender) holding the task token.
    /// @param tokenId Task token whose acceptance authority this contract is.
    /// @param submissionId The submission being ruled on.
    /// @param expectedTaskVersion Must equal `submissionOf(...).taskVersion` (consistency, not authenticity).
    /// @param expectedResultHash Must equal `submissionOf(...).resultHash` (consistency, not authenticity).
    /// @param decisionRef / policyCommitment / artifactHash / signature The raw verdict fields, emitted
    ///        in `VerdictRelayed` for off-chain re-verification.
    /// @param approved true -> acceptFulfillment, false -> rejectFulfillment.
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
        _checkRelay(taskContract, tokenId, submissionId, expectedTaskVersion, expectedResultHash);

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
