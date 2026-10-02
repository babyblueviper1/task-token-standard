// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

// EXPERIMENTAL — not part of the ERC's reference implementation.
// A companion sketch that composes with the ERC-8414 kernel unchanged. It is not normative,
// and nothing in ERC-8414 depends on it.

import {ITaskTender} from "../contracts/interfaces/ITaskTender.sol";
import {ITaskToken} from "../contracts/interfaces/ITaskToken.sol";
import {Bip340} from "./Bip340.sol";

/// @title  Invinoveritas verdict acceptance authority, signature-checked (experimental ERC-8414 companion)
/// @notice The follow-up named in InvinoveritasVerdictAuthority's trust boundary: the BIP-340 verdict signature is
///         verified here, on-chain, and anyone may submit it. There is no designated relayer.
///
/// @dev TRUST BOUNDARY, stated exactly.
///
///      Checked on-chain, per call:
///        (a) Authenticity and correspondence. `sig` must be a valid BIP-340 signature by `verdictKey` over
///            verdictDigest(...), and that digest is built from the kernel's OWN values for this submission
///            (`taskVersion`, `resultHash` read from `submissionOf`) and the task document it was judged against
///            (`tdHash` read from `taskOf`), plus `approved` and `decisionRef`. So the signed verdict names this
///            deliverable, these requirements and this outcome; a caller can choose none of them. If the task was
///            updated after the submission (`taskOf(...).version != taskVersion`), no verdict can rule on it.
///            The cost of that falls on the publisher who updates: an update while a judged-path submission is pending
///            forfeits any ruling on this authority for that submission, so it resolves through the kernel's
///            `claimUnjudged` (once the original `judgmentWindow` has closed, and subject to the kernel's own
///            conditions, including epoch pacing) and resolves paid. That is the kernel's deadline default working as
///            designed (the fulfiller delivered against the document it was shown). Deployments using this authority
///            should freeze the task before funding, as the ERC recommends, which removes this path entirely.
///        (b) Domain binding. The digest also commits to `block.chainid`, this contract's address and the
///            task contract's address, so a verdict signed for one deployment, chain or token cannot be
///            replayed at another.
///        (c) Window compatibility, relay deadline and one ruling per submission, exactly as in
///            InvinoveritasVerdictAuthority.
///
///      Still trusted, and not removable by this contract:
///        - Availability. Nothing here makes a verdict get produced or submitted before the deadline. A missed
///          verdict leaves the kernel's default claim, with the same costs InvinoveritasVerdictAuthority describes.
///        - The key. `verdictKey` is fixed at deployment. Rotation means deploying a new authority for new tokens;
///          like the first companion, this contract exposes no call to move the kernel's authority slot.
///        - The judgment. The signature proves invinoveritas issued this verdict about this deliverable. Whether
///          the verdict is right is what invinoveritas's public ledger exists to make checkable, not this contract.
///
///      Message. verdictDigest = sha256(abi.encode(DOMAIN_TAG, chainid, authority, taskContract, tokenId,
///      submissionId, taskVersion, resultHash, tdHash, approved, decisionRef)), with DOMAIN_TAG =
///      sha256("invinoveritas/verdict-relay/v2"). Every field is a 32-byte ABI word, so an off-chain signer
///      builds the same 352 bytes without an ABI library.
contract InvinoveritasVerdictAuthoritySigned {
    error BadSignature();
    error BadKey();
    error WindowNotInside();
    error WindowExpired();
    error AlreadyRuled();
    error TaskChanged();

    event VerdictRelayed(
        address indexed taskContract,
        uint256 indexed tokenId,
        uint256 indexed submissionId,
        bytes32 decisionRef,
        bool approved,
        bytes32 digest,
        address submitter
    );

    bytes32 public constant DOMAIN_TAG = sha256("invinoveritas/verdict-relay/v2");

    /// @notice invinoveritas's BIP-340 x-only verdict key.
    bytes32 public immutable verdictKey;
    uint64 public immutable internalWindow;
    mapping(bytes32 => bool) public ruled;

    constructor(uint64 _internalWindow, bytes32 _verdictKey) {
        // A key that does not lift to a curve point, or sits outside ecrecover's domain, could never verify.
        if (!Bip340.isValidKey(_verdictKey)) revert BadKey();
        internalWindow = _internalWindow;
        verdictKey = _verdictKey;
    }

    function verdictDigest(
        ITaskTender taskContract,
        uint256 tokenId,
        uint256 submissionId,
        uint64 taskVersion,
        bytes32 resultHash,
        bytes32 tdHash,
        bool approved,
        bytes32 decisionRef
    ) public view returns (bytes32) {
        return sha256(abi.encode(
            DOMAIN_TAG, block.chainid, address(this), address(taskContract),
            tokenId, submissionId, taskVersion, resultHash, tdHash, approved, decisionRef
        ));
    }

    /// @notice Submit one signed invinoveritas verdict. Anyone may call.
    /// @param sig BIP-340 signature, 64 bytes: r (32) || s (32).
    function relayVerdict(
        ITaskTender taskContract,
        uint256 tokenId,
        uint256 submissionId,
        bool approved,
        bytes32 decisionRef,
        bytes calldata sig
    ) external {
        bytes32 key = keccak256(abi.encode(address(taskContract), tokenId, submissionId));
        if (ruled[key]) revert AlreadyRuled();

        ITaskTender.Submission memory sub = taskContract.submissionOf(tokenId, submissionId);
        uint64 jw = taskContract.tenderTermsOf(tokenId).judgmentWindow;
        if (internalWindow >= jw) revert WindowNotInside();
        if (block.timestamp > uint256(sub.submittedAt) + uint256(internalWindow)) revert WindowExpired();

        ITaskToken.TaskBinding memory task = ITaskToken(address(taskContract)).taskOf(tokenId);
        if (task.version != sub.taskVersion) revert TaskChanged();
        bytes32 digest = verdictDigest(
            taskContract, tokenId, submissionId, sub.taskVersion, sub.resultHash, task.tdHash, approved, decisionRef
        );
        if (sig.length != 64 || !Bip340.verify(verdictKey, digest, bytes32(sig[0:32]), bytes32(sig[32:64]))) {
            revert BadSignature();
        }

        ruled[key] = true;
        emit VerdictRelayed(address(taskContract), tokenId, submissionId, decisionRef, approved, digest, msg.sender);

        if (approved) {
            taskContract.acceptFulfillment(tokenId, submissionId);
        } else {
            taskContract.rejectFulfillment(tokenId, submissionId);
        }
    }
}
