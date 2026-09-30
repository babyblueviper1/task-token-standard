// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {TaskToken} from "../contracts/TaskToken.sol";
import {ITaskTender} from "../contracts/interfaces/ITaskTender.sol";
import {Bip340} from "../companions/Bip340.sol";
import {InvinoveritasVerdictAuthoritySigned as SVA} from "../companions/InvinoveritasVerdictAuthoritySigned.sol";

/// Exposes the internal library for direct vector tests.
contract Bip340Harness {
    function verify(bytes32 px, bytes32 m, bytes32 rx, bytes32 s) external view returns (bool) {
        return Bip340.verify(px, m, rx, s);
    }
    function isValidKey(bytes32 px) external view returns (bool) {
        return Bip340.isValidKey(px);
    }
}

/// EXPERIMENTAL companion tests (see companions/). Not part of the kernel's reference suite.
contract InvinoveritasVerdictAuthoritySignedTest is Test {
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    bytes32 constant TAG = sha256("BIP0340/challenge");

    Bip340Harness h;
    TaskToken t;
    address owner = address(0xA11CE);
    address publisher = address(0xB0B);
    address funder = address(0xF00D);
    address worker = address(0xCAFE);
    address anyone = address(0xBAD);

    uint256 constant SK = 0x5EC12E7;          // test verdict key (never a real signer)
    uint256 constant OTHER_SK = 0x07E4;
    bytes32 constant DREF = keccak256("decisionRef");
    bytes32 RES = sha256("deliverable");
    uint64 constant JW = 7 days;
    uint64 constant IW = 3 days;

    function setUp() public {
        h = new Bip340Harness();
        t = new TaskToken("Task Token", "TASK");
        vm.deal(funder, 1000 ether);
        vm.warp(1_700_000_000);
    }

    // ------------------------------------------------------------------ test signer (BIP-340, deterministic nonce)
    function _xonly(uint256 sk) internal returns (bytes32 px, uint256 d) {
        Vm.Wallet memory w = vm.createWallet(sk);
        px = bytes32(w.publicKeyX);
        d = w.publicKeyY % 2 == 0 ? sk : N - sk;
    }

    /// evenR = false makes the signer skip BIP-340's R-negation, producing a signature whose R has odd y.
    function _sign(uint256 sk, bytes32 m, bool evenR) internal returns (bytes32 px, bytes32 rx, bytes32 s) {
        uint256 d;
        (px, d) = _xonly(sk);
        uint256 k0 = uint256(keccak256(abi.encode(sk, m))) % N;
        Vm.Wallet memory R = vm.createWallet(k0);
        while (!evenR && R.publicKeyY % 2 == 0) { k0 = k0 + 1; R = vm.createWallet(k0); }
        uint256 k = (evenR && R.publicKeyY % 2 == 1) ? N - k0 : k0;
        rx = bytes32(R.publicKeyX);
        uint256 e = uint256(sha256(abi.encodePacked(TAG, TAG, rx, px, m))) % N;
        s = bytes32(addmod(k, mulmod(e, d, N), N));
    }

    // ------------------------------------------------------------------ library: fixed vectors
    function test_bip340_official_vector_0() public view {
        // BIP-340 test vector 0: secret key 3, aux 0, message 0.
        assertTrue(h.verify(
            0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9, bytes32(0),
            0xE907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215,
            0x25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0));
    }

    function test_bip340_python_cross_vector() public view {
        // Signed by companions/tools/bip340.py (stdlib reference, full BIP-340 nonce derivation), not by this test.
        assertTrue(h.verify(
            0x8695a4e708bef5d769d094130852dbf4074430f797c86a204ab9e2e847987a59,
            0xbc1794948d666baba3493032b5e2c9777062e20e4640da233b3d8b79c591d6d5,
            0x51e696e45a38757ac962f72ed61d0250c508c8b7e90ca51ed6cff96a563aa1ce,
            0xf4ce7795c2114c375ce7785d1ea37dcf54b1afea215ba15f783f2962478c6598));
    }

    function test_bip340_live_invinoveritas_ledger_signature() public view {
        // invinoveritas's production verdict key over a real ledger record: /ledger/38 (proof_event id and sig,
        // https://api.babyblueviper.com/ledger/38/commitment). This is the key a deployment would pass as verdictKey.
        assertTrue(h.verify(
            0x6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7,
            0xa42205d7e39c684f0aa43f80fe7ea1aa8e180df93ff46e82b5bff95b70c663e9,
            0x7205cfea38ef35886ad83142ed5d08a7545c50eed39f714592ba03280dafb0ac,
            0x8051fd1b87135c41d188acbc48e5e0ad16ea208eaaa00912e1439137dd493a0b));
        assertTrue(h.isValidKey(0x6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7));
    }

    // ------------------------------------------------------------------ library: each rejection class
    function test_bip340_rejects() public {
        bytes32 m = sha256("m");
        (bytes32 px, bytes32 rx, bytes32 s) = _sign(SK, m, true);
        assertTrue(h.verify(px, m, rx, s), "positive control");
        assertFalse(h.verify(px, sha256("m'"), rx, s), "other message");
        assertFalse(h.verify(px, m, rx, bytes32(addmod(uint256(s), 1, N))), "s + 1");
        assertFalse(h.verify(px, m, rx, bytes32(N)), "s = n");
        assertFalse(h.verify(px, m, bytes32(P), s), "r = p");
        assertFalse(h.verify(px, m, bytes32(uint256(5)), s), "r not on the curve (x = 5)");
        assertFalse(h.verify(bytes32(uint256(5)), m, rx, s), "key not on the curve");
        (bytes32 opx,,) = _sign(OTHER_SK, m, true);
        assertFalse(h.verify(opx, m, rx, s), "other key");
        (bytes32 px2, bytes32 rxOdd, bytes32 sOdd) = _sign(SK, m, false);
        assertFalse(h.verify(px2, m, rxOdd, sOdd), "R with odd y: right x, wrong point");
        assertFalse(h.isValidKey(bytes32(0)), "zero key");
        assertFalse(h.isValidKey(bytes32(N)), "key >= n");
    }

    // ------------------------------------------------------------------ companion
    function _tender(address auth, uint64 jw) internal returns (uint256 id) {
        id = t.mintTask(owner, publisher, auth, sha256("TASK.md v1"), sha256("taskroot v1"), "u",
            ITaskTender.TenderTerms(address(0), 1 ether, 0, 0, 0, 0, 0, jw));
        vm.prank(funder);
        t.fundTask{value: 10 ether}(id, 10 ether);
    }

    function _submit(uint256 id) internal returns (uint256 sid) {
        vm.prank(worker);
        sid = t.submitFulfillment(id, RES, "");
    }

    function _verdictSig(SVA a, uint256 sk, uint256 id, uint256 sid, bool approved) internal returns (bytes memory) {
        ITaskTender.Submission memory s = t.submissionOf(id, sid);
        bytes32 m = a.verdictDigest(t, id, sid, s.taskVersion, s.resultHash, approved, DREF);
        (, bytes32 rx, bytes32 sv) = _sign(sk, m, true);
        return abi.encodePacked(rx, sv);
    }

    function _deploy() internal returns (SVA a) {
        (bytes32 px,) = _xonly(SK);
        a = new SVA(IW, px);
    }

    function test_permissionless_approve_and_reject() public {
        SVA a = _deploy();
        uint256 id = _tender(address(a), JW);
        uint256 s1 = _submit(id);
        bytes memory sig = _verdictSig(a, SK, id, s1, true);
        vm.prank(anyone);
        a.relayVerdict(t, id, s1, true, DREF, sig);
        assertEq(uint8(t.submissionOf(id, s1).status), uint8(ITaskTender.SubmissionStatus.Accepted));

        uint256 s2 = _submit(id);
        sig = _verdictSig(a, SK, id, s2, false);
        vm.prank(anyone);
        a.relayVerdict(t, id, s2, false, DREF, sig);
        assertEq(uint8(t.submissionOf(id, s2).status), uint8(ITaskTender.SubmissionStatus.Rejected));
    }

    function test_flipped_outcome_rejected() public {
        SVA a = _deploy();
        uint256 id = _tender(address(a), JW);
        uint256 sid = _submit(id);
        bytes memory rejectSig = _verdictSig(a, SK, id, sid, false);
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, sid, true, DREF, rejectSig);
    }

    function test_signature_for_another_submission_rejected() public {
        SVA a = _deploy();
        uint256 id = _tender(address(a), JW);
        uint256 s1 = _submit(id);
        uint256 s2 = _submit(id);
        bytes memory sig1 = _verdictSig(a, SK, id, s1, true);
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, s2, true, DREF, sig1);
    }

    function test_other_decision_ref_rejected() public {
        SVA a = _deploy();
        uint256 id = _tender(address(a), JW);
        uint256 sid = _submit(id);
        bytes memory sig = _verdictSig(a, SK, id, sid, true);
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, sid, true, keccak256("another decision"), sig);
    }

    function test_domain_binding_other_authority_and_chain() public {
        SVA a = _deploy();
        SVA b = _deploy();
        uint256 ida = _tender(address(a), JW);
        uint256 idb = _tender(address(b), JW);
        uint256 sa = _submit(ida);
        _submit(idb);
        // a verdict signed for authority a, replayed at authority b over the same-shaped submission
        bytes memory sigA = _verdictSig(a, SK, ida, sa, true);
        vm.expectRevert(SVA.BadSignature.selector);
        b.relayVerdict(t, idb, sa, true, DREF, sigA);
        // the same verdict on another chain id
        vm.chainId(8453);
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, ida, sa, true, DREF, sigA);
    }

    function test_wrong_key_and_malformed_sig_rejected() public {
        SVA a = _deploy();
        uint256 id = _tender(address(a), JW);
        uint256 sid = _submit(id);
        bytes memory foreign = _verdictSig(a, OTHER_SK, id, sid, true);
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, sid, true, DREF, foreign);
        bytes memory good = _verdictSig(a, SK, id, sid, true);
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, sid, true, DREF, abi.encodePacked(good, bytes1(0x00)));
    }

    function test_replay_and_windows() public {
        SVA a = _deploy();
        uint256 id = _tender(address(a), JW);
        uint256 sid = _submit(id);
        bytes memory sig = _verdictSig(a, SK, id, sid, true);
        a.relayVerdict(t, id, sid, true, DREF, sig);
        vm.expectRevert(SVA.AlreadyRuled.selector);
        a.relayVerdict(t, id, sid, true, DREF, sig);

        uint256 s2 = _submit(id);
        bytes memory late = _verdictSig(a, SK, id, s2, true);
        vm.warp(block.timestamp + IW + 1);
        vm.expectRevert(SVA.WindowExpired.selector);
        a.relayVerdict(t, id, s2, true, DREF, late);

        uint256 tight = _tender(address(a), IW);
        uint256 s3 = _submit(tight);
        bytes memory sig3 = _verdictSig(a, SK, tight, s3, true);
        vm.expectRevert(SVA.WindowNotInside.selector);
        a.relayVerdict(t, tight, s3, true, DREF, sig3);
    }

    function test_constructor_refuses_unusable_key() public {
        vm.expectRevert(SVA.BadKey.selector);
        new SVA(IW, bytes32(uint256(5)));
        vm.expectRevert(SVA.BadKey.selector);
        new SVA(IW, bytes32(N));
    }
}
