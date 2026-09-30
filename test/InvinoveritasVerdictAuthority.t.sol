// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TaskToken} from "../contracts/TaskToken.sol";
import {ITaskTender} from "../contracts/interfaces/ITaskTender.sol";
import {ITaskVerifier} from "../contracts/interfaces/ITaskVerifier.sol";
import {InvinoveritasVerdictAuthority as IVA} from "../companions/InvinoveritasVerdictAuthority.sol";

/// Machine-path authority that can hand its slot on (to test the machineSettled snapshot).
contract ForwardingVerifier is ITaskVerifier {
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(ITaskVerifier).interfaceId || id == 0x01ffc9a7;
    }
    function verifyFulfillment(address, uint256, uint256, address, bytes32, bytes calldata)
        external pure returns (bool) { return false; }
    function handOff(TaskToken t, uint256 id, address to) external { t.setAcceptanceAuthority(id, to); }
}

/// EXPERIMENTAL companion tests (see companions/). Not part of the kernel's reference suite.
contract InvinoveritasVerdictAuthorityTest is Test {
    TaskToken t;
    address owner = address(0xA11CE);
    address publisher = address(0xB0B);
    address judge = address(0x1CDE);
    address funder = address(0xF00D);
    address worker = address(0xCAFE);
    address relayer = address(0x5E1A);
    address rando = address(0xBAD);

    bytes32 TD = sha256("TASK.md v1");
    bytes32 TH = sha256("taskroot v1");
    bytes32 RES = sha256("deliverable");
    bytes32 constant DREF = keccak256("decisionRef");
    bytes32 constant POL = keccak256("policy");
    bytes32 constant ART = keccak256("artifact");
    bytes constant SIG = hex"01020304";

    uint64 constant JW = 7 days;
    uint64 constant IW = 3 days;

    function setUp() public {
        t = new TaskToken("Task Token", "TASK");
        vm.deal(funder, 1000 ether);
        vm.warp(1_700_000_000);
    }

    function _terms(uint64 jw, uint64 epochLen, uint64 perEpoch) internal pure returns (ITaskTender.TenderTerms memory) {
        return ITaskTender.TenderTerms(address(0), 1 ether, 0, 0, 0, epochLen, perEpoch, jw);
    }

    function _tender(address auth, uint64 jw) internal returns (uint256 id) {
        id = _tenderPaced(auth, jw, 0, 0);
    }

    function _tenderPaced(address auth, uint64 jw, uint64 epochLen, uint64 perEpoch) internal returns (uint256 id) {
        id = t.mintTask(owner, publisher, auth, TD, TH, "u", _terms(jw, epochLen, perEpoch));
        vm.prank(funder);
        t.fundTask{value: 10 ether}(id, 10 ether);
    }

    function _submit(uint256 id, bytes32 res) internal returns (uint256 sid) {
        vm.prank(worker);
        sid = t.submitFulfillment(id, res, "");
    }

    function _relay(IVA a, uint256 id, uint256 sid, bool approved) internal {
        ITaskTender.Submission memory s = t.submissionOf(id, sid);
        vm.prank(relayer);
        a.relayVerdict(t, id, sid, s.taskVersion, s.resultHash, DREF, POL, ART, approved, SIG);
    }

    function _relayExpect(IVA a, uint256 id, uint256 sid, bool approved, bytes4 err) internal {
        ITaskTender.Submission memory s = t.submissionOf(id, sid);
        vm.prank(relayer);
        vm.expectRevert(err);
        a.relayVerdict(t, id, sid, s.taskVersion, s.resultHash, DREF, POL, ART, approved, SIG);
    }

    function _key(uint256 id, uint256 sid) internal view returns (bytes32) {
        return keccak256(abi.encode(address(t), id, sid));
    }

    // ---- per-tender window compatibility: below / at / above, two tenders on one instance
    function test_window_below_at_above() public {
        IVA a = new IVA(IW, relayer);
        uint256 below = _tender(address(a), IW + 1);
        uint256 at = _tender(address(a), IW);
        uint256 above = _tender(address(a), IW - 1);
        uint256 s1 = _submit(below, RES);
        uint256 s2 = _submit(at, RES);
        uint256 s3 = _submit(above, RES);
        _relay(a, below, s1, true);
        assertEq(uint8(t.submissionOf(below, s1).status), uint8(ITaskTender.SubmissionStatus.Accepted));
        _relayExpect(a, at, s2, true, IVA.WindowNotInside.selector);
        _relayExpect(a, above, s3, false, IVA.WindowNotInside.selector);
    }

    function test_two_tenders_one_instance() public {
        IVA a = new IVA(IW, relayer);
        uint256 fits = _tender(address(a), JW);
        uint256 tooShort = _tender(address(a), 2 days);
        uint256 s1 = _submit(fits, RES);
        uint256 s2 = _submit(tooShort, RES);
        _relay(a, fits, s1, false);
        assertEq(uint8(t.submissionOf(fits, s1).status), uint8(ITaskTender.SubmissionStatus.Rejected));
        _relayExpect(a, tooShort, s2, false, IVA.WindowNotInside.selector);
        assertFalse(a.ruled(_key(tooShort, s2)));
    }

    // ---- exact relay-deadline boundary
    function test_deadline_boundary() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tender(address(a), JW);
        uint256 s1 = _submit(id, RES);
        uint256 s2 = _submit(id, sha256("other"));
        uint64 at = t.submissionOf(id, s1).submittedAt;
        vm.warp(uint256(at) + IW);          // exactly at the deadline: allowed
        _relay(a, id, s1, true);
        vm.warp(uint256(at) + IW + 1);      // one second past: refused
        _relayExpect(a, id, s2, true, IVA.WindowExpired.selector);
    }

    // ---- widened arithmetic: the old uint64 sum would overflow and panic here
    function test_widened_arithmetic_extremes() public {
        uint64 maxJw = type(uint64).max;
        IVA a = new IVA(maxJw - 1, relayer);
        uint256 id = _tender(address(a), maxJw);
        uint256 sid = _submit(id, RES);
        vm.warp(block.timestamp + 365 days);
        _relay(a, id, sid, true);
        assertEq(uint8(t.submissionOf(id, sid).status), uint8(ITaskTender.SubmissionStatus.Accepted));
    }

    // ---- successful relays, mismatches, duplicates, access
    function test_approve_and_reject() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tender(address(a), JW);
        uint256 s1 = _submit(id, RES);
        uint256 s2 = _submit(id, sha256("junk"));
        uint256 before = worker.balance;
        _relay(a, id, s1, true);
        assertEq(worker.balance, before + 1 ether);
        _relay(a, id, s2, false);
        assertEq(uint8(t.submissionOf(id, s2).status), uint8(ITaskTender.SubmissionStatus.Rejected));
        assertEq(t.pendingOf(id), 0);
    }

    function test_mismatch_and_duplicate_and_access() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tender(address(a), JW);
        uint256 sid = _submit(id, RES);
        ITaskTender.Submission memory s = t.submissionOf(id, sid);
        vm.startPrank(relayer);
        vm.expectRevert(IVA.SubmissionMismatch.selector);
        a.relayVerdict(t, id, sid, s.taskVersion + 1, s.resultHash, DREF, POL, ART, true, SIG);
        vm.expectRevert(IVA.SubmissionMismatch.selector);
        a.relayVerdict(t, id, sid, s.taskVersion, bytes32(uint256(1)), DREF, POL, ART, true, SIG);
        a.relayVerdict(t, id, sid, s.taskVersion, s.resultHash, DREF, POL, ART, false, SIG);
        vm.expectRevert(IVA.AlreadyRuled.selector);
        a.relayVerdict(t, id, sid, s.taskVersion, s.resultHash, DREF, POL, ART, true, SIG);
        vm.stopPrank();
        vm.prank(rando);
        vm.expectRevert(IVA.NotRelayer.selector);
        a.relayVerdict(t, id, sid, s.taskVersion, s.resultHash, DREF, POL, ART, true, SIG);
    }

    // ---- downstream kernel revert: no stale flag, no surviving event, retry works
    function test_kernel_revert_rolls_back_flag_and_event() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tenderPaced(address(a), JW, 1 days, 1);
        uint256 s1 = _submit(id, RES);
        uint256 s2 = _submit(id, sha256("second"));
        _relay(a, id, s1, true); // uses this epoch's only completion

        ITaskTender.Submission memory s = t.submissionOf(id, s2);
        // The relay's whole frame reverts (the kernel revert is not caught), so nothing it emitted,
        // VerdictRelayed included, can appear in a committed receipt. (vm.recordLogs also sees
        // logs from reverted frames, so the revert itself is the assertion here.)
        vm.prank(relayer);
        (bool ok,) = address(a).call(abi.encodeCall(IVA.relayVerdict,
            (t, id, s2, s.taskVersion, s.resultHash, DREF, POL, ART, true, SIG)));
        assertFalse(ok, "kernel should refuse (epoch exhausted) and the relay must revert with it");
        assertFalse(a.ruled(_key(id, s2)), "stale ruled flag");

        vm.warp(block.timestamp + 1 days); // next epoch, still inside the relay window
        _relay(a, id, s2, true);
        assertTrue(a.ruled(_key(id, s2)));
        assertEq(uint8(t.submissionOf(id, s2).status), uint8(ITaskTender.SubmissionStatus.Accepted));
    }

    // ---- authority installed after submission: judged snapshot relays; machine snapshot stays machine
    function test_install_after_judged_submission() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tender(judge, JW);
        uint256 sid = _submit(id, RES);
        assertFalse(t.submissionOf(id, sid).machineSettled);
        vm.prank(judge);
        t.setAcceptanceAuthority(id, address(a));
        _relay(a, id, sid, true);
        assertEq(uint8(t.submissionOf(id, sid).status), uint8(ITaskTender.SubmissionStatus.Accepted));
    }

    function test_install_does_not_convert_machine_submissions() public {
        IVA a = new IVA(IW, relayer);
        ForwardingVerifier v = new ForwardingVerifier();
        uint256 id = _tender(address(v), JW);
        uint256 sid = _submit(id, RES);
        assertTrue(t.submissionOf(id, sid).machineSettled);
        v.handOff(t, id, address(a));
        assertEq(t.acceptanceAuthorityOf(id), address(a));
        vm.warp(block.timestamp + JW + 1);
        vm.prank(rando);
        vm.expectRevert(bytes("TaskToken: machine-path delivery"));
        t.claimUnjudged(id, sid);
        assertTrue(t.submissionOf(id, sid).machineSettled, "snapshot must not change");
    }

    // ---- missed relay: late approval refused by the SLA, default claim later, paced by epoch
    function test_late_approval_then_default_claim_with_pacing() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tenderPaced(address(a), JW, 1 days, 1);
        uint256 s1 = _submit(id, RES);
        uint256 s2 = _submit(id, sha256("second"));
        uint64 at = t.submissionOf(id, s1).submittedAt;

        vm.warp(uint256(at) + IW + 1);           // relay SLA missed
        _relayExpect(a, id, s1, true, IVA.WindowExpired.selector);
        vm.prank(rando);
        vm.expectRevert(bytes("TaskToken: window open"));
        t.claimUnjudged(id, s1);                 // default not yet open

        vm.warp(uint256(at) + JW + 1);           // default opens
        uint256 before = worker.balance;
        vm.prank(rando);
        t.claimUnjudged(id, s1);
        assertEq(worker.balance, before + 1 ether); // paid by default, not by a verdict
        vm.prank(rando);
        vm.expectRevert(bytes("TaskToken: epoch exhausted"));
        t.claimUnjudged(id, s2);                 // queued, not lost
        vm.warp(block.timestamp + 1 days);
        vm.prank(rando);
        t.claimUnjudged(id, s2);
        assertEq(t.completionsOf(id), 2);
        assertFalse(a.ruled(_key(id, s1)));
    }

    function test_setRelayer_rotates_key_only() public {
        IVA a = new IVA(IW, relayer);
        uint256 id = _tender(address(a), JW);
        vm.prank(rando);
        vm.expectRevert(IVA.NotAdmin.selector);
        a.setRelayer(rando);
        a.setRelayer(rando);
        assertEq(a.relayer(), rando);
        assertEq(t.acceptanceAuthorityOf(id), address(a)); // the slot did not move
    }
}
