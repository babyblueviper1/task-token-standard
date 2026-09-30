// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TaskToken} from "../contracts/TaskToken.sol";
import {ITaskTender} from "../contracts/interfaces/ITaskTender.sol";
import {InvinoveritasVerdictAuthoritySigned as SVA} from "../companions/InvinoveritasVerdictAuthoritySigned.sol";

/// Golden end-to-end: a signature produced by invinoveritas's OWN issuance code (services/verdict_relay.py + the
/// nostr signer, with a published test key) settles a real kernel submission through this contract.
contract VerdictRelayGoldenTest is Test {
    bytes32 constant TEST_KEY = 0x9301e206ba5187ea247cefcbffa57283876abfba1649819c7397ed8a9ac82ad5;  // x-only key of sha256("verdict-relay test key"), never a real signer
    bytes32 constant DREF = 0xabababababababababababababababababababababababababababababababab;

    // Produced by services/verdict_relay.py issue() + nostr PrivateKey.sign_message_hash over the fields below
    // (chainid 31337, this deployment's deterministic addresses, token 1, submission 1, version 1,
    // resultHash sha256("deliverable bytes"), decisionRef 0xab..ab). Python digest == verdictDigest: 0x1354109d...719c. task_document "TASK.md v1" (sha256 = the minted tdHash).
    bytes constant APPROVE_SIG = hex"8760d8859113ad41df318a851910b6068b33aa95c0b8a7f74ca763fb014f086e6d9bf991d92f81cad0447978348b0e20c93b837253fc78982e5c997683f3990a";
    bytes constant REJECT_SIG = hex"2411830cb36220d17c5deacfed5a8a039b898ed6cc0469dac525db9dd7a518fbb532b3291485cd1158a7f0025c55214d8917aa86c851e56c3451d2c4db06c11d";

    function _setup() internal returns (TaskToken t, SVA a, uint256 id, uint256 sid) {
        vm.warp(1_700_000_000);
        t = new TaskToken("Task Token", "TASK");
        a = new SVA(3 days, TEST_KEY);
        id = t.mintTask(address(0xA11CE), address(0xB0B), address(a), sha256("TASK.md v1"), sha256("taskroot v1"), "u",
            ITaskTender.TenderTerms(address(0), 1 ether, 0, 0, 0, 0, 0, 7 days));
        vm.deal(address(0xF00D), 10 ether);
        vm.prank(address(0xF00D));
        t.fundTask{value: 10 ether}(id, 10 ether);
        bytes32 res = sha256("deliverable bytes"); // before the prank: sha256 is a precompile call and would consume it
        vm.prank(address(0xCAFE));
        sid = t.submitFulfillment(id, res, "");
    }

    function test_golden_digest_matches_issuer() public {
        (TaskToken t, SVA a, uint256 id, uint256 sid) = _setup();
        ITaskTender.Submission memory s = t.submissionOf(id, sid);
        assertEq(a.verdictDigest(t, id, sid, s.taskVersion, s.resultHash, t.taskOf(id).tdHash, true, DREF),
            0x1354109d221f52f5b8a3599a1eba229f534c1d09d603f65959094fa06406719c);
    }

    function test_golden_issuer_signature_settles_approval() public {
        (TaskToken t, SVA a, uint256 id, uint256 sid) = _setup();
        uint256 before = address(0xCAFE).balance;
        vm.prank(address(0xBAD)); // anyone
        a.relayVerdict(t, id, sid, true, DREF, APPROVE_SIG);
        assertEq(uint8(t.submissionOf(id, sid).status), uint8(ITaskTender.SubmissionStatus.Accepted));
        assertEq(address(0xCAFE).balance, before + 1 ether);
    }

    function test_golden_issuer_signatures_are_outcome_bound() public {
        (TaskToken t, SVA a, uint256 id, uint256 sid) = _setup();
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, sid, true, DREF, REJECT_SIG);   // a reject verdict cannot approve
        vm.expectRevert(SVA.BadSignature.selector);
        a.relayVerdict(t, id, sid, false, DREF, APPROVE_SIG); // nor an approval reject
        a.relayVerdict(t, id, sid, false, DREF, REJECT_SIG);
        assertEq(uint8(t.submissionOf(id, sid).status), uint8(ITaskTender.SubmissionStatus.Rejected));
    }

    // LIVE (v2): invinoveritas's production verdict key, signature returned by POST /review (verdict_relay) on
    // 2026-09-30 for a real review against a real task document (proof event 06051d02...39c2). Chain id 8453, this
    // deployment's addresses, token 1, submission 1, version 1; tdHash = sha256 of that task document.
    bytes32 constant PROD_KEY = 0x6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7;
    bytes32 constant LIVE_DREF = 0x60c90e70c365c62c5b503f5998f9ea7b1565ca127ec3a0e3c0e623501ab7f976;
    bytes32 constant LIVE_RESULT = 0xd220c82027bdcc8d25c8d5c3eae373941aab870fa8af44df8210f74577fefb95;
    bytes32 constant LIVE_TD = 0x55b9e78f1ba60bb3f0022e8a49859a5c81db52c2a87be9314ffc53c6f64a670f;
    bytes constant LIVE_SIG = hex"ee6866255af0da6c14a6efe3abd6cd88f5fddee4faa573b159a0abfd70ded5d48f2dc40956d703813441230c9fc2a186f92d8b104a0d21bc2e9f74175dbd9a88";

    function test_live_production_signature_settles() public {
        vm.chainId(8453);
        vm.warp(1_700_000_000);
        TaskToken t = new TaskToken("Task Token", "TASK");
        SVA a = new SVA(3 days, PROD_KEY);
        assertEq(address(t), 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f);
        assertEq(address(a), 0x2e234DAe75C793f67A35089C9d99245E1C58470b);
        bytes32 root = sha256("taskroot v1");
        uint256 id = t.mintTask(address(0xA11CE), address(0xB0B), address(a), LIVE_TD, root, "u",
            ITaskTender.TenderTerms(address(0), 1 ether, 0, 0, 0, 0, 0, 7 days));
        vm.deal(address(0xF00D), 10 ether);
        vm.prank(address(0xF00D));
        t.fundTask{value: 10 ether}(id, 10 ether);
        vm.prank(address(0xCAFE));
        uint256 sid = t.submitFulfillment(id, LIVE_RESULT, "");
        assertEq(a.verdictDigest(t, id, sid, 1, LIVE_RESULT, LIVE_TD, true, LIVE_DREF), 0xe11843ac7be74a8e5f1e44e05bf3aa03e9f419764ccd5702c38cfced048bc47c);
        uint256 before = address(0xCAFE).balance;
        vm.prank(address(0xBAD));
        a.relayVerdict(t, id, sid, true, LIVE_DREF, LIVE_SIG);
        assertEq(uint8(t.submissionOf(id, sid).status), uint8(ITaskTender.SubmissionStatus.Accepted));
        assertEq(address(0xCAFE).balance, before + 1 ether);
    }
}
