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
    // resultHash sha256("deliverable bytes"), decisionRef 0xab..ab). Python digest == verdictDigest: 0x650b0881...a5b3.
    bytes constant APPROVE_SIG = hex"f8345e948680875e1de3d4487fdb6d75b42338c2f3fe9a6fcdd9d2f5bebd0af276326ebb9ae7d05ada7185586ad10fab26d7be8d29b8b9c2505df453c9e2e7b3";
    bytes constant REJECT_SIG = hex"f342dd15e140d64b07e361dfb3bb826a92d5680268260a18bf4cc674a62fc90dd27ab5d770a28d88e6385d49a582f067156fe8ffd399623b23fac78f9ce0eec8";

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
        assertEq(a.verdictDigest(t, id, sid, s.taskVersion, s.resultHash, true, DREF),
            0x650b0881d50f13f46acbdcbb4699b5af33dd82ab7128369168a5b03f98dfa5b3);
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

    // LIVE: invinoveritas's production verdict key, signature returned by POST /review (verdict_relay_v1) on 2026-09-30
    // for a real review (proof event 6475d9a0...b2a4, decision_ref sha256:d26158c4...5762). Chain id 8453, this
    // deployment's addresses, token 1, submission 1, version 1, resultHash = sha256 of the reviewed deliverable.
    bytes32 constant PROD_KEY = 0x6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7;
    bytes32 constant LIVE_DREF = 0xd26158c4319d726137a853872c527cf041e40131c20659acaf2dcc0291965762;
    bytes32 constant LIVE_RESULT = 0xd220c82027bdcc8d25c8d5c3eae373941aab870fa8af44df8210f74577fefb95;
    bytes constant LIVE_SIG = hex"3bcd431a334a6ffbd6e0d55ba819cdfdd376f99881b44e96d27493f6460b0e841cae6dd014da69551305f5b095e73336448143b9a6817d6640d9b0c9222211fc";

    function test_live_production_signature_settles() public {
        vm.chainId(8453);
        vm.warp(1_700_000_000);
        TaskToken t = new TaskToken("Task Token", "TASK");
        SVA a = new SVA(3 days, PROD_KEY);
        assertEq(address(t), 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f);
        assertEq(address(a), 0x2e234DAe75C793f67A35089C9d99245E1C58470b);
        uint256 id = t.mintTask(address(0xA11CE), address(0xB0B), address(a), sha256("TASK.md v1"), sha256("taskroot v1"), "u",
            ITaskTender.TenderTerms(address(0), 1 ether, 0, 0, 0, 0, 0, 7 days));
        vm.deal(address(0xF00D), 10 ether);
        vm.prank(address(0xF00D));
        t.fundTask{value: 10 ether}(id, 10 ether);
        vm.prank(address(0xCAFE));
        uint256 sid = t.submitFulfillment(id, LIVE_RESULT, "");
        assertEq(a.verdictDigest(t, id, sid, 1, LIVE_RESULT, true, LIVE_DREF),
            0x325068a9cadb5d7894d4664519d45b57041f706de17028274a312f1fa1bd5960);
        uint256 before = address(0xCAFE).balance;
        vm.prank(address(0xBAD));
        a.relayVerdict(t, id, sid, true, LIVE_DREF, LIVE_SIG);
        assertEq(uint8(t.submissionOf(id, sid).status), uint8(ITaskTender.SubmissionStatus.Accepted));
        assertEq(address(0xCAFE).balance, before + 1 ether);
    }
}
