// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/DVASQuorumSettle.sol";

contract DVASQuorumSettleTest is Test {
    DVASQuorumSettle internal sc;
    uint256[5] internal pk = [uint256(0xA11CE), 0xB0B, 0xC0C0A, 0xD00D, 0xE1E1];
    address[5] internal sv;
    address internal payer = address(0xCAFE);
    uint256 internal constant RESERVE = 1000;
    uint256 internal constant CAPTURE = 720;
    uint256 internal constant REFUND = 280;

    function setUp() public {
        for (uint256 i = 0; i < 5; i++) sv[i] = vm.addr(pk[i]);
        address[] memory three = new address[](3);
        three[0] = sv[0]; three[1] = sv[1]; three[2] = sv[2];
        sc = new DVASQuorumSettle(three, 2);
    }

    // ---------------------------------------------------------------- helpers
    function _ids(uint256 i) internal pure returns (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 meter, bytes32 rd, bytes32 hp) {
        tid = keccak256(abi.encodePacked("tid", i));
        rho = keccak256(abi.encodePacked("rho", i));
        sid = keccak256(abi.encodePacked("sid", i));
        meter = keccak256(abi.encodePacked("meter", i));
        rd = keccak256(abi.encodePacked("receipt", i));
        hp = keccak256(abi.encodePacked("hpriv", i));
    }

    function _prepare(uint256 i) internal returns (DVASQuorumSettle.RBCBody memory b) {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 meter, bytes32 rd, bytes32 hp) = _ids(i);
        sc.authorize(tid, rho, sid, meter, payer, RESERVE);
        sc.submitReceipt(tid, rd, hp);
        b = DVASQuorumSettle.RBCBody(tid, sid, rho, meter, rd, hp, CAPTURE, REFUND, sc.POLICY_ID(), sc.verifierSetEpoch());
    }

    function _sign(uint256 key, DVASQuorumSettle.RBCBody memory b, uint64 epoch) internal view returns (bytes memory) {
        bytes32 d = sc.attestationDigest(sc.decisionDigest(b), epoch);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    /// signatures of the given verifier indices, sorted by signer address
    function _quorum(DVASQuorumSettle.RBCBody memory b, uint256[] memory idx)
        internal view returns (bytes[] memory sigs, uint64[] memory eps)
    {
        uint256 n = idx.length;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (sv[idx[j]] < sv[idx[i]]) (idx[i], idx[j]) = (idx[j], idx[i]);
            }
        }
        sigs = new bytes[](n);
        eps = new uint64[](n);
        for (uint256 i = 0; i < n; i++) {
            (, uint64 e) = sc.verifiers(sv[idx[i]]);
            eps[i] = e;
            sigs[i] = _sign(pk[idx[i]], b, e);
        }
    }

    function _idx(uint256 a, uint256 b2) internal pure returns (uint256[] memory r) {
        r = new uint256[](2); r[0] = a; r[1] = b2;
    }

    function _idx1(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1); r[0] = a;
    }

    function _idx3(uint256 a, uint256 b2, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3); r[0] = a; r[1] = b2; r[2] = c;
    }

    function _gas(string memory name, uint256 used) internal pure {
        console2.log(string.concat("GAS_RESULT ", name), used);
    }

    function _release(DVASQuorumSettle.RBCBody memory b, bytes[] memory sigs, uint64[] memory eps) internal {
        sc.releaseByQuorumRBC(b, sigs, eps);
    }

    // ---------------------------------------------------------------- accept paths
    function testRelease2of3() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(1);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 2));
        uint256 g = gasleft();
        sc.releaseByQuorumRBC(b, s, e);
        _gas("releaseByQuorumRBC_2of3", g - gasleft());
        (,,,,,,, uint256 cap,, DVASQuorumSettle.Status st) = sc.records(b.tid);
        assertEq(cap, CAPTURE);
        assertEq(uint256(st), uint256(DVASQuorumSettle.Status.Settled));
    }

    function testRelease3of3() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(2);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx3(0, 1, 2));
        uint256 g = gasleft();
        sc.releaseByQuorumRBC(b, s, e);
        _gas("releaseByQuorumRBC_3of3", g - gasleft());
    }

    function testRelease3of5() public {
        sc.addVerifier(sv[3]);
        sc.addVerifier(sv[4]);
        sc.setThreshold(3);
        DVASQuorumSettle.RBCBody memory b = _prepare(3);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx3(0, 3, 4));
        uint256 g = gasleft();
        sc.releaseByQuorumRBC(b, s, e);
        _gas("releaseByQuorumRBC_3of5", g - gasleft());
    }

    function testRelease1of1() public {
        address[] memory one = new address[](1);
        one[0] = sv[0];
        sc = new DVASQuorumSettle(one, 1);
        DVASQuorumSettle.RBCBody memory b = _prepare(4);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx1(0));
        uint256 g = gasleft();
        sc.releaseByQuorumRBC(b, s, e);
        _gas("releaseByQuorumRBC_1of1", g - gasleft());
    }

    function testGasLifecycle() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 meter, bytes32 rd, bytes32 hp) = _ids(50);
        uint256 g = gasleft();
        sc.authorize(tid, rho, sid, meter, payer, RESERVE);
        _gas("authorize", g - gasleft());
        g = gasleft();
        sc.submitReceipt(tid, rd, hp);
        _gas("submitReceipt", g - gasleft());
    }

    // ---------------------------------------------------------------- reject paths
    function _expectRejected(string memory name, DVASQuorumSettle.RBCBody memory b, bytes[] memory s, uint64[] memory e,
                             bytes memory reason) internal {
        uint256 g = gasleft();
        try this.callRelease(b, s, e) {
            revert("expected revert");
        } catch (bytes memory err) {
            _gas(name, g - gasleft());
            assertEq(keccak256(err), keccak256(abi.encodeWithSignature("Error(string)", string(reason))));
        }
    }

    function callRelease(DVASQuorumSettle.RBCBody memory b, bytes[] memory s, uint64[] memory e) external {
        sc.releaseByQuorumRBC(b, s, e);
    }

    function testReject1of3() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(10);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx1(1));
        _expectRejected("reject_1of3_below_threshold", b, s, e, "below threshold");
    }

    function testRejectDuplicateSigner() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(11);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx1(0));
        bytes[] memory s2 = new bytes[](2); uint64[] memory e2 = new uint64[](2);
        s2[0] = s[0]; s2[1] = s[0]; e2[0] = e[0]; e2[1] = e[0];
        _expectRejected("reject_duplicate_signer", b, s2, e2, "duplicate or unordered signer");
    }

    function testRejectUnknownSigner() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(12);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 3)); // sv[3] not registered
        _expectRejected("reject_unknown_verifier", b, s, e, "unknown or revoked verifier");
    }

    function testRejectRevokedSigner() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(13);
        sc.revokeVerifier(sv[2]);
        b.verifierSetEpoch = sc.verifierSetEpoch();
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 2));
        _expectRejected("reject_revoked_verifier", b, s, e, "unknown or revoked verifier");
    }

    function testRejectStaleVerifierSet() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(14);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        sc.addVerifier(sv[3]);
        _expectRejected("reject_stale_verifier_set", b, s, e, "stale verifier set");
    }

    function testRejectStaleKeyEpoch() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(15);
        sc.bumpVerifierEpoch(sv[0]); // key rotation for sv[0]: epoch 1 -> 2
        b.verifierSetEpoch = sc.verifierSetEpoch();
        // sv[0] still signs with its OLD key epoch 1
        bool order = sv[0] < sv[1];
        (, uint64 e1) = sc.verifiers(sv[1]);
        bytes[] memory s = new bytes[](2); uint64[] memory e = new uint64[](2);
        s[order ? 0 : 1] = _sign(pk[0], b, 1); e[order ? 0 : 1] = 1;
        s[order ? 1 : 0] = _sign(pk[1], b, e1); e[order ? 1 : 0] = e1;
        _expectRejected("reject_stale_key_epoch", b, s, e, "stale verifier epoch");
    }

    function testRejectWrongRoot() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(16);
        b.rho = keccak256("wrong rho");
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        _expectRejected("reject_wrong_root", b, s, e, "wrong rho");
    }

    function testRejectWrongSession() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(17);
        b.sid = keccak256("wrong sid");
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        _expectRejected("reject_wrong_session", b, s, e, "wrong sid");
    }

    function testRejectWrongReceiptDigest() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(18);
        b.hPriv = keccak256("substituted private payload");
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        _expectRejected("reject_wrong_receipt_or_hpriv", b, s, e, "wrong receipt digest");
    }

    function testRejectInvalidAmount() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(19);
        b.capture = RESERVE + 1;
        b.refund = 0;
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        _expectRejected("reject_capture_exceeds_reserve", b, s, e, "amount exceeds reserve");
        b.capture = CAPTURE;
        b.refund = REFUND + 1;
        (s, e) = _quorum(b, _idx(0, 1));
        _expectRejected("reject_refund_mismatch", b, s, e, "refund mismatch");
    }

    function testRejectInvalidVerifierSignature() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(20);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        bytes memory bad = s[1];
        bad[10] = bytes1(uint8(bad[10]) ^ 0xff);
        s[1] = bad;
        uint256 g = gasleft();
        try this.callRelease(b, s, e) { revert("expected revert"); } catch {
            _gas("reject_invalid_verifier_signature", g - gasleft());
        }
    }

    function testRejectDifferentDecisionDigests() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(21);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx1(0));
        DVASQuorumSettle.RBCBody memory other = DVASQuorumSettle.RBCBody(
            b.tid, b.sid, b.rho, b.meterId, b.receiptDigest, b.hPriv, CAPTURE - 1, REFUND + 1, b.policyId,
            b.verifierSetEpoch);
        (bytes[] memory s2, uint64[] memory e2) = _quorum(other, _idx1(1));
        bytes[] memory mix = new bytes[](2); uint64[] memory em = new uint64[](2);
        bool order = sv[0] < sv[1];
        mix[0] = order ? s[0] : s2[0]; mix[1] = order ? s2[0] : s[0];
        em[0] = order ? e[0] : e2[0]; em[1] = order ? e2[0] : e[0];
        // the mismatched signature recovers to a non-verifier address
        uint256 g = gasleft();
        try this.callRelease(b, mix, em) { revert("expected revert"); } catch {
            _gas("reject_different_decision_digests", g - gasleft());
        }
    }

    function testRejectReplay() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(22);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(0, 1));
        sc.releaseByQuorumRBC(b, s, e);
        _expectRejected("reject_replayed_rbc", b, s, e, "receipt not submitted");
        // same receipt digest submitted for a new trade
        (bytes32 tid2, bytes32 rho2, bytes32 sid2, bytes32 meter2,,) = _ids(2200);
        sc.authorize(tid2, rho2, sid2, meter2, payer, RESERVE);
        vm.expectRevert(bytes("receipt used"));
        sc.submitReceipt(tid2, b.receiptDigest, b.hPriv);
    }

    function testRejectThresholdConfig() public {
        vm.expectRevert(bytes("threshold must exceed n/2"));
        sc.setThreshold(1);
    }

    function testOneUnavailableStillSettles() public {
        DVASQuorumSettle.RBCBody memory b = _prepare(23);
        (bytes[] memory s, uint64[] memory e) = _quorum(b, _idx(1, 2)); // sv[0] offline
        sc.releaseByQuorumRBC(b, s, e);
    }
}
