// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/DBASETGasFeasibility.sol";

contract DBASETGasFeasibilityTest is Test {
    bytes32 internal constant PRIVATE_EVIDENCE_DIGEST = keccak256("rbc-private-evidence");
    DBASETGasFeasibility internal sc;

    uint256 internal verifierPk = 0xA11CE;
    uint256 internal badVerifierPk = 0xB0B;
    address internal verifier;
    address internal badVerifier;
    address internal payer = address(0xCAFE);

    uint256 internal constant RESERVE = 1000;
    uint256 internal constant CAPTURE = 720;
    uint256 internal constant REFUND = 280;

    function setUp() public {
        verifier = vm.addr(verifierPk);
        badVerifier = vm.addr(badVerifierPk);
        sc = new DBASETGasFeasibility(verifier);
    }

    function _tid(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("tid", i));
    }

    function _rho(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("rho", i));
    }

    function _sid(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("sid", i));
    }

    function _receipt(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("receipt", i));
    }

    function _evidence(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("evidence", i));
    }

    function _reason(string memory r) internal pure returns (bytes32) {
        return keccak256(bytes(r));
    }

    function _sig(
        uint256 pk,
        bytes32 tid,
        bytes32 rho,
        bytes32 sid,
        bytes32 receiptHash,
        uint256 captureAmount,
        uint256 refundAmount
    ) internal view returns (bytes memory) {
        bytes32 digest = sc.rbcDigest(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, captureAmount, refundAmount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _authorizeAndSubmit(uint256 i)
        internal
        returns (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash)
    {
        tid = _tid(i);
        rho = _rho(i);
        sid = _sid(i);
        receiptHash = _receipt(i);
        sc.authorize(tid, rho, sid, payer, RESERVE);
        sc.submitReceiptHash(tid, receiptHash);
    }

    function testSetVerifierGas() public {
        address newVerifier = address(0x1234);
        sc.setVerifier(newVerifier);
        assertEq(sc.verifier(), newVerifier);
    }

    function testAuthorizeGas() public {
        sc.authorize(_tid(1), _rho(1), _sid(1), payer, RESERVE);
        (
            address storedPayer,
            bytes32 storedRho,
            bytes32 storedSid,
            bytes32 storedReceipt,
            uint256 reservedAmount,
            uint256 capturedAmount,
            uint256 refundedAmount,
            DBASETGasFeasibility.Status status
        ) = sc.records(_tid(1));

        assertEq(storedPayer, payer);
        assertEq(storedRho, _rho(1));
        assertEq(storedSid, _sid(1));
        assertEq(storedReceipt, bytes32(0));
        assertEq(reservedAmount, RESERVE);
        assertEq(capturedAmount, 0);
        assertEq(refundedAmount, 0);
        assertEq(uint256(status), uint256(DBASETGasFeasibility.Status.Authorized));
    }

    function testRejectZeroReserveGas() public {
        vm.expectRevert(bytes("zero reserve"));
        sc.authorize(_tid(2), _rho(2), _sid(2), payer, 0);
    }

    function testSubmitReceiptHashGas() public {
        bytes32 tid = _tid(3);
        sc.authorize(tid, _rho(3), _sid(3), payer, RESERVE);
        sc.submitReceiptHash(tid, _receipt(3));
    }

    function testRejectDuplicateReceiptSubmissionGas() public {
        bytes32 tid = _tid(4);
        sc.authorize(tid, _rho(4), _sid(4), payer, RESERVE);
        sc.submitReceiptHash(tid, _receipt(4));
        vm.expectRevert(bytes("not authorized"));
        sc.submitReceiptHash(tid, _receipt(4));
    }

    function testReleaseByRBCGas() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(5);
        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        assertTrue(sc.usedReceipts(receiptHash));
    }

    function testRejectReplayAtReleaseGas() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(6);
        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);

        bytes32 tid2 = _tid(6006);
        bytes32 rho2 = _rho(6006);
        bytes32 sid2 = _sid(6006);
        sc.authorize(tid2, rho2, sid2, payer, RESERVE);
        sc.submitReceiptHash(tid2, receiptHash);
        bytes memory sig2 = _sig(verifierPk, tid2, rho2, sid2, receiptHash, CAPTURE, REFUND);

        vm.expectRevert(bytes("receipt used"));
        sc.releaseByRBC(tid2, rho2, sid2, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig2);
    }

    function testRejectWrongRootGas() public {
        (bytes32 tid,, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(7);
        bytes32 wrongRho = keccak256("wrong rho");
        bytes memory sig = _sig(verifierPk, tid, wrongRho, sid, receiptHash, CAPTURE, REFUND);
        vm.expectRevert(bytes("wrong rho"));
        sc.releaseByRBC(tid, wrongRho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
    }

    function testRejectWrongSessionGas() public {
        (bytes32 tid, bytes32 rho,, bytes32 receiptHash) = _authorizeAndSubmit(8);
        bytes32 wrongSid = keccak256("wrong sid");
        bytes memory sig = _sig(verifierPk, tid, rho, wrongSid, receiptHash, CAPTURE, REFUND);
        vm.expectRevert(bytes("wrong sid"));
        sc.releaseByRBC(tid, rho, wrongSid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
    }

    function testRejectWrongReceiptDigestGas() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(9);
        bytes32 wrongReceiptHash = keccak256("wrong receipt");
        bytes memory sig = _sig(verifierPk, tid, rho, sid, wrongReceiptHash, CAPTURE, REFUND);
        vm.expectRevert(bytes("wrong receipt hash"));
        sc.releaseByRBC(tid, rho, sid, wrongReceiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        assertTrue(receiptHash != bytes32(0));
    }

    function testRejectOverCaptureGas() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(10);
        uint256 badCapture = 1001;
        uint256 badRefund = 1;
        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, badCapture, badRefund);
        vm.expectRevert(bytes("amount exceeds reserve"));
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, badCapture, badRefund, sig);
    }

    function testRejectBadVerifierSignatureGas() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(11);
        bytes memory sig = _sig(badVerifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);
        vm.expectRevert(bytes("bad verifier sig"));
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        assertTrue(badVerifier != verifier);
    }

    function testRefundGas() public {
        bytes32 tid = _tid(12);
        sc.authorize(tid, _rho(12), _sid(12), payer, RESERVE);
        sc.refund(tid, RESERVE);
    }

    function testRejectRefundExceedsReserveGas() public {
        bytes32 tid = _tid(13);
        sc.authorize(tid, _rho(13), _sid(13), payer, RESERVE);
        vm.expectRevert(bytes("refund exceeds reserve"));
        sc.refund(tid, RESERVE + 1);
    }

    function testOpenDisputeGas() public {
        (bytes32 tid,,,) = _authorizeAndSubmit(14);
        sc.openDispute(tid, _reason("amount-preauth"), _evidence(14));
        assertEq(sc.disputeReason(tid), _reason("amount-preauth"));
        assertEq(sc.disputeEvidenceRoot(tid), _evidence(14));
    }

    function testOpenDisputeAfterReleaseGas() public {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(15);
        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        sc.openDispute(tid, _reason("rbc-semantic-challenge"), _evidence(15));
    }

    function testRejectUnknownDisputeGas() public {
        vm.expectRevert(bytes("unknown trade"));
        sc.openDispute(_tid(16), _reason("replay"), _evidence(16));
    }
}
