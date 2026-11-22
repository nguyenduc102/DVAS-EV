// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/DBASETGasFeasibility.sol";

contract DBASETGasFeasibilityMeasuredTest is Test {
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

    event GasResult(string name, uint256 gasUsed);

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

    function _report(string memory name, uint256 gasUsed) internal {
        console2.log(string.concat("GAS_RESULT ", name), gasUsed);
        emit GasResult(name, gasUsed);
    }

    function testGasMeasureContractFacingCalls() public {
        vm.pauseGasMetering();

        _measureDeployment();
        _measureSetVerifier();
        _measureAuthorize();
        _measureSubmitReceiptHash();
        _measureReleaseByRBC();
        _measureRefund();
        _measureOpenDispute();

        _measureRejectReplayAtRelease();
        _measureRejectWrongRoot();
        _measureRejectWrongSession();
        _measureRejectWrongReceiptDigest();
        _measureRejectOverCapture();
        _measureRejectBadVerifierSignature();

        assertTrue(true);
    }

    function _measureDeployment() internal {
        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        DBASETGasFeasibility local = new DBASETGasFeasibility(verifier);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("deployment", used);
        _report("deployment_size_bytes", address(local).code.length);
    }

    function _measureSetVerifier() internal {
        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.setVerifier(address(0x1234));
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("setVerifier", used);

        sc.setVerifier(verifier);
    }

    function _measureAuthorize() internal {
        bytes32 tid = _tid(100);
        bytes32 rho = _rho(100);
        bytes32 sid = _sid(100);

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.authorize(tid, rho, sid, payer, RESERVE);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("authorize", used);
    }

    function _measureSubmitReceiptHash() internal {
        bytes32 tid = _tid(101);
        sc.authorize(tid, _rho(101), _sid(101), payer, RESERVE);

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.submitReceiptHash(tid, _receipt(101));
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("submitReceiptHash", used);
    }

    function _measureReleaseByRBC() internal {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(102);

        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("releaseByRBC", used);
    }

    function _measureRefund() internal {
        bytes32 tid = _tid(103);
        sc.authorize(tid, _rho(103), _sid(103), payer, RESERVE);

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.refund(tid, RESERVE);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("refund", used);
    }

    function _measureOpenDispute() internal {
        (bytes32 tid,,,) = _authorizeAndSubmit(104);

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.openDispute(tid, _reason("amount-preauth"), _evidence(104));
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("openDispute", used);
    }

    function _measureRejectReplayAtRelease() internal {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(105);

        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);

        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);

        bytes32 tid2 = _tid(10505);
        bytes32 rho2 = _rho(10505);
        bytes32 sid2 = _sid(10505);

        sc.authorize(tid2, rho2, sid2, payer, RESERVE);
        sc.submitReceiptHash(tid2, receiptHash);

        bytes memory sig2 = _sig(verifierPk, tid2, rho2, sid2, receiptHash, CAPTURE, REFUND);

        vm.expectRevert(bytes("receipt used"));

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid2, rho2, sid2, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig2);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("rejectReplayAtRelease", used);
    }

    function _measureRejectWrongRoot() internal {
        (bytes32 tid,, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(106);

        bytes32 wrongRho = keccak256("wrong rho");

        bytes memory sig = _sig(verifierPk, tid, wrongRho, sid, receiptHash, CAPTURE, REFUND);

        vm.expectRevert(bytes("wrong rho"));

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid, wrongRho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("rejectWrongRoot", used);
    }

    function _measureRejectWrongSession() internal {
        (bytes32 tid, bytes32 rho,, bytes32 receiptHash) = _authorizeAndSubmit(107);

        bytes32 wrongSid = keccak256("wrong sid");

        bytes memory sig = _sig(verifierPk, tid, rho, wrongSid, receiptHash, CAPTURE, REFUND);

        vm.expectRevert(bytes("wrong sid"));

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid, rho, wrongSid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("rejectWrongSession", used);
    }

    function _measureRejectWrongReceiptDigest() internal {
        (bytes32 tid, bytes32 rho, bytes32 sid,) = _authorizeAndSubmit(108);

        bytes32 wrongReceiptHash = keccak256("wrong receipt");

        bytes memory sig = _sig(verifierPk, tid, rho, sid, wrongReceiptHash, CAPTURE, REFUND);

        vm.expectRevert(bytes("wrong receipt hash"));

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid, rho, sid, wrongReceiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("rejectWrongReceiptDigest", used);
    }

    function _measureRejectOverCapture() internal {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(109);

        uint256 badCapture = RESERVE + 1;
        uint256 badRefund = 1;

        bytes memory sig = _sig(verifierPk, tid, rho, sid, receiptHash, badCapture, badRefund);

        vm.expectRevert(bytes("amount exceeds reserve"));

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, badCapture, badRefund, sig);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("rejectOverCapture", used);
    }

    function _measureRejectBadVerifierSignature() internal {
        (bytes32 tid, bytes32 rho, bytes32 sid, bytes32 receiptHash) = _authorizeAndSubmit(110);

        bytes memory sig = _sig(badVerifierPk, tid, rho, sid, receiptHash, CAPTURE, REFUND);

        vm.expectRevert(bytes("bad verifier sig"));

        vm.resumeGasMetering();
        uint256 g0 = gasleft();
        sc.releaseByRBC(tid, rho, sid, receiptHash, PRIVATE_EVIDENCE_DIGEST, CAPTURE, REFUND, sig);
        uint256 used = g0 - gasleft();
        vm.pauseGasMetering();

        _report("rejectBadVerifierSignature", used);

        assertTrue(badVerifier != verifier);
    }
}
