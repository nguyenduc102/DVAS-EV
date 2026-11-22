// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DBASETGasFeasibility {
    enum Status {
        None,
        Authorized,
        ReceiptSubmitted,
        Released,
        Refunded,
        Disputed
    }

    struct TradeRecord {
        address payer;
        bytes32 rho;
        bytes32 sid;
        bytes32 receiptHash;
        uint256 reservedAmount;
        uint256 capturedAmount;
        uint256 refundedAmount;
        Status status;
    }

    address public owner;
    address public verifier;

    mapping(bytes32 => TradeRecord) public records;
    mapping(bytes32 => bool) public usedReceipts;
    mapping(bytes32 => bytes32) public disputeEvidenceRoot;
    mapping(bytes32 => bytes32) public disputeReason;

    event VerifierUpdated(address indexed verifier);
    event Authorized(bytes32 indexed tid, address indexed payer, bytes32 rho, bytes32 sid, uint256 reservedAmount);
    event ReceiptHashSubmitted(bytes32 indexed tid, bytes32 receiptHash);
    event ReleasedByRBC(
        bytes32 indexed tid,
        bytes32 receiptHash,
        bytes32 privateEvidenceDigest,
        uint256 captureAmount,
        uint256 refundAmount
    );
    event Refunded(bytes32 indexed tid, uint256 refundAmount);
    event DisputeOpened(bytes32 indexed tid, bytes32 reason, bytes32 evidenceRoot);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialVerifier) {
        owner = msg.sender;
        verifier = initialVerifier;
        emit VerifierUpdated(initialVerifier);
    }

    function setVerifier(address newVerifier) external onlyOwner {
        require(newVerifier != address(0), "zero verifier");
        verifier = newVerifier;
        emit VerifierUpdated(newVerifier);
    }

    function authorize(bytes32 tid, bytes32 rho, bytes32 sid, address payer, uint256 reservedAmount) external {
        require(tid != bytes32(0), "zero tid");
        require(rho != bytes32(0), "zero rho");
        require(sid != bytes32(0), "zero sid");
        require(payer != address(0), "zero payer");
        require(reservedAmount > 0, "zero reserve");
        require(records[tid].status == Status.None, "trade exists");

        records[tid] = TradeRecord({
            payer: payer,
            rho: rho,
            sid: sid,
            receiptHash: bytes32(0),
            reservedAmount: reservedAmount,
            capturedAmount: 0,
            refundedAmount: 0,
            status: Status.Authorized
        });

        emit Authorized(tid, payer, rho, sid, reservedAmount);
    }

    function submitReceiptHash(bytes32 tid, bytes32 receiptHash) external {
        TradeRecord storage r = records[tid];
        require(r.status == Status.Authorized, "not authorized");
        require(receiptHash != bytes32(0), "zero receipt");
        require(r.receiptHash == bytes32(0), "receipt already submitted");

        r.receiptHash = receiptHash;
        r.status = Status.ReceiptSubmitted;

        emit ReceiptHashSubmitted(tid, receiptHash);
    }

    function releaseByRBC(
        bytes32 tid,
        bytes32 rho,
        bytes32 sid,
        bytes32 receiptHash,
        bytes32 privateEvidenceDigest,
        uint256 captureAmount,
        uint256 refundAmount,
        bytes calldata verifierSignature
    ) external {
        TradeRecord storage r = records[tid];

        require(r.status == Status.ReceiptSubmitted, "receipt not submitted");
        require(r.rho == rho, "wrong rho");
        require(r.sid == sid, "wrong sid");
        require(r.receiptHash == receiptHash, "wrong receipt hash");
        require(!usedReceipts[receiptHash], "receipt used");
        require(captureAmount + refundAmount <= r.reservedAmount, "amount exceeds reserve");

        bytes32 digest = rbcDigest(tid, rho, sid, receiptHash, privateEvidenceDigest, captureAmount, refundAmount);
        require(_recover(digest, verifierSignature) == verifier, "bad verifier sig");

        usedReceipts[receiptHash] = true;
        r.capturedAmount = captureAmount;
        r.refundedAmount = refundAmount;
        r.status = Status.Released;

        emit ReleasedByRBC(tid, receiptHash, privateEvidenceDigest, captureAmount, refundAmount);
    }

    function refund(bytes32 tid, uint256 refundAmount) external {
        TradeRecord storage r = records[tid];

        require(r.status == Status.Authorized || r.status == Status.ReceiptSubmitted, "not refundable");
        require(refundAmount <= r.reservedAmount, "refund exceeds reserve");

        r.refundedAmount = refundAmount;
        r.status = Status.Refunded;

        emit Refunded(tid, refundAmount);
    }

    function openDispute(bytes32 tid, bytes32 reason, bytes32 evidenceRoot) external {
        TradeRecord storage r = records[tid];

        require(r.status != Status.None, "unknown trade");
        require(reason != bytes32(0), "zero reason");
        require(evidenceRoot != bytes32(0), "zero evidence");

        disputeReason[tid] = reason;
        disputeEvidenceRoot[tid] = evidenceRoot;
        r.status = Status.Disputed;

        emit DisputeOpened(tid, reason, evidenceRoot);
    }

    function rbcDigest(
        bytes32 tid,
        bytes32 rho,
        bytes32 sid,
        bytes32 receiptHash,
        bytes32 privateEvidenceDigest,
        uint256 captureAmount,
        uint256 refundAmount
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "DBAS-ET-RBC-v1",
                block.chainid,
                address(this),
                tid,
                rho,
                sid,
                receiptHash,
                privateEvidenceDigest,
                captureAmount,
                refundAmount
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        require(v == 27 || v == 28, "bad v");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad ecrecover");
        return signer;
    }
}
