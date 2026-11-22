// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DVASQuorumSettle
/// @notice On-chain public-invariant and quorum checks for DVAS-EV settlement.
/// @dev Semantic verification (PAM openings, Match predicate, meter signature,
///      private-evidence decryption) is performed off-chain by independent
///      settlement verifiers. This contract only checks:
///        - tid/sid/rho/receipt-digest/h_priv binding to its own state,
///        - capture/refund bounds against the reserved amount,
///        - replay state (receipt digest and RBC digest),
///        - >= threshold ECDSA attestations from distinct, active verifiers at
///          the current key epoch, all over the same decision digest.
///      Verifier attestations are ECDSA (secp256k1): this settlement path is
///      classical, which is why the overall DVAS-EV design is labelled HYBRID.
contract DVASQuorumSettle {
    enum Status { None, Authorized, ReceiptSubmitted, Settled }

    struct TradeRecord {
        address payer;
        bytes32 rho;
        bytes32 sid;
        bytes32 meterId;
        bytes32 receiptDigest;
        bytes32 hPriv;
        uint256 reserved;
        uint256 captured;
        uint256 refunded;
        Status status;
    }

    struct VerifierInfo {
        bool active;
        uint64 epoch;
    }

    struct RBCBody {
        bytes32 tid;
        bytes32 sid;
        bytes32 rho;
        bytes32 meterId;
        bytes32 receiptDigest;
        bytes32 hPriv;
        uint256 capture;
        uint256 refund;
        bytes32 policyId;
        uint64 verifierSetEpoch;
    }

    bytes32 public constant POLICY_ID = keccak256("P.settlement/dvas-ev-layout-v1/v1");

    address public owner;
    uint8 public threshold;
    uint64 public verifierSetEpoch;
    uint256 public activeVerifiers;

    mapping(address => VerifierInfo) public verifiers;
    mapping(bytes32 => TradeRecord) public records;
    mapping(bytes32 => bool) public usedReceipts;
    mapping(bytes32 => bool) public usedRbc;

    event VerifierSetChanged(address indexed verifier, bool active, uint64 epoch, uint64 setEpoch);
    event Authorized(bytes32 indexed tid, address indexed payer, bytes32 rho, bytes32 sid, uint256 reserved);
    event ReceiptSubmitted(bytes32 indexed tid, bytes32 receiptDigest, bytes32 hPriv);
    event SettledByQuorum(bytes32 indexed tid, bytes32 decisionDigest, uint256 capture, uint256 refund, uint256 attestations);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address[] memory initialVerifiers, uint8 t) {
        owner = msg.sender;
        for (uint256 i = 0; i < initialVerifiers.length; i++) {
            _addVerifier(initialVerifiers[i]);
        }
        _setThreshold(t);
    }

    // ------------------------------------------------------------------ registry
    function _addVerifier(address v) internal {
        require(v != address(0), "zero verifier");
        require(!verifiers[v].active, "already active");
        verifiers[v] = VerifierInfo({active: true, epoch: verifiers[v].epoch + 1});
        activeVerifiers += 1;
        verifierSetEpoch += 1;
        emit VerifierSetChanged(v, true, verifiers[v].epoch, verifierSetEpoch);
    }

    function _setThreshold(uint8 t) internal {
        require(t >= 1 && t <= activeVerifiers, "bad threshold");
        require(uint256(t) * 2 > activeVerifiers, "threshold must exceed n/2");
        threshold = t;
    }

    function addVerifier(address v) external onlyOwner {
        _addVerifier(v);
    }

    function revokeVerifier(address v) external onlyOwner {
        require(verifiers[v].active, "not active");
        verifiers[v].active = false;
        activeVerifiers -= 1;
        verifierSetEpoch += 1;
        require(uint256(threshold) <= activeVerifiers, "threshold unreachable");
        emit VerifierSetChanged(v, false, verifiers[v].epoch, verifierSetEpoch);
    }

    /// @notice Key rotation: same verifier identity, new epoch (old signatures become stale).
    function bumpVerifierEpoch(address v) external onlyOwner {
        require(verifiers[v].active, "not active");
        verifiers[v].epoch += 1;
        verifierSetEpoch += 1;
        emit VerifierSetChanged(v, true, verifiers[v].epoch, verifierSetEpoch);
    }

    function setThreshold(uint8 t) external onlyOwner {
        _setThreshold(t);
    }

    // ------------------------------------------------------------------ lifecycle
    function authorize(bytes32 tid, bytes32 rho, bytes32 sid, bytes32 meterId, address payer, uint256 reserved) external {
        require(tid != bytes32(0) && rho != bytes32(0) && sid != bytes32(0), "zero id");
        require(payer != address(0), "zero payer");
        require(reserved > 0, "zero reserve");
        require(records[tid].status == Status.None, "trade exists");
        records[tid] = TradeRecord(payer, rho, sid, meterId, bytes32(0), bytes32(0), reserved, 0, 0, Status.Authorized);
        emit Authorized(tid, payer, rho, sid, reserved);
    }

    function submitReceipt(bytes32 tid, bytes32 receiptDigest, bytes32 hPriv) external {
        TradeRecord storage r = records[tid];
        require(r.status == Status.Authorized, "not authorized");
        require(receiptDigest != bytes32(0) && hPriv != bytes32(0), "zero receipt");
        require(!usedReceipts[receiptDigest], "receipt used");
        r.receiptDigest = receiptDigest;
        r.hPriv = hPriv;
        r.status = Status.ReceiptSubmitted;
        emit ReceiptSubmitted(tid, receiptDigest, hPriv);
    }

    function decisionDigest(RBCBody calldata b) public view returns (bytes32) {
        return keccak256(abi.encode(
            "DVAS-EV-RBC-v1", block.chainid, address(this),
            b.tid, b.sid, b.rho, b.meterId, b.receiptDigest, b.hPriv,
            b.capture, b.refund, b.policyId, b.verifierSetEpoch
        ));
    }

    function attestationDigest(bytes32 decision, uint64 epoch) public pure returns (bytes32) {
        return keccak256(abi.encode("DVAS-EV-ATTEST-v1", decision, epoch));
    }

    /// @param sigs  65-byte ECDSA signatures, ordered by strictly increasing signer address
    /// @param epochs key epoch claimed by each signer
    function releaseByQuorumRBC(RBCBody calldata b, bytes[] calldata sigs, uint64[] calldata epochs) external {
        TradeRecord storage r = records[b.tid];
        // structure / state
        require(r.status == Status.ReceiptSubmitted, "receipt not submitted");
        require(sigs.length == epochs.length && sigs.length > 0, "bad attestation list");
        require(b.policyId == POLICY_ID, "wrong policy");
        // binding
        require(r.rho == b.rho, "wrong rho");
        require(r.sid == b.sid, "wrong sid");
        require(r.meterId == b.meterId, "wrong meter");
        require(r.receiptDigest == b.receiptDigest && r.hPriv == b.hPriv, "wrong receipt digest");
        // amounts
        require(b.capture <= r.reserved, "amount exceeds reserve");
        require(b.refund == r.reserved - b.capture, "refund mismatch");
        // replay
        require(!usedReceipts[b.receiptDigest], "receipt used");
        bytes32 d = decisionDigest(b);
        require(!usedRbc[d], "rbc used");
        // quorum
        require(b.verifierSetEpoch == verifierSetEpoch, "stale verifier set");
        address last = address(0);
        uint256 valid = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = _recover(attestationDigest(d, epochs[i]), sigs[i]);
            require(signer > last, "duplicate or unordered signer");
            VerifierInfo memory vi = verifiers[signer];
            require(vi.active, "unknown or revoked verifier");
            require(vi.epoch == epochs[i], "stale verifier epoch");
            last = signer;
            valid += 1;
        }
        require(valid >= threshold, "below threshold");
        // atomic consumption
        usedReceipts[b.receiptDigest] = true;
        usedRbc[d] = true;
        r.captured = b.capture;
        r.refunded = b.refund;
        r.status = Status.Settled;
        emit SettledByQuorum(b.tid, d, b.capture, b.refund, valid);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 rr;
        bytes32 ss;
        uint8 v;
        assembly {
            rr := calldataload(sig.offset)
            ss := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        require(v == 27 || v == 28, "bad v");
        require(uint256(ss) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "high s");
        address signer = ecrecover(digest, v, rr, ss);
        require(signer != address(0), "bad signature");
        return signer;
    }
}
