// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DBASETMock
/// @notice Minimal Solidity feasibility artifact for DBAS-ET reserve/release semantics.
/// @dev This is not a production smart contract and does not verify full projection proofs on-chain.
contract DBASETMock {
    struct AuthRecord {
        address user;
        bytes32 rho;
        uint256 heldAmount;
        bool receiptSubmitted;
        bool settled;
    }

    mapping(bytes32 => AuthRecord) public records;
    mapping(bytes32 => bytes32) public submittedReceiptHash;
    mapping(bytes32 => bool) public usedReceipts;

    event Authorized(bytes32 indexed tradeId, address indexed user, bytes32 rho, uint256 heldAmount);
    event ReceiptSubmitted(bytes32 indexed tradeId, bytes32 receiptHash);
    event Settled(bytes32 indexed tradeId, uint256 capturedAmount, uint256 refund);

    function authorizeTrade(bytes32 tradeId, bytes32 rho, uint256 holdAmount) external payable {
        require(records[tradeId].user == address(0), "already-authorized");
        require(msg.value == holdAmount, "hold-mismatch");
        require(holdAmount > 0, "zero-hold");

        records[tradeId] =
            AuthRecord({user: msg.sender, rho: rho, heldAmount: holdAmount, receiptSubmitted: false, settled: false});

        emit Authorized(tradeId, msg.sender, rho, holdAmount);
    }

    function submitReceiptHash(bytes32 tradeId, bytes32 receiptHash) external {
        AuthRecord storage rec = records[tradeId];
        require(rec.user != address(0), "missing-auth");
        require(!rec.settled, "already-settled");
        require(receiptHash != bytes32(0), "zero-receipt");
        require(!usedReceipts[receiptHash], "replay");

        rec.receiptSubmitted = true;
        submittedReceiptHash[tradeId] = receiptHash;

        emit ReceiptSubmitted(tradeId, receiptHash);
    }

    function releaseSettlement(bytes32 tradeId, bytes32 receiptHash, uint256 capturedAmount) external {
        AuthRecord storage rec = records[tradeId];
        require(rec.user != address(0), "missing-auth");
        require(!rec.settled, "already-settled");
        require(rec.receiptSubmitted, "missing-receipt");
        require(submittedReceiptHash[tradeId] == receiptHash, "receipt-mismatch");
        require(!usedReceipts[receiptHash], "replay");
        require(capturedAmount <= rec.heldAmount, "over-hold");

        usedReceipts[receiptHash] = true;
        rec.settled = true;

        uint256 refund = rec.heldAmount - capturedAmount;

        emit Settled(tradeId, capturedAmount, refund);

        if (refund > 0) {
            (bool ok,) = payable(rec.user).call{value: refund}("");
            require(ok, "refund-failed");
        }
    }
}
