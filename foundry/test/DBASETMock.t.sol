// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/DBASETMock.sol";

contract DBASETMockTest is Test {
    DBASETMock dbas;

    receive() external payable {}

    function setUp() public {
        dbas = new DBASETMock();
        vm.deal(address(this), 100 ether);
    }

    function testAuthorizeAndReleaseSettlement() public {
        bytes32 tradeId = keccak256("trade-1");
        bytes32 rho = keccak256("rho-1");
        bytes32 receipt = keccak256("receipt-1");

        dbas.authorizeTrade{value: 1 ether}(tradeId, rho, 1 ether);
        dbas.submitReceiptHash(tradeId, receipt);
        dbas.releaseSettlement(tradeId, receipt, 0.4 ether);

        (address user, bytes32 storedRho, uint256 held, bool receiptSubmitted, bool settled) = dbas.records(tradeId);

        assertEq(user, address(this));
        assertEq(storedRho, rho);
        assertEq(held, 1 ether);
        assertTrue(receiptSubmitted);
        assertTrue(settled);
        assertTrue(dbas.usedReceipts(receipt));
    }

    function testReplayRejectedAtSubmitAfterSettlement() public {
        bytes32 tradeId = keccak256("trade-2");
        bytes32 rho = keccak256("rho-2");
        bytes32 receipt = keccak256("receipt-2");

        dbas.authorizeTrade{value: 1 ether}(tradeId, rho, 1 ether);
        dbas.submitReceiptHash(tradeId, receipt);
        dbas.releaseSettlement(tradeId, receipt, 0.4 ether);

        vm.expectRevert(bytes("already-settled"));
        dbas.submitReceiptHash(tradeId, receipt);
    }

    function testReplayRejectedAtReleaseAfterSettlement() public {
        bytes32 tradeId = keccak256("trade-3");
        bytes32 rho = keccak256("rho-3");
        bytes32 receipt = keccak256("receipt-3");

        dbas.authorizeTrade{value: 1 ether}(tradeId, rho, 1 ether);
        dbas.submitReceiptHash(tradeId, receipt);
        dbas.releaseSettlement(tradeId, receipt, 0.4 ether);

        vm.expectRevert(bytes("already-settled"));
        dbas.releaseSettlement(tradeId, receipt, 0.4 ether);
    }

    function testOverHoldRejected() public {
        bytes32 tradeId = keccak256("trade-4");
        bytes32 rho = keccak256("rho-4");
        bytes32 receipt = keccak256("receipt-4");

        dbas.authorizeTrade{value: 1 ether}(tradeId, rho, 1 ether);
        dbas.submitReceiptHash(tradeId, receipt);

        vm.expectRevert(bytes("over-hold"));
        dbas.releaseSettlement(tradeId, receipt, 2 ether);
    }
}
