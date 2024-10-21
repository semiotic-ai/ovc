// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct Receipt {
    TxType txType;
    bool success;
    uint256 cumulativeGasUsed;
    Log[] logs;
}

enum TxType {
    Legacy,
    EIP2930,
    EIP1559
}

struct Log {
    address addr;
    bytes32[] topics;
    bytes data;
}

library ReceiptLib {}
