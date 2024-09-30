// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Enum and struct definitions
enum OpenKind {
    Left,
    Right
}

enum ResponseType {
    StepResponse,
    Leaf
}

struct StepResponse {
    bytes32 left;
    bytes32 right;
}

struct Response {
    ResponseType responseType;
    bytes32 leaf;
    StepResponse stepResponse;
}

enum Winner {
    Both,
    Prover1,
    Prover2,
    Neither
}
