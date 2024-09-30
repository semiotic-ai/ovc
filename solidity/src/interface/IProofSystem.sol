// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Pairing} from "../utils/Pairing.sol";
/**
 * @title Interface for a proof system
 */

interface IProofSystem {
    function verifyProof(
        Pairing.G1Point memory commitmentKeyElement,
        bytes memory serializedCommitment,
        uint256 index,
        bytes32 rootHash,
        bytes memory proof
    ) external pure returns (bool);
}
