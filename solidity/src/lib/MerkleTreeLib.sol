// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../utils/Pairing.sol"; // Import from the same directory

library MerkleTreeLib {
    using Pairing for Pairing.G1Point;

    struct MerkleTree {
        bytes32 root;
        bytes32[] leaves;
    }

    function commitAndMerkle(Pairing.G1Point[] memory commitKey, uint256[] memory hashedLogsVec)
        internal
        pure
        returns (
            Pairing.G1Point memory commitment,
            MerkleTree memory merkleTree,
            bytes[] memory unrolledCommitmentSerialized
        )
    {
        require(commitKey.length == hashedLogsVec.length, "Input lengths must match");

        (Pairing.G1Point[] memory unrolledCommitment, Pairing.G1Point memory _commitment) =
            commitUnrolled(commitKey, hashedLogsVec);

        commitment = _commitment;

        unrolledCommitmentSerialized = new bytes[](unrolledCommitment.length);
        bytes32[] memory merkleLeaves = new bytes32[](unrolledCommitment.length);

        for (uint256 i = 0; i < unrolledCommitment.length; i++) {
            unrolledCommitmentSerialized[i] = abi.encodePacked(unrolledCommitment[i].X, unrolledCommitment[i].Y);
            merkleLeaves[i] = keccak256(unrolledCommitmentSerialized[i]);
        }

        bytes32 root = computeMerkleRoot(merkleLeaves);
        merkleTree = MerkleTree(root, merkleLeaves);
    }

    function commitUnrolled(Pairing.G1Point[] memory commitKey, uint256[] memory hashedLogsVec)
        internal
        pure
        returns (Pairing.G1Point[] memory unrolledCommitment, Pairing.G1Point memory commitment)
    {
        unrolledCommitment = new Pairing.G1Point[](commitKey.length);
        commitment = Pairing.G1Point(0, 0);

        for (uint256 i = 0; i < commitKey.length; i++) {
            unrolledCommitment[i] = commitKey[i].mul(hashedLogsVec[i]);
            commitment = commitment.add(unrolledCommitment[i]);
        }
    }

    function computeMerkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "Empty leaf array");

        while (leaves.length > 1) {
            if (leaves.length % 2 != 0) {
                leaves.push(leaves[leaves.length - 1]);
            }

            uint256 length = leaves.length / 2;
            bytes32[] memory newLeaves = new bytes32[](length);

            for (uint256 i = 0; i < length; i++) {
                newLeaves[i] = keccak256(abi.encodePacked(leaves[2 * i], leaves[2 * i + 1]));
            }

            leaves = newLeaves;
        }

        return leaves[0];
    }

    function hashVec(bytes memory bytesVec) internal pure returns (uint256) {
        bytes32 hash = keccak256(bytesVec);

        // Convert the hash to a uint256, which we'll use as our "field element"
        uint256 fieldElement = uint256(hash);

        // Ensure the value is within a typical prime field range
        uint256 prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        return fieldElement % prime;
    }
}
