// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-solidity/contracts/utils/cryptography/MerkleProof.sol";
import "./utils/Pairing.sol"; // BN254 curve pairing (import your BN254 library here)

contract ProverVerifier {
    struct Prover {
        bytes32 root;
        bytes32[] leftLeaves;
        bytes32[] rightLeaves;
        Pairing.G1Point commitment;
        uint256 disagreementIdx;
    }

    enum OpenKind {
        Left,
        Right
    }

    struct StepResponse {
        bytes32 left;
        bytes32 right;
    }

    struct Response {
        StepResponse stepResponse;
        bytes32 leaf;
    }

    struct Referee {
        bytes32 prover1Root;
        bytes32 prover2Root;
        uint256 treeSize;
        Pairing.G1Point[] commitmentKey;
    }

    struct Winner {
        bool both;
        bool prover1;
        bool prover2;
        bool neither;
    }

    function hashReceipt(bytes memory data) public pure returns (bytes32) {
        return sha256(data);
    }

    function commitAndMerkle(Pairing.G1Point[] memory commitKey, bytes32[] memory hashedReceipts)
        public
        pure
        returns (Pairing.G1Point memory, bytes32, bytes32[] memory)
    {
        Pairing.G1Point memory commitment = commitUnrolled(commitKey, hashedReceipts);
        bytes32[] memory leaves = new bytes32[](commitKey.length);
        for (uint256 i = 0; i < commitKey.length; i++) {
            leaves[i] = keccak256(abi.encodePacked(commitKey[i].X, commitKey[i].Y, hashedReceipts[i]));
        }
        bytes32 merkleRoot = getMerkleRoot(leaves);
        return (commitment, merkleRoot, leaves);
    }

    function commitUnrolled(Pairing.G1Point[] memory commitKey, bytes32[] memory hashedReceipts)
        public
        pure
        returns (Pairing.G1Point memory)
    {
        Pairing.G1Point memory commitment = Pairing.G1Point(0, 0);
        for (uint256 i = 0; i < commitKey.length; i++) {
            Pairing.G1Point memory mulResult = Pairing.scalar_mul(commitKey[i], uint256(hashedReceipts[i]));
            commitment = Pairing.addition(commitment, mulResult);
        }
        return commitment;
    }

    function getMerkleRoot(bytes32[] memory leaves) public pure returns (bytes32) {
        bytes32[] memory merkleNodes = leaves;
        while (merkleNodes.length > 1) {
            uint256 n = merkleNodes.length / 2;
            bytes32[] memory nextLevel = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                nextLevel[i] = sha256(abi.encodePacked(merkleNodes[2 * i], merkleNodes[2 * i + 1]));
            }
            merkleNodes = nextLevel;
        }
        return merkleNodes[0];
    }

    function firstResponse(Prover storage prover) public view returns (StepResponse memory) {
        bytes32 leftMerkleRoot = getMerkleRoot(prover.leftLeaves);
        bytes32 rightMerkleRoot = getMerkleRoot(prover.rightLeaves);
        return StepResponse(leftMerkleRoot, rightMerkleRoot);
    }

    function findDisagreementStepResponse(Prover storage prover, OpenKind openSide) public returns (Response memory) {
        bytes32[] memory leaves = openSide == OpenKind.Left ? prover.leftLeaves : prover.rightLeaves;
        prover.disagreementIdx = 2 * prover.disagreementIdx + (openSide == OpenKind.Left ? 0 : 1);

        if (leaves.length == 1) {
            return Response(StepResponse(bytes32(0), bytes32(0)), leaves[0]);
        }

        bytes32[] memory leftLeaves = new bytes32[](leaves.length / 2);
        bytes32[] memory rightLeaves = new bytes32[](leaves.length / 2);
        for (uint256 i = 0; i < leaves.length / 2; i++) {
            leftLeaves[i] = leaves[i];
            rightLeaves[i] = leaves[leaves.length / 2 + i];
        }

        prover.leftLeaves = leftLeaves;
        prover.rightLeaves = rightLeaves;

        return Response(
            StepResponse(sha256(abi.encodePacked(leftLeaves)), sha256(abi.encodePacked(rightLeaves))), bytes32(0)
        );
    }

    function verifyMerkleProof(bytes32 root, bytes32 leaf, bytes32[] memory proof, uint256 index)
        public
        pure
        returns (bool)
    {
        return MerkleProof.verify(proof, root, leaf);
    }

    // Example pairing-based verification (using BN254)
    function verifyCommitment(
        Pairing.G1Point memory commitment,
        Pairing.G1Point memory key,
        bytes32 commitmentBytes,
        uint256 idx,
        bytes32 rootHash
    ) public view returns (bool) {
        // Add verification logic based on your proof system
        return true; // Placeholder logic
    }
}
