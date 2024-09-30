// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import {IProver} from "./interface/IProver.sol";
import {Pairing} from "./utils/Pairing.sol";
import {OpenKind, ResponseType, StepResponse, Response, Winner} from "./interface/IOVC.sol";

contract Prover is IProver {
    using ECDSA for bytes32;
    using Pairing for Pairing.G1Point;

    bytes32[] public root;
    bytes32[] public leftLeaves;
    bytes32[] public rightLeaves;
    Pairing.G1Point public commitment;
    uint256 public disagreementIdx;

    constructor(Pairing.G1Point[] memory commitKey, bytes[] memory dataBytesVec) {
        uint256[] memory hashVec = new uint256[](dataBytesVec.length);
        for (uint256 i = 0; i < dataBytesVec.length; i++) {
            hashVec[i] = hashVec(dataBytesVec[i]);
        }

        (Pairing memory _commitment, bytes32 _root, bytes32[] memory leaves) = commitAndMerkle(commitKey, hashVec);

        root = _root;
        uint256 mid = leaves.length / 2;
        for (uint256 i = 0; i < mid; i++) {
            leftLeaves.push(leaves[i]);
        }
        for (uint256 i = mid; i < leaves.length; i++) {
            rightLeaves.push(leaves[i]);
        }
        commitment = _commitment;
        disagreementIdx = 0;
    }

    // Retrieves the commitment and Merkle tree root
    function getCommitmentAndRoot() public view returns (Pairing memory, bytes32) {
        return (commitment, root);
    }

    // Gets the current disagreement index
    function getDisagreementIdx() public view returns (uint256) {
        return disagreementIdx;
    }

    // Generates the initial response in the OVC protocol
    function firstResponse() public view returns (StepResponse memory) {
        bytes32 leftRoot = computeMerkleRoot(leftLeaves);
        bytes32 rightRoot = computeMerkleRoot(rightLeaves);

        return StepResponse({left: leftRoot, right: rightRoot});
    }

    // Generates a response for a single round in the OVC dispute protocol
    function findDisagreementStepResponse(OpenKind openSide) public returns (Response memory) {
        bytes32[] memory leaves = openSide == OpenKind.Left ? leftLeaves : rightLeaves;

        disagreementIdx = 2 * disagreementIdx + (openSide == OpenKind.Left ? 0 : 1);

        if (leaves.length == 1) {
            return Response({
                responseType: ResponseType.Leaf,
                leaf: leaves[0],
                stepResponse: StepResponse({left: bytes32(0), right: bytes32(0)})
            });
        }

        uint256 mid = leaves.length / 2;
        bytes32[] memory leftSubLeaves = new bytes32[](mid);
        bytes32[] memory rightSubLeaves = new bytes32[](leaves.length - mid);

        for (uint256 i = 0; i < mid; i++) {
            leftSubLeaves[i] = leaves[i];
        }
        for (uint256 i = mid; i < leaves.length; i++) {
            rightSubLeaves[i - mid] = leaves[i];
        }

        if (leftSubLeaves.length == 1) {
            bytes32 leftLeafHash = keccak256(abi.encodePacked(leftSubLeaves[0]));
            bytes32 rightLeafHash = keccak256(abi.encodePacked(rightSubLeaves[0]));

            leftLeaves = leftSubLeaves;
            rightLeaves = rightSubLeaves;

            return Response({
                responseType: ResponseType.StepResponse,
                leaf: bytes32(0),
                stepResponse: StepResponse({left: leftLeafHash, right: rightLeafHash})
            });
        } else {
            bytes32 leftRoot = computeMerkleRoot(leftSubLeaves);
            bytes32 rightRoot = computeMerkleRoot(rightSubLeaves);

            leftLeaves = leftSubLeaves;
            rightLeaves = rightSubLeaves;

            return Response({
                responseType: ResponseType.StepResponse,
                leaf: bytes32(0),
                stepResponse: StepResponse({left: leftRoot, right: rightRoot})
            });
        }
    }

    // The final step in the OVC protocol
    function computeOpeningProof(bytes memory witness, bytes memory inputData) public view returns (bytes memory) {
        // This function would need to be implemented based on your specific proof system
        // Here's a placeholder implementation
        return abi.encodePacked(witness, inputData);
    }
}
