// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import {MerkleTreeLib} from "./lib/MerkleTree.sol";
import {IReferee} from "./interface/IReferee.sol";
import {IProofSystem} from "./interface/IProofSystem.sol";
import {Pairing} from "./utils/Pairing.sol";

import {OpenKind, Winner, StepResponse} from "./interfaces/IOVC.sol";

contract Referee is IReferee {
    using Pairing for Pairing.G1Point;
    using ProverLib for *;

    bytes32 public prover1Root;
    bytes32 public prover2Root;
    uint256 public treeSize;
    Pairing.G1Point[] public commitmentKey;

    IProofSystem public proofSystem;

    constructor(
        bytes32 _prover1Root,
        bytes32 _prover2Root,
        uint256 _treeSize,
        Pairing.G1Point[] memory _commitmentKey,
        address _proofSystem
    ) {
        prover1Root = _prover1Root;
        prover2Root = _prover2Root;
        treeSize = _treeSize;
        commitmentKey = _commitmentKey;
        proofSystem = IProofSystem(_proofSystem);
    }

    function findDisagreementStep(StepResponse memory prover1Response, StepResponse memory prover2Response)
        public
        returns (OpenKind)
    {
        bytes32 prover1LChild = prover1Response.left;
        bytes32 prover1RChild = prover1Response.right;
        bytes32 prover2LChild = prover2Response.left;
        bytes32 prover2RChild = prover2Response.right;

        bytes32 prover1Node;
        bytes32 prover2Node;

        if (treeSize == 2) {
            prover1Node = keccak256(abi.encodePacked(prover1LChild, prover1RChild));
            prover2Node = keccak256(abi.encodePacked(prover2LChild, prover2RChild));
        } else {
            prover1Node = keccak256(abi.encodePacked(prover1LChild, prover1RChild));
            prover2Node = keccak256(abi.encodePacked(prover2LChild, prover2RChild));
        }

        require(prover1Node == prover1Root, "Prover 1 response invalid");
        require(prover2Node == prover2Root, "Prover 2 response invalid");

        if (prover1LChild != prover2LChild) {
            prover1Root = prover1LChild;
            prover2Root = prover2LChild;
            treeSize = treeSize / 2;
            return OpenKind.Left;
        } else {
            prover1Root = prover1RChild;
            prover2Root = prover2RChild;
            treeSize = treeSize / 2;
            return OpenKind.Right;
        }
    }

    function openingProofVerify(
        uint256 disagreementIdx,
        bytes memory proof1,
        bytes32 root1Hash,
        bytes memory serializedCommitment1,
        bytes memory proof2,
        bytes32 root2Hash,
        bytes memory serializedCommitment2
    ) public view returns (Winner) {
        bool prover1Passed = proofSystem.verifyProof(
            commitmentKey[disagreementIdx], serializedCommitment1, disagreementIdx, root1Hash, proof1
        );

        bool prover2Passed = proofSystem.verifyProof(
            commitmentKey[disagreementIdx], serializedCommitment2, disagreementIdx, root2Hash, proof2
        );

        if (prover1Passed && prover2Passed) {
            return Winner.Both;
        } else if (prover1Passed && !prover2Passed) {
            return Winner.Prover1;
        } else if (!prover1Passed && prover2Passed) {
            return Winner.Prover2;
        } else {
            return Winner.Neither;
        }
    }
}
