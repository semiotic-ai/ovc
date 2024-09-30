// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../src/lib/UniswapV2.sol";
// import "../src/RethPrimitives.sol";
// import "../src/PatriciaTrie.sol";

contract OVCTests {
    using RethPrimitives for RethPrimitives.Receipt;

    OVC public ovc;
    UniswapV2Event public uniswapV2Event;
    PatriciaTrie public patriciaTrie;

    constructor() {
        ovc = new OVC();
        uniswapV2Event = new UniswapV2Event();
        patriciaTrie = new PatriciaTrie();
    }

    function testCommitUnrolled() public {
        // Generate random vector of G1Projective and Fr
        Pairing.G1Point[] memory commitKey = new Pairing.G1Point[](10);
        uint256[] memory hashedLogsVec = new uint256[](10);

        for (uint256 i = 0; i < 10; i++) {
            commitKey[i] = Pairing.randomG1(i);
            hashedLogsVec[i] = uint256(keccak256(abi.encodePacked(i)));
        }

        // Compute unrolled commitment
        (Pairing.G1Point[] memory unrolledCommitment, Pairing.G1Point memory commitment) =
            ovc.commitUnrolled(commitKey, hashedLogsVec);

        // Check length of unrolled commitment
        require(unrolledCommitment.length == 10, "Incorrect unrolled commitment length");

        // Check that commitment equals expected value
        Pairing.G1Point memory expectedCommitment = Pairing.mulMSM(commitKey, hashedLogsVec);
        require(Pairing.eq(commitment, expectedCommitment), "Commitment mismatch");

        // Check that unrolled commitment values are as expected
        Pairing.G1Point memory expectedCommitment5 = Pairing.mul(commitKey[5], hashedLogsVec[5]);
        require(Pairing.eq(unrolledCommitment[5], expectedCommitment5), "Unrolled commitment mismatch");
    }

    function testCommitAndMerkle() public {
        // Generate random vector of G1Projective
        Pairing.G1Point[] memory commitKey = new Pairing.G1Point[](8);
        for (uint256 i = 0; i < 8; i++) {
            commitKey[i] = Pairing.randomG1(i);
        }

        // Read receipts and commit
        RethPrimitives.Receipt[] memory receipts = loadReceipts();
        uint256[] memory hashedLogsVec = new uint256[](8);
        for (uint256 i = 0; i < 8; i++) {
            bytes memory receiptBytes = RethPrimitives.encodeReceipt(receipts[i]);
            hashedLogsVec[i] = uint256(keccak256(receiptBytes));
        }

        // Compute Merkle tree
        (Pairing.G1Point memory commitment, bytes32 merkleRoot, bytes[] memory unrolledCommitmentSerialized) =
            ovc.commitAndMerkle(commitKey, hashedLogsVec);

        // Check inclusion proof
        bytes memory testBytes = abi.encodePacked(Pairing.mul(commitKey[5], hashedLogsVec[5]));
        bytes32[] memory inclusionProof = patriciaTrie.generateProof(merkleRoot, 5);
        require(patriciaTrie.verifyProof(merkleRoot, 5, testBytes, inclusionProof), "Invalid inclusion proof");
    }

    function testBuildFromReceipts() public {
        RethPrimitives.Receipt[] memory receipts = loadReceipts();
        bytes32 root = patriciaTrie.buildFromReceipts(receipts);

        bytes32 expectedRoot = 0xb95803aa78485a25e5e3230fd13dd0e7834cf53b1d2f11248c4259caacef6fc9;
        require(root == expectedRoot, "Incorrect root");
    }

    function testInclusionProof() public {
        RethPrimitives.Receipt[] memory receipts = loadReceipts();
        bytes32 root = patriciaTrie.buildFromReceipts(receipts);

        uint256 key = 62;
        bytes32[] memory proof = patriciaTrie.getProof(root, key);
        bytes memory leafValProof = patriciaTrie.verifyProof(root, key, proof);

        RethPrimitives.Receipt memory testReceipt = receipts[key];
        bytes memory expectedLeafVal = RethPrimitives.encodeReceiptWithBloom(testReceipt);

        require(keccak256(leafValProof) == keccak256(expectedLeafVal), "Invalid leaf value");
    }

    function testOVC() public {
        uint256 logNumReceipts = 6;
        uint256 numReceipts = 2 ** logNumReceipts;
        uint256 diffIdx = 2 ** logNumReceipts - 7;

        // Generate random vector of G1Projective
        Pairing.G1Point[] memory commitKey = new Pairing.G1Point[](numReceipts);
        for (uint256 i = 0; i < numReceipts; i++) {
            commitKey[i] = Pairing.randomG1(i);
        }

        // Read receipts and build receipt trie
        RethPrimitives.Receipt[] memory receipts = loadReceipts();
        bytes32 receiptRoot = patriciaTrie.buildFromReceipts(receipts);

        // Run OVC protocol
        bytes[] memory receiptsBytesVec = new bytes[](numReceipts);
        for (uint256 i = 0; i < numReceipts; i++) {
            receiptsBytesVec[i] = RethPrimitives.encodeReceipt(receipts[i]);
        }

        OVC.Prover memory ovcProver1 = ovc.newProver(commitKey, receiptsBytesVec);

        // Skip a receipt to simulate a prover who misses a receipt
        RethPrimitives.Receipt[] memory receipts2 = new RethPrimitives.Receipt[](numReceipts);
        for (uint256 i = 0; i < diffIdx; i++) {
            receipts2[i] = receipts[i];
        }
        for (uint256 i = diffIdx; i < numReceipts - 1; i++) {
            receipts2[i] = receipts[i + 1];
        }
        bytes[] memory receiptsBytesVec2 = new bytes[](numReceipts);
        for (uint256 i = 0; i < numReceipts; i++) {
            receiptsBytesVec2[i] = RethPrimitives.encodeReceipt(receipts2[i]);
        }

        OVC.Prover memory ovcProver2 = ovc.newProver(commitKey, receiptsBytesVec2);

        // First check if the commitments provided by the two provers differ
        (Pairing.G1Point memory prover1Commitment, bytes32 prover1Root) = ovc.getCommitmentAndRoot(ovcProver1);
        (Pairing.G1Point memory prover2Commitment, bytes32 prover2Root) = ovc.getCommitmentAndRoot(ovcProver2);
        require(!Pairing.eq(prover1Commitment, prover2Commitment), "Commitments should differ");

        // Initialize referee
        OVC.Referee memory ovcVerifier = ovc.newReferee(prover1Root, prover2Root, numReceipts, commitKey);

        // Run OVC protocol
        OVC.StepResponse memory prover1Response = ovc.firstResponse(ovcProver1);
        OVC.StepResponse memory prover2Response = ovc.firstResponse(ovcProver2);
        OVC.OpenKind verifierRequest = ovc.findDisagreementStep(ovcVerifier, prover1Response, prover2Response);

        for (uint256 i = 0; i < logNumReceipts; i++) {
            OVC.Response memory response1 = ovc.findDisagreementStepResponse(ovcProver1, verifierRequest);
            OVC.Response memory response2 = ovc.findDisagreementStepResponse(ovcProver2, verifierRequest);

            if (
                response1.responseType == OVC.ResponseType.StepResponse
                    && response2.responseType == OVC.ResponseType.StepResponse
            ) {
                verifierRequest = ovc.findDisagreementStep(ovcVerifier, response1.stepResponse, response2.stepResponse);
            } else if (
                response1.responseType == OVC.ResponseType.Leaf && response2.responseType == OVC.ResponseType.Leaf
            ) {
                require(ovc.getDisagreementIdx(ovcProver1) == diffIdx, "Incorrect disagreement index for prover 1");
                require(ovc.getDisagreementIdx(ovcProver2) == diffIdx, "Incorrect disagreement index for prover 2");

                OVC.OpeningProof memory proof1 = ovc.computeOpeningProof(ovcProver1, receipts, receipts[diffIdx]);
                OVC.OpeningProof memory proof2 = ovc.computeOpeningProof(ovcProver2, receipts2, receipts2[diffIdx]);

                OVC.Winner winner = ovc.openingProofVerify(
                    ovcVerifier, diffIdx, proof1, receiptRoot, response1.leaf, proof2, receiptRoot, response2.leaf
                );

                require(winner == OVC.Winner.Prover1, "Incorrect winner");
                return;
            } else {
                revert("Mismatched provers");
            }
        }
        revert("OVC protocol did not complete");
    }

    function testIsEventInReceipt() public {
        RethPrimitives.Receipt[] memory receipts = loadReceipts();
        UniswapV2Event.Swap memory swap = UniswapV2Event.Swap({
            amount0In: 1487592416523998074,
            amount1In: 0,
            amount0Out: 0,
            amount1Out: 71530900099000000000000000000,
            amount2In: 0,
            amount3In: 0,
            amount2Out: 0,
            amount3Out: 0,
            amount4Out: 0,
            sender: 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,
            to: 0x40fbA1C5aFB5c03E80C2CA2C07c38B5bD9d4d150
        });

        uint256 numEventsInBlock = 0;
        for (uint256 i = 0; i < receipts.length; i++) {
            if (uniswapV2Event.isEventInReceipt(swap, receipts[i])) {
                numEventsInBlock++;
            }
        }
        require(numEventsInBlock == 1, "Incorrect number of events in block");
    }

    function testEventToBytes() public {
        UniswapV2Event.Swap memory swap = UniswapV2Event.Swap({
            amount0In: 1487592416523998074,
            amount1In: 0,
            amount0Out: 0,
            amount1Out: 71530900099000000000000000000,
            amount2In: 0,
            amount3In: 0,
            amount2Out: 0,
            amount3Out: 0,
            amount4Out: 0,
            sender: 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,
            to: 0x40fbA1C5aFB5c03E80C2CA2C07c38B5bD9d4d150
        });

        bytes memory swapBytes = uniswapV2Event.toBytes(swap);
        UniswapV2Event.Swap memory decodedSwap = uniswapV2Event.fromBytes(swapBytes);

        require(swap.amount0In == decodedSwap.amount0In, "amount0In mismatch");
        require(swap.amount1Out == decodedSwap.amount1Out, "amount1Out mismatch");
        require(swap.sender == decodedSwap.sender, "sender mismatch");
        require(swap.to == decodedSwap.to, "to mismatch");
        // ... check other fields ...
    }

    function loadReceipts() internal pure returns (RethPrimitives.Receipt[] memory) {
        RethPrimitives.Receipt[] memory receipts = new RethPrimitives.Receipt[](100);
        // ... populate receipts ...
        return receipts;
    }
}
