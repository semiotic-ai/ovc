// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Pairing} from "./utils/Pairing.sol";
import {MerkleTreeLib} from "./lib/MerkleTreeLib.sol";

import {Receipt} from "./ReceiptProof.sol";

library FilteredReceiptProof {
    using Pairing for Pairing.G1Point;

    struct Event {
        // Define the structure of your Event here
        // This is a placeholder and should be replaced with later implementation
        bytes data;
    }

    struct EventReceipt {
        Event eventData;
        Receipt receipt;
    }

    struct EventOpeningProof {
        Event eventData;
        Receipt receipt;
        bytes32[] inclusionProof;
    }

    function isEventInReceipt(Event memory eventData, Receipt memory receipt) public pure returns (bool) {
        // Implement the logic to check if the event is in the receipt
        // This is a placeholder and should be replaced with later implementation
        return true;
    }

    function eventToBytes(Event memory eventData) public pure returns (bytes memory) {
        // Implement the logic to convert event to bytes
        // This is a placeholder and should be replaced with later implementation
        return eventData.data;
    }

    function eventFromBytes(bytes memory data) public pure returns (Event memory) {
        // Implement the logic to convert bytes to event
        // This is a placeholder and should be replaced with later implementation
        return Event(data);
    }

    function newEventOpeningProof(EventReceipt memory inputData, Receipt[] memory witness)
        public
        view
        returns (EventOpeningProof memory)
    {
        bytes32[] memory inclusionProof = getProof(inputData.receipt, witness);
        return EventOpeningProof(inputData.eventData, inputData.receipt, inclusionProof);
    }

    function verify(
        EventOpeningProof memory self,
        Pairing.G1Point memory commitmentKey,
        bytes memory commitmentBytes,
        uint256 disagreementIdx,
        bytes32 rootHash
    ) public view returns (bool) {
        // Check that the event is included in the claimed receipt
        if (!isEventInReceipt(self.eventData, self.receipt)) {
            return false;
        }

        // Check that receipt opening the commitment is correct
        bytes memory receiptsBytes = encodeReceipt(self.receipt);
        uint256 hashedReceipt = uint256(keccak256(receiptsBytes));
        Pairing.G1Point memory commitment = commitmentKey.mul(hashedReceipt);
        bytes memory serializedCommitmentBytes = serializeG1Point(commitment);

        if (!bytesEqual(commitmentBytes, serializedCommitmentBytes)) {
            return false;
        }

        // Check that inclusion proof is valid with computed commitment
        bool validProof =
            MerkleTreeLib.verify(self.inclusionProof, rootHash, keccak256(serializedCommitmentBytes), disagreementIdx);

        if (!validProof) {
            return false;
        }

        // Check that proof is valid receipt at leaf in opening proof matches claimed receipt
        bytes memory encodedReceipt = encodeReceiptWithBloom(self.receipt);
        bytes32 leafBytes = self.inclusionProof[self.inclusionProof.length - 1];

        return keccak256(encodedReceipt) == leafBytes;
    }

    // Helper functions
    function encodeReceipt(Receipt memory receipt) internal pure returns (bytes memory) {
        // Implement the encoding of your Receipt structure
        // This is a placeholder and should be replaced with later implementation
        return receipt.data;
    }

    function encodeReceiptWithBloom(Receipt memory receipt) internal pure returns (bytes memory) {
        // Implement the encoding of your Receipt with Bloom filter
        // This is a placeholder and should be replaced with later implementation
        return receipt.data;
    }

    function serializeG1Point(Pairing.G1Point memory point) internal pure returns (bytes memory) {
        return abi.encodePacked(point.X, point.Y);
    }

    function bytesEqual(bytes memory a, bytes memory b) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }
}
