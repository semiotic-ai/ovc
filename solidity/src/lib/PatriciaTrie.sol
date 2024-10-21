// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Receipt} from "./Receipt.sol";

struct Node {
    bytes value;
    mapping(bytes1 => bytes32) children;
}

struct PatriciaTrie {
    bytes32 rootHash;
    mapping(bytes32 => Node) nodes;
}

library PatriciaTrieLib {
    function buildFromReceipts(Receipt[] memory receipts) internal returns (PatriciaTrie storage) {
        PatriciaTrie storage trie;

        require(receipts.length > 0, "Receipts array is empty");

        for (uint256 idx = 0; idx < receipts.length; idx++) {
            bytes memory key = abi.encodePacked(idx);
            bytes memory value = encodeReceiptWithBloom(receipts[idx]);
            trie = insert(trie, key, value);
        }

        return trie;
    }

    function insert(PatriciaTrie storage self, bytes memory key, bytes memory value)
        internal
        pure
        returns (PatriciaTrie storage)
    {
        bytes32 currentNodeHash = self.rootHash;
        for (uint256 i = 0; i < key.length; i++) {
            bytes1 currentByte = key[i];
            Node storage currentNode = self.nodes[currentNodeHash];
            if (currentNode.children[currentByte] == bytes32(0)) {
                bytes32 newNodeHash = keccak256(abi.encodePacked(currentNodeHash, currentByte));
                currentNode.children[currentByte] = newNodeHash;
            }
            currentNodeHash = currentNode.children[currentByte];
        }
        self.nodes[currentNodeHash].value = value;
        return self;
    }

    // Implement
    function encodeReceiptWithBloom(Receipt memory receipt) internal pure returns (bytes memory) {
        // TODO: Implement bloom filter
        return abi.encodePacked("bloom");
    }

    function getProof(PatriciaTrie storage self, bytes memory key) internal view returns (bytes[] memory) {
        bytes[] memory path = new bytes[](16); // Max depth of trie (assuming 16 nibbles)
        uint256 pathLength = 0;
        bytes32 currentNodeHash = self.rootHash;
        bytes memory nibbles = toNibbles(key);

        for (uint256 i = 0; i < nibbles.length; i++) {
            if (currentNodeHash == bytes32(0)) break;

            Node storage currentNode = self.nodes[currentNodeHash];
            path[pathLength] = encodeNode(currentNode);
            pathLength++;

            bytes1 currentNibble = nibbles[i];
            currentNodeHash = currentNode.children[currentNibble];
        }

        // Include the last node (leaf or branch) if we haven't reached an empty node
        if (currentNodeHash != bytes32(0)) {
            Node storage lastNode = self.nodes[currentNodeHash];
            path[pathLength] = encodeNode(lastNode);
            pathLength++;
        }

        // Create the final proof array with the correct length
        bytes[] memory proof = new bytes[](pathLength);
        for (uint256 i = 0; i < pathLength; i++) {
            proof[i] = path[pathLength - 1 - i]; // Reverse the order
        }

        return proof;
    }

    function toNibbles(bytes memory key) private pure returns (bytes memory) {
        bytes memory nibbles = new bytes(key.length * 2);
        for (uint256 i = 0; i < key.length; i++) {
            nibbles[i * 2] = bytes1(uint8(key[i]) / 16);
            nibbles[i * 2 + 1] = bytes1(uint8(key[i]) % 16);
        }
        return nibbles;
    }

    function encodeNode(Node storage node) private view returns (bytes memory) {
        bytes[] memory encoded = new bytes[](17);
        encoded[0] = node.value;
        uint256 childCount = 0;
        for (uint256 i = 0; i < 16; i++) {
            bytes32 child = node.children[bytes1(uint8(i))];
            if (child != bytes32(0)) {
                encoded[i + 1] = abi.encodePacked(child);
                childCount++;
            }
        }

        bytes[] memory compactEncoded = new bytes[](childCount + 1);
        compactEncoded[0] = encoded[0];
        uint256 j = 1;
        for (uint256 i = 1; i < 17; i++) {
            if (encoded[i].length > 0) {
                compactEncoded[j] = encoded[i];
                j++;
            }
        }

        bytes memory result;
        for (uint256 i = 0; i < compactEncoded.length; i++) {
            result = abi.encodePacked(result, compactEncoded[i]);
        }
        return result;
    }
}
