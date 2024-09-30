// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UniswapV2Swap {
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );

    struct UniswapV2Event {
        uint256 amount0In;
        uint256 amount0Out;
        uint256 amount1In;
        uint256 amount1Out;
        address contractAddress;
        uint256 evtBlockNumber;
        uint256 evtBlockTime;
        uint256 evtIndex;
        bytes32 evtTxHash;
        address sender;
        address to;
    }

    function recordEvent(
        uint256 _amount0In,
        uint256 _amount0Out,
        uint256 _amount1In,
        uint256 _amount1Out,
        address _contractAddress,
        uint256 _evtBlockNumber,
        uint256 _evtBlockTime,
        uint256 _evtIndex,
        bytes32 _evtTxHash,
        address _sender,
        address _to
    ) public returns (UniswapV2Event memory) {
        UniswapV2Event memory newEvent = UniswapV2Event({
            amount0In: _amount0In,
            amount0Out: _amount0Out,
            amount1In: _amount1In,
            amount1Out: _amount1Out,
            contractAddress: _contractAddress,
            evtBlockNumber: _evtBlockNumber,
            evtBlockTime: _evtBlockTime,
            evtIndex: _evtIndex,
            evtTxHash: _evtTxHash,
            sender: _sender,
            to: _to
        });

        emit Swap(_sender, _amount0In, _amount1In, _amount0Out, _amount1Out, _to);
        return newEvent;
    }
}
