
use reth_primitives::Receipt;
use serde::{Serialize, Deserialize};
use alloy_sol_macro::sol;
use alloy_sol_types::SolEvent;

use self::UniswapV2Swap::Swap;

use super::Event;

sol! {
    interface UniswapV2Swap{
        event Swap(
            address indexed sender,
            uint amount0In,
            uint amount1In,
            uint amount0Out,
            uint amount1Out,
            address indexed to
        );
    }
}

#[derive(Serialize, Deserialize)]
pub struct UniswapV2Event{
    amount0in: String,
    amount0out: String,
    amount1in: String,
    amount1out: String,
    contract_address: String,
    evt_block_number: String,
    evt_block_time: String,
    evt_index: String,
    evt_tx_hash: String,
    sender: String,
    to: String,
}

impl UniswapV2Event {
    pub fn new(
        amount0in: String,
        amount0out: String,
        amount1in: String,
        amount1out: String,
        contract_address: String,
        evt_block_number: String,
        evt_block_time: String,
        evt_index: String,
        evt_tx_hash: String,
        sender: String,
        to: String,
    ) -> Self {
        Self {
            amount0in,
            amount0out,
            amount1in,
            amount1out,
            contract_address,
            evt_block_number,
            evt_block_time,
            evt_index,
            evt_tx_hash,
            sender,
            to,
        }
    }
}

impl Event for UniswapV2Event {
    fn is_event_in_receipt(&self, receipt: &Receipt) -> bool {
        let logs = receipt.logs.clone();
        for log in logs {
            let topic_slice = log.topics.into_iter().map(|b| b.0).collect::<Vec<[u8; 32]>>();
            let swap = Swap::decode_log(topic_slice, log.data.to_vec().as_slice(), true);
            if let Ok(swap) = swap {
                if swap.sender.to_string() == self.sender && swap.to.to_string() == self.to && swap.amount0In.to_string() == self.amount0in && swap.amount0Out.to_string() == self.amount0out && swap.amount1In.to_string() == self.amount1in && swap.amount1Out.to_string() == self.amount1out{
                    return true;
                }
            }
        }
        false
    }
}
