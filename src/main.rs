use std::{collections::HashSet, net::SocketAddr, str::FromStr};

use chia::{
    bls::{master_to_wallet_unhardened_intermediate, DerivableKey, PublicKey},
    protocol::{Bytes32, CoinStateFilters},
    puzzles::{standard::StandardArgs, DeriveSynthetic},
};
use chia_wallet_sdk::{connect_peer, create_rustls_connector, load_ssl_cert};
use hex_literal::hex;
use indexmap::IndexMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert = load_ssl_cert("wallet.crt", "wallet.key")?;
    let connector = create_rustls_connector(&cert)?;
    let (peer, mut receiver) = connect_peer(
        "testnet11".to_string(),
        connector,
        SocketAddr::from_str("127.0.0.1:58444")?,
    )
    .await?;

    tokio::spawn(async move { while let Some(_message) = receiver.recv().await {} });

    println!("Connected to peer {}", peer.socket_addr());

    let master_pk = PublicKey::from_bytes(&hex!(""))?;
    let intermediate_pk = master_to_wallet_unhardened_intermediate(&master_pk);

    let puzzle_hashes: IndexMap<Bytes32, u32> = (0..5000)
        .map(|index| {
            let synthetic_key = intermediate_pk.derive_unhardened(index).derive_synthetic();
            let puzzle_hash = StandardArgs::curry_tree_hash(synthetic_key).into();
            (puzzle_hash, index)
        })
        .collect();

    println!("Derived {} puzzle hashes", puzzle_hashes.len());

    let mut coin_states = Vec::new();
    let mut current_index = 0;

    let puzzle_hash_vec: Vec<Bytes32> = puzzle_hashes.keys().copied().collect();

    let batch_size = 250;

    for chunk in puzzle_hash_vec.chunks(batch_size) {
        println!(
            "Requesting chunk {}-{}",
            current_index,
            current_index + chunk.len()
        );
        current_index += chunk.len();

        let batch = peer
            .request_puzzle_state(
                chunk.to_vec(),
                None,
                hex!("37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615").into(),
                CoinStateFilters::new(true, true, false, 0),
                false,
            )
            .await?
            .expect("rejection")
            .coin_states;

        println!("Found {} coins", batch.len());

        coin_states.extend(batch);
    }

    println!(
        "Total balance is {} TXCH",
        coin_states
            .iter()
            .filter(|cs| cs.spent_height.is_none())
            .map(|coin_state| coin_state.coin.amount)
            .sum::<u64>() as f64
            / 1e12
    );

    for spent in [false, true] {
        let used_puzzle_hashes: HashSet<Bytes32> = coin_states
            .iter()
            .filter(|coin_state| coin_state.spent_height.is_some() == spent)
            .map(|coin_state| coin_state.coin.puzzle_hash)
            .collect();

        let mut used_indices = used_puzzle_hashes
            .iter()
            .filter_map(|puzzle_hash| puzzle_hashes.get(puzzle_hash).copied())
            .collect::<Vec<_>>();

        used_indices.sort();

        let mut range_start = used_indices[0];
        let mut range_current = range_start;
        let mut ranges = Vec::new();

        for index in used_indices {
            if index == range_start || index == range_current + 1 {
                range_current += 1;
            } else {
                ranges.push(range_start..range_current);
                range_start = index;
                range_current = index;
            }
        }

        ranges.push(range_start..range_current);

        println!(
            "{:?} are {}",
            ranges,
            if spent { "spent" } else { "unspent" }
        );
    }

    Ok(())
}
