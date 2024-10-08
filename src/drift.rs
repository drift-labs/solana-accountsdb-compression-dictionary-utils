use itertools::Itertools;
use sha2::{Digest, Sha256};
use solana_account_decoder::UiAccountEncoding;
use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_client::{
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    rpc_filter::{Memcmp, RpcFilterType},
};
use solana_sdk::{account::Account, pubkey::Pubkey};
use std::collections::HashSet;
use std::str::FromStr;

pub const DRIFT_PID: &str = "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH";

fn calculate_discriminator(account_name: &str, namespace: Option<&str>) -> [u8; 8] {
    // Format the preimage based on the presence of a namespace
    let preimage = match namespace {
        Some(ns) => format!("{}:{}", ns, account_name),
        None => format!("account:{}", account_name),
    };

    // Compute the SHA256 hash of the preimage
    let hash = Sha256::digest(preimage.as_bytes());

    // Extract the first 8 bytes as the discriminator
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}

pub enum MarketType {
    Perp,
    Spot,
}

pub fn get_market_accounts_raw(
    client: &RpcClient,
    market_type: MarketType,
) -> Result<Vec<(Pubkey, Account)>, ClientError> {
    let discriminator = match market_type {
        MarketType::Perp => calculate_discriminator("PerpMarket", None),
        MarketType::Spot => calculate_discriminator("SpotMarket", None),
    };

    client.get_program_accounts_with_config(
        &Pubkey::from_str(DRIFT_PID).unwrap(),
        RpcProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                0,
                &discriminator,
            ))]),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                data_slice: None,
                commitment: None,
                min_context_slot: None,
            },
            with_context: None,
        },
    )
}

/// both spot and perp markets have oracle in same memory location
pub fn parse_oracles_from_market_accounts(
    accounts: &Vec<(Pubkey, Account)>,
) -> Result<Vec<(Pubkey, Pubkey)>, Box<dyn std::error::Error>> {
    accounts
        .iter()
        .map(|(pubkey, account)| {
            let oracle_pubkey =
                Pubkey::new_from_array(account.data[(8 + 32)..(8 + 32 + 32)].try_into()?);
            Ok((*pubkey, oracle_pubkey))
        })
        .collect()
}

const SPOT_MARKET_VAULT_OFFSET: usize = 8 + 32 * 3;
const SPOT_IF_VAULT_OFFSET: usize = 8 + 32 * 5 + 48 + 40 + 24 * 2;
pub fn parse_token_accounts_from_spot_market_account(
    accounts: &Vec<(Pubkey, Account)>,
) -> Result<Vec<Pubkey>, Box<dyn std::error::Error>> {
    let mut token_accounts = Vec::new();
    for (_, account) in accounts {
        let spot_vault = Pubkey::new_from_array(
            account.data[SPOT_MARKET_VAULT_OFFSET..(SPOT_MARKET_VAULT_OFFSET + 32)].try_into()?,
        );
        let if_vault = Pubkey::new_from_array(
            account.data[SPOT_IF_VAULT_OFFSET..(SPOT_IF_VAULT_OFFSET + 32)].try_into()?,
        );
        token_accounts.push(spot_vault);
        token_accounts.push(if_vault);
    }

    Ok(token_accounts)
}

pub fn get_oracles_and_token_accounts_for_markets(
    client: &RpcClient,
) -> Result<(Vec<Pubkey>, Vec<Pubkey>), Box<dyn std::error::Error>> {
    let perp_accounts = get_market_accounts_raw(client, MarketType::Perp)?;
    let spot_accounts = get_market_accounts_raw(client, MarketType::Spot)?;

    let perp_oracles = parse_oracles_from_market_accounts(&perp_accounts)?;
    let spot_oracles = parse_oracles_from_market_accounts(&spot_accounts)?;

    let mut oracle_set = HashSet::new();

    for (_, oracle) in perp_oracles
        .clone()
        .iter()
        .chain(spot_oracles.clone().iter())
    {
        oracle_set.insert(*oracle);
    }

    let token_accounts = parse_token_accounts_from_spot_market_account(&spot_accounts)?;

    Ok((
        oracle_set.into_iter().collect_vec(),
        token_accounts.into_iter().collect_vec(),
    ))
}

#[cfg(test)]
mod tests {

    use base64::Engine;

    use super::*;

    #[test]
    fn test_get_discriminator() {
        let discriminator = calculate_discriminator("User", None);
        let encoded = bs58::encode(discriminator).into_string();

        // println!("{:?}", encoded);
        assert_eq!(encoded, "TfwwBiNJtao");
    }

    #[test]
    #[ignore]
    fn test_get_program_accounts() {
        // Initialize RPC client
        let url = std::env::var("RPC_ENDPOINT").expect("RPC_ENDPOINT environment variable not set");
        let client = RpcClient::new(url);

        let perp_accounts =
            get_market_accounts_raw(&client, MarketType::Perp).expect("failed to get accounts");
        let spot_accounts =
            get_market_accounts_raw(&client, MarketType::Spot).expect("failed to get accounts");

        println!("got perp accounts: {:?}", perp_accounts.len());
        println!("got spot accounts: {:?}", spot_accounts.len());

        // Verify that we received some accounts
        assert!(!perp_accounts.is_empty(), "No program accounts found");
        assert!(!spot_accounts.is_empty(), "No program accounts found");

        let perp_oracles =
            parse_oracles_from_market_accounts(&perp_accounts).expect("failed to parse oracles");
        let spot_oracles =
            parse_oracles_from_market_accounts(&spot_accounts).expect("failed to parse oracles");

        // Optional: Print out some information about the accounts
        for (account, oracle) in &perp_oracles {
            println!("perp market: {}: {}", account, oracle);
        }
        for (account, oracle) in &spot_oracles {
            println!("spot market: {}: {}", account, oracle);
        }

        let gma = client
            .get_multiple_accounts(
                &perp_oracles
                    .iter()
                    .map(|x| x.1)
                    .chain(spot_oracles.iter().map(|x| x.1))
                    .collect_vec(),
            )
            .expect("failed to get multiple accounts");
        assert!(gma.len() == perp_oracles.len() + spot_oracles.len());

        // Collect unique owner fields from gma results
        let unique_owners: std::collections::HashSet<Pubkey> = gma
            .iter()
            .filter_map(|account_option| account_option.as_ref().map(|account| account.owner))
            .collect();

        println!("Unique owners:");
        for owner in &unique_owners {
            println!("{}", owner);
        }

        println!("Total unique owners: {}", unique_owners.len());

        // Optionally, you can assert that there's at least one unique owner
        assert!(!unique_owners.is_empty(), "No unique owners found");
    }

    #[test]
    #[ignore]
    fn test_get_all_oracles() {
        let url = std::env::var("RPC_ENDPOINT").expect("RPC_ENDPOINT environment variable not set");
        let client = RpcClient::new(url);

        let (oracles, market_tokens) =
            get_oracles_and_token_accounts_for_markets(&client).expect("failed to get oracles");
        assert!(!oracles.is_empty(), "no oracles found");
        assert!(!market_tokens.is_empty(), "no market tokens found");

        println!("got {} oracles", oracles.len());
        for oracle in &oracles {
            println!("{}", oracle);
        }

        println!("got {} market tokens", market_tokens.len());
        for token in &market_tokens {
            println!("{}", token);
        }
    }

    #[test]
    fn test_contains_pubkey() {
        let key_0 = Pubkey::from_str("DRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH").unwrap();
        let key_1 = Pubkey::from_str("He8KawAPxw9Qyz4kRWcz3n34vDS6kx69yFuu8vbkBeLn").unwrap();
        let key_2 = Pubkey::from_str("GoPXvJnLffnU89NGw1jqArYw8f8zWrMDrdcuB68BfxRZ").unwrap();
        let key_3 = Pubkey::from_str("2uTryLcuZqYXMYSb3iBeNLK6J472tMifC79nZAG7hMGT").unwrap();
        let key_4 = Pubkey::from_str("2t5h9fnbSsk23VsMVsTySBZwYbYzMpDYB5xV9NGbLFch").unwrap();
        let oracles = vec![key_0, key_1, key_2, key_3];

        assert!(oracles.contains(&key_0) == true);
        assert!(oracles.contains(&key_1) == true);
        assert!(oracles.contains(&key_2) == true);
        assert!(oracles.contains(&key_3) == true);
        assert!(oracles.contains(&key_4) == false);
    }

    #[test]
    fn test_parse_spot_market_for_token_accounts() {
        let spot_market = base64::engine::general_purpose::STANDARD.decode("ZLEIa6hBQSc8PneF/UaEHXUvNAKBDYzFEth8zuNsU/RjhT3POJeVtH29BUUxTm/izrxCmvmE71Qipt4AMCT0gQnMuKstsICKIzzqR01stRPa1CHILmgfgO11EkVd+5H8aDY7mdkVZYImEGLbWKmQIQDHgAf+18OTFJGMv5G6fep4zl3vqc926ndCVEMgICAgICAgICAgICAgICAgICAgICAgICAgICAgi1nl1w0AAAA9z2cFAAAAACcAAAAAAAAAkVJk2g0AAADuQs3ZDQAAAHBnzmYAAAAAEICN4AsAAAAAFOhdDwAAAOFtO58NAAAA4W07nw0AAADZ6IdmAAAAAJE1BAAAAAAAAAAAAAAAAAADAAAAAAAAAOlmdMOsAAAAAAAAAAAAAAAAAAAAAAAAAMVlHSELrQJ7Nn5RJ6oJu2KIpMq03lncOs4Msa86qgGtB5PgAAAAAAAAAAAAAAAAAHBh3QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgCMRAAAAAAA3Xs5mAAAAABAOAAAAAAAAQA0DAGDqAADvZWxSAAAAAAAAAAAAAAAAY2+6VxQAAAAAAAAAAAAAAL48iooFAAAAAAAAAAAAAAB1EYlVAgAAAAAAAAAAAAAA8GieWgIAAAAAAAAAAAAAAJcIAAAAAAAAAAAAAAAAAACEJBMAAAAAAAAAAAAAAAAAAITXFwAAAAAAyBeoBAAAAM/XAO8BAAAAsq+MegAAAAD1xAMAAAAAAHBnzmYAAAAAcGfOZgAAAAAAAAAAAAAAABAnAAAAAAAAECcAAAAAAAAQJwAAAAAAAAAAAAAAAAAAuA0AAAAAAAAmLAAAAAAAAEAfAAAoIwAA4C4AAPgqAAAomgEATB0AAPR+AAAgoQcAoIYBAGDjFgAIAAAAAwABBwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKByThgJAAAAAAABAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let test_account = vec![(
            Pubkey::default(),
            Account {
                lamports: 0,
                data: spot_market,
                owner: Pubkey::default(),
                executable: false,
                rent_epoch: 0,
            },
        )];
        let token_accounts = parse_token_accounts_from_spot_market_account(&test_account)
            .expect("failed to parse token accounts");
        assert_eq!(token_accounts.len(), 2);
        assert_eq!(
            token_accounts[0],
            Pubkey::from_str("3Zaz6vATY8br9WceXWD1Xa7fcyCpKSNanWFDRTEjjPqb").unwrap(),
            "wrong spot vault"
        ); // vault
        assert_eq!(
            token_accounts[1],
            Pubkey::from_str("EHYk36mtiATVB1gR7FHAwwoy5DHAaoPAaGbNaQQzDgU4").unwrap(),
            "wrong IF vault"
        ); // IF vault
    }
}
