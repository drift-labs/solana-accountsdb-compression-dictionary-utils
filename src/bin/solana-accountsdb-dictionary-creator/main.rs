use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use lazy_static::lazy_static;
use log::warn;
use serde_json::{json, Value};
use solana_accounts_db::account_storage::meta::StoredMetaWriteVersion;
use solana_client::rpc_client::RpcClient;
use solana_sdk::account::{Account, ReadableAccount};
use solana_sdk::pubkey::Pubkey;
use spl_token::state::{Account as TokenAccount, GenericTokenAccount};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use {
    log::{error, info},
    solana_accountsdb_compression_dictionary_utils::{
        append_vec::AppendVec, append_vec_iter, archived::ArchiveSnapshotExtractor,
        drift::get_oracles_and_token_accounts_for_markets, parallel::AppendVecConsumer,
        SnapshotExtractor,
    },
    std::fs::{create_dir_all, File},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'a', long)]
    pub snapshot_archive_path: String,

    #[arg(short = 'm', long, default_value_t = 10000)]
    pub max_accounts_per_file: usize,

    #[arg(short = 'o', long, default_value_t = String::from("out"))]
    pub out_dir: String,

    #[arg(short = 'r', long, env = "RPC_ENDPOINT")]
    pub rpc_endpoint: Option<String>,
}

struct KeyedAccount {
    pub pubkey: Pubkey,
    pub write_version: StoredMetaWriteVersion,
    pub slot: u64,
    pub account: Account,
}

lazy_static! {
    static ref DRIFT_PID: Pubkey =
        Pubkey::from_str("dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH").unwrap();
    static ref DRIFT_TOKEN_ACCOUNT_OWNER: Pubkey =
        Pubkey::from_str("JCNCMFXo5M5qwUPg2Utu1u6YWp3MbygxqBsBeXXJfrw").unwrap();
    static ref SYSVAR_PID: Pubkey =
        Pubkey::from_str("Sysvar1111111111111111111111111111111111111").unwrap();
    static ref DRIFT_ORACLE_RECV_PID: Pubkey =
        Pubkey::from_str("G6EoTTTgpkNBtVXo96EQp2m6uwwVh2Kt6YidjkmQqoha").unwrap();
    static ref SWITCHBOARD_PID: Pubkey =
        Pubkey::from_str("SW1TCH7qEPTdLsDHRgPuMQjbQxKdH2aBStViMFnt64f").unwrap();
    static ref TOKEN_PROGRAM_ID: Pubkey =
        Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    static ref ADDRESS_LUT_PID: Pubkey =
        Pubkey::from_str("AddressLookupTab1e1111111111111111111111111").unwrap();
    static ref DRIFT_LUTS: Vec<Pubkey> = vec![
        Pubkey::from_str("D9cnvzswDikQDf53k4HpQ3KJ9y1Fv3HGGDFYMXnK5T6c").unwrap(),
        Pubkey::from_str("GPZkp76cJtNL2mphCvT6FXkJCVPpouidnacckR6rzKDN").unwrap(),
    ];
}

fn is_owner_of_interest(owner: Pubkey) -> bool {
    owner == *DRIFT_PID
        || owner == *SYSVAR_PID
        || owner == *DRIFT_ORACLE_RECV_PID
        || owner == *SWITCHBOARD_PID
        || owner == *TOKEN_PROGRAM_ID
        || owner == *ADDRESS_LUT_PID
}

fn filter_oracle_accounts(account: Pubkey, oracle_accounts: &Vec<Pubkey>) -> bool {
    oracle_accounts.contains(&account)
}

fn filter_token_accounts(token_account: Pubkey, token_accounts_of_interest: &Vec<Pubkey>) -> bool {
    token_accounts_of_interest.contains(&token_account)
}

fn filter_address_lut_accounts(account: Pubkey) -> bool {
    DRIFT_LUTS.contains(&account)
}

fn include_account_for_owner(
    owner: Pubkey,
    account: Pubkey,
    oracle_accounts: &Vec<Pubkey>,
    token_accounts_of_interest: &Vec<Pubkey>,
) -> bool {
    if !is_owner_of_interest(owner) {
        return false;
    }

    if owner == *SWITCHBOARD_PID {
        return filter_oracle_accounts(account, oracle_accounts);
    }

    if owner == *TOKEN_PROGRAM_ID {
        return filter_token_accounts(account, token_accounts_of_interest);
    }

    if owner == *ADDRESS_LUT_PID {
        return filter_address_lut_accounts(account);
    }

    true
}

pub fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let args = Args::parse();
    println!("tester args : {:?}", args);

    let Args {
        out_dir,
        snapshot_archive_path,
        max_accounts_per_file,
        rpc_endpoint,
    } = Args::parse();

    if rpc_endpoint.is_none() {
        error!(
            "RPC endpoint is not set, either from `-r,--rpc_endpoint` or `RPC_ENDPOINT` env var"
        );
        std::process::exit(1);
    }
    let rpc_client = RpcClient::new(rpc_endpoint.unwrap());
    let (oracles, token_accounts_of_interest) =
        get_oracles_and_token_accounts_for_markets(&rpc_client).expect("failed to get oracles");
    info!("got {} oracles for drift markets", oracles.len());

    let archive_path = PathBuf::from_str(snapshot_archive_path.as_str()).unwrap();

    let mut loader: ArchiveSnapshotExtractor<File> =
        ArchiveSnapshotExtractor::open(&archive_path).unwrap();

    let mut latest_accounts: HashMap<Pubkey, KeyedAccount> = HashMap::new();
    let mut pid_accounts_counter: HashMap<Pubkey, u64> = HashMap::new();

    let mut counter = 0u64;
    let mut last_counter = 0u64;
    let mut found_counter = 0u64;
    let mut found_same_acc_same_slot = 0u64;
    let start_time = std::time::Instant::now();
    let mut last_log_time = start_time;

    let bank_slot = loader.bank_slot();
    info!("bank slot: {}", bank_slot);

    for vec in loader.iter() {
        let current_time = std::time::Instant::now();
        let time_elapsed = current_time.duration_since(last_log_time).as_secs();
        if time_elapsed >= 10 {
            let counter_diff = counter - last_counter;
            let rate = counter_diff as f64 / time_elapsed as f64;
            info!(
                "Progress: total: {} (rate: {} accounts/s), saved: {}, pid_accounts: {:?}, elapsed: {:?}",
                counter,
                rate,
                found_counter,
                pid_accounts_counter,
                start_time.elapsed()
            );
            last_log_time = current_time;
            last_counter = counter;
        }

        let append_vec = vec.unwrap();

        for handle in append_vec_iter(&append_vec) {
            counter += 1;
            let stored = handle.access().unwrap();
            if stored.account_meta.owner == Pubkey::default() || stored.meta.data_len < 8 {
                continue;
            }

            let account_owner = stored.account_meta.owner;

            if !include_account_for_owner(
                account_owner,
                stored.meta.pubkey,
                &oracles,
                &token_accounts_of_interest,
            ) {
                continue;
            }

            match latest_accounts.entry(stored.meta.pubkey) {
                std::collections::hash_map::Entry::Occupied(mut occ) => {
                    // this is the second+ time we see this account, only insert if its slot is higher than previously seen
                    let prev_slot = occ.get().slot;
                    if append_vec.slot() > prev_slot {
                        occ.insert(KeyedAccount {
                            pubkey: stored.meta.pubkey,
                            write_version: stored.meta.write_version_obsolete,
                            slot: append_vec.slot(),
                            account: Account {
                                lamports: stored.account_meta.lamports,
                                data: stored.data.to_vec(),
                                owner: account_owner,
                                executable: stored.account_meta.executable,
                                rent_epoch: stored.account_meta.rent_epoch,
                            },
                        });
                    } else if append_vec.slot() == prev_slot {
                        warn!(
                            "got update for same slot for {} : {}, old slot: {}, new slot: {}",
                            account_owner,
                            stored.meta.pubkey,
                            prev_slot,
                            append_vec.slot()
                        );
                        found_same_acc_same_slot += 1;
                    }
                }
                std::collections::hash_map::Entry::Vacant(vac) => {
                    pid_accounts_counter
                        .entry(account_owner)
                        .and_modify(|x| *x += 1)
                        .or_insert(1);

                    vac.insert(KeyedAccount {
                        pubkey: stored.meta.pubkey,
                        write_version: stored.meta.write_version_obsolete,
                        slot: append_vec.slot(),
                        account: Account {
                            lamports: stored.account_meta.lamports,
                            data: stored.data.to_vec(),
                            owner: account_owner,
                            executable: stored.account_meta.executable,
                            rent_epoch: stored.account_meta.rent_epoch,
                        },
                    });
                    found_counter += 1;
                }
            };
        }
    }
    let duration = start_time.elapsed();
    info!(
        "Completed: total: {}, saved: {}, same_acc_same_slot: {}, took {:?}",
        counter, found_counter, found_same_acc_same_slot, duration
    );

    info!("pid accounts counter: {:?}", pid_accounts_counter);

    let mut all_accounts: Vec<Value> = vec![];

    for (_, data) in latest_accounts.drain() {
        all_accounts.push(json!({
            "pubkey": data.pubkey.to_string(),
            "write_version": data.write_version,
            "slot": data.slot,
            "data": general_purpose::STANDARD.encode(&data.account.data),
            "executable": data.account.executable,
            "lamports": data.account.lamports,
            "owner": data.account.owner().to_string(),
            "rentEpoch": data.account.rent_epoch,
        }));
    }

    let total_chunks = all_accounts.len() / max_accounts_per_file;
    info!("writing accounts out in {} chunks", total_chunks);
    for (i, chunk) in all_accounts.chunks(max_accounts_per_file).enumerate() {
        let json_data = serde_json::to_string_pretty(&chunk).unwrap();

        let out_file = format!("{}/{}.json", out_dir, i);
        let path = Path::new(&out_file);
        if let Some(parent) = path.parent() {
            create_dir_all(parent).expect("failed to create directory");
        }
        std::fs::write(out_file, json_data).expect("failed to write output file");
    }

    Ok(())
}

struct SimpleLogConsumer {}

#[async_trait::async_trait]
impl AppendVecConsumer for SimpleLogConsumer {
    async fn on_append_vec(&mut self, append_vec: AppendVec) -> anyhow::Result<()> {
        info!("size: {:?}", append_vec.len());
        info!("slot: {:?}", append_vec.slot());
        for handle in append_vec_iter(&append_vec) {
            let stored = handle.access().unwrap();
            info!(
                "account {:?}: {} at slot {}",
                stored.meta.pubkey,
                stored.account_meta.lamports,
                append_vec.slot()
            );
        }
        Ok(())
    }
}
