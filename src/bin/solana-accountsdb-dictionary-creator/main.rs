use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use itertools::Itertools;
use log::warn;
use serde_json::{json, Value};
use solana_accounts_db::account_storage::meta::StoredMetaWriteVersion;
use solana_accountsdb_compression_dictionary_utils::partial_pubkey_by_bits::PartialPubkeyByBits;
use solana_client::rpc_client::RpcClient;
use solana_sdk::account::{Account, ReadableAccount};
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use {
    log::{error, info},
    solana_accountsdb_compression_dictionary_utils::{
        append_vec::AppendVec, append_vec_iter, archived::ArchiveSnapshotExtractor,
        drift::get_oracle_list_for_markets, parallel::AppendVecConsumer, SnapshotExtractor,
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

struct Samples {
    pub samples: Vec<KeyedAccount>,
}

impl Samples {
    pub fn new(data: KeyedAccount) -> Self {
        Self {
            samples: vec![data],
        }
    }

    pub fn add(&mut self, data: KeyedAccount) {
        self.samples.push(data);
    }
}

type DictionaryMap = HashMap<PartialPubkeyByBits, Vec<u8>>;

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
    let oracles = get_oracle_list_for_markets(&rpc_client).expect("failed to get oracles");
    info!("got {} oracles for drift markets", oracles.len());

    let archive_path = PathBuf::from_str(snapshot_archive_path.as_str()).unwrap();

    let mut loader: ArchiveSnapshotExtractor<File> =
        ArchiveSnapshotExtractor::open(&archive_path).unwrap();

    // let mut samples: HashMap<PartialPubkey<4>, Samples<u8>> = HashMap::new();
    // let mut samples: HashMap<Pubkey, Samples> = HashMap::new();
    let mut latest_accounts: HashMap<Pubkey, KeyedAccount> = HashMap::new();
    let mut pid_accounts_counter: HashMap<Pubkey, u64> = HashMap::new();

    let drift_pid = Pubkey::from_str("dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH")?;
    let sysvar_pid = Pubkey::from_str("Sysvar1111111111111111111111111111111111111")?;
    let drift_oracle_recv_pid = Pubkey::from_str("G6EoTTTgpkNBtVXo96EQp2m6uwwVh2Kt6YidjkmQqoha")?;
    let switchboard_pid = Pubkey::from_str("SW1TCH7qEPTdLsDHRgPuMQjbQxKdH2aBStViMFnt64f")?;

    let sysvar_clock_account = Pubkey::from_str("SysvarC1ock11111111111111111111111111111111")?;

    let mut counter = 0u64;
    let mut found_counter = 0u64;
    let mut found_oracle_counter = 0u64;
    let mut found_same_acc_same_slot = 0u64;
    let start_time = std::time::Instant::now();
    let mut last_log_time = start_time;

    let bank_slot = loader.bank_slot();
    info!("bank slot: {}", bank_slot);

    for vec in loader.iter() {
        let current_time = std::time::Instant::now();
        if current_time.duration_since(last_log_time).as_secs() >= 10 {
            info!(
                "Progress: total: {}, saved: {}, oracle: {}, pid_accounts: {:?}, elapsed: {:?}",
                counter,
                found_counter,
                found_oracle_counter,
                pid_accounts_counter,
                start_time.elapsed()
            );
            last_log_time = current_time;
        }

        let append_vec = vec.unwrap();

        for handle in append_vec_iter(&append_vec) {
            counter += 1;
            let stored = handle.access().unwrap();
            if stored.account_meta.owner == Pubkey::default() || stored.meta.data_len < 8 {
                continue;
            }

            let account_owner = stored.account_meta.owner;
            match latest_accounts.entry(stored.meta.pubkey) {
                std::collections::hash_map::Entry::Occupied(mut occ) => {
                    match account_owner {
                        pid if pid == drift_pid
                            || pid == sysvar_pid
                            || pid == switchboard_pid
                            || pid == drift_oracle_recv_pid =>
                        {
                            let mut include = false;
                            if pid == drift_pid || pid == sysvar_pid {
                                include = true;
                            } else if oracles.contains(&stored.meta.pubkey) {
                                include = true;
                            }

                            if include {
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
                                            owner: pid,
                                            executable: stored.account_meta.executable,
                                            rent_epoch: stored.account_meta.rent_epoch,
                                        },
                                    });
                                } else if append_vec.slot() == prev_slot {
                                    warn!(
                                        "got update for same slot for {} : {}, old slot: {}, new slot: {}",
                                        pid,
                                        stored.meta.pubkey,
                                        prev_slot,
                                        append_vec.slot()
                                    );
                                    found_same_acc_same_slot += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                std::collections::hash_map::Entry::Vacant(vac) => match account_owner {
                    pid if pid == drift_pid
                        || pid == sysvar_pid
                        || pid == switchboard_pid
                        || pid == drift_oracle_recv_pid =>
                    {
                        let mut include = false;
                        if pid == drift_pid || pid == sysvar_pid {
                            include = true;
                        } else if oracles.contains(&stored.meta.pubkey) {
                            include = true;
                            found_oracle_counter += 1;
                        }
                        if include {
                            pid_accounts_counter
                                .entry(pid)
                                .and_modify(|x| *x += 1)
                                .or_insert(1);

                            vac.insert(KeyedAccount {
                                pubkey: stored.meta.pubkey,
                                write_version: stored.meta.write_version_obsolete,
                                slot: append_vec.slot(),
                                account: Account {
                                    lamports: stored.account_meta.lamports,
                                    data: stored.data.to_vec(),
                                    owner: pid,
                                    executable: stored.account_meta.executable,
                                    rent_epoch: stored.account_meta.rent_epoch,
                                },
                            });
                            found_counter += 1;
                        }
                    }
                    _ => {}
                },
            };
        }
    }
    let duration = start_time.elapsed();
    info!(
        "Completed: total: {}, saved: {}, oracle: {}, same_acc_same_slot: {}, took {:?}",
        counter, found_counter, found_oracle_counter, found_same_acc_same_slot, duration
    );

    // let all_program_ids = samples.iter().map(|x| *x.0).collect_vec();
    // info!("total program ids in samples: {:?}", all_program_ids.len());
    info!("pid accounts counter: {:?}", pid_accounts_counter);

    let mut all_accounts: Vec<Value> = vec![];

    for (_, data) in latest_accounts.drain() {
        all_accounts.push(json!({
            "pubkey": data.pubkey.to_string(),
            "write_version": data.write_version,
            "slot": data.slot,
            "data": [general_purpose::STANDARD.encode(&data.account.data)],
            "executable": data.account.executable,
            "lamports": data.account.lamports,
            "owner": data.account.owner().to_string(),
            "rentEpoch": data.account.rent_epoch,
        }));
        // let accounts: Vec<Value> = ite_sample
        //     .samples
        //     .iter()
        //     .map(|data| {
        //         json!({
        //             "pubkey": data.pubkey.to_string(),
        //             "write_version": data.write_version,
        //             "slot": data.slot,
        //             "data": [general_purpose::STANDARD.encode(&data.account.data)],
        //             "executable": data.account.executable,
        //             "lamports": data.account.lamports,
        //             "owner": key.to_string(),
        //             "rentEpoch": data.account.rent_epoch,
        //         })
        //     })
        //     .collect();

        // let accounts_len = accounts.len();
        // all_accounts.extend(accounts);
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
