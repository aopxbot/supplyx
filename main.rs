use std::collections::HashMap;
use std::time::{SystemTime};
use ed25519_dalek::{Keypair, PublicKey, Signature};
use sha3::{Sha3_256, Digest};
use rand::rngs::OsRng;

// Structures principales
#[derive(Clone, Debug)]
struct Validator {
    public_key: PublicKey,
    stake: u64,
    contribution_score: f64,
    last_validated_block: Option<u64>,
}

#[derive(Clone, Debug)]
struct Block {
    index: u64,
    timestamp: u64,
    transactions: Vec<Transaction>,
    previous_hash: Vec<u8>,
    current_hash: Vec<u8>,
    validator_signature: Signature,
    validator_pubkey: PublicKey,
}

#[derive(Clone, Debug)]
struct Transaction {
    sender: PublicKey,
    recipient: PublicKey,
    amount: u64,
    signature: Signature,
    timestamp: u64,
}

struct Blockchain {
    chain: Vec<Block>,
    validators: HashMap<PublicKey, Validator>,
    pending_transactions: Vec<Transaction>,
    current_difficulty: u64,
}

impl Blockchain {
    fn new() -> Self {
        Blockchain {
            chain: Vec::new(),
            validators: HashMap::new(),
            pending_transactions: Vec::new(),
            current_difficulty: 4,
        }
    }

    fn select_validator(&self) -> Option<PublicKey> {
        let total_weighted_stake: f64 = self.validators.values()
            .map(|v| (v.stake as f64) * v.contribution_score)
            .sum();

        let mut rng = OsRng;
        let random_point: f64 = rng.gen::<f64>() * total_weighted_stake;

        let mut cumulative_weight = 0.0;
        for (pubkey, validator) in &self.validators {
            cumulative_weight += (validator.stake as f64) * validator.contribution_score;
            if cumulative_weight >= random_point {
                return Some(*pubkey);
            }
        }
        None
    }

    fn create_transaction(&mut self, sender: &Keypair, recipient: &PublicKey, amount: u64) -> Result<(), &'static str> {
        if amount == 0 {
            return Err("Invalid transaction amount");
        }

        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let transaction = Transaction {
            sender: sender.public,
            recipient: *recipient,
            amount,
            signature: sender.sign(&self.hash_transaction_data(sender.public, *recipient, amount, timestamp)),
            timestamp,
        };

        self.pending_transactions.push(transaction);
        Ok(())
    }

    fn hash_transaction_data(&self, sender: PublicKey, recipient: PublicKey, amount: u64, timestamp: u64) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(sender.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.finalize().to_vec()
    }

    fn validate_and_create_block(&mut self, validator_keypair: &Keypair) -> Result<Block, &'static str> {
        let validator_pubkey = validator_keypair.public;

        if let Some(validator) = self.validators.get(&validator_pubkey) {
            if validator.stake < 1000 || validator.contribution_score < 0.5 {
                return Err("Validator not qualified");
            }
        } else {
            return Err("Validator not registered");
        }

        let previous_hash = if let Some(last_block) = self.chain.last() {
            last_block.current_hash.clone()
        } else {
            vec![0; 32]
        };

        let index = self.chain.len() as u64;
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let current_hash = self.calculate_block_hash(&previous_hash, &self.pending_transactions);

        let block = Block {
            index,
            timestamp,
            transactions: self.pending_transactions.clone(),
            previous_hash,
            current_hash: current_hash.clone(),
            validator_signature: validator_keypair.sign(&current_hash),
            validator_pubkey,
        };

        self.chain.push(block.clone());
        self.pending_transactions.clear();

        Ok(block)
    }

    fn calculate_block_hash(&self, previous_hash: &[u8], transactions: &[Transaction]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(previous_hash);
        for tx in transactions {
            hasher.update(self.hash_transaction_data(tx.sender, tx.recipient, tx.amount, tx.timestamp));
        }
        hasher.finalize().to_vec()
    }

    fn register_validator(&mut self, validator_keypair: &Keypair, initial_stake: u64) -> Result<(), &'static str> {
        let pubkey = validator_keypair.public;

        if self.validators.contains_key(&pubkey) {
            return Err("Validator already registered");
        }

        if initial_stake < 500 {
            return Err("Insufficient stake to become a validator");
        }

        self.validators.insert(pubkey, Validator {
            public_key: pubkey,
            stake: initial_stake,
            contribution_score: 1.0,
            last_validated_block: None,
        });

        Ok(())
    }

    fn ajuster_contribution_score(&mut self, pubkey: &PublicKey, ajustement: f64) {
        if let Some(validator) = self.validators.get_mut(pubkey) {
            validator.contribution_score = (validator.contribution_score + ajustement).clamp(0.0, 10.0);
        }
    }
}

fn main() {
    let mut blockchain = Blockchain::new();
    let validator_keypair = Keypair::generate(&mut OsRng);

    blockchain.register_validator(&validator_keypair, 1000).unwrap();

    let recipient_keypair = Keypair::generate(&mut OsRng);
    blockchain.create_transaction(&validator_keypair, &recipient_keypair.public, 50).unwrap();

    let new_block = blockchain.validate_and_create_block(&validator_keypair).unwrap();
    println!("Block created: {:?}", new_block);
}
