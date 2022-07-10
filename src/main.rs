use ethers::core::k256::ecdsa::SigningKey;
use ethers::core::rand;
use ethers::core::utils::{
    secret_key_to_address,
    to_checksum,
};
use ethers::utils::hex;
use std::collections::HashMap;
use std::time::SystemTime;
use ethers::types::Address;

// Number of EOAs to mine
const NUM_ADDRESSES: usize = 128;
// Byte offset in the compiled smart contract bytecode where the addresses will be stored
const BYTE_OFFSET: usize = 241;

fn prefix_length_bytes() -> usize {
    let highest_prefix = format!("{:x}", index_to_offset(NUM_ADDRESSES -1));
    highest_prefix.len() + (highest_prefix.len() % 2)
}

fn offset_to_prefix(i: usize, prefix_len: usize) -> String {
    // lower case hex, left-padded with zeroes to be of length prefix_len
    format!("{:0len$x}", i, len=prefix_len)
}

fn prefix_to_offset(s: &String) -> usize {
    usize::from_str_radix(&s, 16).unwrap()
}

fn offset_to_index(offset: usize) -> usize {
    (offset-BYTE_OFFSET) / 32
}

fn index_to_offset(i: usize) -> usize {
    BYTE_OFFSET+i*32
}

fn address_to_prefix(a: Address, prefix_len: usize) -> String {
    hex::encode(a.to_fixed_bytes()).chars().take(prefix_len).collect()
}

fn main() {
    let prefix_len = prefix_length_bytes();

    let mut desired_prefixes = HashMap::new();
    for i in 0..NUM_ADDRESSES {
        let prefix = offset_to_prefix(index_to_offset(i), prefix_len);
        desired_prefixes.insert(prefix, true);
    }

    // TODO: better way to initialize empty arrays, especially keys?
    const INIT: Option<Box<SigningKey>> = None;
    let mut keys: [Option<Box<SigningKey>>; NUM_ADDRESSES] = [INIT; NUM_ADDRESSES];
    let mut addresses: [Address; NUM_ADDRESSES] = [Address::zero(); NUM_ADDRESSES];

    let start = SystemTime::now();

    loop {
        let rng = rand::thread_rng();
        // TODO: faster way to generate new random signer?
        let signer = SigningKey::random(rng);
        let address = secret_key_to_address(&signer);

        let address_prefix = address_to_prefix(address, prefix_len);

        // Check if this is a desired prefix that we haven't yet found
        if !desired_prefixes.contains_key(&address_prefix) {
            continue
        }

        desired_prefixes.remove(&address_prefix);

        // Update the keys and addresses arrays
        let index = offset_to_index(prefix_to_offset(&address_prefix));
        keys[index] = Some(Box::new(signer));
        addresses[index] = address;

        if desired_prefixes.len() == 0 {
            break
        }
    }

    println!("Mining addresses took {:?}ms", SystemTime::now().duration_since(start).unwrap().as_millis());

    println!("{:64} {:42}", "Private Key", "Address");
    for i in 0..keys.len() {
        match &keys[i] {
            None => {
                // This shouldn't happen
                println!("ERROR: no key for index {}", i)
            }
            Some(signer) => {
                println!("{} {}", hex::encode(signer.to_bytes()), to_checksum(&addresses[i], None));
            }
        }
    }

    println!("String to paste into the contract:");
    println!("{}", addresses
        .map(|x| hex::encode(x.as_bytes()))
        .map(|x| format!("{:0>64}", x))
        .concat()
    );

    println!("Array for testAuth in Contract.t.sol:");
    println!("[{}]", addresses
        .map(|x| to_checksum(&x, None))
        .join(", ")
    );
}
