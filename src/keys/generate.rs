use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn generate_api_key() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let plaintext = format!("kv_{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_key(&plaintext);
    (plaintext, hash)
}

pub fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_session_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let plaintext = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_key(&plaintext);
    (plaintext, hash)
}

const EMOJI_POOL: &[&str] = &[
    "🦊", "🐬", "🎸", "🌊", "🔥", "⚡", "🌈", "🎯",
    "🦋", "🌙", "⭐", "🎪", "🦁", "🐉", "🌺", "🎨",
    "🔮", "🎭", "🦄", "🌸", "🎵", "🏔", "🌿", "🦅",
    "🐧", "🦀", "🌴", "🎃", "🦩", "🐙", "🌋", "🎠",
    "🦜", "🐳", "🌵", "🎡", "🦢", "🐝", "🌻", "🎺",
    "🦚", "🐞", "🌾", "🎻", "🦝", "🦋", "🍄", "🎲",
    "🦠", "🌍", "🏜", "🎳", "🦌", "🌠", "🏝", "🎯",
    "🦏", "🌌", "🏕", "🎪", "🦓", "🌅", "🏔", "🎭",
];

pub fn generate_emoji_sequence() -> String {
    let mut rng = rand::thread_rng();
    let count = 3 + (rand::random::<u8>() % 2) as usize; // 3 or 4
    let indices = rand::seq::index::sample(&mut rng, EMOJI_POOL.len(), count);
    indices.iter().map(|i| EMOJI_POOL[i]).collect::<Vec<_>>().join("")
}
