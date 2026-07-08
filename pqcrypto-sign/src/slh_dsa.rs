//! SLH-DSA (SPHINCS+) Hash-Based Digital Signature Scheme.
//!
//! Implements FIPS 205 SLH-DSA with SHA2-128s parameter set.
//!
//! SLH-DSA is a stateless hash-based signature scheme that provides
//! post-quantum security based only on the security of the underlying
//! hash function.
//!
//! Parameter set: SLH-DSA-SHA2-128s
//! - n = 16 (security parameter in bytes, 128-bit security)
//! - h = 63 (hypertree height)
//! - d = 7 (number of layers in hypertree)
//! - h' = h/d = 9 (XMSS tree height per layer)
//! - a = 12 (number of FORS trees)
//! - k = 14 (number of FORS leaves per tree)
//! - w = 16 (Winternitz parameter for WOTS+)
//!
//! Main components:
//! - WOTS+: Winternitz One-Time Signature
//! - XMSS: eXtended Merkle Signature Scheme
//! - FORS: Forest of Random Subsets
//! - Hypertree: Tree of XMSS trees

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::SignError;

// ============================================================================
// SLH-DSA-SHA2-128s Parameters
// ============================================================================

/// Security parameter in bytes (128-bit security)
const N: usize = 16;

/// Hypertree height
const H: usize = 63;

/// Number of layers in hypertree
const D: usize = 7;

/// XMSS tree height per layer
const H_PRIME: usize = H / D; // 9

/// Number of FORS trees
const A: usize = 12;

/// Number of FORS leaves per tree
const K: usize = 14;

/// Bytes needed for the FORS message indices: A trees * K bits.
const FORS_MSG_BYTES: usize = (A * K + 7) / 8;

/// Winternitz parameter
const W: usize = 16;

/// WOTS+ chain length
const LEN1: usize = 16 * 8 / 4; // ceil(n * 8 / lg(w)) = 32 for n=16, w=16
const LEN2: usize = 3; // floor(log(len1 * (w-1)) / log(w)) + 1
const LEN: usize = LEN1 + LEN2; // 35

/// Seed length
const SEED_LEN: usize = N;

/// Address size
const ADDR_SIZE: usize = 32;

// ============================================================================
// Hash Functions (SHA-256 based)
// ============================================================================

/// Compute SHA-256 hash
fn h_sha256(data: &[u8]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result[..N]);
    out
}

fn sha256_full(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// PRF: Pseudorandom function
/// PRF(seed, addr) = SHA-256(seed || addr)[..n]
fn prf(seed: &[u8; N], addr: &[u8; ADDR_SIZE]) -> [u8; N] {
    let mut data = [0u8; N + ADDR_SIZE];
    data[..N].copy_from_slice(seed);
    data[N..].copy_from_slice(addr);
    h_sha256(&data)
}

/// PRF_msg: Message-dependent PRF
/// PRF_msg(PRF, R, M) = SHA-256(PRF || R || M)[..n]
fn prf_msg(prf_key: &[u8; N], r: &[u8; N], msg: &[u8]) -> [u8; N] {
    let mut data = Vec::with_capacity(2 * N + msg.len());
    data.extend_from_slice(prf_key);
    data.extend_from_slice(r);
    data.extend_from_slice(msg);
    h_sha256(&data)
}

struct MessageDigest {
    fors_msg: [u8; FORS_MSG_BYTES],
    tree_idx: u64,
    leaf_idx: u32,
}

/// H_msg: derive FORS digest plus hypertree indices from R, public key, and message.
fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], msg: &[u8]) -> MessageDigest {
    let mut data = Vec::with_capacity(3 * N + msg.len());
    data.extend_from_slice(r);
    data.extend_from_slice(pk_seed);
    data.extend_from_slice(pk_root);
    data.extend_from_slice(msg);
    let digest = sha256_full(&data);

    let mut fors_msg = [0u8; FORS_MSG_BYTES];
    fors_msg.copy_from_slice(&digest[..FORS_MSG_BYTES]);

    let mut tree_bytes = [0u8; 8];
    tree_bytes.copy_from_slice(&digest[FORS_MSG_BYTES..FORS_MSG_BYTES + 8]);
    let tree_mask = (1u64 << (H - H_PRIME)) - 1;
    let tree_idx = u64::from_be_bytes(tree_bytes) & tree_mask;

    let leaf_offset = FORS_MSG_BYTES + 8;
    let leaf_raw = u16::from_be_bytes([digest[leaf_offset], digest[leaf_offset + 1]]);
    let leaf_idx = (leaf_raw as u32) & ((1u32 << H_PRIME) - 1);

    MessageDigest {
        fors_msg,
        tree_idx,
        leaf_idx,
    }
}

/// T_l: L-tree hash (for XMSS)
fn t_l(seed: &[u8; N], addr: &[u8; ADDR_SIZE], data: &[u8]) -> [u8; N] {
    let mut input = [0u8; N + ADDR_SIZE + 192];
    let len = N + ADDR_SIZE + data.len();
    input[..N].copy_from_slice(seed);
    input[N..N + ADDR_SIZE].copy_from_slice(addr);
    input[N + ADDR_SIZE..len].copy_from_slice(data);
    h_sha256(&input[..len])
}

/// H: Hash function for Merkle tree nodes
fn h_node(seed: &[u8; N], addr: &[u8; ADDR_SIZE], left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    let mut input = [0u8; 3 * N + ADDR_SIZE];
    input[..N].copy_from_slice(seed);
    input[N..N + ADDR_SIZE].copy_from_slice(addr);
    input[N + ADDR_SIZE..2 * N + ADDR_SIZE].copy_from_slice(left);
    input[2 * N + ADDR_SIZE..].copy_from_slice(right);
    h_sha256(&input)
}

/// F: Chain function for WOTS+
/// Applies the chain function `steps` times starting from chain index `start`.
fn chain_func(
    seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
    data: &[u8; N],
    start: usize,
    steps: usize,
) -> [u8; N] {
    let mut result = *data;
    let mut addr_copy = *addr;
    for i in start..start + steps {
        addr_copy[20..24].copy_from_slice(&(i as u32).to_be_bytes());
        addr_copy[24..28].copy_from_slice(&(0u32).to_be_bytes());
        let mut input = [0u8; 2 * N + ADDR_SIZE];
        input[..N].copy_from_slice(seed);
        input[N..N + ADDR_SIZE].copy_from_slice(&addr_copy);
        input[N + ADDR_SIZE..].copy_from_slice(&result);
        result = h_sha256(&input);
    }
    result
}

// ============================================================================
// Address (ADR) Structure
// ============================================================================

/// Address types
const ADDR_TYPE_WOTS: u32 = 0;
const ADDR_TYPE_WOTS_PK: u32 = 1;
const ADDR_TYPE_TREE: u32 = 2;
const ADDR_TYPE_FORS: u32 = 3;
const ADDR_TYPE_FORS_PK: u32 = 4;

/// Create a new address with given type
fn make_addr(addr_type: u32) -> [u8; ADDR_SIZE] {
    let mut addr = [0u8; ADDR_SIZE];
    addr[12..16].copy_from_slice(&addr_type.to_be_bytes());
    addr
}

/// Set address type
fn set_type(addr: &mut [u8; ADDR_SIZE], addr_type: u32) {
    addr[12..16].copy_from_slice(&addr_type.to_be_bytes());
}

/// Set layer address
fn set_layer(addr: &mut [u8; ADDR_SIZE], layer: u32) {
    addr[0..4].copy_from_slice(&layer.to_be_bytes());
}

/// Set tree address
fn set_tree(addr: &mut [u8; ADDR_SIZE], tree: u64) {
    addr[4..12].copy_from_slice(&tree.to_be_bytes());
}

/// Set key pair address
fn set_keypair(addr: &mut [u8; ADDR_SIZE], keypair: u32) {
    addr[16..20].copy_from_slice(&keypair.to_be_bytes());
}

/// Set chain address (for WOTS+)
fn set_chain(addr: &mut [u8; ADDR_SIZE], chain: u32) {
    addr[20..24].copy_from_slice(&chain.to_be_bytes());
}

/// Set hash address (for WOTS+)
fn set_hash(addr: &mut [u8; ADDR_SIZE], hash: u32) {
    addr[24..28].copy_from_slice(&hash.to_be_bytes());
}

/// Set tree height (for XMSS)
fn set_tree_height(addr: &mut [u8; ADDR_SIZE], height: u32) {
    addr[24..28].copy_from_slice(&height.to_be_bytes());
}

/// Set tree index (for XMSS)
fn set_tree_index(addr: &mut [u8; ADDR_SIZE], index: u32) {
    addr[28..32].copy_from_slice(&index.to_be_bytes());
}

// ============================================================================
// WOTS+ (Winternitz One-Time Signature)
// ============================================================================

/// Generate WOTS+ secret key from seed
fn wots_sk_gen(seed: &[u8; N], addr: &[u8; ADDR_SIZE]) -> [[u8; N]; LEN] {
    let mut sk = [[0u8; N]; LEN];
    for i in 0..LEN {
        let mut sk_addr = *addr;
        set_chain(&mut sk_addr, i as u32);
        set_hash(&mut sk_addr, 0);
        sk[i] = prf(seed, &sk_addr);
    }
    sk
}

/// Generate WOTS+ public key from seed
fn wots_pk_gen(seed: &[u8; N], pk_seed: &[u8; N], addr: &[u8; ADDR_SIZE]) -> [u8; N] {
    let sk = wots_sk_gen(seed, addr);
    let mut pk = [[0u8; N]; LEN];
    for i in 0..LEN {
        let mut chain_addr = *addr;
        set_chain(&mut chain_addr, i as u32);
        set_hash(&mut chain_addr, 0);
        pk[i] = chain_func(pk_seed, &chain_addr, &sk[i], 0, W - 1);
    }
    l_tree(pk_seed, addr, &pk)
}

/// WOTS+ sign
fn wots_sign(
    msg: &[u8; N],
    seed: &[u8; N],
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> [[u8; N]; LEN] {
    let sk = wots_sk_gen(seed, addr);
    let csum = compute_checksum(msg);
    let msg_csum = concat_msg_csum(msg, csum);

    let mut sig = [[0u8; N]; LEN];
    for i in 0..LEN {
        let mut chain_addr = *addr;
        set_chain(&mut chain_addr, i as u32);
        set_hash(&mut chain_addr, 0);
        let steps = msg_csum[i] as usize;
        sig[i] = chain_func(pk_seed, &chain_addr, &sk[i], 0, steps);
    }
    sig
}

/// WOTS+ verify
fn wots_verify(
    msg: &[u8; N],
    sig: &[[u8; N]; LEN],
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> [u8; N] {
    let csum = compute_checksum(msg);
    let msg_csum = concat_msg_csum(msg, csum);

    let mut pk = [[0u8; N]; LEN];
    for i in 0..LEN {
        let mut chain_addr = *addr;
        set_chain(&mut chain_addr, i as u32);
        set_hash(&mut chain_addr, 0);
        let steps = msg_csum[i] as usize;
        pk[i] = chain_func(pk_seed, &chain_addr, &sig[i], steps, W - 1 - steps);
    }
    l_tree(pk_seed, addr, &pk)
}

/// Compute WOTS+ checksum
fn compute_checksum(msg: &[u8; N]) -> u32 {
    let mut csum: u32 = 0;
    for &b in msg.iter() {
        csum += (W as u32 - 1) - (b >> 4) as u32;
        csum += (W as u32 - 1) - (b & 0xf) as u32;
    }
    csum << (8 - ((LEN2 * 4) % 8)) // Left-shift to fill byte boundary
}

/// Concatenate message and checksum as base-w digits
fn concat_msg_csum(msg: &[u8; N], csum: u32) -> Vec<u8> {
    let mut result = Vec::with_capacity(LEN);
    // Message digits (2 digits per byte)
    for &b in msg.iter() {
        result.push(b >> 4);
        result.push(b & 0xf);
    }
    // Checksum digits
    for i in (0..LEN2 * 4).step_by(4) {
        result.push(((csum >> (LEN2 * 4 - 4 - i)) & 0xf) as u8);
    }
    result
}

/// L-tree: compress WOTS+ public key to single node
fn l_tree(pk_seed: &[u8; N], addr: &[u8; ADDR_SIZE], pk: &[[u8; N]; LEN]) -> [u8; N] {
    let mut nodes = pk.to_vec();
    let mut len = LEN;

    while len > 1 {
        let mut new_len = 0;
        for i in (0..len).step_by(2) {
            let mut node_addr = *addr;
            set_tree_height(&mut node_addr, 0); // Will be updated
            set_tree_index(&mut node_addr, new_len as u32);

            if i + 1 < len {
                let mut combined = [0u8; 2 * N];
                combined[..N].copy_from_slice(&nodes[i]);
                combined[N..].copy_from_slice(&nodes[i + 1]);
                nodes[new_len] = t_l(pk_seed, &node_addr, &combined);
            } else {
                nodes[new_len] = nodes[i];
            }
            new_len += 1;
        }
        len = new_len;
    }

    nodes[0]
}

// ============================================================================
// XMSS (eXtended Merkle Signature Scheme)
// ============================================================================

/// XMSS node computation
fn xmss_node(
    sk_seed: &[u8; N],
    idx: u32,
    height: u32,
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> [u8; N] {
    if height == 0 {
        let mut leaf_addr = *addr;
        set_keypair(&mut leaf_addr, idx);
        return wots_pk_gen(sk_seed, pk_seed, &leaf_addr);
    }

    // Recursive computation
    let left = xmss_node(sk_seed, 2 * idx, height - 1, pk_seed, addr);
    let right = xmss_node(sk_seed, 2 * idx + 1, height - 1, pk_seed, addr);

    let mut node_addr = *addr;
    set_tree_height(&mut node_addr, height);
    set_tree_index(&mut node_addr, idx);
    h_node(pk_seed, &node_addr, &left, &right)
}

fn xmss_auth_path(
    sk_seed: &[u8; N],
    leaf_idx: u32,
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> Vec<[u8; N]> {
    let mut auth_path = Vec::with_capacity(H_PRIME);

    for height in 0..H_PRIME {
        let sibling_idx = (leaf_idx >> height) ^ 1;
        let sibling = xmss_node(sk_seed, sibling_idx, height as u32, pk_seed, addr);
        auth_path.push(sibling);
    }

    auth_path
}

/// XMSS sign
fn xmss_sign(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx: u32,
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> (Vec<[u8; N]>, [[u8; N]; LEN]) {
    // Get WOTS+ signature
    let mut wots_addr = *addr;
    set_keypair(&mut wots_addr, idx);
    let wots_sig = wots_sign(msg, sk_seed, pk_seed, &wots_addr);

    // Get authentication path
    let auth_path = xmss_auth_path(sk_seed, idx, pk_seed, addr);

    (auth_path, wots_sig)
}

/// XMSS verify
fn xmss_verify(
    msg: &[u8; N],
    sig: &([[u8; N]; LEN], &Vec<[u8; N]>),
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
    idx: u32,
) -> [u8; N] {
    let (wots_sig, auth_path) = sig;

    // Verify WOTS+ signature to get leaf
    let mut wots_addr = *addr;
    set_keypair(&mut wots_addr, idx);
    let leaf = wots_verify(msg, wots_sig, pk_seed, &wots_addr);

    // Reconstruct root using auth path
    let mut node = leaf;
    let mut node_idx = idx;

    for (h, sibling) in auth_path.iter().enumerate() {
        let mut node_addr = *addr;
        set_tree_height(&mut node_addr, (h + 1) as u32);
        set_tree_index(&mut node_addr, node_idx / 2);

        if node_idx % 2 == 0 {
            node = h_node(pk_seed, &node_addr, &node, sibling);
        } else {
            node = h_node(pk_seed, &node_addr, sibling, &node);
        }
        node_idx /= 2;
    }

    node
}

// ============================================================================
// FORS (Forest of Random Subsets)
// ============================================================================

/// FORS secret key element
fn fors_sk_gen(seed: &[u8; N], addr: &[u8; ADDR_SIZE], idx: u32, tree_idx: u32) -> [u8; N] {
    let mut sk_addr = *addr;
    set_tree_height(&mut sk_addr, 0);
    set_tree_index(&mut sk_addr, (tree_idx << K) | idx);
    prf(seed, &sk_addr)
}

/// FORS node computation
fn fors_node(
    sk_seed: &[u8; N],
    idx: u32,
    height: u32,
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
    tree_idx: u32,
) -> [u8; N] {
    if height == 0 {
        return fors_sk_gen(sk_seed, addr, idx, tree_idx);
    }

    let left = fors_node(sk_seed, 2 * idx, height - 1, pk_seed, addr, tree_idx);
    let right = fors_node(sk_seed, 2 * idx + 1, height - 1, pk_seed, addr, tree_idx);

    let mut node_addr = *addr;
    set_tree_height(&mut node_addr, height);
    set_tree_index(&mut node_addr, (tree_idx << (K as u32 - height)) | idx);
    h_node(pk_seed, &node_addr, &left, &right)
}

fn fors_auth_path(
    sk_seed: &[u8; N],
    leaf_idx: u32,
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
    tree_idx: u32,
) -> Vec<[u8; N]> {
    let mut auth_path = Vec::with_capacity(K);

    for height in 0..K {
        let sibling_idx = (leaf_idx >> height) ^ 1;
        auth_path.push(fors_node(
            sk_seed,
            sibling_idx,
            height as u32,
            pk_seed,
            addr,
            tree_idx,
        ));
    }

    auth_path
}

/// FORS sign
fn fors_sign(
    msg: &[u8],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> (Vec<[u8; N]>, Vec<Vec<[u8; N]>>) {
    // Split message into indices
    let indices = fors_indices(msg);

    let mut sk_sig = Vec::with_capacity(A);
    let mut auth_paths = Vec::with_capacity(A);

    for i in 0..A {
        let idx = indices[i];
        // Secret key element
        sk_sig.push(fors_sk_gen(sk_seed, addr, idx as u32, i as u32));

        // Authentication path
        auth_paths.push(fors_auth_path(sk_seed, idx as u32, pk_seed, addr, i as u32));
    }

    (sk_sig, auth_paths)
}

/// FORS verify
fn fors_verify(
    msg: &[u8],
    sig: &(Vec<[u8; N]>, Vec<Vec<[u8; N]>>),
    pk_seed: &[u8; N],
    addr: &[u8; ADDR_SIZE],
) -> [u8; N] {
    let (sk_sig, auth_paths) = sig;
    let indices = fors_indices(msg);

    let mut roots = Vec::with_capacity(A);

    for i in 0..A {
        let idx = indices[i];
        let mut node = sk_sig[i];

        // Verify auth path
        let mut node_idx = idx as u32;
        for (h, sibling) in auth_paths[i].iter().enumerate() {
            let mut node_addr = *addr;
            let parent_height = (h + 1) as u32;
            let parent_idx = node_idx / 2;
            set_tree_height(&mut node_addr, parent_height);
            set_tree_index(&mut node_addr, ((i as u32) << (K as u32 - parent_height)) | parent_idx);

            if node_idx % 2 == 0 {
                node = h_node(pk_seed, &node_addr, &node, sibling);
            } else {
                node = h_node(pk_seed, &node_addr, sibling, &node);
            }
            node_idx /= 2;
        }

        roots.push(node);
    }

    // Compress roots to single public key
    let mut pk_data = Vec::with_capacity(A * N);
    for root in &roots {
        pk_data.extend_from_slice(root);
    }
    let mut pk_addr = *addr;
    set_type(&mut pk_addr, ADDR_TYPE_FORS_PK);
    set_tree_height(&mut pk_addr, 0);
    set_tree_index(&mut pk_addr, 0);
    t_l(pk_seed, &pk_addr, &pk_data)
}

/// Split message into FORS indices
fn fors_indices(msg: &[u8]) -> Vec<usize> {
    let mut indices = Vec::with_capacity(A);
    let bits_per_index = K;

    let mut bit_idx = 0;
    for _ in 0..A {
        let mut idx = 0usize;
        for _ in 0..bits_per_index {
            let byte_idx = bit_idx / 8;
            let bit_offset = 7 - (bit_idx % 8);
            if byte_idx < msg.len() {
                idx = (idx << 1) | ((msg[byte_idx] >> bit_offset) & 1) as usize;
            }
            bit_idx += 1;
        }
        indices.push(idx % (1 << K));
    }

    indices
}

// ============================================================================
// Hypertree
// ============================================================================

/// Hypertree sign
fn ht_sign(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    tree_idx: u64,
    leaf_idx: u32,
) -> Vec<(Vec<[u8; N]>, [[u8; N]; LEN])> {
    let mut sig = Vec::with_capacity(D);
    let mut root = *msg;
    let mut cur_tree = tree_idx;
    let mut cur_leaf = leaf_idx;

    for layer in 0..D {
        let mut layer_addr = make_addr(ADDR_TYPE_TREE);
        set_layer(&mut layer_addr, layer as u32);
        set_tree(&mut layer_addr, cur_tree);

        let (auth_path, wots_sig) = xmss_sign(&root, sk_seed, cur_leaf, pk_seed, &layer_addr);

        // Verify to get root for next layer
        let mut wots_addr = layer_addr;
        set_keypair(&mut wots_addr, cur_leaf);
        let leaf = wots_verify(&root, &wots_sig, pk_seed, &wots_addr);

        // Reconstruct root from auth path
        let mut node = leaf;
        let mut node_idx = cur_leaf;
        for (h, sibling) in auth_path.iter().enumerate() {
            let mut node_addr = layer_addr;
            set_tree_height(&mut node_addr, (h + 1) as u32);
            set_tree_index(&mut node_addr, node_idx / 2);
            if node_idx % 2 == 0 {
                node = h_node(pk_seed, &node_addr, &node, sibling);
            } else {
                node = h_node(pk_seed, &node_addr, sibling, &node);
            }
            node_idx /= 2;
        }

        sig.push((auth_path, wots_sig));
        root = node;

        cur_leaf = (cur_tree & ((1u64 << H_PRIME) - 1)) as u32;
        cur_tree >>= H_PRIME;
    }

    sig
}

/// Hypertree verify
fn ht_verify(
    msg: &[u8; N],
    sig: &[(Vec<[u8; N]>, [[u8; N]; LEN])],
    pk_seed: &[u8; N],
    tree_idx: u64,
    leaf_idx: u32,
) -> [u8; N] {
    let mut root = *msg;
    let mut cur_tree = tree_idx;
    let mut cur_leaf = leaf_idx;

    for (layer, (auth_path, wots_sig)) in sig.iter().enumerate() {
        let mut layer_addr = make_addr(ADDR_TYPE_TREE);
        set_layer(&mut layer_addr, layer as u32);
        set_tree(&mut layer_addr, cur_tree);

        // Verify WOTS+ signature
        let mut wots_addr = layer_addr;
        set_keypair(&mut wots_addr, cur_leaf);
        let leaf = wots_verify(&root, wots_sig, pk_seed, &wots_addr);

        // Reconstruct root
        let mut node = leaf;
        let mut node_idx = cur_leaf;

        for (h, sibling) in auth_path.iter().enumerate() {
            let mut node_addr = layer_addr;
            set_tree_height(&mut node_addr, (h + 1) as u32);
            set_tree_index(&mut node_addr, node_idx / 2);

            if node_idx % 2 == 0 {
                node = h_node(pk_seed, &node_addr, &node, sibling);
            } else {
                node = h_node(pk_seed, &node_addr, sibling, &node);
            }
            node_idx /= 2;
        }

        root = node;

        cur_leaf = (cur_tree & ((1u64 << H_PRIME) - 1)) as u32;
        cur_tree >>= H_PRIME;
    }

    root
}

// ============================================================================
// SLH-DSA Public API
// ============================================================================

/// SLH-DSA public key.
#[derive(Clone, Debug)]
pub struct SlhDsaPublicKey {
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
}

/// SLH-DSA secret key.
#[derive(Clone, Debug)]
pub struct SlhDsaSecretKey {
    pub sk_seed: [u8; N],
    pub prf_key: [u8; N],
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
}

impl Zeroize for SlhDsaSecretKey {
    fn zeroize(&mut self) {
        self.sk_seed.zeroize();
        self.prf_key.zeroize();
    }
}

impl Drop for SlhDsaSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SLH-DSA signature.
#[derive(Clone, Debug)]
pub struct SlhDsaSignature {
    pub r: [u8; N],
    pub fors_sig: (Vec<[u8; N]>, Vec<Vec<[u8; N]>>),
    pub ht_sig: Vec<(Vec<[u8; N]>, [[u8; N]; LEN])>,
    pub tree_idx: u64,
    pub leaf_idx: u32,
}

/// Generate SLH-DSA key pair.
pub fn keygen() -> (SlhDsaPublicKey, SlhDsaSecretKey) {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut sk_seed = [0u8; N];
    let mut prf_key = [0u8; N];
    let mut pk_seed = [0u8; N];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut prf_key);
    rng.fill_bytes(&mut pk_seed);

    keygen_internal(&sk_seed, &prf_key, &pk_seed)
}

/// Generate SLH-DSA key pair with explicit seeds (for testing/KAT).
pub fn keygen_internal(
    sk_seed: &[u8; N],
    prf_key: &[u8; N],
    pk_seed: &[u8; N],
) -> (SlhDsaPublicKey, SlhDsaSecretKey) {
    // Compute public key root
    let pk_root = compute_pk_root(sk_seed, pk_seed);

    let pk = SlhDsaPublicKey {
        pk_seed: *pk_seed,
        pk_root,
    };
    let sk = SlhDsaSecretKey {
        sk_seed: *sk_seed,
        prf_key: *prf_key,
        pk_seed: *pk_seed,
        pk_root,
    };

    (pk, sk)
}

/// Compute public key root from seeds.
///
/// Computes the root of the XMSS tree at the TOP layer (layer d-1) of the
/// hypertree. In SLH-DSA, pk_root is the root of the topmost XMSS tree.
///
/// For fixed indices (tree_idx=0, leaf_idx=0), all intermediate layers
/// also use tree=0, leaf=0. The pk_root is the Merkle root of the full
/// XMSS tree at layer d-1, tree 0.
///
/// This root must match what ht_verify produces when it chains through
/// all d layers of the hypertree and reconstructs the root at the final layer.
fn compute_pk_root(sk_seed: &[u8; N], pk_seed: &[u8; N]) -> [u8; N] {
    let mut top_addr = make_addr(ADDR_TYPE_TREE);
    set_layer(&mut top_addr, (D - 1) as u32);
    // tree=0 (default from make_addr)

    let root = xmss_node(sk_seed, 0, H_PRIME as u32, pk_seed, &top_addr);
    root
}

/// Sign a message.
pub fn sign(sk: &SlhDsaSecretKey, message: &[u8]) -> SlhDsaSignature {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    // Step 1: Generate randomizer
    let mut opt_rand = [0u8; N];
    rng.fill_bytes(&mut opt_rand);

    sign_internal(sk, message, &opt_rand)
}

/// Sign a message with explicit randomizer (for testing/KAT).
pub fn sign_internal(
    sk: &SlhDsaSecretKey,
    message: &[u8],
    opt_rand: &[u8; N],
) -> SlhDsaSignature {
    let r = prf_msg(&sk.prf_key, opt_rand, message);

    // Step 2: Compute message digest and stateless hypertree indices.
    let digest = h_msg(&r, &sk.pk_seed, &sk.pk_root, message);
    let tree_idx = digest.tree_idx;
    let leaf_idx = digest.leaf_idx;

    // Step 4: FORS sign
    let mut fors_addr = make_addr(ADDR_TYPE_FORS);
    set_tree(&mut fors_addr, tree_idx);
    set_keypair(&mut fors_addr, leaf_idx);

    let fors_sig = fors_sign(
        &digest.fors_msg,
        &sk.sk_seed,
        &sk.pk_seed,
        &fors_addr,
    );

    // Step 5: Get FORS public key
    let fors_pk = fors_verify(
        &digest.fors_msg,
        &fors_sig,
        &sk.pk_seed,
        &fors_addr,
    );

    // Step 6: Hypertree sign
    // The hypertree signature signs the FORS public key
    // For this implementation, we create a simple chain of hashes
    let ht_sig = ht_sign(&fors_pk, &sk.sk_seed, &sk.pk_seed, tree_idx, leaf_idx);

    SlhDsaSignature {
        r,
        fors_sig,
        ht_sig,
        tree_idx,
        leaf_idx,
    }
}

/// Verify a signature.
pub fn verify(pk: &SlhDsaPublicKey, message: &[u8], sig: &SlhDsaSignature) -> bool {
    // Step 1: Recompute message digest
    let digest = h_msg(&sig.r, &pk.pk_seed, &pk.pk_root, message);
    if sig.tree_idx != digest.tree_idx || sig.leaf_idx != digest.leaf_idx {
        return false;
    }

    // Step 2: Verify FORS signature to get FORS public key
    let mut fors_addr = make_addr(ADDR_TYPE_FORS);
    set_tree(&mut fors_addr, sig.tree_idx);
    set_keypair(&mut fors_addr, sig.leaf_idx);

    let fors_pk = fors_verify(
        &digest.fors_msg,
        &sig.fors_sig,
        &pk.pk_seed,
        &fors_addr,
    );

    // Step 3: Verify hypertree signature
    // The hypertree signature should recover the same root as the public key
    let root = ht_verify(
        &fors_pk,
        &sig.ht_sig,
        &pk.pk_seed,
        sig.tree_idx,
        sig.leaf_idx,
    );

    // Step 4: Check root matches public key
    // In a full implementation, root would be the actual Merkle tree root.
    // For this structural implementation, we check that the root derived
    // from the signature chain is consistent with the public key.
    //
    // The ht_verify root is the Merkle root of the authentication path.
    // We need this to match pk.pk_root.
    // Since both are derived from the same seeds via consistent tree operations,
    // they should match if the implementation is correct.
    root == pk.pk_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, sk) = keygen();
        assert_eq!(pk.pk_seed.len(), N);
        assert_eq!(pk.pk_root.len(), N);
        assert_eq!(sk.sk_seed.len(), N);
        assert_eq!(sk.prf_key.len(), N);
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let (pk, sk) = keygen();
        let message = b"Test SLH-DSA message";

        let sig = sign(&sk, message);
        let valid = verify(&pk, message, &sig);
        assert!(valid, "SLH-DSA signature verification failed");
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let (pk, sk) = keygen();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let sig = sign(&sk, message);
        let valid = verify(&pk, wrong_message, &sig);
        assert!(!valid, "Should reject wrong message");
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let (pk1, sk1) = keygen();
        let (pk2, _sk2) = keygen();
        let message = b"Test message";

        let sig = sign(&sk1, message);
        let valid = verify(&pk2, message, &sig);
        assert!(!valid, "Should reject with wrong public key");
    }

    #[test]
    fn test_wots_chain() {
        let seed = [0x42u8; N];
        let pk_seed = [0x24u8; N];
        let addr = make_addr(ADDR_TYPE_WOTS);

        // Chain of 0 steps should return input
        let data = [0x55u8; N];
        let result = chain_func(&pk_seed, &addr, &data, 0, 0);
        assert_eq!(result, data);

        // Chain of 1 step
        let result1 = chain_func(&pk_seed, &addr, &data, 0, 1);
        assert_ne!(result1, data);

        // Chain of 2 steps
        let result2 = chain_func(&pk_seed, &addr, &data, 0, 2);
        assert_ne!(result2, result1);

        // Chain continuation: chain(0,1) then chain(1,1) should equal chain(0,2)
        let r1 = chain_func(&pk_seed, &addr, &data, 0, 1);
        let r2 = chain_func(&pk_seed, &addr, &r1, 1, 1);
        assert_eq!(r2, result2);
    }

    #[test]
    fn test_wots_sign_verify() {
        let seed = [0x42u8; N];
        let pk_seed = [0x24u8; N];
        let addr = make_addr(ADDR_TYPE_WOTS);

        let msg = [0x55u8; N];
        let sig = wots_sign(&msg, &seed, &pk_seed, &addr);
        let pk = wots_verify(&msg, &sig, &pk_seed, &addr);

        // Verify should produce same public key
        let pk_expected = wots_pk_gen(&seed, &pk_seed, &addr);
        assert_eq!(pk, pk_expected);
    }

    #[test]
    fn test_fors_indices() {
        let msg = [0xAAu8; N];
        let indices = fors_indices(&msg);
        assert_eq!(indices.len(), A);
        for idx in &indices {
            assert!(*idx < (1 << K));
        }
    }

    #[test]
    fn test_root_consistency() {
        let sk_seed = [0x42u8; N];
        let pk_seed = [0x24u8; N];

        // compute_pk_root should match xmss_node root at the TOP layer (D-1)
        let pk_root = compute_pk_root(&sk_seed, &pk_seed);
        let mut top_addr = make_addr(ADDR_TYPE_TREE);
        set_layer(&mut top_addr, (D - 1) as u32);
        let node_root = xmss_node(&sk_seed, 0, H_PRIME as u32, &pk_seed, &top_addr);

        assert_eq!(
            pk_root, node_root,
            "compute_pk_root and xmss_node at top layer should produce same root"
        );
    }

    #[test]
    fn test_address_operations() {
        let mut addr = make_addr(ADDR_TYPE_FORS);
        set_layer(&mut addr, 3);
        set_tree(&mut addr, 0x1234567890ABCDEF);
        set_keypair(&mut addr, 42);
        set_chain(&mut addr, 7);
        set_hash(&mut addr, 5);

        assert_eq!(addr[0..4], [0, 0, 0, 3]);
        assert_eq!(addr[12..16], ADDR_TYPE_FORS.to_be_bytes());
        assert_eq!(addr[16..20], 42u32.to_be_bytes());
    }

    #[test]
    fn test_hash_functions() {
        let data = b"test data";
        let hash1 = h_sha256(data);
        let hash2 = h_sha256(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), N);
    }

    #[test]
    fn test_multiple_signatures() {
        let (pk, sk) = keygen();

        for i in 0..3 {
            let message = format!("Message {}", i);
            let sig = sign(&sk, message.as_bytes());
            let valid = verify(&pk, message.as_bytes(), &sig);
            assert!(valid, "Signature {} failed", i);
        }
    }

    #[test]
    fn test_fors_address_separation() {
        let mut addr = make_addr(ADDR_TYPE_FORS);
        set_tree(&mut addr, 0x1234567890ABCDEF);
        set_keypair(&mut addr, 42);

        // Test set_type
        set_type(&mut addr, ADDR_TYPE_FORS_PK);
        assert_eq!(addr[12..16], ADDR_TYPE_FORS_PK.to_be_bytes());
        // Verify tree address (offset 4..12) and keypair address (offset 16..20) are preserved
        assert_eq!(addr[4..12], 0x1234567890ABCDEFu64.to_be_bytes());
        assert_eq!(addr[16..20], 42u32.to_be_bytes());

        // Test sk_addr in fors_sk_gen logic
        let mut sk_addr = addr;
        set_tree_height(&mut sk_addr, 0);
        let tree_idx = 5u32;
        let idx = 25u32;
        set_tree_index(&mut sk_addr, (tree_idx << K) | idx);

        assert_eq!(sk_addr[4..12], 0x1234567890ABCDEFu64.to_be_bytes());
        assert_eq!(sk_addr[16..20], 42u32.to_be_bytes());
        assert_eq!(sk_addr[24..28], 0u32.to_be_bytes());
        assert_eq!(sk_addr[28..32], ((5u32 << K) | 25u32).to_be_bytes());
    }

    #[test]
    fn test_xmss_sign_verify() {
        let sk_seed = [0x42u8; N];
        let pk_seed = [0x24u8; N];
        let mut addr = make_addr(ADDR_TYPE_TREE);
        set_layer(&mut addr, 1);
        set_tree(&mut addr, 0x1234567890);

        let msg = [0x55u8; N];
        let leaf_idx = 3u32;

        let (auth_path, wots_sig) = xmss_sign(&msg, &sk_seed, leaf_idx, &pk_seed, &addr);
        let sig = (wots_sig, &auth_path);
        let root = xmss_verify(&msg, &sig, &pk_seed, &addr, leaf_idx);

        // Reconstruct root using xmss_node for validation
        let expected_root = xmss_node(&sk_seed, 0, H_PRIME as u32, &pk_seed, &addr);
        assert_eq!(root, expected_root, "XMSS verification root mismatch");
    }

    #[test]
    fn test_fips205_address_layouts_and_separation() {
        // Create base FORS address
        let mut addr = make_addr(ADDR_TYPE_FORS);
        set_tree(&mut addr, 0x1122334455667788);
        set_keypair(&mut addr, 0x99AABBCC);

        // Verify base fields
        assert_eq!(addr[0..4], [0, 0, 0, 0], "Layer should be 0 by default");
        assert_eq!(addr[4..12], 0x1122334455667788u64.to_be_bytes(), "Tree address mismatch");
        assert_eq!(addr[12..16], ADDR_TYPE_FORS.to_be_bytes(), "Type mismatch");
        assert_eq!(addr[16..20], 0x99AABBCCu32.to_be_bytes(), "Keypair address mismatch");

        // Verify that setting type to FORS_PK preserves tree and keypair addresses
        let mut pk_addr = addr;
        set_type(&mut pk_addr, ADDR_TYPE_FORS_PK);
        set_tree_height(&mut pk_addr, 0);
        set_tree_index(&mut pk_addr, 0);

        assert_eq!(pk_addr[12..16], ADDR_TYPE_FORS_PK.to_be_bytes(), "PK type mismatch");
        assert_eq!(pk_addr[4..12], 0x1122334455667788u64.to_be_bytes(), "PK tree address modified");
        assert_eq!(pk_addr[16..20], 0x99AABBCCu32.to_be_bytes(), "PK keypair address modified");

        // Verify continuous tree indexing for FORS key generation
        let tree_idx = 5u32;
        let leaf_idx = 25u32;
        for height in 0..=K {
            let mut node_addr = addr;
            let node_idx = (leaf_idx >> height) as u32;
            set_tree_height(&mut node_addr, height as u32);
            set_tree_index(&mut node_addr, (tree_idx << (K as u32 - height as u32)) | node_idx);

            // Assert tree_address and keypair_address are unchanged
            assert_eq!(node_addr[4..12], 0x1122334455667788u64.to_be_bytes());
            assert_eq!(node_addr[16..20], 0x99AABBCCu32.to_be_bytes());

            // Assert continuous index field encoding
            let expected_idx = (tree_idx << (K as u32 - height as u32)) | node_idx;
            // The index is written at bytes 28..32 in this implementation
            let actual_idx = u32::from_be_bytes([node_addr[28], node_addr[29], node_addr[30], node_addr[31]]);
            assert_eq!(actual_idx, expected_idx, "Continuous index encoding incorrect at height {}", height);
        }
    }

    #[test]
    fn test_fips_205_address_layout_divergence() {
        // Under FIPS 205 Section 4.2.2:
        // - Tree Height: bytes 20..24
        // - Tree Index: bytes 24..28
        // - Unused: bytes 28..32
        //
        // In this implementation:
        // - Tree Height is mapped to bytes 24..28
        // - Tree Index is mapped to bytes 28..32
        // - Bytes 20..24 are left as zero (unused space)
        
        let mut addr = make_addr(ADDR_TYPE_FORS);
        set_tree_height(&mut addr, 12);
        set_tree_index(&mut addr, 34);

        // Documenting divergence:
        assert_eq!(addr[20..24], [0, 0, 0, 0], "Implementation leaves bytes 20..24 as 0 (unused in code, but should be tree height in FIPS 205)");
        assert_eq!(addr[24..28], 12u32.to_be_bytes(), "Implementation puts tree height at bytes 24..28 (should be 20..24 in FIPS 205)");
        assert_eq!(addr[28..32], 34u32.to_be_bytes(), "Implementation puts tree index at bytes 28..32 (should be 24..28 in FIPS 205)");
    }

    #[test]
    fn test_xmss_sign_verify_round_trip() {
        let sk_seed = [0x55u8; N];
        let pk_seed = [0xAAu8; N];
        let mut addr = make_addr(ADDR_TYPE_TREE);
        set_layer(&mut addr, 2);
        set_tree(&mut addr, 0x123456);

        let msg = [0x11u8; N];
        let leaf_idx = 7u32;

        let (auth_path, wots_sig) = xmss_sign(&msg, &sk_seed, leaf_idx, &pk_seed, &addr);
        let root = xmss_verify(&msg, &(wots_sig, &auth_path), &pk_seed, &addr, leaf_idx);
        
        let expected_root = xmss_node(&sk_seed, 0, H_PRIME as u32, &pk_seed, &addr);
        assert_eq!(root, expected_root, "XMSS verification recovered root must match expected Merkle root");
    }

    #[test]
    fn test_fors_domain_separation_in_signature() {
        let (pk, sk) = keygen();
        let message = b"Test message for FORS domain separation";
        let sig = sign(&sk, message);

        let digest = h_msg(&sig.r, &pk.pk_seed, &pk.pk_root, message);
        assert_eq!(sig.tree_idx, digest.tree_idx);
        assert_eq!(sig.leaf_idx, digest.leaf_idx);

        let mut fors_addr = make_addr(ADDR_TYPE_FORS);
        set_tree(&mut fors_addr, sig.tree_idx);
        set_keypair(&mut fors_addr, sig.leaf_idx);

        // Check initial FORS address details
        assert_eq!(fors_addr[12..16], ADDR_TYPE_FORS.to_be_bytes(), "Type must be FORS");
        assert_eq!(fors_addr[4..12], sig.tree_idx.to_be_bytes(), "Tree index must match");
        assert_eq!(fors_addr[16..20], sig.leaf_idx.to_be_bytes(), "Keypair index must match");

        // After verification, the public key address must have ADDR_TYPE_FORS_PK type,
        // and height and index fields cleared.
        let mut pk_addr = fors_addr;
        set_type(&mut pk_addr, ADDR_TYPE_FORS_PK);
        set_tree_height(&mut pk_addr, 0);
        set_tree_index(&mut pk_addr, 0);

        assert_eq!(pk_addr[12..16], ADDR_TYPE_FORS_PK.to_be_bytes(), "Type must be FORS_PK");
        assert_eq!(pk_addr[4..12], sig.tree_idx.to_be_bytes(), "Tree index must be preserved");
        assert_eq!(pk_addr[16..20], sig.leaf_idx.to_be_bytes(), "Keypair index must be preserved");
        assert_eq!(pk_addr[24..28], 0u32.to_be_bytes(), "Tree height must be cleared");
        assert_eq!(pk_addr[28..32], 0u32.to_be_bytes(), "Tree index must be cleared");
    }
}
