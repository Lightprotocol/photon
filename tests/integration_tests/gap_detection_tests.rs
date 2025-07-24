use light_compressed_account::TreeType;
use photon_indexer::common::typedefs::account::AccountWithContext;
use photon_indexer::common::typedefs::account::{Account, AccountContext};
use photon_indexer::common::typedefs::{
    hash::Hash, serializable_pubkey::SerializablePubkey, unsigned_integer::UnsignedInteger,
};
use photon_indexer::ingester::parser::indexer_events::RawIndexedElement;
use photon_indexer::ingester::parser::state_update::{
    IndexedTreeLeafUpdate, LeafNullification, SequenceGapError, StateUpdate,
};
use solana_pubkey::pubkey;

fn create_indexed_tree_update(
    tree: solana_pubkey::Pubkey,
    leaf_index: u64,
    seq: u64,
) -> IndexedTreeLeafUpdate {
    IndexedTreeLeafUpdate {
        tree,
        tree_type: TreeType::AddressV1,
        hash: [0u8; 32],
        leaf: RawIndexedElement {
            value: [0u8; 32],
            next_index: 0,
            next_value: [0u8; 32],
            index: leaf_index as usize,
        },
        seq,
    }
}

fn create_leaf_nullification(tree: solana_pubkey::Pubkey, seq: u64) -> LeafNullification {
    LeafNullification {
        tree,
        leaf_index: 0,
        seq,
        signature: solana_sdk::signature::Signature::default(),
    }
}

fn create_account_with_context(tree: solana_pubkey::Pubkey, leaf_index: u32) -> AccountWithContext {
    AccountWithContext {
        account: Account {
            hash: Hash::new(&[0u8; 32]).unwrap(),
            data: None,
            owner: SerializablePubkey::try_from([0u8; 32]).unwrap(),
            lamports: UnsignedInteger(0),
            address: None,
            tree: SerializablePubkey::from(tree),
            leaf_index: UnsignedInteger(leaf_index as u64),
            seq: None,
            slot_created: UnsignedInteger(0),
        },
        context: AccountContext {
            queue: SerializablePubkey::try_from([0u8; 32]).unwrap(),
            in_output_queue: false,
            spent: false,
            nullified_in_tree: false,
            nullifier_queue_index: None,
            nullifier: None,
            tx_hash: None,
            tree_type: 0,
        },
    }
}

#[test]
fn test_no_gap_sequential_sequences() {
    let tree = pubkey!("BPF9L8vwCHcqW3xrLHgVrwCzxxH6VbSk1KDHhE1ZBFP9");
    let mut state_update = StateUpdate::new();

    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 0), create_indexed_tree_update(tree, 0, 1));
    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 1), create_indexed_tree_update(tree, 1, 2));
    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 2), create_indexed_tree_update(tree, 2, 3));

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_ok());
}

#[test]
fn test_gap_detected_indexed_merkle_tree() {
    let tree = pubkey!("amt1Ayt45jfbdw5YSo7iz6WZxUmnZsQTYXy82hVwyC2");
    let mut state_update = StateUpdate::new();

    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 0), create_indexed_tree_update(tree, 0, 1));
    state_update.indexed_merkle_tree_updates.insert(
        (tree, 1),
        create_indexed_tree_update(tree, 1, 3), // Gap here
    );

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_err());

    if let Err(SequenceGapError::GapDetected(gaps)) = result {
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].tree, tree);
        assert_eq!(gaps[0].expected_seq, 2);
        assert_eq!(gaps[0].actual_seq, 3);
    }
}

#[test]
fn test_gap_detected_leaf_nullifications() {
    let tree = pubkey!("smt1NamzXdq4AMqS2fS2F1i5KTYPZRhoHgWx38d8WsT");
    let mut state_update = StateUpdate::new();

    state_update
        .leaf_nullifications
        .insert(create_leaf_nullification(tree, 1));
    state_update
        .leaf_nullifications
        .insert(create_leaf_nullification(tree, 2));
    state_update
        .leaf_nullifications
        .insert(create_leaf_nullification(tree, 4)); // Gap here (missing 3)

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_err());

    if let Err(SequenceGapError::GapDetected(gaps)) = result {
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].tree, tree);
        assert_eq!(gaps[0].expected_seq, 3);
        assert_eq!(gaps[0].actual_seq, 4);
    }
}

#[test]
fn test_gap_detected_output_accounts() {
    // Use an actual StateV1 tree for testing output accounts
    let tree = pubkey!("smt2rJAFdyJJupwMKAqTNAJwvjhmiZ4JYGZmbVRw1Ho");
    let mut state_update = StateUpdate::new();

    state_update
        .out_accounts
        .push(create_account_with_context(tree, 1));
    state_update
        .out_accounts
        .push(create_account_with_context(tree, 2));
    state_update
        .out_accounts
        .push(create_account_with_context(tree, 4)); // Gap here (missing 3)

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_err());

    if let Err(SequenceGapError::GapDetected(gaps)) = result {
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].tree, tree);
        assert_eq!(gaps[0].expected_seq, 3);
        assert_eq!(gaps[0].actual_seq, 4);
    }
}

#[test]
fn test_multiple_gaps_detected() {
    let tree1 = pubkey!("amt1Ayt45jfbdw5YSo7iz6WZxUmnZsQTYXy82hVwyC2");
    let tree2 = pubkey!("smt3AFtReRGVcrP11D6bSLEaKdUmrGfaTNowMVccJeu");
    let mut state_update = StateUpdate::new();

    state_update
        .indexed_merkle_tree_updates
        .insert((tree1, 0), create_indexed_tree_update(tree1, 0, 1));
    state_update
        .indexed_merkle_tree_updates
        .insert((tree1, 1), create_indexed_tree_update(tree1, 1, 2));
    state_update.indexed_merkle_tree_updates.insert(
        (tree1, 2),
        create_indexed_tree_update(tree1, 2, 4), // Gap in tree1 (missing 3)
    );
    state_update
        .leaf_nullifications
        .insert(create_leaf_nullification(tree2, 1));
    state_update
        .leaf_nullifications
        .insert(create_leaf_nullification(tree2, 2));
    state_update
        .leaf_nullifications
        .insert(create_leaf_nullification(tree2, 4)); // Gap in tree2 (missing 3)

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_err());

    if let Err(SequenceGapError::GapDetected(gaps)) = result {
        assert_eq!(gaps.len(), 2);
    }
}

#[test]
fn test_deduplication_no_false_gaps() {
    let tree = pubkey!("BPF9L8vwCHcqW3xrLHgVrwCzxxH6VbSk1KDHhE1YBFPA");
    let mut state_update1 = StateUpdate::new();
    let mut state_update2 = StateUpdate::new();

    state_update1
        .indexed_merkle_tree_updates
        .insert((tree, 0), create_indexed_tree_update(tree, 0, 1));
    state_update1
        .indexed_merkle_tree_updates
        .insert((tree, 1), create_indexed_tree_update(tree, 1, 2));

    state_update2.indexed_merkle_tree_updates.insert(
        (tree, 0),
        create_indexed_tree_update(tree, 0, 3), // Overwrites seq 1
    );

    let result =
        StateUpdate::merge_updates_with_slot(vec![state_update1, state_update2], Some(100));
    assert!(result.is_ok());
}

#[test]
fn test_empty_state_update() {
    let result = StateUpdate::merge_updates_with_slot(vec![StateUpdate::new()], Some(100));
    assert!(result.is_ok());
}

#[test]
fn test_single_sequence_no_gap() {
    let tree = pubkey!("BPF9L8vwCHcqW3xrLHgVrwCzxxH6VbSk1KDHhE1ZBFP8");
    let mut state_update = StateUpdate::new();

    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 0), create_indexed_tree_update(tree, 0, 5));

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_ok());
}

#[test]
fn test_out_of_order_sequences() {
    let tree = pubkey!("BPF9L8vwCHcqW3xrLHgVrwCzxxH6VbSk1KDHhE1YBFPB");
    let mut state_update = StateUpdate::new();

    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 2), create_indexed_tree_update(tree, 2, 3));
    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 0), create_indexed_tree_update(tree, 0, 1));
    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 1), create_indexed_tree_update(tree, 1, 2));

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_ok());
}

#[test]
fn test_gap_detected_batch_new_addresses() {
    let tree = pubkey!("amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx");
    let mut state_update = StateUpdate::new();

    use photon_indexer::common::typedefs::serializable_pubkey::SerializablePubkey;
    use photon_indexer::ingester::parser::state_update::AddressQueueUpdate;

    state_update.batch_new_addresses.push(AddressQueueUpdate {
        tree: SerializablePubkey::from(tree),
        address: [1u8; 32],
        queue_index: 1,
    });
    state_update.batch_new_addresses.push(AddressQueueUpdate {
        tree: SerializablePubkey::from(tree),
        address: [2u8; 32],
        queue_index: 2,
    });
    state_update.batch_new_addresses.push(AddressQueueUpdate {
        tree: SerializablePubkey::from(tree),
        address: [3u8; 32],
        queue_index: 4, // Gap here (missing 3)
    });

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_err());

    if let Err(SequenceGapError::GapDetected(gaps)) = result {
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].tree, tree);
        assert_eq!(gaps[0].expected_seq, 3);
        assert_eq!(gaps[0].actual_seq, 4);
    }
}

#[test]
fn test_starting_from_snapshot_no_gap() {
    let tree = pubkey!("BPF9L8vwCHcqW3xrLHgVrwCzxxH6VbSk1KDHhE1ZBFP3");
    let mut state_update = StateUpdate::new();

    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 0), create_indexed_tree_update(tree, 0, 4256));

    state_update
        .indexed_merkle_tree_updates
        .insert((tree, 1), create_indexed_tree_update(tree, 1, 4257));

    let result = StateUpdate::merge_updates_with_slot(vec![state_update], Some(100));
    assert!(result.is_ok());
}
