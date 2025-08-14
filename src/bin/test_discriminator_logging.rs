use photon_indexer::api::method::utils::parse_discriminator_string;
use photon_indexer::common::typedefs::account::AccountData;
use photon_indexer::common::typedefs::bs64_string::Base64String;
use photon_indexer::common::typedefs::hash::Hash;
use photon_indexer::common::typedefs::unsigned_integer::UnsignedInteger;

fn main() {
    // Initialize simple logging - just print to stdout for now
    // env_logger not available, will use println! for demo

    println!("🧪 Testing discriminator logging flow...");

    // Test the discriminator value from your original precision loss issue
    let bytes = [247u8, 237, 227, 245, 215, 195, 222, 70];
    let expected_u64 = u64::from_le_bytes(bytes);
    println!("Original discriminator: {}", expected_u64);

    // Simulate storage (string conversion)
    let stored_as_string = expected_u64.to_string();
    println!("Stored as: '{}'", stored_as_string);

    // Simulate retrieval (string parsing) - this will log
    println!("\n--- Testing retrieval logging ---");
    let retrieved_u64 = parse_discriminator_string(stored_as_string).unwrap();
    println!("Retrieved: {}", retrieved_u64);

    // Test JSON serialization logging
    println!("\n--- Testing JSON serialization logging ---");
    let account_data = AccountData {
        discriminator: UnsignedInteger(expected_u64),
        data: Base64String(vec![1, 2, 3]),
        data_hash: Hash::default(),
    };

    let json = serde_json::to_string(&account_data).unwrap();
    println!("JSON: {}", json);

    // Verify precision preserved
    assert_eq!(expected_u64, retrieved_u64);
    println!("\n✅ Discriminator logging test completed successfully!");
}
