use std::format;

use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};

use super::*;

#[test]
fn package_serialization_roundtrip() {
    let cases = 128; // since the test is quite expensive, 128 cases should be enough to cover all edge cases
                     // (default is 256)
    TestRunner::new(Config::with_cases(cases))
        .run(&any::<Package>(), move |package| {
            let bytes = package.write_to_bytes().unwrap();
            let deserialized = Package::read_from_bytes(&bytes).unwrap();
            prop_assert_eq!(package, deserialized);
            Ok(())
        })
        .unwrap();
}
