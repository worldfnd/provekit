use std::collections::BTreeMap;
use std::path::PathBuf;

use noir_runner::{NoirRunner, ToNoir};
use proptest::{prelude::prop, test_runner::TestRunner};
use sha2::{Digest, Sha256};

#[test]
fn test_prop_sha256_1() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 1>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_sha256_1", input).unwrap().unwrap();

            let expected: [u8; 32] = Sha256::digest(vector).into();

            assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_prop_sha256_200() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 200>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.clone().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_sha256_200", input).unwrap().unwrap();

            let expected: [u8; 32] = Sha256::digest(vector).into();

            assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_prop_sha256_511() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 511>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.clone().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_sha256_511", input).unwrap().unwrap();

            let expected: [u8; 32] = Sha256::digest(vector).into();

            assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_prop_sha256_512() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 512>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.clone().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_sha256_512", input).unwrap().unwrap();

            let expected: [u8; 32] = Sha256::digest(vector).into();

            assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}
