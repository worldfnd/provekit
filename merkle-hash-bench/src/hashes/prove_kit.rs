#![cfg(feature = "zkhash")]
use crate::{register_hash, Field, HashFn, SmolHasher};

struct Reference;
struct Simple;
struct Ver1;
struct Block3;
struct Block4;

register_hash!(Reference);
register_hash!(Simple);
register_hash!(Block3);
register_hash!(Block4);
register_hash!(Ver1);

impl SmolHasher for Reference {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper2(1)
    }

    fn implementation(&self) -> &str {
        "pk-ref"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        skyscraper::reference::compress_many(messages, hashes);
    }
}

impl SmolHasher for Simple {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper2(1)
    }

    fn implementation(&self) -> &str {
        "pk-simple"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        skyscraper::simple::compress_many(messages, hashes);
    }
}

impl SmolHasher for Block3 {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper2(1)
    }

    fn implementation(&self) -> &str {
        "pk-block3"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        skyscraper::block3::compress_many(messages, hashes);
    }
}

impl SmolHasher for Block4 {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper2(1)
    }

    fn implementation(&self) -> &str {
        "pk-block4"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        skyscraper::block4::compress_many(messages, hashes);
    }
}

impl SmolHasher for Ver1 {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper1(1)
    }

    fn implementation(&self) -> &str {
        "pk-v1"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        skyscraper::v1::compress_many(messages, hashes);
    }
}
