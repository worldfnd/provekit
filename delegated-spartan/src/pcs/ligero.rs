use {
    crate::{
        merkle_tree::MerkleTree,
        ntt::{intt, ntt, transpose},
        pcs::hyrax::compute_contraction,
        poseidon::compress,
        reed_solomon::encode,
        transcript::Prover,
    },
    ark_bn254::Fr,
    ark_ff::{Field, PrimeField},
    std::iter::once,
};

pub struct LigeroCommitter {
    pub rows:         usize,
    pub cols:         usize,
    pub code:         usize,
    pub queries:      usize,
    pub combinations: usize,
}

pub struct LigeroCommitment<'a> {
    comitter: &'a LigeroCommitter,
    matrix:   Vec<Fr>,
    tree:     MerkleTree,
}

impl LigeroCommitter {
    pub fn new(security_bits: f64, size: usize) -> Self {
        let expansion = 4;

        let queries =
            (security_bits / (1.0 - (1.0 + 1.0 / (expansion as f64)).log2())).ceil() as usize;

        // Pick matrix aspect to minimize proof size.
        let rows = divisor_close_to(
            size,
            (2.0 * (size as f64) / (queries as f64)).sqrt() as usize,
        );
        let cols = size / rows;
        assert_eq!(rows * cols, size, "Invalid size.");

        let code = expansion * cols;
        let combinations =
            1 + ((security_bits - 1.0) / (253.6 - (code as f64).log2())).floor() as usize;
        assert_eq!(
            combinations, 1,
            "Multiple combinations should not happen at this field size."
        );

        Self {
            rows,
            cols,
            code,
            queries,
            combinations,
        }
    }

    pub fn commit(&self, transcript: &mut Prover, f: &[Fr]) -> LigeroCommitment {
        assert_eq!(f.len(), self.rows * self.cols);

        // Encode values
        let mut buffer = vec![Fr::ZERO; self.cols];
        let mut encoded = vec![Fr::ZERO; self.rows * self.code];
        for (f, e) in f
            .chunks_exact(self.cols)
            .zip(encoded.chunks_exact_mut(self.code))
        {
            buffer.copy_from_slice(f);
            encode(&mut buffer, e);
        }

        // Hash columns and construct merkle tree.
        transpose(&mut encoded, self.rows, self.code);
        let tree = MerkleTree::new(encoded.chunks_exact(self.rows).map(compress).collect());

        transcript.write(tree.root());
        LigeroCommitment {
            comitter: self,
            matrix: encoded,
            tree,
        }
    }
}

impl LigeroCommitment<'_> {
    pub fn prove_contraction(
        &self,
        transcript: &mut Prover,
        a: &[Fr], // Values
        b: &[Fr], // Values
    ) {
        assert_eq!(a.len(), self.comitter.rows);
        assert_eq!(b.len(), self.comitter.cols);

        // Generate random factors combinations
        let mut r = Vec::with_capacity(self.comitter.combinations * self.comitter.rows);
        for _r in 0..self.comitter.combinations {
            for _i in 0..self.comitter.rows {
                r.push(transcript.read());
            }
        }

        // Compute the linear combinations of the rows and send to verifier.
        for a in once(a).chain(r.chunks_exact(self.comitter.rows)) {
            let mut combination = vec![Fr::ZERO; self.comitter.cols];
            // TODO: Matrix doesn't have right transposition, plus code is not necessarily
            // systematized.
            for (a, row) in a.iter().zip(self.matrix.chunks_exact(self.comitter.code)) {
                let row = &row[..self.comitter.cols];
                for (c, row) in combination.iter_mut().zip(row.iter()) {
                    *c += a * row;
                }
            }
            combination.into_iter().for_each(|c| transcript.write(c));
        }

        // Decommit columns
        let indices: Vec<usize> = (0..self.comitter.queries)
            .map(|_| {
                let index = transcript.read();
                index.into_bigint().as_ref()[0] as usize % self.comitter.cols
            })
            .collect();
        for index in indices {
            let column = self
                .matrix
                .chunks_exact(self.comitter.rows)
                .nth(index)
                .unwrap();
            for value in column {
                transcript.reveal(*value);
            }
            self.tree.reveal(transcript, index);
        }
    }
}

fn divisor_close_to(n: usize, target: usize) -> usize {
    // Assume n is a power of two.
    // TODO: More generic method.
    1 << target.ilog2()
}
