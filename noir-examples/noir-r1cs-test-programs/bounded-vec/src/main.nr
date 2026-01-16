fn main(data: BoundedVec<u8, 32>, suffix: [u8; 4]) -> pub [u8; 36] {
    let result = concat(data, suffix);
    result.storage()
}

fn concat<let N: u32>(a: BoundedVec<u8, N>, b: [u8; 4]) -> BoundedVec<u8, N + 4> {
    let mut result = [0 as u8; N + 4];
    let mut j = 0;  

    for i in 0..N {
        if i < a.len() {
            result[j] = a.get(i);
            j += 1;  // <-- Conditional increment
        }
    }

    for i in 0..4 {
        result[j] = b[i];
        j += 1;
    }

    BoundedVec::from_parts(result, j)
}