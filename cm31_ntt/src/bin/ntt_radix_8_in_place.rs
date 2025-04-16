use cm31_ntt::cm31::CF;
use cm31_ntt::ntt::ntt_radix_8_in_place;
use cm31_ntt::ntt_utils::get_root_of_unity;
use num_traits::Zero;

fn main() {
    let n = 8usize.pow(8);
    
    let mut input = vec![CF::zero(); n];
    for i in 0..n {
        input[i] = CF::new(0, i as u32);
    }
    
    let wn = get_root_of_unity(n);
    let _output = ntt_radix_8_in_place(&mut input, wn);
}
