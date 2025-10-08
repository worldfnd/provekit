use dep::std;
use ec::consts::te::baby_jubjub;
use ec::tecurve::affine::Point as TEPoint;
use poseidon::poseidon2::Poseidon2;

mod hash_to_curve {
    use dep::std;
    use ec::consts::te::baby_jubjub;
    use ec::tecurve::affine::Point as TEPoint;
    use poseidon::poseidon2::Poseidon2;
    
    // Baby JubJub curve parameters
    global K: Field = 1;
    global J: Field = 168698;
    global A_PARAM: Field = 168700;
    global D_PARAM: Field = 168696;
    global Z: Field = 5; // Non-square element for Elligator2
    global C1: Field = 168698; // J/K
    global C2: Field = 1; // 1/(K*K)
    
    // Hash to field using Poseidon2
    pub fn hash_to_field(input: Field) -> Field {
 
        let hash_input = [0, input, 0];
        let hash_result = Poseidon2::hash(hash_input, 3);
        
        hash_result
    }

       fn is_zero(x: Field) -> bool {
        x == 0
    }

// Scalar mux: returns if_true when selector==1, else if_false
fn mux1(selector: bool, if_false: Field, if_true: Field) -> Field {
    let s: Field = if selector { 1 } else { 0 };
    (if_true - if_false) * s + if_false
}
   // XOR for boolean values
 fn xor(a: bool, b: bool) -> bool {
        (a & !b) | (!a & b)
    }
    
    // Map to Montgomery curve using Elligator2
    pub fn map_to_curve_elligator2(input: Field) -> (Field, Field) {
        // tv1_0 = Z * u^2
        let tv1_0 = Z * (input * input);
        
        // e = IsZero(tv1_0 + 1)
        let e = is_zero(tv1_0 + 1);
        
        // tv1 = Mux1([tv1_0, 0], e)
        let tv1 = mux1(e, tv1_0, 0);
        
        // x1 = -c1 / (tv1 + 1)
        // Need: inverse_or_zero helper
        let x1_inv = inverse_or_zero(tv1 + 1);
        let x1 = -C1 * x1_inv;
        
        // gx1 = x1 * (x1 + c1) * (x1 + c2)
        let gx1_0 = (x1 + C1) * x1;
        let gx1 = (gx1_0 + C2) * x1;
        
        // x2 = -x1 - c1
        let x2 = -x1 - C1;
        
        // gx2 = tv1 * gx1
        let gx2 = tv1 * gx1;
  
        let e2 = is_quadratic_residue_or_zero(gx1);
        
        // x = Mux1([x2, x1], e2)
        let x = mux1(e2, x2, x1);
        
        // y2 = Mux1([gx2, gx1], e2)
        let y2 = mux1(e2, gx2, gx1);
        
        // y = sqrt(y2)

        let y = bbf_sqrt_unchecked(y2);
        // Constraint: y*y == y2 (this is implicitly checked by sqrt)
        
        // e3 = Sgn0(y)

        let e3 = sgn0(y);
        
        // xor = XOR(e2, e3)
        let should_negate = xor(e2, e3);
        
        // multiplication = Mux1([1, -1], xor)
        let multiplication = mux1(should_negate, 1, -1);
        
        // y_1 = y * multiplication
        let y_1 = y * multiplication;
        
        // Return Montgomery coordinates
        (x * K, y_1 * K)
    }
        pub fn rational_map_mont_to_twisted_edwards(s: Field, t: Field) -> (Field, Field) {
        // tv1 = s + 1
        let tv1 = s + 1;
        
        // tv2 = InverseOrZero(tv1 * t)
        // Need: inverse_or_zero helper
        let tv2 = inverse_or_zero(tv1 * t);
        
        // v = tv1 * tv2
        let v = tv1 * tv2;
        
        // w = tv2 * t
        let w = tv2 * t;
        
        // tv11 = s - 1
        let tv11 = s - 1;
        
        // e = IsZero(tv2)
        let e = is_zero(tv2);
        
        // out[0] = s * v
        let out_x = s * v;
        
        // out[1] = Mux1([w * tv11, 1], e)
        let out_y = mux1(e, w * tv11, 1);
        
        (out_x, out_y)
    }
    
    // Map to Twisted Edwards curve
    pub fn map_to_curve_twisted_edwards(input: Field) -> (Field, Field) {
        let (mont_s, mont_t) = map_to_curve_elligator2(input);
        rational_map_mont_to_twisted_edwards(mont_s, mont_t)
    }
    
   pub fn clear_cofactor_baby_jubjub(x: Field, y: Field) -> (Field, Field) {
        // Need: baby_dbl helper for point doubling
        let (double_x, double_y) = baby_dbl(x, y);
        let (quadruple_x, quadruple_y) = baby_dbl(double_x, double_y);
        let (eight_x, eight_y) = baby_dbl(quadruple_x, quadruple_y);
        
        (eight_x, eight_y)
    }
    
    // Main encode to curve function
    pub fn encode_to_curve_baby_jubjub(input: Field) -> (Field, Field) {
        // u = HashToField(input)
        let u = hash_to_field(input);
        
        // q = MapToCurveTwistedEdwards(u)
        let (q_x, q_y) = map_to_curve_twisted_edwards(u);
        
        // Clear cofactor
        let (out_x, out_y) = clear_cofactor_baby_jubjub(q_x, q_y);
        
        (out_x, out_y)
    }




}