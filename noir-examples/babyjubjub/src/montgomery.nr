use super::BabyJubJubPoint;

// Reference: https://github.com/iden3/circomlib/blob/master/circuits/montgomery.circom

pub struct MontgomeryPoint {
    pub u: Field,
    pub v: Field,
}
global MONT_A: Field = 168698;
global MONT_B: Field = 1;

impl BabyJubJubPoint {

    /*

               1 + y       1 + y
    [u, v] = [ -------  , ---------- ]
                1 - y      (1 - y)x

    */

    unconstrained fn to_montgomery_unconstrained(self) -> (Field, Field) {
        let u = (1 + self.y) / (1 - self.y);
        let v = u / self.x;
        (u, v)
    }
    pub fn to_montgomery(self) -> MontgomeryPoint {
        // Safety: cast to unconstrained field
        let (u, v) = unsafe { self.to_montgomery_unconstrained() };

        assert(u * (1 - self.y) == 1 + self.y);
        assert(v * self.x == u);

        MontgomeryPoint { u, v }
    }

    /*

                u    u - 1
    [x, y] = [ ---, ------- ]
                v    u + 1

    */
    unconstrained fn from_montgomery_unconstrained(p: MontgomeryPoint) -> (Field, Field) {
        let x = p.u / p.v;
        let y = (p.u - 1) / (p.u + 1);
        (x, y)
    }

    pub fn from_montgomery(p: MontgomeryPoint) -> Self {
        // Safety: cast to unconstrained field
        let (x, y) = unsafe { Self::from_montgomery_unconstrained(p) };

        assert(x * p.v == p.u);
        assert(y * (p.u + 1) == p.u - 1);

        BabyJubJubPoint { x, y }
    }
}

impl MontgomeryPoint {

    unconstrained fn add_lambda_unconstrained(self, q: MontgomeryPoint) -> Field {
        (q.v - self.v) / (q.u - self.u)
    }

    pub fn add(self, q: MontgomeryPoint) -> MontgomeryPoint {
        // Safety: cast to unconstrained field
        let lambda = unsafe { Self::add_lambda_unconstrained(self, q) };
        assert(lambda * (q.u - self.u) == q.v - self.v);

        let u3 = MONT_B * lambda * lambda - MONT_A - self.u - q.u;
        let v3 = lambda * (self.u - u3) - self.v;

        MontgomeryPoint { u: u3, v: v3 }
    }

    unconstrained fn double_lambda_unconstrained(self) -> Field {
        let u = self.u;
        let v = self.v;
        let num = 3 * u * u + 2 * MONT_A * u + 1;
        let den = 2 * v;
        num / den
    }

    pub fn double(self) -> MontgomeryPoint {
        // Safety: cast to unconstrained field
        // lambda = (3*u^2 + 2*A*u + 1) / (2*v)
        let lamda = unsafe { Self::double_lambda_unconstrained(self) };
        let num = 3 * self.u * self.u + 2 * MONT_A * self.u + 1;
        let den = 2 * self.v;
        assert(lamda * den == num);

        let u3 = MONT_B * lamda * lamda - MONT_A - 2 * self.u;
        let v3 = lamda * (self.u - u3) - self.v;

        MontgomeryPoint { u: u3, v: v3 }
    }
}

#[test]
fn test_edwards_to_montgomery_and_back() {
    let g = BabyJubJubPoint::generator();

    let mg = g.to_montgomery();

    let result = BabyJubJubPoint::from_montgomery(mg);

    assert_eq(result.x, g.x);
    assert_eq(result.y, g.y);
}

#[test]
fn test_montgomery_double() {
    let g = BabyJubJubPoint::generator();

    let g2_edwards = g.add(g);

    let mg = g.to_montgomery();
    let mg2 = mg.double();

    let g2_from_montgomery = BabyJubJubPoint::from_montgomery(mg2);

    assert_eq(g2_from_montgomery.x, g2_edwards.x);
    assert_eq(g2_from_montgomery.y, g2_edwards.y);
}

#[test]
fn test_montgomery_add() {
    // Generator point
    let g = BabyJubJubPoint::generator();

    // g2 = g + g
    let g2_edwards = g.add(g);

    // g3 = g + g2
    let g3_edwards = g.add(g2_edwards);

    let mg = g.to_montgomery();
    let mg2 = g2_edwards.to_montgomery();

    let mg3 = mg.add(mg2);

    let g3_from_montgomery = BabyJubJubPoint::from_montgomery(mg3);

    assert_eq(g3_from_montgomery.x, g3_edwards.x);
    assert_eq(g3_from_montgomery.y, g3_edwards.y);
}
