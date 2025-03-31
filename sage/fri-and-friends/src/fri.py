from sage.arith.misc import is_power_of_two
from sage.misc.functional import log, sqrt
from sage.misc.misc_c import prod
from sage.misc.prandom import random
from sage.rings.finite_rings.all import *
from sage.rings.polynomial.all import *
from sage.coding.grs_code import ReedSolomonCode
from sage.matrix.all import *
from sage.modules.all import vector;
from typing import *

def is_majority(lst):
    votes = sum([1 if v else 0 for v in lst]) 
    return votes > len(lst)//2

def is_overwhelming_majority(lst):
    votes = sum([1 if v else 0 for v in lst]) 
    return votes > (2*len(lst))//3

## Split a polynomial into powers of `split_degree`
def poly_ksplit(poly, split_degree):
    chunks = poly.degree()//split_degree
    splits = [ poly.parent()(0) for _ in range(split_degree) ]
    indeterminate = poly.parent().gen()

    for (i,coef) in enumerate(poly.list()):
        ndx = i % split_degree
        deg = i // split_degree
        splits[ndx] = splits[ndx] + coef*(indeterminate**deg)

    pp = poly.parent()(0)

    for (j,mini_poly) in enumerate(splits):
        pp = pp + mini_poly.subs({ indeterminate : indeterminate** split_degree})*(indeterminate**j)
    assert pp == poly, "Reconstruction works!!!"

    return splits


class FRIRound:
    def __init__(self, 
                 input_polynomial : Polynomial,
                 ntt_omega : int,       # must have order 2^k
                 rate_factor : int,      # Rate of Reed Solomon Code
                 folding_factor: int    # folding factor of FRI 
                 ):
        
        self.poly = input_polynomial
        self.PolyRing = self.poly.parent()
        self.Fq = self.PolyRing.base_ring()
        self.omega  = self.Fq(ntt_omega)
        self.rate_factor = rate_factor

        # Assuming small field size, typically less than 64-bits
        self.mutl_order = self.omega.multiplicative_order()

        if not is_power_of_two(self.mutl_order):
            raise ValueError(f"The multiplicative order of RS generator {self.omega} must be a power of two!")
        
        if not is_power_of_two(rate_factor) or rate_factor > self.mutl_order:
            raise ValueError(f"Invalid rate factor: {rate_factor}. Must be a \
                             power of 2 and smaller than the multiplicative  \
                            order of the RS generator")
        
        if not is_power_of_two(folding_factor):
            raise ValueError(f"Folding factor must be a power of 2")

        self.dimension = self.mutl_order // rate_factor
        self.folding_factor = folding_factor
        self.folding_root = self.omega**(self.mutl_order // self.folding_factor)

        assert self.folding_root**folding_factor == 1

        self.RS_CODE = ReedSolomonCode(self.Fq, self.mutl_order, self.dimension, self.omega)
        self.encoder = self.RS_CODE.encoder("EvaluationPolynomial", polynomial_ring=input_polynomial.parent())
        self._evaluation_points = None

    def evaluation_points(self):
        if not self._evaluation_points:
            self._evaluation_points = self.RS_CODE.evaluation_points()
        return self._evaluation_points

    def ndx_with_folding_roots(self, ndx):
        order = self.mutl_order
        step = self.mutl_order // self.folding_factor
        indexes = [ (ndx + j*step) % order for j in range(self.folding_factor) ]
        if __debug__:
            reference = self.evaluation_points()[ndx]**self.folding_factor
            entries = [self.evaluation_points()[j]**self.folding_factor for j in indexes]
            assert all([reference == e for e in entries])

        return indexes

    def ud_radius(self):
        return  (1 - float(1/self.rate_factor))/2.0
    
    def jb_radius(self):
        return 1 - sqrt(float(1/self.rate_factor))

    def gen_proof(self, corrupt_fn = None) -> list[FiniteField]:
        encoded = self.encoder.encode(self.poly)

        if corrupt_fn:
            for i in range(len(encoded)):
                if corrupt_fn(i):
                    encoded[i] = self.Fq.random_element()
        return encoded

    def fold(self, fold_challenge, ood_challenges = None):
        splits = poly_ksplit(self.poly, self.folding_factor)
        poly_tbf = self.PolyRing(0)

        for i in range(self.folding_factor):
            poly_tbf += (fold_challenge**i)*splits[i]

        ood_response = None

        if ood_challenges:
            if not isinstance(ood_challenges, (list,)):
                ood_challenges = [ood_challenges]

            num,den = FRIRound.deep_rational_poly(poly_tbf, ood_challenges=ood_challenges)

            new_num = poly_tbf - num
            assert new_num % den == 0
            poly_tbf = new_num // den
            ood_response = num / den

        new_omega = self.omega ** self.folding_factor
        return (FRIRound(poly_tbf, new_omega, self.rate_factor, self.folding_factor), ood_response)

    def decode_upto_ud(self, proof_code):
        decoder = self.RS_CODE.decoder("KeyEquationSyndrome")
        decoded = self.PolyRing(list(decoder.decode_to_message(proof_code)))
        return decoded
    
    def decode_upto_jb(self, proof_code):
        pass

    @staticmethod
    def deep_rational_poly(eval_poly, ood_challenges):
        PolyRing = eval_poly.parent()
        poly_evals = [(v, eval_poly(v)) for v in ood_challenges]
        numerator = PolyRing.lagrange_polynomial(poly_evals)
        x = PolyRing.gen()
        denomonator = prod([(x - v) for v in ood_challenges])
        return (numerator, denomonator)

    @staticmethod
    def consistancy_cross_check(this_round: Self, prev_round : Self, folding_challenge, queries = 1, ood_response = None):
        previous_round_proof = prev_round.gen_proof()
        this_round_proof = this_round.gen_proof()
        alphas = [prev_round.folding_root**i for i in range(prev_round.folding_factor)]
        success = list()

        for _ in range(queries):
            ndx = int(random()*len(previous_round_proof))
            check_indices = prev_round.ndx_with_folding_roots(ndx)
            new_ndx = ndx % this_round.mutl_order
            if __debug__:
                this_elem = this_round.evaluation_points()[new_ndx]
                prev_elem = prev_round.evaluation_points()[check_indices[0]]
                expected = prev_elem**prev_round.folding_factor
                assert this_elem == expected

            values = [previous_round_proof[i] for i in check_indices]
            eval_point = prev_round.evaluation_points()[ndx]

            vander = [[(eval_point*alpha)**k for k in range(this_round.folding_factor)] for alpha in alphas ]
            M = Matrix(this_round.Fq, vander)
            val = vector(this_round.Fq, values)
            coeff = M.inverse()*val
            expected = sum([c*(folding_challenge**i) for (i,c) in enumerate(coeff)])

            value_this_round = this_round_proof[new_ndx]
            
            check_passed = value_this_round == expected

            if ood_response:
                this_round_omega = this_round.evaluation_points()[new_ndx]
                num = ood_response.numerator()(this_round_omega)
                den = ood_response.denominator()(this_round_omega)
                value_this_round = den*value_this_round + num
                check_passed = value_this_round == expected

            success.append(check_passed)

        return is_overwhelming_majority(success)
            
class FRIOPP:

    class RoundData:
        def __init__(self, fri_round, fold_random, deep_poly = None):
            self.fri_round = fri_round
            self.fold_randomness  = fold_random
            self.deep_poly = deep_poly

    def __init__(self, 
                 input_polynomial : Polynomial,
                 ntt_omega : int,       # must have order 2^k
                 rate_factor : int,     # Rate of Reed Solomon Code
                 folding_factor: int,    # folding factor of FRI 
                 ood_count: int = 0, # Number of OOD Random samples
                 ):
        self.Rx = input_polynomial.parent()
        self.Fq = input_polynomial.base_ring()
        self.rounds = list()
        first_round = FRIRound(input_polynomial, ntt_omega, rate_factor, folding_factor)

        self.oracle = first_round

        self.rounds.append(FRIOPP.RoundData(first_round, None, None))

        this_round = first_round

        while this_round.poly.degree() > folding_factor:
            fold_challenge = this_round.Fq.random_element()
            ood_challenge = [self.Fq.random_element() for _ in range(ood_count) ] if ood_count > 0 else None
            (this_round, ood_frac) = this_round.fold(fold_challenge, ood_challenge)
            self.rounds.append(FRIOPP.RoundData(this_round, fold_challenge, ood_frac))

    def verify_proximity(self, max_degree, query_count = 10):
        prev_round = self.rounds[0].fri_round

        round_max_degree = max_degree

        if prev_round.dimension < max_degree:
            # Can't test degree if max_degree is higher than code dimension
            return False

        for this_round in self.rounds[1:]:
            this_fri = this_round.fri_round
            fold_random = this_round.fold_randomness
            deep_frac = this_round.deep_poly
            is_good = FRIRound.consistancy_cross_check(this_fri, 
                                                       prev_round, 
                                                       fold_random, 
                                                       query_count,
                                                       deep_frac)
            if not is_good:
                return False
            
            prev_round = this_fri

            round_max_degree = round_max_degree // this_fri.folding_factor + 1

            if deep_frac:
                round_max_degree -= deep_frac.denominator().degree()
            
            if round_max_degree <= this_fri.folding_factor :
                break

        last_round_poly = self.Rx.lagrange_polynomial(zip(prev_round.evaluation_points(),
                                                           prev_round.gen_proof()))
        
        if last_round_poly.degree() > prev_round.folding_factor:
            return False
        else:
            return True

    def proof_oracle(self):
        return self.oracle
    
class FRIPCS_Prover:
    def __init__(self,
                ntt_omega : int,       # must have order 2^k
                rate_factor : int,     # Rate of Reed Solomon Code
                folding_factor: int,    # folding factor of FRI 
                ood_count: int = 0, # Number of OOD Random samples
                ):
        self.ntt_omega = ntt_omega
        self.rate_factor = rate_factor
        self.folding_factor = folding_factor
        self.ood_count = ood_count

    def commit(self, input_poly : Polynomial):
        self.input_poly = input_poly
        self.input_oracle = FRIOPP(self.input_poly, 
                                   self.ntt_omega, 
                                   self.rate_factor, 
                                   self.folding_factor, 
                                   self.ood_count)
        return self.input_oracle

    def open(self, evaluation_point):
        evaluated_value = self.input_poly(evaluation_point)
        quot = (self.input_poly - evaluated_value) // (self.input_poly.variables()[0] - evaluation_point)
        quot_oracle = FRIOPP(quot, 
                             self.ntt_omega, 
                             self.rate_factor, 
                             self.folding_factor, 
                             self.ood_count)
        return (evaluated_value, quot_oracle)
    
    
class FRIPCS_Verifier:
    def __init__(self, poly_degree, query_count = 10):
        self.poly_degree = poly_degree
        self.query_count = query_count
        pass

    def verify_proof(self, 
                     original_commit : FRIOPP, 
                     quot_commit : FRIOPP, 
                     evaluation_point : FiniteField,
                     expected_value : FiniteField):
        
        if original_commit.verify_proximity(self.poly_degree, self.query_count) == False:
            return False
        
        if quot_commit.verify_proximity(self.poly_degree - 1, self.query_count) == False:
            return False
        
        # TODO: Check that RS data rates are compatible

        original = original_commit.proof_oracle()
        quot = quot_commit.proof_oracle()
        eval_points = original.evaluation_points()
        
        if eval_points != quot.evaluation_points():
            # Reed Solomon evaluation domains are incompatible!
            return False
        
        rs_orignal = original.gen_proof()
        rs_quot = quot.gen_proof()
        votes = 0

        for _ in range(self.query_count):
            ndx = int(random()*len(rs_orignal))
            reconstructed = expected_value + (rs_quot[ndx] * (eval_points[ndx] - evaluation_point))
            if reconstructed == rs_orignal[ndx]:
                votes += 1

        # Overwhelming majority might be too weak!
        if votes > (2*self.query_count) // 3:
            return True
        else:
            return False


if __name__ == '__main__':
    from proth_primes import proth_in_range

    (p, cofactor, twodicity) = proth_in_range(15, 15, 27,27)
    Fq = GF(p)
    
    PolyRing = PolynomialRing(Fq, "X")
    omega = Fq.multiplicative_generator()

    def run_test_friopp(code_dimension=2048, rate_factor=4, folding_factor=4, ood_count = 5):
        ntt_omega = omega**(cofactor*2**(twodicity - log(code_dimension, 2)))
        poly_degree =  code_dimension//rate_factor - int(random()*(code_dimension//10))
        input = PolyRing.random_element(poly_degree - 1)

        iopp = FRIOPP(input_polynomial=input, 
                      ntt_omega=ntt_omega, 
                      rate_factor=rate_factor, 
                      folding_factor=folding_factor, 
                      ood_count=ood_count)

        assert iopp.verify_proximity(poly_degree), "FRI IOPP varification should work"
        assert not iopp.verify_proximity(poly_degree // folding_factor - 1), "FRI IOPP varification should fail if the max degree is 1/folding factor away"


    def run_test_fri_round(code_dimension=2048, rate_factor=4, folding_factor=4, ood_count = 5):
        ntt_omega = omega**(cofactor*2**(twodicity - log(code_dimension, 2)))
        poly_degree =  code_dimension//rate_factor
        input = PolyRing.random_element(poly_degree-1)

        first_oracle = FRIRound(input, ntt_omega, rate_factor, 2)
        folding_randomness = Fq.random_element()
        ood_randomness = [Fq.random_element() for _ in range(ood_count)]
        (second_oracle, ood_response) = first_oracle.fold(folding_randomness, ood_randomness)
        assert FRIRound.consistancy_cross_check(second_oracle, first_oracle, folding_challenge=folding_randomness, queries=5, ood_response=ood_response)

    def run_test_pcs(code_dimension=2048, rate_factor=4, folding_factor=4, ood_count = 5):
        ntt_omega = omega**(cofactor*2**(twodicity - log(code_dimension, 2)))
        poly_degree =  code_dimension//rate_factor - int(random()*(code_dimension//10))
        input_poly = PolyRing.random_element(poly_degree - 1)
        evaluation_point = PolyRing.base_ring().random_element()
        
        prover = FRIPCS_Prover(ntt_omega, rate_factor, folding_factor, ood_count)
        commitment = prover.commit(input_poly=input_poly)
        (expected_value, proof) = prover.open(evaluation_point)
        
        verifier = FRIPCS_Verifier(poly_degree)

        assert verifier.verify_proof(commitment, proof, evaluation_point, expected_value), \
                "A valid opening should succeed, but it didn't"

        assert not verifier.verify_proof(commitment, proof, evaluation_point + 1, expected_value), \
                "An invalid opening of evaluation point should not succeed, but it did"
        
        assert not verifier.verify_proof(commitment, proof, evaluation_point, expected_value + 1), \
                "An invalid opening of evaluation value shoud not succeed, but it did"

    run_test_fri_round()
    run_test_friopp()
    run_test_pcs()
    