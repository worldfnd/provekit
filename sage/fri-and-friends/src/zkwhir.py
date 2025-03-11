import os
import sys
src_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, src_dir)

from sage.functions.other import ceil
from sage.misc.functional import log
from sage.rings.integer import Integer
from sage.coding.grs_code import ReedSolomonCode
from whir import *


def bit_decom(i, min_len):
    b = Integer(i).bits()
    pad_len = min_len - len(b)
    if pad_len > 0:
        b.extend([0 for _ in range(pad_len)])

    return b

def uni_to_multi(univar, MVarPoly):
    poly_vars = MVarPoly.gens()
    results_dict = {}

    for (i,b) in enumerate(univar.list()):
        decompose = bit_decom(i, len(poly_vars))
        results_dict[tuple(decompose)] = b

    mpoly = MVarPoly(results_dict)
    return mpoly

def upgrade_ring(input_poly, OutputRing):
    new_dict = {}

    for (k,v) in input_poly.dict().items():
        vv = list(k) + [0]
        new_dict[tuple(vv)] = v

    return OutputRing(new_dict)

#
# WARNING: This way of masking is probably not uniformly random.
# Finding a _multilinear_ polynomial mask such that its evaluation 
# outside the boolean hypercube is uniformly random and zero within
# the boolean hypercube is WIP!!!
# 
def mask_polynomial(input_poly, query_threshold, folding_factor):
    mask_degree =  query_threshold*folding_factor
    input_degree = 2**len(input_poly.variables())
    nzc = 2**ceil(log(input_degree + mask_degree, 2)) - input_degree - 1

    MaskPolyRing = PolynomialRing(input_poly.base_ring(), "T")

    # create a random univariate polynomial of degree d-1
    random_poly = MaskPolyRing.random_element(nzc)

    multivars = input_poly.parent().gens()

    FinalPolyRing = gen_mvariate_ring(input_poly.base_ring(), len(multivars) + 1)
    last_var = FinalPolyRing.gens()[-1]
    random_multivar = uni_to_multi(random_poly, FinalPolyRing)

    input_poly = upgrade_ring(input_poly, FinalPolyRing)

    output_poly = input_poly + random_multivar*last_var # Multiplied to the last variable
    
    if __debug__:
        BR = output_poly.base_ring()
        # print(f"Input polynomial: {input_poly}\n")
        # print(f"Masked polynomial: {output_poly}\n")
        # print(f"Delta: {output_poly - input_poly}\n")

        random_eq = eq_polynomial(FinalPolyRing, [BR.random_element() for _ in range(len(FinalPolyRing.gens()) -1)] + [0])
        old_sum = compute_hypercube_sum(input_poly * random_eq)
        new_sum = compute_hypercube_sum(output_poly * random_eq)
        assert old_sum == new_sum
        assert input_poly == output_poly.subs( { last_var : 0 })

    return output_poly

class CommitmentData:
    def __init__(self, 
                 committed_poly : ReedSolomonCode, 
                 scheck_mask : ReedSolomonCode,
                 PolyRing : PolynomialRing):
        
        self.PolyRing = PolyRing
        self.func = committed_poly
        self.scheck_mask = scheck_mask # The mask during the sumcheck protocol

        self.pcs_evaluation = None      # Value of evaluation
        self.scheck_evaluation = None   # Value of evaluation of schek randomness
        self.whir_first_round = None    # First FRI WHIR oracle


class ZKWhirPCS:

    def __init__(self, 
                 input_polynomial, 
                 ntt_omega, 
                 query_threshold = 3,
                 folding_factor = 4,
                 ntt_order_omega = None):
        
        self.input_poly = input_polynomial
        self.Fq = input_polynomial.base_ring()
        # Mask to hide information about the input polynomial.
        self.masked_poly = mask_polynomial(self.input_poly, 
                                           query_threshold, 
                                           folding_factor)   
        print(f"    Masked input: {self.masked_poly}\n")
        self.MaskingRing = self.masked_poly.parent()
        self.ProverWeightRing = PolynomialRing(self.masked_poly.parent(), "Z")
        self.RS_RING = PolynomialRing(self.Fq, "h")
        self.folding_factor = folding_factor

        # Mask used during the sumcheck round 
        self.scheck_mask = random_multilinear_poly(self.MaskingRing)
        
        print(f"    Sumcheck Mask Polynomial: {self.masked_poly}")

        self.omega  = self.Fq(ntt_omega)
        self.multi_order = ntt_order_omega or ntt_omega.multiplicative_order()
        self.dimension = 2**len(self.MaskingRing.gens())

    
    def commit(self) -> CommitmentData:
        rs_code = ReedSolomonCode(self.Fq, self.multi_order, self.dimension, self.omega)
        encoder = rs_code.encoder("EvaluationPolynomial", polynomial_ring=self.RS_RING)
        fn_masked = WhirRound.to_univariate(self.masked_poly, self.RS_RING.gen())
        fn_scheck = WhirRound.to_univariate(self.scheck_mask, self.RS_RING.gen())

        masked_oracle = encoder.encode(fn_masked)
        scheck_oracle = encoder.encode(fn_scheck)

        return CommitmentData(masked_oracle, scheck_oracle, self.input_poly.parent())

    def open(self, 
             evaluation_point : list[FiniteField], 
             verifier_challenge : FiniteField, 
             commitment : CommitmentData):
        
        commitment.pcs_evaluation = self.input_poly(evaluation_point)

        # 
        # Set the last variable in the the weight polynomial to zero. This undoes 
        # the effect of masking. Note that the challenger does not get to select 
        # this last co-ordinate.
        # 

        extended_eval_point = evaluation_point + [0]

        assert self.masked_poly(extended_eval_point) == commitment.pcs_evaluation
        commitment.scheck_evaluation = self.scheck_mask(extended_eval_point)

        #
        # Sumcheck weight polynomial has last co-ordinate set to zero.
        # 
        weight_poly = eq_weight_polynomial(self.ProverWeightRing, extended_eval_point)

        #
        # First round of oracle happens over the virtual oracle
        virtual_oracle = verifier_challenge*commitment.func + commitment.scheck_mask

        # 
        # Virtual sumcheck polynomial is 
        #   verifier_challenge * masked_polynomial + sumcheck_polynomial
        # 

        sumcheck_poly = verifier_challenge*self.masked_poly + self.scheck_mask

        claimed_sum = verifier_challenge*commitment.pcs_evaluation + \
                commitment.scheck_evaluation
        
        # print(f"P: Prover's claimed sum: {claimed_sum}")

        assert sumcheck_poly(extended_eval_point) == claimed_sum
        
        first_round = WhirRound(sumcheck_poly, weight_poly, self.omega, claimed_sum)

        assert first_round.fri_oracle() == virtual_oracle, "The virtual oracle doesn't match with expected codeword of sumcheck polynomial"

        # first_round.set_fri_oracle(virtual_oracle)
        commitment.whir_first_round = first_round

        return commitment
    
    def verify(self, evaluation_point, verifier_challenge, commitment_data):
        claimed_value = commitment_data.pcs_evaluation
        random_sum  = commitment_data.scheck_evaluation
        whir_prover = commitment_data.whir_first_round

        combined_sum = verifier_challenge*claimed_value + random_sum

        # The verifier weight polynomial is just as before
        weight_poly = eq_weight_polynomial(self.ProverWeightRing, evaluation_point + [0])

        verifier = WhirVerifier(weight_poly, 
                                self.omega, 
                                combined_sum, 
                                self.folding_factor)
        
        return verifier.validate_pcs_claim(whir_prover)


if __name__ == '__main__':
    from proth_primes import proth_in_range

    def test_zk_whir(variables_count = 10, rate_factor=8, fold_factor = 4, shift_query_count = 10, trace=True):
        (p, cofactor, twodicity) = proth_in_range(15, 15, 27,27)
        Fq = GF(p)

        code_length = rate_factor*(2**(variables_count+1)) # Accommodate for masking

        omega = Fq.multiplicative_generator()
        omega = omega**(cofactor*2**(twodicity - log(code_length, 2)))

        MultilinearRing = gen_mvariate_ring(base_ring=Fq, variables_count=variables_count)

        input_poly =  random_multilinear_poly(MultilinearRing)
        evaluation_point = [Fq.random_element() for _ in range(variables_count)] 
        verifier_challenge = Fq.random_element()

        print(f"Test setup:")
        print(f"    Input polynomial: {input_poly}")
        print(f"    Evaluation point: {evaluation_point}")
        print(f"    Verifier's Sigma ZK Challenge: {verifier_challenge}")

        zkWHIR = ZKWhirPCS(input_poly, ntt_omega=omega)
        commitment = zkWHIR.commit()
        commitment = zkWHIR.open(evaluation_point, verifier_challenge, commitment)
        zkWHIR.verify(evaluation_point, verifier_challenge, commitment)

    test_zk_whir(variables_count=10, fold_factor = 4)

