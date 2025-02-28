import os
import sys
src_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, src_dir)

from sage.rings.polynomial.all import PolynomialRing, Polynomial
from sage.arith.misc import is_power_of_two
from sage.rings.finite_rings.all import GF, FiniteField
from sage.misc.functional import log
from sage.misc.misc_c import prod
from sage.rings.integer import Integer
from chat_gpt_generated import to_subscript
from sage.coding.grs_code import ReedSolomonCode
from sage.matrix.all import *
from sage.modules.all import vector;
from sage.misc.prandom import random
from typing import *

def eq_list(poly_vars, eq_values):
    if len(poly_vars) != len(eq_values):
        raise ValueError(f"The number of variables in the base ring does not match eq_values")

    one_term = lambda x_var, r_val : (x_var*r_val  + (1-x_var)*(1-r_val))

    result = poly_vars[0].parent()(1)

    for (x_var, r_val) in zip(poly_vars, eq_values):
        result *= one_term(x_var, r_val)

    return result

def eq_polyomial(poly_ring, eq_values):
    Fq = poly_ring.base_ring()
    poly_vars = poly_ring.gens()
    return eq_list(poly_vars, eq_values)

def monomial_basis(poly_ring):
    poly_vars = list(poly_ring.gens())
    basis = list()
    for i in range(2**len(poly_vars)):
        b = Integer(i).bits()
        this_round = prod([x**b for (x,b) in zip(poly_vars, b)])
        basis.append(this_round)
    return basis

def random_multilinear_poly(poly_ring):
    basis = monomial_basis(poly_ring)
    result = poly_ring(0)

    for b in basis:
        c = poly_ring.base_ring().random_element()
        result = result + c*b

    return result

def eq_weight_polynomial(WeightRing, evaluation_point):
    base_poly = WeightRing.base_ring()
    ep = eq_polyomial(base_poly, evaluation_point)
    z = WeightRing.gen()
    return z* WeightRing(ep)

def gen_mvariate_ring(base_ring, variables_count : int, var_name = "X"):
    variable_names = tuple([f"{var_name}{to_subscript(i)}" for i in range(variables_count)])
    return PolynomialRing(base_ring=base_ring, names = variable_names )

def tensor_map(sumcheck_challenges):
    """
    Given the list of sumcheck challenges, say 
    [a_0, a_1, •••, a_ℓ], it computes the 2^ℓ tensor product 
    _basis_ of (1, a_0)⊗(1, a_1)⊗ ••• ⊗(1, a_ℓ) and stores 
    them in a dictionary of size 2^ℓ. 

    Since there's a bijection between univariate polynomials and multilinear 
    polynomial, given a polynomial written as bilinear form 

            f(x) = <(f_0, f_1, •••, f_{ℓ-1}),  (1, x, x^2, •••, x^{ℓ-1})>

    one can write 

            fold(f, [a_0, a_1, •••, a_ℓ] ) = 
                <(f_0, f_1, •••, f_{ℓ-1}), (1, a_0)⊗(1, a_0)⊗ ••• ⊗(1, a_ℓ)>

    """
    degree_map = dict()

    for i in range(2**len(sumcheck_challenges)):
        bits = Integer(i).bits()
        value = 1
        
        for (j,v) in enumerate(bits):
            if v == 1:
                value *= sumcheck_challenges[j]
        
        degree_map[i] = value

    return degree_map


def fold_virtually(oracle_ndxes : list[int],  # list of indxes in proof oracle 
                  proof_oracle : vector,      # Reed-Solomon code word
                  fold_challenges : list[FiniteField], # fold_factor = 2^|fold_challenge|
                  ntt_omega : FiniteField,    # Generator of Reed-Solomon code word
                ):
    """
    This function computes the folded value of `ndx`-th element from 
    proof oracle. There might be more efficient ways to achieve this 
    that does not involve Vandermonde Matrix, but this is the 
    cleanest algorithm I could think of. Here's how the algorithm 
    works.

    1. First compute the fold_factor ℓ := 2^{len(fold_challenges)}
    2. Compute ℓ-th roots of unity `fold_omega` from `ntt_omega`. 
    2. Given `ndx`, compute other indicies that are ℓ-th root 
        conjugates corresponding to `ndx`.
    3. Given a polynomial f(x), it can be written as 
        f(x) = f_0(x^ℓ) + x•f_1(x^ℓ) + ••• + x^{ℓ}•f_{ℓ-1}(x^ℓ)
       Therefore for all i, (ntt_omega•fold_omega^i) ^ ℓ =  ntt_omega^ℓ.
       This gives us a way to compute f_j(x^ℓ) for all j.

    4. One the values of f_j(ntt_omega^{4•ndx}) if computed for all j,
        uses the bijection between the multilinear polynomal and univariate
        polynomial to compute the fold. See function `tensor_map` for details.

    """

    # Compute the sumcheck tensor and cache it
    schk_tensor = tensor_map(fold_challenges)

    folding_factor = 2**len(fold_challenges)
    order = len(proof_oracle) 

    assert order > folding_factor and order % folding_factor == 0

    fold_omega = ntt_omega**(order // folding_factor)

    assert fold_omega**folding_factor == 1

    Fq = proof_oracle[0].base_ring()
    step = order // folding_factor

    result = list()

    for ndx in oracle_ndxes:
        # Compute the query indicides. 
        query_ndx = [ (ndx + j*step) % order for j in range(folding_factor) ]
        query_resp = vector([proof_oracle[i] for i in query_ndx])
        q_omega = ntt_omega**ndx

        # 
        # Compute the Vandermonte matrix for the fold_factor root 
        # conjugates of q_omega
        # 
        vander = [[(q_omega*(fold_omega**j))**k for k in range(folding_factor)] \
                for j in  range(folding_factor)]
        
        M = Matrix(Fq, vander)
        coefficients = M.inverse()*query_resp

        fold_value = Fq(0)
        for (i, coeff) in enumerate(coefficients):
            fold_value = fold_value + schk_tensor[i]*coeff

        result.append((q_omega**folding_factor, fold_value))

    return result

class WhirRound:

    class FoldData:
        def __init__(self,
                     last_whir_round: Self,
                     whir_round : Self,
                     ood_data: dict[FiniteField, FiniteField] ,
                     shift_qeries : list[FiniteField],
                     ):
            self.last_round = last_whir_round
            self.this_round = whir_round
            self.ood_data = ood_data
            self.shift_queries = shift_qeries


    def __init__(self,
                 input_polynomial : Polynomial,    # Witness multilinear polynomial
                 weight_polynomial : Polynomial,   # Compatible with input Ring
                 ntt_omega : FiniteField,              # must have order 2^k
                 claimed_sum : FiniteField = None,     # Claimed value of sum
                 ntt_order_omega : int = None,         # Multiplicative order of generator
                 hypercube = [0,1]                     # Hypercube to sum over
                ):

        assert weight_polynomial.parent().base_ring() == input_polynomial.parent(), \
                "Weight polynomial should be a polynomial ring over input polynomial"

        self.poly = input_polynomial
        self.weight_poly = weight_polynomial

        self.Fq = input_polynomial.base_ring()
        self.PolyRing = input_polynomial.parent()

        self.polyvars = input_polynomial.variables()
        self.weight_var = weight_polynomial.variables()[0]

        self.omega  = self.Fq(ntt_omega)
        self.multi_order = ntt_order_omega or ntt_omega.multiplicative_order()
        self.dimension = 2**len(self.polyvars)

        if not is_power_of_two(self.multi_order):
            raise ValueError(f"The order of multiplicative generator must be a power of two")

        if self.dimension > self.multi_order // 2:
            raise ValueError(f"The multiplicative order of RS is too small compared to the input variables count")

        self.RS_CODE = ReedSolomonCode(self.Fq, self.multi_order, self.dimension, self.omega)
        self.RS_RING = PolynomialRing(self.Fq, "h")

        self.encoder = self.RS_CODE.encoder("EvaluationPolynomial", polynomial_ring=self.RS_RING)
        self._evaluation_points = None

        self.hypercube = hypercube
        self.sumcheck_challenges = list()
        self.sumcheck_poly = self.weight_poly.subs({ self.weight_var : self.poly })
        self.claimed_sum = claimed_sum or self.do_hypercube_sum(None)

        if claimed_sum and __debug__:
           check_match = self.do_hypercube_sum(None)
           assert check_match == claimed_sum

        temp_var = self.RS_RING.gen()
        univar = WhirRound.to_univariate(self.poly, temp_var)
        self._code_value = self.encoder.encode(univar)

    def weight_coefficient(self):
        return self.weight_poly.coefficient(1)


    def evaluation_points(self):
        if not self._evaluation_points:
            self._evaluation_points = self.RS_CODE.evaluation_points()

        return self._evaluation_points

    def fri_oracle(self):
        assert self._code_value is not None
        return self._code_value

    def folded_poly(self):
        temp_var = self.RS_RING.gen()
        return WhirRound.to_univariate(self.poly, temp_var)

    def ntt_value(self, index):
        if index > self.RS_CODE.length():
            raise ValueError("Invalid index for RS Code")


    @staticmethod
    def eval_as_univarite(multi_variate : Polynomial, value : FiniteField) -> FiniteField:
        from copy import deepcopy

        result = deepcopy(multi_variate)
        variables = result.variables()

        for (i,v) in enumerate(variables):
            subst_value = value**(2**i)
            result = result.subs( { v : subst_value })

        return result

    @staticmethod
    def to_univariate(mvar_poly : Polynomial, univariate_gen : Polynomial) -> FiniteField:
        from copy import deepcopy
        result = deepcopy(mvar_poly).change_ring(univariate_gen.parent())
        variables = result.variables()
        for (ndx,var) in enumerate(variables):
            result = result.subs( {var : univariate_gen**(2**ndx) })
        return univariate_gen.parent()(result)


    def do_hypercube_sum(self, skip_variables = []):
        sc_val = self.sumcheck_poly
        variables = self.sumcheck_poly.variables()
        skip_variables = skip_variables or []

        for xvar in variables:
            if xvar in skip_variables:
                continue

            this_round = 0

            for hval in self.hypercube:
                this_round += sc_val.subs({xvar : hval})

            sc_val = this_round

        return sc_val


    def sumcheck_prover_round(self, sumcheck_challenge=None):
        if sumcheck_challenge is None and len(self.sumcheck_challenges) > 0:
            raise ValueError(f"Only first round of sumcheck is allowed to have None as challenge")

        if len(self.sumcheck_challenges) == len(self.polyvars):
            return self.sumcheck_poly


        if sumcheck_challenge is not None:
            this_var = self.polyvars[len(self.sumcheck_challenges)]
            self.sumcheck_challenges.append(sumcheck_challenge)

            # Update the sumcheck polynomial with new randomness
            self.sumcheck_poly = self.sumcheck_poly.subs({this_var : sumcheck_challenge })

            # Update the polynomial in tandem with sumcheck polynomial
            self.poly = self.poly.subs({this_var : sumcheck_challenge })

            # Update the weigth polynomial so that at the end we only need to add
            # swift combination rounds
            weight_update = self.weight_coefficient().subs( {this_var : sumcheck_challenge })
            self.weight_poly = self.weight_var*weight_update

        skip_var = self.polyvars[len(self.sumcheck_challenges)]

        # Get the sumcheck round polynomial by skipping the first veriable from updated sumcheck polynomial
        result = self.do_hypercube_sum([skip_var])
        interminate = result.variables()[0]
        self.claimed_sum = result.subs({ interminate : 0}) + result.subs({ interminate : 1})

        return result

    def update_weight(self,
                       gamma: FiniteField,
                       ood_sample: FiniteField,
                       shift_query: list[FiniteField],
                       trace : bool = True
                       ):

        folded_poly = self.folded_poly()
        ood_reply = folded_poly(ood_sample)

        weight_eq_vars = self.poly.variables()

        frobenious_char2 = lambda inp : [ inp**(2**i) for i,_ in enumerate(weight_eq_vars) ]
        weight_updt = lambda point : eq_list(weight_eq_vars, frobenious_char2(point) )

        weight = weight_updt(ood_sample)

        if trace:
            print(f"\n    P> Weight update for OOD challenge {ood_sample} => {ood_reply} : {self.weight_var}*({weight})")

        update_sum = gamma*weight_updt(ood_sample)

        for (i,query) in enumerate(shift_query):
            weight = weight_updt(query)
            if trace:
                print(f"    P> Weight update for shift query {query} : {self.weight_var}*({weight})")
            update_sum += weight*gamma**(i+2)

        new_weight = self.weight_poly + self.weight_var * self.weight_var.parent()(update_sum)

        if trace:
            print(f"    P> Updated new weight: {new_weight}")

        h_terms = [ood_reply] + [folded_poly(q) for q in shift_query]
        h_update = sum([ sresp * gamma**(i+1) for (i,sresp) in enumerate(h_terms)])

        if trace:
            print(f"    P> Sumcheck claim combination randomness additional sum : {h_update}")

        return (ood_reply, new_weight, h_update)

    def fold_round(self,
                   gamma : FiniteField,
                   ood_sample : FiniteField,          # OOD randomness
                   shift_queries : list[FiniteField],  # Verifier's shift queries
                   trace = True
                   ) -> FoldData :

        generator = self.omega
        (ood_resp, new_weight, h_update) = self.update_weight(gamma, ood_sample, shift_queries, trace=trace)
        claimed_sum = h_update + self.claimed_sum

        if trace:
            print(f"    P> Updated Sumcheck claim: {claimed_sum}")

        next_whir_round = WhirRound(self.poly,
                                    new_weight,
                                    ntt_omega=generator**2,
                                    claimed_sum=claimed_sum)

        last_whir_round = self

        return WhirRound.FoldData(last_whir_round,
                                  next_whir_round,
                                  { ood_sample : ood_resp},
                                  shift_queries)

class WhirVerifier:

    def __init__(self,
                weight_polynomial : Polynomial,
                ntt_omega : FiniteField,              # must have order 2^k
                claimed_sum : FiniteField,            # Claimed value of sum
                fold_factor : int = 2,                # Determines sumcheck rounds
                shift_query_count : int = 2,          # Number of shift queries to make
                ntt_omega_order : int = None,         # Multiplicative order of generator
                hypercube = [0,1]                     # Hypercube to sum over
    ):
        self.weight_polynomial = weight_polynomial
        self.verifier_omega = ntt_omega
        self.claimed_sum = claimed_sum
        self.hypercube = hypercube
        self.schk_rounds = int(log(fold_factor, 2))
        self.shift_query_count = shift_query_count

        self.Fq = weight_polynomial.base_ring().base_ring()
        self.weight_var = weight_polynomial.variables()[0]

        #
        # Warning: If the order is not given and the multiplicative group is
        # not smooth for what ever reason (not our use case), Sage/Pari
        # falls back to factoring and can take a long time for large primes.
        #
        self.mult_order = ntt_omega_order or ntt_omega.multiplicative_order()
        assert is_power_of_two(self.mult_order) and     \
                self.verifier_omega**self.mult_order == 1 and    \
                self.verifier_omega**(self.mult_order // 2) != 1

        self.schk_challenges = []

    def weight_coefficient(self):
        return self.weight_polynomial.coefficient(1)

    def polyvars(self):
        variables = self.weight_coefficient().variables()
        return variables

    def do_sumcheck(self,
                      prover : WhirRound,
                      print_round_poly : bool = True):
        prev_poly = None
        prev_var = None
        claimed_sum = self.claimed_sum

        if print_round_poly:
                print(f"Current sumcheck claim: {self.claimed_sum}")

        polyvars = self.polyvars()

        for (i,v) in zip(range(self.schk_rounds+1), polyvars):
            if i > 0:
                challenge = self.Fq.random_element()
                claimed_sum = prev_poly.subs({prev_var : challenge})
                self.schk_challenges.append(challenge)
                weight_update = self.weight_coefficient().subs({prev_var : challenge })
                self.weight_polynomial = self.weight_var*weight_update
            else:
                challenge = None

            h_poly = prover.sumcheck_prover_round(challenge)

            if print_round_poly:
                print(f"Round-{i} poly: {h_poly}, challenge: {challenge}")

            hyper_sum = sum( [ h_poly.subs( {v : h} ) for h in self.hypercube] )
            if hyper_sum != claimed_sum:
                return False
            elif print_round_poly:
                print(f"Hypercube sum {hyper_sum} matches claimed sum {claimed_sum}")

            prev_poly = h_poly
            prev_var = v

        self.claimed_sum = claimed_sum

        if print_round_poly:
                print(f"Updated sumcheck claim: {self.claimed_sum}")

    def virtual_shift_response(self,
                               last_round : WhirRound,
                               shift_queries : list[FiniteField], 
                               shift_queries_ndxes : list[int]):
        
        assert len(shift_queries) == len(shift_queries_ndxes)
        schk_challenges = self.schk_challenges[-self.schk_rounds:]
        proof_oracle = last_round.fri_oracle()
        ntt_omega = last_round.omega

        result = fold_virtually(oracle_ndxes=shift_queries_ndxes , 
                                proof_oracle=proof_oracle, 
                                fold_challenges=schk_challenges, 
                                ntt_omega=ntt_omega)

        if __debug__:
            folded_poly = last_round.folded_poly()
            virtual_responses = [(query, folded_poly(query)) for query in shift_queries]

            for (a,b) in zip(virtual_responses, result):
                assert a == b

        return result

    def update_weight(self,
                       gamma: FiniteField,
                       ood_query: dict[FiniteField, FiniteField],
                       shift_query: list[(FiniteField, FiniteField)],
                       trace : bool = True
                       ):
        ood_challenge = list(ood_query.keys())[0]
        ood_reponse = ood_query[ood_challenge]

        weight_eq_vars = self.polyvars()

        frobenious_char2 = lambda inp : [ inp**(2**i) for i,_ in enumerate(weight_eq_vars) ]
        weight_updt = lambda point : eq_list(weight_eq_vars, frobenious_char2(point) )

        weight = weight_updt(ood_challenge)

        if trace:
            print(f"\n    V> Weight update for OOD challenge {ood_challenge} => {ood_reponse} : {self.weight_var}*({weight})")

        update_sum = gamma*weight

        for (i,(query,resp)) in enumerate(shift_query):
            weight = weight_updt(query)
            if trace:
                print(f"    V> Weight update for shift query {query} => {resp} : {self.weight_var}*({weight})")
            update_sum += weight*gamma**(i+2)

        self.weight_polynomial += self.weight_var * self.weight_var.parent()(update_sum)

        if trace:
            print(f"    V> Updated new weight: {self.weight_polynomial}")

        h_terms = [ood_reponse] + [r for (_,r) in shift_query]
        h_update = sum([ sresp * gamma**(i+1) for (i,sresp) in enumerate(h_terms)])

        if trace:
            print(f"    V> Sumcheck claim combination randomness additional sum : {h_update}")

        self.claimed_sum += h_update

        if trace:
            print(f"    V> Updated sumcheck claim: {self.claimed_sum}")

    def fold_check(self, prover: WhirRound, shift_query_count : int, trace=True):
        gamma = self.Fq.random_element()         # This should be sent after OOD response
        ood_challenge = self.Fq.random_element() # TODO: Check it's not in evalualation domain

        fold_factor = 2**self.schk_rounds
        assert prover.multi_order % fold_factor == 0

        shift_omega = prover.omega**fold_factor
        shift_query_ndxes = [int(prover.multi_order*random()) for _ in range(shift_query_count)]

        shift_queries = [shift_omega**i for i in shift_query_ndxes]

        if trace:
            print(f"Current Sumcheck claim: {self.claimed_sum}")
            print(f"OOD challenge: {ood_challenge}")
            print(f"Shift queries: {shift_queries}")
            print(f"Combination randomness 𝛾: {gamma}")

        prover_fold = prover.fold_round(gamma, ood_challenge, shift_queries)

        last_round = prover_fold.last_round
        new_round = prover_fold.this_round
        ood_data = prover_fold.ood_data

        shift_responses = self.virtual_shift_response(last_round, 
                                                      shift_queries, 
                                                      shift_query_ndxes)

        if trace:
            print(f"\nProver OOD response: {next(iter(ood_data.values()))}")
            print(f"Verifier computed shift response: {shift_responses}")

        self.update_weight(gamma, ood_query=ood_data, shift_query=shift_responses, trace=trace)
        return new_round

    def validate_pcs_claim(self, first_round : WhirRound, trace = True):
        folding_factor = 2**self.schk_rounds
        current_round = first_round

        while current_round.RS_CODE.dimension() > folding_factor:
            if trace:
                print("\n----- New Sumcheck Round -----\n")

            if self.do_sumcheck(current_round, trace) is False:
                print("ERROR: Sumcheck claim failed")
                return False

            if trace:
                print("\n----- Next OOD + STIR Round -----\n")
            current_round = self.fold_check(current_round, self.shift_query_count)

        if trace:
            print("\n----- Final Round -----\n")

        last_round_poly = current_round.poly

        if trace:
            print(f"Final Sumcheck claim: {self.claimed_sum}")
            print(f"Final Folded Poly: {last_round_poly}")

        sumcheck_poly = self.weight_polynomial.subs({self.weight_var : last_round_poly })

        expected_sum = sumcheck_poly

        for v in sumcheck_poly.variables():
            this_round = self.Fq(0)
            for h in self.hypercube:
                 this_round += expected_sum.subs( { v : h})
            expected_sum = this_round

        if trace:
            print(f"Final evaluated sum: {expected_sum}. Expected claimed sum: {self.claimed_sum}")

        if expected_sum != self.claimed_sum:
            print(f"PCS claim invalid")
            return False
        else:
            print(f"It's a match! PCS claim is valid.")
            return True


if __name__ == '__main__':
    from proth_primes import proth_in_range

    def test_whir(variables_count = 10, rate_factor=8, fold_factor = 4, shift_query_count = 2):
        (p, cofactor, twodicity) = proth_in_range(15, 15, 27,27)
        Fq = GF(p)


        code_length = rate_factor*(2**variables_count)

        omega = Fq.multiplicative_generator()
        omega = omega**(cofactor*2**(twodicity - log(code_length, 2)))
        mult_order = omega.multiplicative_order()
        mult_order_log = int(log(mult_order, 2))

        MultilinearRing = gen_mvariate_ring(base_ring=Fq, variables_count=variables_count)
        WeightRing = PolynomialRing(MultilinearRing, "Z")
        input_poly = random_multilinear_poly(MultilinearRing)

        evaluation_point = [Fq.random_element() for _ in range(variables_count)]
        weight_poly = eq_weight_polynomial(WeightRing, evaluation_point)
        pcs_claim  = input_poly(evaluation_point)

        print(f"TEST SETUP:")
        print(f"    Finite Field: {Fq} ({cofactor}⋅2^{twodicity} + 1)")
        print(f"    RS Generator: {omega}, multiplicatie order: {mult_order} (2^{mult_order_log})")
        print(f"    Polynomial Variable: {input_poly.variables()}")
        print(f"    PCS Evaluation point: {evaluation_point}")
        print(f"    PCS Evaluation claim: {pcs_claim}")
        print(f"    Input polynomial : {input_poly}")
        print(f"    Weight Polynomial: {weight_poly}\n")

        wr = WhirRound(input_poly, weight_poly, omega, pcs_claim)
        wv = WhirVerifier(weight_poly, omega, pcs_claim, fold_factor, shift_query_count)

        assert wv.validate_pcs_claim(wr)


    test_whir(variables_count=8)
