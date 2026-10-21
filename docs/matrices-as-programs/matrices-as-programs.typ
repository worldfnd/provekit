#import "@preview/lemmify:0.1.8": *
#import "@preview/finite:0.5.1": automaton

#set heading(numbering: "1.1.")
#set cite(style: "alphanumeric")
#set math.equation(supplement: none, numbering: numbering.with("(1)"))

#let (
  theorem, lemma, corollary,
  remark, proposition, example,
  proof, rules: thm-rules
) = default-theorems("thm-group", lang: "en")
#let (
  definition, algorithm, protocol,
  rules: add-rules
) = new-theorems("thm-group", (
  "definition":[Definition],
  "algorithm":[Algorithm],
  "protocol":[Protocol],
))
#show: thm-rules
#show: add-rules


// Upper case (e.g. matrices) defaults to upright instead of italic
#show math.equation: eq => {
  show regex("[A-Z]"): math.upright
  eq
}

#let eq = math.op("eq")


= Introduction

In Spartan @Set19 and derived protocols such as GR1CS @DMS24 when instantiated using inner-product commitment schemes like WHIR @ACFY24, we can omit the lincheck step and instead rely on the identity

$
  ⟨M 𝒘, eq_𝜸⟩ = ⟨𝒘, M^⊤ eq_𝜸⟩
$ <eq-opening>

to convert the lincheck to an inner product opening. As with lincheck, this reduces to a public claim

$
  ⟨eq_𝜹, M^⊤ eq_𝜸⟩
$ <eq-claim>

that the verifier can check directly. The resulting protocol has succinct proof sizes and can be made zero-knowledge, but does not necessarily have a succinct verifier as @eq-claim can require work proportional in the size of $M$.

We will show that when the witness $𝒘$ and constraint vectors $M_i 𝒘$ can be produced by a succinctly described program (a _witness generator_), then we can efficiently compute the opening covector @eq-opening and verifier claim @eq-claim.

This makes the verifier succinct, but it is still circuit dependent. For recursion it is desirable to have a uniform verifier that only depends on some size bounds of the circuit. For this we will present a simple VM solution similar to SPARK @Set19 and V-SPARK @SR25.

= Succinct Vectors

Certain $𝐪$ allow succinct evaluation of $tilde(q)(𝛄) ≔ ⟨eq_𝛄, 𝐪⟩_(𝔽)$, but this doesn't immediately mean that the packed query $Q(𝐪)$ can be succinctly evaluated as $⟨eq_(𝛄'), Q(𝐪)⟩_(𝔼)$. We will show that for a large class of succinct $𝐪$ this is the case. First we define what succinctness means:

A vector $𝐪 ∈ 𝔽^n$ for $n = 2^k$ is called _succinct_ if it admits a tensor decomposition

$
  mat(delim: "[", m_10; m_11) ⊗ mat(delim: "[", m_20; m_21) ⊗ ⋯ ⊗ mat(delim: "[", m_(k 0); m_(k 1))
$

where typically $m_(i j) ∈ 𝔽$. The multilinear extension of $𝐪$, viewed as a function on ${0, 1 }^k$, then becomes

$
  tilde(q)(𝐫) = product_(i ∈ [k]) ((1 - r_i) m_(i 0) + r_i m_(i 1)) .
$

which can be evaluated in $O(k)$ field operations.

More generally, the coefficients $m_(i j)$ need not themselves be field elements. It suffices that they belong to an associative $𝔽$-algebra in which every complete product $m_(1 b_1) m_(2 b_1) ⋯ m_(k b_k)$ evaluates to an element of $𝔽$. Consequently, every vector entry and every value of
the multilinear extension remains an element of $𝔽$. As the $m_(i j)$ no longer need to be commutative we must therefore also fix a permutation of the variables $𝐫$.

Since every finite-dimensional associative algebra admits a matrix representation, we may, without loss of generality, assume that the objects $m_(i j)$ are matrices. In fact, it suffices to take $m_(i j) ∈ 𝔽^(w_i × w_(i + 1))$ with boundary dimensions $w_1 = w_(k+1) = 1$. We call $max w_i$ the _width_ of the representation, which is known as a _matrix branching program_ (MBP). Since every vector can be represented with unbounded width, we require a succinct vector to have width sublinear in the length of the vector.

The canonical example of a succinct vector is the multilinear evaluation vector $eq_𝐫$ itself, obtained by taking $m_(i 0) = 1 - r_i$ and $m_(i 1) = r_i$. Another classical example is the geometric progression $(1, x, x^2,… )$ obtained by taking $m_(i 0) = 1$ and $m_(i 1) = x^(2^i)$. An illustrative non-scalar example is the counting vector $(0, 1, 2,… )$ represented by

$
  m_(1 b) & = mat(delim: "[", 2, b) &
  m_(i b) & = mat(delim: "[", 2, b; 0, 1) &
  m_(k b) & = mat(delim: "[", b; 1).
$

== Finding Minimal MBPs

See @Kie20 for the minimization algorithm:

#algorithm(name: "MBP Width Minimization")[\
  _Input_: Cores $M_(i b) ∈ 𝔽^(w_i × w_(i+1))$
  for $i ∈ [k]$, $b ∈ {0,1}$, with
  $w_1 = w_k = 1$.\
  _Output_: Equivalent cores with minimum internal widths
  under the same variable ordering.\
  _Time bound_: $O(k w^3)$ field operations,
  where $w = max_i w_i$ for the input.\
  _Auxiliary space bound_: $O(w^2)$.

  All rank factorizations below are exact over $𝔽$:
  $A = L R$ has inner dimension $op("rank")(A)$.

  + For $i = 1, …, k - 1$:
    - Compute a rank factorization
      $
        mat(delim: "[", M_(i 0); M_(i 1)) = L R .
      $
    - Split $L$ into two equal row blocks:
      $
        L = mat(delim: "[", L_0; L_1).
      $
    - For each $b ∈ {0,1}$, update
      $
        M_(i b) &← L_b, &quad
        M_(i+1, b) &← R M_(i+1, b).
      $

  + For $i = k, …, 2$:
    - Compute a rank factorization
      $
        mat(delim: "[", M_(i 0), M_(i 1)) = L R .
      $
    - Split $R$ into two equal column blocks:
      $
        R = mat(delim: "[", R_0, R_1).
      $
    - For each $b ∈ {0,1}$, update
      $
        M_(i b) &← R_b, &quad
        M_(i-1, b) &← M_(i-1, b) L.
      $

  + Return the modified cores.
] <alg-mbp-min>


#algorithm(name: "Minimal width MBP extraction")[\
  _Input_: A vector $𝒗 ∈ 𝔽^(2^k)$. \
  _Output_: A width-minimal MBP for $𝒗$.\

  + Represent $𝒗$ as a set of unique non-zero values $v_i$ and the disjoint sets of occurrence indices $𝒮_i$ such that
    $
     (𝒗)_j = cases(
        v_i  &quad j ∈ 𝒮_i, 
        0    &quad "Otherwise".
      )
    $
  + Fix a variable order.
  + Construct the minimal multi-rooted CQBDD for the sets $𝒮_i$ using @alg-robdd.
  + Assign weights $v_i$ to the respective roots.
  + Convert the weighted CQBDD to an MBP.
  + Rank-minimize the MBP using @alg-mbp-min.
]

This algorithm works well for sparse vectors as at step 1 we ignore all the non-zero entries.


== Succinct Inner Products

Given two succinct vectors of equal dimension and variable order, we can compute their inner product in time sub-linear in their length:

#algorithm(name: "Succinct Inner Products")[\
  _Input_: $𝒖, 𝒗$ succinct vectors with common variable ordering, $k$ variables, width bounds $w_u, w_v$ and entries $U_(i j), V_(i j)$.\
  _Output_: $⟨𝒖, 𝒗⟩$.\
  _Time bound_: $O(k w_u w_v (w_u + w_v))$.\
  _Auxiliary Space Bound_: $O(w_u w_v)$.
  
  + Initialize $X ← mat(delim: "[", 1)$.
  + For $i = 1, …, k$, update
    $
      X ← U_(i 0)^⊤ X V_(i 0)
        + U_(i 1)^⊤ X V_(i 1) .
    $
  + Return the scalar $X_(1 1)$.
] <alg-ip>

#proof[
  After processing $1, …, i$, the accumulator satisfies
  $
    X = sum_((b_1, …, b_i) ∈ {0,1}^i)
      (U_(1 b_1) ⋯ U_(i b_i))^⊤
      (V_(1 b_1) ⋯ V_(i b_i)) .
  $

  The initialization represents the empty prefix. Splitting the sum according to $b_i ∈ {0,1}$ gives exactly the update rule. At $i = k$, both complete products are scalars, so

  $
    X_(1 1) =
    sum_(𝐛 ∈ {0,1}^k) u_𝐛 v_𝐛 =
    ⟨𝐮, 𝐯⟩ .
  $

  The size of $X$ is bounded by $w_u × w_v$. Computing $U_(i 0)^⊤ X$ costs $O(w_u^2 w_v)$ operations, multiplying the result by $V_(i 0)$ costs $O(w_v^2 w_u)$. This is repeated twice for each value $b$ and then summed, costing $O(w_u w_v)$.
]

= Succinct Index Sets

An index set $𝒮 ⊆ [2^k_1]×[2^k_2]$ is called succinct if its indicator vector $𝟏_𝒮 ∈ {0,1}^(2^(k_1 k_2)) $ is succinct.

#let complemented = (
  mark: (
    start: (symbol: "circle", fill: white, length: .18, width: .18),
    end: (symbol: ">", fill: black),
  ),
)


Consider the sets $𝒮_1 = {(r, c) | r < c}$, $𝒮_1 = {(r, v) | r ≤ c}$ containing $6$ and $10$ nonzero values each. The sets can be represented using a width $3$ automaton, see @fig-automaton.

$
  𝟏_(𝒮_1) &= mat(
    0, 1, 1, 1;
    0, 0, 1, 1;
    0, 0, 0, 1;
    0, 0, 0, 0;
  ) &quad
  𝟏_(𝒮_2) &= mat(
    1, 1, 1, 1;
    0, 1, 1, 1;
    0, 0, 1, 1;
    0, 0, 0, 1;
  )
$


#figure(
  caption: [
    Automaton for two sets $𝒮_1 = {(r, c) | r < c}$, $𝒮_1 = {(r, v) | r ≤ c}$.
  ],
  
  automaton(
    (
      root1: (R: none),
      root2: (S: none),
  
      R: (B: 0, C: 1),
      S: (A: 0, B: 1),
      A: (E: (0, 1)),
      B: (D: 0, E: 1),
      C: (D: (0, 1)),
      D: (F: 0, G: 1),
      E: (G: 0, F: 1),
      F: (T0: 0, T1: 1),
      G: (T: (0, 1)),
  
      T: none,
      T0: none,
      T1: none,
    ),
    initial: none,
    final: ("T",),
    labels: (
      root1: $𝒮_1$, root2: $𝒮_2$,
      T: $1$, T0: none, T1: none,
    ),
    layout: (
      root1: (-2, -1.5), root2: (-2, 1.5),
      R: (0, -1.5), S: (0, 1.5),
      A: (3, 3), B: (3, 0), C: (3, -3),
      D: (6, -1.5), E: (6, 1.5),
      F: (9, -1.5), G: (9, 1.5),
      T: (12, 0), T0: (12, 0), T1: (12, 0),
    ),
    style: (
      state: (label: (fill: black)),
      transition: (curve: 0),
      root1: (stroke: none, fill: none, radius: .35),
      root2: (stroke: none, fill: none, radius: .35),
      // Coincident, invisible aliases of T, for parallel edges.
      T0: (stroke: none, fill: none),
      T1: (stroke: none, fill: none),
  
      root1-R: complemented,
      R-B: complemented,
      B-D: complemented,
      D-F: complemented,
      D-G: (label: (pos: .7)),
      E-F: (label: (pos: .7)),
      F-T0: complemented + (curve: .7),
      F-T1: (curve: -.7),
    ),
  )
) <fig-automaton>


#algorithm(name: "Multi-root CQBDD Extraction")[\
  _Input_: Explicit index sets
  $S_1, …, S_m ⊆ [0, 2^K) × [0, 2^K)$.\
  _Output_: A shared, fully layered OBDD with complemented
  edges and signed root IDs $ρ_1, …, ρ_m$,
  under interleaved LSB order.\
  _Expected time bound_: $O(m + (N + 1) K)$.\
  _Space bound_: $O(N + G + K + m)$,
  where $N = sum_(j=1)^m |S_j|$ and $G$ is the number
  of nonterminal output nodes.

  + Fix the variable order
    $
      (z_1, …, z_(2K))
      = (r_0, c_0, r_1, c_1, …, r_(K-1), c_(K-1)).
    $

  + Assign every node a positive integer ID.
    A signed reference $a$ represents the function of node
    $|a|$, complemented when $a < 0$.
    Store each nonterminal node as a triple
    $(ε, v_0, v_1)$, where $v_0, v_1$ are positive IDs
    and $ε$ indicates whether the low child is complemented.
    The high child is always uncomplemented.

  + Create terminal node $1$, representing the constant $1$.
    Thus reference $-1$ represents the constant $0$.
    Initialize the constant-chain cache with $C_(2K+1) ← 1$.
    Create empty unique tables $H_ℓ$, allocated on demand.

  + Define $"Make"(ℓ, a_0, a_1)$ for signed references:
    - For $b ∈ {0,1}$, let $ε_b = 1$ if $a_b < 0$,
      and $ε_b = 0$ otherwise.
    - Form the normalized node description
      $
        D ← (ε_0 ⊕ ε_1, |a_0|, |a_1|).
      $
    - Look up $D$ in $H_ℓ$.
      If absent, create a node with description $D$,
      assign it a fresh positive ID, and store it in $H_ℓ$.
      Let $v$ be the resulting node ID.
    - Return $(-1)^(ε_1) v$.
      Retain the node even when $a_0 = a_1$.

  + Define $"One"(ℓ)$, representing the constant $1$
    on all remaining variables:
    - If $C_ℓ$ is cached, return it.
    - Compute $a ← "One"(ℓ+1)$.
    - Set $C_ℓ ← "Make"(ℓ, a, a)$ and return $C_ℓ$.

  + Store each $S_j$ in a mutable array.
    Recursive calls operate on ranges of these arrays.

  + Define $"Build"(ℓ, T)$ recursively:
    - If $T = ∅$, return $-"One"(ℓ)$.
    - If $ℓ = 2K + 1$, return $1$.
    - Partition $T$ in place into ranges
      $
        T_b = {(r,c) ∈ T | z_ℓ(r,c) = b},
        quad b ∈ {0,1}.
      $
    - Compute
      $
        a_0 &← "Build"(ℓ+1, T_0), &quad
        a_1 &← "Build"(ℓ+1, T_1).
      $
    - Return $"Make"(ℓ, a_0, a_1)$.

  + For $j = 1, …, m$, compute
    $ρ_j ← "Build"(1, S_j)$,
    sharing the unique tables and constant-chain cache
    across all roots.

  + Return the shared graph and $(ρ_1, …, ρ_m)$.
] <alg-robdd>

#algorithm(name: "Multi-root ROBDD Extraction")[\
  _Input_: Explicit index sets
  $S_1, …, S_m ⊆ [0, 2^K) × [0, 2^K)$.\
  _Output_: A shared ROBDD graph with roots $ρ_1, …, ρ_m$,
  where $ρ_j$ represents membership in $S_j$,
  under interleaved MSB order.\
  _Expected time bound_: $O(m + N K)$.\
  _Space bound_: $O(N + G + K + m)$,
  where $G$ is the number of nonterminal output nodes.

  + Create terminals $0$ and $1$, and empty unique tables $H_ℓ$.

  + Define $"Build"(ℓ, T)$ recursively:
    - If $T = ∅$, return terminal $0$.
    - If $ℓ = 2K + 1$, return terminal $1$.
    - Partition $T$ into
      $
        T_b &= {(r,c) ∈ T | z_ℓ(r,c) = b} &quad
        "for" &b ∈ {0,1}.
      $
    - Compute
      $
        v_0 &← "Build"(ℓ+1, T_0), &quad
        v_1 &← "Build"(ℓ+1, T_1).
      $
    - Otherwise, look up $(v_0, v_1)$ in $H_ℓ$.
      If absent, create and store a node testing $z_ℓ$
      with children $v_0$ and $v_1$.
      Return that node.

  + For $j = 1, …, m$, compute
    $ρ_j ← "Build"(1, S_j)$,
    retaining the same table $H_ℓ$ throughout.

  + Return the shared graph and $(ρ_1, …, ρ_m)$.
] <alg-robdd>


= Rest of the paper

#let vec = math.op("vec")

Let $vec : 𝔽^(m × n) → 𝔽^(m n)$ be take a matrix to a vector representing the coefficients in row-major order, then the matrix double contraction can be represented as an inner product

$
   𝒖^⊤ M 𝒗 = ⟨vec(M), 𝒖 ⊗ 𝒗⟩ .
$ <eq-claim-ip>

If $𝒖, 𝒗$ are succinct, then so is $𝒖 ⊗ 𝒗$. If $vec(M)$ is also succinct with a variable ordering compatible with $𝒖 ⊗ 𝒗$, then we can use @alg-ip to efficiently compute @eq-claim-ip. We do this abstractly keeping the challenges $𝝆, 𝜸, 𝜹$ as indeterminate. This produces a succinct evaluator for the verifier claim. What remains is showing $vec(M)$ has a succinct representation.

$
"Program description" → "Program MBP" → "Evaluator"
$

= Succinct Vectors from Witness Programs

- Define witness programs

Basic blocks + occurrence sets.

== Representable index sets

We'll introduce multi-rooted @Bry86

#definition(name: "Read-once Binary Decision Diagrams (ROBDD)")[
  #lorem(40)
]

we have an algorithm for finding the optimal multi-rooted ROBDD given sets of index sets.

#algorithm(name: "Minimal ROBDD")[
  #lorem(40)
]


$
"deterministic ordered graph" ⊆ "unambigious ordered graph" ⊆ "matrix branching program"
$

To show the strengths and weaknesses of this approach we'll show that an arbitrary loop can be handled efficiently:

```
prefix
repeat p:
  body
suffix
```

the index set for `body` is 

$
  {n_"prefix" + i · n_"body" | i ∈ [0,p) }
$

and this can be efficiently represented. But a doubly-nested loop already poses difficulty consider

```
repeat p:
  prefix
  repeat q:
    body
```

the index set for `body` is 

The index set for a nested rectangular loop is an affine combination:

$
  {s_0 + s_1 i_1 + s_2 i_2 + ⋯ | i_1 ∈ [0,n_1), i_2 ∈ [0,n_2), … } .
$

Where $s_i ∈ ℕ^2$ are offset and stride in the witness and constraint direction.

For properly nested loops we have 
$
  sum_(i > j) (n_j - 1) s_j < s_i .
$

@Kla08

#theorem[
  Given $p, q ≥ 1$, define index set
  $
    𝒮 = {i q + i + j + 1 | i ∈ [0,p), j ∈ [0, q) }
  $
  and its indicator vector $𝟏_𝒮$. Construct an succinct binary vector $𝒖 ∈ {0, 1}^(2^k)$
  $
   𝒖 &= ⨂_i mat(delim:"[", u_(i 0); u_(i 1)) &
   quad u_(i j) & ∈ {0,1} .
  $
  Then computing the inner product $⟨𝟏_𝒮, 𝒖⟩$ is $\#P$-complete under polynomial-time Turing reductions. In particular, it is polynomial-time equivalent to counting subset sums.
]
#proof[
  Consider a counting subset-sum instance with positive integers $𝒂 = (a_1,…,a_n)$ and target $T$. We must compute
  $
    C = abs({𝒙 ∈ {0, 1}^n | ⟨𝒂, 𝒙⟩ = T}) .
  $
  We may assume $0 ≤ T ≤ A ≔ sum_i a_i$, since otherwise the answer is zero. Choose a power of two $B = 2^b > A$, and set
  $
    H &= sum_(i ∈ [n]) a_i B^(n-1-i),&
    p &= B^n, &
    L &= 1 + B^n H, &
    q &= L - 1
  $
]

== Sufficient padding

Let $d$ be the maximum nesting depth we want to represent succinctly, then set

$
R = 2^(ceil(log_2 d / ))
$

= References

#bibliography("refs.bib", style: "association-for-computing-machinery")
