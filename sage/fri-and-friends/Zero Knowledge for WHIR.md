# Zero Knowledge for WHIR

### Zero-Knowledge WHIR as a PCS

The following scheme describes a Zero-Knowledge variant of WHIR as a PCS. The original ideas came from other people. The scheme uses a single run of non-ZK WHIR as a subprotocol. The scheme is zero knowledge in the bounded query model.

Given a witness polynomial  $f(x_1,\cdots, x_\mu)$, the protocol works as follows:

1. Prover ($\mathsf{P}$) masks $f$ by adding a new variable $y$ to create a new randomized *multilinear* polynomial
    
    $$
    \hat{f}(x_1,\cdots,x_{\mu},y) := f(x_1,\cdots,x_{\mu}) + y\cdot \mathsf{msk}(x_1, \cdots, x_\mu)
    $$
    
    where $\mathsf{msk}(\vec{x})$ should be random with at least as many non-zero coefficients as the *total* query bound. Furthermore, it must also not evaluate to zero on the NTT evaluation domain. (Looking ahead, the oracle corresponding to $\hat{f}$ will only be queried on NTT evaluation domain and never as part of queries to the Sumcheck protocol.)
    
2. $\mathsf{P}$ additionally samples a random $\mu + 1$-variate *multilinear polynomial* $g(x_1,\cdots,x_\mu, y)$.
3. **Commitment**: $\mathsf{P}$ commits to $f$ by sending two FRI oracles $([[\hat{f}]], [[g]])$, to the verifier $\mathsf{V}$.
4. **Opening**: Verifier sends the evaluation point $\vec{a} := (a_1, \cdots, a_\mu)$ to the prover who opens $f$ by computing the following:
    - Honest Prover computes $F = f(a_1, \cdots, a_\mu) = \hat{f}(a_1, \cdots, a_\mu, 0)$.
    - Honest Prover computes $G = g(a_1, \cdots, a_\mu, 0)$. (Notice $y$ is set to zero.)
    - $\mathsf{P} \longrightarrow \mathsf{V}$: Prover sends the pair $(F, G)$ to the verifier.
5. **Proof Verification**: After receiving $(F, G)$, the protocol starts verification as follows:
    - $\mathsf{V} \longrightarrow \mathsf{P}$: Verifier sends a random challenge $\rho$ to the prover. Verifier expects $\mathsf{P}$ to prove the claim
    
    $$
    
    \rho\cdot F + G = \rho\cdot f(\vec{a}) + g(\vec{a}, 0)
    
    $$
    
    - Prover and Verifier proceed with non-ZK WHIR opening proof of the previous claim as follows:
    - Verifier:
        - Creates the **virtual oracle** $L := \rho \cdot [[\hat{f}]] + [[g]]$ and sets it as the first WHIR FRI oracle.
        - Verifier creates the WHIR weight polynomial $w(z,x_1,\cdots,x_\mu, y) := z\cdot\mathsf{eq}(\vec{x},y;\; \vec{a},0)$.
        - Verifier runs the standard WHIR Sumcheck rounds receiving new folded FRI oracles as usual. If the prover is honest, the folded FRI oracles will consist of the
        folding of the polynomial
            
            $$
            
            h(\vec{x}, y) := \rho\cdot \hat{f}(x_1,\cdots,x_\mu, y) + g(x_1,\cdots,x_\mu, y)
            
            $$
            
            And an honest prover's Sumcheck rounds will prove the claim:
            
            $$
            
            \rho\cdot F + G = \rho\cdot \hat{f}(\vec{a},0) + g(\vec{a},0) = \sum_{\vec{x} \in \{0,1\}^{\mu+1}}  \left [\rho\cdot\hat{f}(\vec{x}) + g(\vec{x}) \right ]\mathsf{eq}(\vec{x};\; \vec{a}, 0)
            
            $$
            
            Notice that since $f(\vec{a}) = \hat{f}(\vec{a}, 0)$, the Sumcheck opening proof is indeed a proof of evaluation of $f$ and is therefore binding, in spite of the mask!
            
        - **OOD Queries**: The verifier should make its out-of-domain (OOD) queries as usual.
        - **Shift Queries**: At the end of the first Sumcheck round and on receiving the first *folded* oracle corresponding to $h(\vec{x},y)$, the Verifier should compute it's shift-query response using the virtual oracle $L$. For subsequent rounds, the protocol should follow normal WHIR operations.
        - **Termination Check**: The verifier should do termination check as normal WHIR terminal check, i.e., locally compute the Sumcheck over final $w(z,\vec{x},y)$, with $z$ replaced by the last round of FRI oracle $h(\vec{r},y)$ now sent in clear. Verifier should also check that the final FRI oracle is not a constant, i.e., it must have a non-zero $y$-coefficient. (Degree of $y$ should also be one.)
            
            Note that at the $\mu$-th Sumcheck round, an honest prover would have sent
            
            $$
            
            h(\vec{r}, y)\cdot \mathsf{eq}(\vec{r}, y; \vec{a},0) =  (\rho\cdot[f(\vec{r}) + y\cdot \mathsf{msk}(\vec{r})] + g(\vec{r},y) )\cdot \mathsf{eq}(\vec{r}, y; \vec{a},0)
            
            $$
            
            and the corresponding FRI oracle, sent in clear to the Verifier will be
            
            $$
            
            \rho\cdot[f(\vec{r}) + y\cdot \mathsf{msk}(\vec{r})] + g(\vec{r},y)
            
            $$
            
            where $\vec{r}$ is the randomness sent during Sumcheck. Since the verifier had set $\vec{w}(z,\vec{x},y) = z\cdot\mathsf{eq}(\vec{x},y;\; \vec{a},0)$ at the start of the protocol, the result of locally computing
            
            $$
            
            \sum_{y\in\{0,1\}} h(\vec{r},y)\cdot\mathsf{eq}(\vec{r}, y; \vec{a},0)) = h(\vec{r}, 0) = \rho\cdot f(\vec{r})  + g(\vec{r},0)
            
            $$
            
    - Honest Prover
        - On receiving verifier's challenge $\rho$, the prover starts WHIR PCS evaluation proof for $(\vec{a}, 0)$ on the polynomial $h(\vec{x}, y) = \rho\cdot \hat{f}(x_1,\cdots,x_\mu, y) + g(x_1,\cdots,x_\mu, y)$. However, unlike a standard proof, the Prover should not compute the first proof oracle.
        - **OOD Queries**: For an out-of-domain (OOD) query $q_o$, the prover should respond with the evaluation of $h\left(\textsf{pow2}(q_o), q_o^{2^\mu}\right )$ (i.e., without setting y to zero) to the verifier. Notice that out-of-domain queries are meant for $h(\vec{x})$, which by construction is blinded by $g$, and therefore doesn't leak information about $f$.

### Zero-Knowledge WHIR for $\Sigma$-IOP

The following Zero-Knowledge variant of WHIR is applicable to $\Sigma$-IOP.

Given:

- A private *multilinear* witness polynomial $f(x_1,\cdots,x_\mu)$
- A public WHIR weight polynomial $w$ of the form $w(z,x_1,\cdots,x_\mu) = z\cdot W(x_1,\cdots,x_\mu)$, and
- A $\Sigma$-IOP claim $F = \sum_{\vec{b}\in \{0,1\}^\mu} f(\vec{b})\cdot W(\vec{b})$

The following protocol proves the above claim in zero-knowledge using non-ZK WHIR as a subprotocol. The protocol proceeds as follows:

1. As in the case of PCS, the Prover ($\mathsf{P}$) masks $f$ by adding a new variable $y$ to create a new randomized multilinear polynomial with same requirements as in the case of PCS:

$$
\hat{f}(x_1,\cdots,x_{\mu},y) := f(x_1,\cdots,x_{\mu}) + y\cdot \mathsf{msk}(x_1, \cdots, x_\mu)
$$

1. $\mathsf{P}$ additionally samples a random $\mu + 1$-variate multilinear polynomial $g(x_1,\cdots,x_\mu, y)$.
2. **Commitment**: $\mathsf{P}$ commits to the claim $F = \sum_{\vec{b}\in \{0,1\}^\mu} f(\vec{b})\cdot W(\vec{b})$ as follows:
    - Prover computes a new weight polynomial
    
    $$
    \hat{w}(z,\vec{x}, y) := z\cdot W(\vec{x})\cdot \textsf{eq}(0,y) = z\cdot  (1-y) \cdot W(\vec{x})
    $$
    
    - Prover computes
        
        $$
        G =  \sum_{\vec{b}\in \{0,1\}^{\mu}} g(\vec{b}, 0)\cdot W(\vec{b})
        $$
        
    - Prover computes the FRI oracles $[[\hat{f}]]$ and $[[g]]$
    - $\mathsf{P} \longrightarrow \mathsf{V}$: Prover sends the quadruple $(F, G, [[\hat{f}]], [[g]])$ to the verifier.
3. **Proof Verification**: After receiving $(F,G, [[\hat{f}]], [[g]])$, the protocol starts verification as follows:
    - $\mathsf{V} \longrightarrow \mathsf{P}$: Verifier sends a random challenge $\rho$ to the prover. Verifier expects $\mathsf{P}$ to prove the claim
        
        $$
        \rho\cdot F + G = \sum_{\vec{b}\in \{0,1\}^\mu} [\rho\cdot f(\vec{b}) + g(\vec{b},0)]\cdot W(\vec{b})
        $$
        
    - Prover and Verifier proceed with non-ZK WHIR opening proof of the previous claim as follows:
    - Verifier:
        - Creates the **virtual oracle** $L := \rho \cdot [[\hat{f}]] + [[g]]$ and sets it as the first WHIR FRI oracle.
        - Verifier creates a new WHIR weight polynomial
            
            $$
            \hat{w}(z,x_1,\cdots,x_\mu, y) := z\cdot (1-y) \cdot W(x_1,\cdots, x_\mu)
            $$
            
        
        and runs non-ZK WHIR as usual, expecting $\mathsf{P}$ to prove the $\Sigma$-IOP claim on $\rho\cdot F + G$. 
        
        - Rest of the protocol should follow the same algorithm for OOD-queries, Shift-queries, and Termination checks as in the case of WHIR PCS.
    - Honest Prover should use the weight polynomial computed during the commitment phase, and follow rest of the protocol as in case of WHIR PCS.