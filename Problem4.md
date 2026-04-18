Problem 4: Zero-Knowledge Proof of Knowledge and Correct Evaluation of

a Secret Polynomial
4.1 Problem Description
Polynomials play a central role in modern cryptography and form the foundation of many

advanced zero-knowledge proof systems. In this assignment, the prover possesses a secret poly-
nomial and must convince the verifier that they know this polynomial and that it evaluates

correctly at a given point, without revealing the polynomial itself.
Let Gq be a cyclic group of prime order q with public generators g and h, where the discrete
logarithm relation between g and h is unknown. All arithmetic operations are performed modulo
q.
The prover possesses a secret polynomial of degree d defined as:

P(x) = a0 + a1x + a2x

2 + · · · + adx
d

where the coefficients:

a0, a1, . . . , ad ∈ Zq

are known only to the prover.

To commit to the polynomial, the prover generates Pedersen commitments to each coeffi-
cient:

Ci = g
aih
ri
, for i = 0, 1, . . . , d
where each ri ∈ Zq is randomly chosen and kept secret.
The prover must convince the verifier that the committed polynomial evaluates to a claimed
value at a given public point, without revealing the polynomial coefficients.
4.2 Public Inputs
The following information is publicly known to both the prover and the verifier:
• Group parameters (Gq, q, g, h)
• Polynomial degree d
• Polynomial coefficient commitments:

C0, C1, . . . , Cd

• Evaluation point:

z ∈ Zq
• Claimed evaluation value, that is, P(z):
y ∈ Zq

• Number of protocol rounds k
These values will be provided to students as part of the assignment input files.
4.3 Private Inputs
The prover possesses the following secret information:
• Polynomial coefficients:

a0, a1, . . . , ad

• Commitment randomness:

r0, r1, . . . , rd

such that:

Ci = g
aih
ri
, ∀i

and

y =
X
d
i=0
aiz
i
(mod q)

4.4 Goal
The prover must convince the verifier of the following statement:
”I know polynomial coefficients corresponding to commitments C0, C1, . . . , Cd, and the

polynomial evaluates to y at the point z.”

while ensuring that:
• The verifier learns no information about the polynomial coefficients.
• The verifier cannot reconstruct the polynomial.
• A prover who does not know valid polynomial coefficients cannot convince the verifier,
except with negligible probability.
4.5 Protocol Requirements
Students must implement the following components:
1. Commitment Generation
Implement the Pedersen commitment scheme and generate commitments to polynomial
coefficients.
2. Interactive Zero-Knowledge Protocol
Implement a multi-round interactive zero-knowledge protocol that allows the prover to
demonstrate knowledge of polynomial coefficients consistent with the commitments and
evaluation.
3. Non-Interactive Version
Implement a non-interactive version of the protocol using the Fiat–Shamir transform,
where verifier challenges are generated using a cryptographic hash function.
4. Prover Program
The prover program must take as input:
• Polynomial coefficients
• Commitment randomness
• Evaluation point z
• Group parameters
and must output:
• Polynomial commitments
• Claimed evaluation value y
• Proof transcript
5. Verifier Program
The verifier program must take as input:
• Polynomial commitments
• Evaluation point z
• Claimed evaluation value y
• Proof transcript
and must output:
• ACCEPT if the proof is valid
• REJECT otherwise
4.6 Input and Output Specifications
Students will be provided with:
• Group parameters (Gq, q, g, h)
• Polynomial degree d
• Evaluation point z
• Protocol configuration parameters
Students must implement both prover and verifier programs.
4.7 Security Requirements
The implemented protocol must satisfy:
• Completeness: An honest prover can convince the verifier.
• Soundness: A dishonest prover cannot convince the verifier of an incorrect evaluation.
• Zero-Knowledge: The verifier learns no information about the polynomial coefficients.
4.8 Implementation Constraints
Students must:
• Implement all commitment schemes and proof protocols from scratch.
• Implement both interactive and non-interactive versions.
• Use only standard hash functions (e.g., SHA-256).
• Not use any external cryptographic protocol or zero-knowledge proof libraries.
