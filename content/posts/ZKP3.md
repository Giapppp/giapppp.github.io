---
author: "Giap"
title: "Zero Knowledge Proof: Interactive Proofs (Not done)"
date: "2024-03-07"
tags: [
    "Learning", "ZKP"
]
---

In this post, we will dig deeper about Interactive Proofs, which was described in [my previous post](https://giapppp.github.io/posts/zkp1/). 

## Resources

[ZKP MOOC Lecture 4: Interactive Proofs](https://www.youtube.com/watch?v=4018OYyoAf8)

[Computational Complexity: A Modern Approach, Chapter 8](https://theory.cs.princeton.edu/complexity/book.pdf)

[Cryptonote-Ehrant](https://crypto-notes-erhant.vercel.app/zklearning/snarks-via-ips.html#relation-to-interactive-proofs)

## Detail

### Interactive Proofs: Motivation & Model

In an interactive proof, there are two parties: a prover $P$ and a verifier $V$

- $P$ solves problem, then tell $V$ the answer

- Then they start a conversation, and the goal of $P$ is convince $V$ the answer is correct

There are some requirements for interactive proof

- __Completeness:__ an honest $P$ can convince $V$ that the answer is correct

- __(Statistical) Soundness:__ $V$ will catch a lying $P$ with high probability. This must hold even if $P$ is computationally unbound and trying to trick $V$ into accept incorrect answer

If soundness holds only against polynomial-time provers, then the protocol is called an __interactive argument__

#### Soundness & Knowledge Soundness

We will compare __soundness__ and __knowledge soundness__ for circuit-satisfiability

Let $C$ be some public arithmetic circuit $$C(x, w) \to \mathbb{F}$$ where $x \in \mathbb{F}^n$ is some public statement and $w \in \mathbb{F}^m$ is some secret witness. Let us look at the types of "soundness" with this example:

- __Soundness:__ $V$ accepts $\implies \exists w: C(x, w) = 0$

- __Knowledge Soundness:__ $V$ accepts $\implies P \ {"knows"} \ w: C(x, w) = 0$

Therefore, we can see that knowledge soundness is stronger, because the verifier must know witness

But standard soundness is meaningful even in contexts where knowledge soundness isn't, an example is $P$ claims the output of $V$'s program on $x$ is 42. Knowledge soundness isn't meaningful at below example because there's no natural witness

Vice-versa, knowledge soundness is meaningful in contexts where standard soundness isn't. For example, $P$ claims to know the secret key that controls a certain bitcoin wallet. In this one, there does exist a private key to that account for sure, so if using soundness, the verifier can just ignore the verifier and accept, but when using knowledge soundness, $P$ must know the witness

SNARK's that don't have knowledge soundness are called SNARGs, and they are studied too!

#### Public Verifiability

Interactive proofs and arguments only convince the party that is choosing/sending the random challenges, and this is bad if there are many verifiers, cuz the prover would have to convince each verifier separately

To deal with this problem, we can use Fiat-Shamir Transform [Fiat, Shamir 87'](https://link.springer.com/content/pdf/10.1007/3-540-47721-7_12.pdf) to makes the protocol non-interactive and publicly verifiable

In summary

| SNARKs             | Interactive Proofs |
|--------------------|--------------------|
|Non-interactive|Interactive|
|Computationally Secure (?)|Information Theoretically Secure (aka Statistically Secure)|
|Knowledge Sound|Not necessary need Knowledge Sound|

### SNARKs from interactive proofs: outline

#### Recall: The trivial SNARK is not a SNARK

(a) Prover sends $w$ to verifier

(b) Verifier checks if $C(x, w) = 0$ 

__Problems with this:__

(1) $w$ might be long: we want a "short" proof

(2) Computing $C(x, w)$ maybe hard: we want a "fast" verifier

#### SNARKs from Interactive Proofs (IPs)

- Slight less trivial: $P$ sends $w$ to $V$, and uses an IP to prove that $w$ satisfies the claimed property

    - Fast $V$, but proof is still too long

#### Actual SNARKs

What actually happens in SNARKs is that, instead of sending $w$ explicitly, the prover will cryptographically commit to $w$ and send that commitment.

- $P$ uses an IP to prove that $w$ satisfies the claimed property

- The prover will reveal __just enough__ information about the committed witness $w$ to allow $V$ to run its checks in the IP

- The proof can be made non-interactive using Fiat-Shamir transform

### Review of functional commitments

From previous lecture, we had talked about three important functional commitments

- __Polynomial commitments:__ commit to a <u>univariate</u> $f(X)$ in $\mathbb{F}_p^{(\le d)}[X]$

- __Multilinear commitments:__ commit to multilinear $f$ in $\mathbb{F}_p^{\le 1}[X_1,...,X_k]$

- __Vector commitments (e.g. Merkle Trees):__ commit to $\overrightarrow{c} = (u_1,...u_d) \in \mathbb{F}_p^d$

Now, we will discuss more about each one of them

#### Merkle Trees: The commitment

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/zkp3_1.png)

In this binary tree, every node is made up of the hash of its children:

- `m1 = H(M, Y)`

- `h2 = H(m3, m4)`

- `k1 = H(h1, h2)`

The root `k1` is the __commitment__ to this vector

When the prover is asked to show that indeed some element of the vector exists at some position, it will provide only the necessary nodes.

For example, a verifier could ask "is there really a `t` as position 6?". The prover will give `c`, `t`, `h7` and `h2` and the verifier will calculate `m4`, `h1`, `k1`. Then, the verifier will compare the calculate `h1` to the root given as a commitment by the prover. If they match, then `t` is indeed at that specific position in the committed vector

Summary, we have:

- Commitment to vector is root hash

- To open an entry of the committed vector (leaf of the tree):

    - Send sibling hashes of all nodes on root-to-leaf path

    - $V$ checks these are consistent with the root hash

    - "Opening proof" size is O(log n) hash values

- Binding: one the root hash is sent, the committer is bound to a fixed vector

    - Opening any leaf to two different values requires finding a hash collision (assumed to be intractable)

#### A First Polynomial commitment: commit to a univariate f(X) in $\mathbb{F}_7^{\le d}[X]$

Suppose that we have a polynomial $f(x) \in \mathbb{F}_7^{\le d} [X]$, so this polynomial has values defined onver a very small $n = 7$. The degree should be small too, say something like $d = 3$

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/zkp3_2.png)

- $P$ Merkle-commits to all evaluations of the polynomial $f$

- When $V$ requests $f(r)$, $P$ reveals the associated leaf along with opening information

There exists two problems in this method:

1. The number of leaves is $|\mathbb{F}|$, which means the time to compute the commitment is at least $|\mathbb{F}|$

    - Big problem when working over large fields (say, $|\mathbb{F}| \approx 2^{64}$ or $|\mathbb{F}| \approx 2^{128}$)

2. $V$ does not know if $f$ has degree at most $d$

We will see ways to solve these problems within the lecture

### Interactive proof design: Technical preliminaries

#### Recap: SZDL Lemma

- __Fact:__ Let $p \ne q$ be univariate polynomials of degree at most $d$. Then $Pr_{r \in \mathbb{F}}[p(r) = q(r)] \le \frac{d}{|\mathbb{F}|}$

- The __Schwarts-Zippel-Demillo-Lipton lemma__ is a multivariate generalization:

    - Let $p \ne q$ be a $l$-variate polynomials of total degree at most $d$. Then $Pr_{r \in \mathbb{F}^l[p(r) = q(r)]} \le \frac{d}{|\mathbb{F}|}$

    - "Total degree" refers to the maximum sum of degrees of all variables in any term. E.g., $x_1^2 x_2 + x_1 x_2$ has total degree 3

#### Low-Degree and Multilinear Extensions

- Definition __[Extension].__ Given a function $f:{0, 1}^l \to \mathbb{F}$, a $l$-variate polynomial $g$ over $\mathbb{F}$ is said to __extend__ $f$ if $f(x) = g(x)$ for all $x \in {0, 1}^l$

- Definition __[Multilinear Extensions].__ Any function $f:{0, 1}^l \in \mathbb{F}$ has a __unique__ multilinear extension (MLE), denoted $\tilde{f}$

    - Multilinear means the polynomial has degree at most 1 in each variable
    
    - $(1 - x_1)(1 - x_2)$ is multilinear, $x_1^2x_2$ is not

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/zkp3_3.png)

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/zkp3_4.png)

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/zkp3_5.png)

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/zkp3_6.png)

#### Evaluating multilinear extensions quickly

Given as input all $2^l$ evaluations of a function $f: \{0, 1\}^l \to \mathbb{F}$, for any point $r \in \mathbb{F}^l$ there is an $\mathcal{O}(2^l)$-time algorithm for evaluating the MLE $\tilde{f}(r)$

We will use __Lagrange Interpolation__. For every input $\omega = (\omega_1, \omega_2,...,\omega_l) \in \{0, 1\}^l$, define the multilinear __Lagrange Basis polynomial__ as follow $$\tilde{\delta} _ {\omega}(r) = \prod _ {i=1}^{l}(r_i\omega_i + (1 - r_i)(1 - \omega_i))$$ 

So we can get the evaluation of $\tilde{f}(r)$ using these: $$f(r) = \sum _ {\omega \in \lbrace 0, 1 \rbrace^l}f(\omega) \times \tilde{\delta} _ {\omega}(r)$$

For each $\omega \in \{0, 1\}^l$, the result $\tilde{\delta} _ {\omega}(r)$ can be computed with $\mathcal{O}(l)$ field operations. As such, the overall algorithm for $2^l$ points takes time $\mathcal{O}(l2^l)$. Using dynamic programming, this can be reduced to $\mathcal{O}(2^l)$

### The sum-check protocol

We are going to work with the sum-check protocol [Lund-Fortnow-Karloff-Nissan'90](https://dl.acm.org/doi/10.1145/146585.146605).

The verifier $V$ given oracle access to a $l$-variate polynomial $g$ over field $\mathbb{F}$, and the goal of $V$ is compute the quantity: $$\sum {b_1 \in \lbrace 0, 1 \rbrace} \sum {b_2 \in \lbrace 0, 1 \rbrace} ... \sum {b_l \in \lbrace 0, 1 \rbrace} g(b_1, b_2,...,b_l)$$

In the naive method, the verifier would query each input, and find the sum in a total of $2^l$ queries. We will consider this to be a costly operation

Instead, a prover will compute the sum and convince a verifier that this sum is correct. In doing so, the verifier will make only a single query to the oracle! Let's see how. Denote $P$ as prover and $V$ as verifier

- __Start:__ $P$ sends the claimed answer $C_1$. The protocol must check that indeed:

$$C_1 = \sum _ {b_1 \lbrace 0, 1 \rbrace} \sum _ {b_2 \lbrace 0, 1 \rbrace} ... \sum _ {b_l \lbrace 0, 1 \rbrace} g(b_1, b_2,...,b_l)$$

- __Round 1:__ $P$ sends __univariate__ polynomial $s_1(X_1)$ claimed to equal $H_1(X_1)$ (H standing for honest):

$$H_1(X_1) =  \sum _ {b_1 \lbrace 0, 1 \rbrace} \sum _ {b_2 \lbrace 0, 1 \rbrace} ... \sum _ {b_l \lbrace 0, 1 \rbrace} g(X_1, b_2,...,b_l)$$

-- $V$ need to check two things: 

1. Does $s_1$ equal $H_1$ ?

2. If $s_1$ does equal $H_1$, is that consistent with the true answer being $C_1$ ?

-- For the second question, the verifier simply checks that $C_1 = s_1(0) + s_1(1)$. If this check passes, it is safe for $V$ to believe that $C_1$ is the correct answer, so long as $V$ believes that $s_1 = H_1$

-- For the first question, $V$ just check that $s_1$ and $H_1$ agree at a random point $r_1$

-- Remember that, $V$ can compute $s_1(r_1)$ directly from $P$'s first message, but not $H_1(r_1)$

- __Round 2:__ They recursively check that $s_1(r_1) = H_1(r_1)$. i.e., that $$s_1(r_1) = = \sum _ {b_2 \lbrace 0, 1 \rbrace} ... \sum _ {b_l \lbrace 0, 1 \rbrace} g(r_1, b_2,...,b_l)$$

- __Recursion into Rounds 3,4,...,$l$:__ The verifier and prover keep doing this until the last round

- __Final Round (Round $l$):__ $P$ sends univariate polynomial $s_l(X_l)$ claimed to equal $$H_l := g(r_1,...,r_{l-1}, X_l)$$

-- $V$ checks that $s_{l-1}(r_{l-1}) = s_l(0) + s_l(1)$

-- $V$ picks $r_l$ at random, and needs to check that $s_l(r_l) = g(r_1,...,r_l)$

- The verifier doesn't need for more rounds, because $V$ can perform this check with one oracle query