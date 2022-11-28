# CRYSTALS-Dilithium Python Implementation

This repository contains a pure python implementation of CRYSTALS-Dilithium 
following (at the time of writing) the most recent 
[specification](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
(v3.1)

This project has followed [`kyber-py`](https://github.com/jack4818/kyber-py)
which is a pure-python implementation of CRYSTALS-Kyber and reuses a lot of
code. 

## Disclaimer

:warning: **Under no circumstances should this be used for a cryptographic
application.** :warning:

I have written `dilithium-py` as a way to learn about the way protocol works,
and to try and create a clean, well commented implementation which people can
learn from.

This code is not constant time, or written to be performant. Rather, it was 
written so that reading though the pseudocode of the 
[specification](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
closely matches the code which we use within `dilithium.py` and supporting files.

### KATs

This implementation passes all the KAT vectors, generated from the reference
implementation version 3.1.

These tests, as well as other internal unit tests are the file 
[`test_dilithium.py`](test_dilithium.py).

### Generating KAT files

This implementation is based off the most recent specification (v3.1). 
There were 
[breaking changes](https://github.com/pq-crystals/dilithium/commit/e989e691ae3d3f5933d012ab074bdc413ebc6fad) 
to the KAT files submitted to NIST when Dilithium was updated to 3.1, so the
NIST KAT files will not match our code.

To deal with this, we generated our own KAT files from the 
[reference implementation](https://github.com/pq-crystals/dilithium/releases/tag/v3.1)
for version 3.1. These are the files inside [assets](assets/).

### Dependencies

Originally, as with `kyber-py`, this project was planned to have zero
dependencies, however like `kyber-py`, to pass the KATs, I need  a 
deterministic CSRNG. The reference implementation uses
AES256 CTR DRBG. I have implemented this in [`ase256_ctr_drbg.py`](ase256_ctr_drbg.py). 
However, I have not implemented AES itself, instead I import this from `pycryptodome`.

To install dependencies, run `pip -r install requirements`.

If you're happy to use system randomness (`os.urandom`) then you don't need
this dependency.

## Using dilithium-py

There are three functions exposed on the `Dilithium` class which are intended
for use:

- `Dilithium.keygen()`: generate a bit-packed keypair `(pk, sk)`
- `Dilithium.sign(sk, msg)`: generate a bit-packed signature `sig` 
from the message `msg` and bit-packed secret key `sk`.
- `Dilithium.verify(pk, msg, sig)`: verify that the bit-packed `sig` is
valid for a given message `msg` and bit-packed public key `pk`.

To use `Dilithium()`, it must be initialised with a dictionary of the 
protocol parameters. An example can be seen in `DEFAULT_PARAMETERS` in
the file [`dilithium.py`](dilithium.py)

Additionally, the class has been initialised with these default parameters, 
so you can simply import the NIST level you want to play with:

#### Example

```python
>>> from dilithium import Dilithium2
>>>
>>> # Example of signing
>>> pk, sk = Dilithium2.keygen()
>>> msg = b"Your message signed by Dilithium"
>>> sig = Dilithium2.sign(sk, msg)
>>> assert Dilithium2.verify(pk, msg, sig)
>>>
>>> # Verification will fail with the wrong msg or pk
>>> assert not Dilithium2.verify(pk, b"", sig)
>>> pk_new, sk_new = Dilithium2.keygen()
>>> assert not Dilithium2.verify(pk_new, msg, sig)
```

The above example would also work with the other NIST levels
`Dilithium3` and `Dilithium5`.

### Benchmarks

Some very rough benchmarks to give an idea about performance:

|  500 Iterations          | `Dilithium2` | `Dilithium3` | `Dilithium5` |
|--------------------------|--------------|--------------|--------------|
| `KeyGen()` Median Time   |  0.014s      | 0.022s       | 0.033s       |
| `Sign()`   Median Time   |  0.073s      | 0.113s       | 0.143s       |
| `Sign()`   Average Time  |  0.092s      | 0.143s       | 0.175s       |
| `Verify()` Median Time   |  0.017s      | 0.025s       | 0.039s       |

All times recorded using a Intel Core i7-9750H CPU. 

## Future Plans

* **First plan**: Add documentation to the code
* Add examples for each of the functions
* Add documentation on how each of the components works
* Add documentation for working with DRBG and setting the seed

## Discussion of Implementation

### Polynomials

The file [`polynomials.py`](polynomials.py) contains the classes 
`PolynomialRing` and 
`Polynomial`. This implements the univariate polynomial ring

$$
R_q = \mathbb{F}_q[X] /(X^n + 1) 
$$

The implementation is inspired by `SageMath` and you can create the
ring $R_{11} = \mathbb{F}_{11}[X] /(X^8 + 1)$ in the following way:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>> f = 3*x**3 + 4*x**7
>>> g = R.random_element(); g
5 + x^2 + 5*x^3 + 4*x^4 + x^5 + 3*x^6 + 8*x^7
>>> f*g
8 + 9*x + 10*x^3 + 7*x^4 + 2*x^5 + 5*x^6 + 10*x^7
>>> f + f
6*x^3 + 8*x^7
>>> g - g
0
```

### Modules

The file [`modules.py`](modules.py) contains the classes `Module` and `Matrix`.
A module is a generalisation of a vector space, where the field
of scalars is replaced with a ring. In the case of Dilithium, we 
need the module with the ring $R_q$ as described above. 

`Matrix` allows elements of the module to be of size $m \times n$
For Dilithium, we need vectors of length $k$ and $l$ and a matrix
of size $l \times k$. 

As an example of the operations we can perform with out `Module`
lets revisit the ring from the previous example:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>>
>>> M = Module(R)
>>> # We create a matrix by feeding the coefficients to M
>>> A = M([[x + 3*x**2, 4 + 3*x**7], [3*x**3 + 9*x**7, x**4]])
>>> A
[    x + 3*x^2, 4 + 3*x^7]
[3*x^3 + 9*x^7,       x^4]
>>> # We can add and subtract matricies of the same size
>>> A + A
[  2*x + 6*x^2, 8 + 6*x^7]
[6*x^3 + 7*x^7,     2*x^4]
>>> A - A
[0, 0]
[0, 0]
>>> # A vector can be constructed by a list of coefficents
>>> v = M([3*x**5, x])
>>> v
[3*x^5, x]
>>> # We can compute the transpose
>>> v.transpose()
[3*x^5]
[    x]
>>> v + v
[6*x^5, 2*x]
>>> # We can also compute the transpose in place
>>> v.transpose_self()
[3*x^5]
[    x]
>>> v + v
[6*x^5]
[  2*x]
>>> # Matrix multiplication follows python standards and is denoted by @
>>> A @ v
[8 + 4*x + 3*x^6 + 9*x^7]
[        2 + 6*x^4 + x^5]
```

### Number Theoretic Transform

**TODO**: More details about the NTT.

We can transform polynomials to NTT form and from NTT form
with `poly.to_ntt()` and `poly.from_ntt()`.

When we perform operations between polynomials, `(+, -, *)`
either both or neither must be in NTT form.

```py
>>> f = R.random_element()
>>> f == f.to_ntt().from_ntt()
True
>>> g = R.random_element()
>>> h = f*g
>>> h == (f.to_ntt() * g.to_ntt()).from_ntt()
True
```

While writing this README, performing multiplication of of polynomials
in NTT form is about 100x faster when working with the ring used by
Dilithium.

```py
>>> # Lets work in the ring we use for Dilithium
>>> R = Dilithium2.R
>>> # Generate some random elements
>>> f = R.random_element()
>>> g = R.random_element()
>>> # Takes about 10 seconds to perform 1000 multiplications
>>> timeit.timeit("f*g", globals=globals(), number=1000)
9.621509193995735
>>> # Now lets convert to NTT and try again
>>> f.to_ntt()
>>> g.to_ntt()
>>> # Now it only takes ~0.1s to perform 1000 multiplications!
>>> timeit.timeit("f*g", globals=globals(), number=1000)
0.12979038299818058
```

These functions extend to modules

```py
>>> M = Dilithium2.M
>>> R = Dilithium2.R
>>> v = M([R.random_element(), R.random_element()])
>>> u = M([R.random_element(), R.random_element()]).transpose()
>>> A = u @ v
>>> A == (u.to_ntt() @ v.to_ntt()).from_ntt()
True
```

As operations on the module are just operations between elements, 
we expect a similar 100x speed up when working in NTT form:

```py
>>> u = M([R.random_element(), R.random_element()]).transpose()
>>> v = M([R.random_element(), R.random_element()])
>>> timeit.timeit("u@v", globals=globals(), number=1000)
38.39359304799291
>>> u = u.to_ntt()
>>> v = v.to_ntt()
>>> timeit.timeit("u@v", globals=globals(), number=1000)
0.495470915993792
```

### Bit Packing

```
TODO
```

### Random Sampling

```
TODO
```

### AES256-CTR-DRBG

```
TODO
```
