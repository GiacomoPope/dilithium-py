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

:rotating_light: 
:skull_and_crossbones:
**This implementation does not pass the specification's KAT files.**
Currently, there seems to be some bugs... :bug: :ant: :bee:.

I'm (currently) actively working on making `dilithium-py` pass all KATs.
:skull_and_crossbones:
:rotating_light: 

As the whole specification works self-consistently, I assume these
bugs come from:

- How vectors are being packed
- How polynomials are being sampled
- How seeds are being generated

### Bug(?) in specification

Additionally, there seems to be a bug in the KAT files themselves.
Unpacking the secret key, we find that the value denoted `K` in the
specification and `key` in the implementation 
seems to have been taken as the bytes `seed_bytes[64:96]` rather than
the intended `seed_bytes[96:128]`.

For more information, see the minimal example showing this bug in
the file [`minimal_example.py`](minimal_example.py).

### Dependencies

Originally, as with `kyber-py`, this project was planned to have zero
dependencies, however like `kyber-py`, to pass the KATs, I need  a 
deterministic CSRNG. The reference implementation uses
AES256 CRT DRGB. I have implemented this in [`ase256_crt_drgb.py`](ase256_crt_drgb.py). 
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

**TODO**: Better benchmarks? Although this was never about speed.

For now, here are some approximate benchmarks:

|  500 Iterations          | `Dilithium2` | `Dilithium3` | `Dilithium5` |
|--------------------------|--------------|--------------|--------------|
| `KeyGen()` Median Time   |  0.014s      | 0.023s       | 0.036s       |
| `Sign()`   Median Time   |  0.084s      | 0.140s       | 0.167s       |
| `Sign()`   Average Time  |  0.115s      | 0.173s       | 0.213s       |
| `Verify()` Median Time   |  0.017s      | 0.027s       | 0.042s       |

All times recorded using a Intel Core i7-9750H CPU. 

## Future Plans

All plans are on hold for documentation until the KAT vectors pass.

* Add examples for each of the functions
* Add documentation on how each of the components works
* Add documentation for working with DRGB and setting the seed

