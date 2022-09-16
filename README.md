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

This implementation follows all the KAT vectors, generated from the reference
implementation.

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
| `KeyGen()` Median Time   |  0.014s      | 0.022s       | 0.033s       |
| `Sign()`   Median Time   |  0.073s      | 0.113s       | 0.143s       |
| `Sign()`   Average Time  |  0.092s      | 0.143s       | 0.175s       |
| `Verify()` Median Time   |  0.017s      | 0.025s       | 0.039s       |

All times recorded using a Intel Core i7-9750H CPU. 

## Future Plans

* **First plan**: Add documentation to the code
* Add examples for each of the functions
* Add documentation on how each of the components works
* Add documentation for working with DRGB and setting the seed

