def reduce_mod_pm(x, n):
    """
    Takes an integer 0 < x < n and represents
    it as an integer in the range

    r = x % n

    for n odd:
        -(n-1)/2 < r <= (n-1)/2
    for n even:
        - n / 2  < r <= n / 2
    """
    x = x % n
    if x > (n >> 1):
        x -= n
    # assert x > -(n >> 1)
    # assert x <= (n >> 1)

    return x


def decompose(r, a, q):
    """
    Takes an element r and represents
    it as:

    r = r1*a + r0

    With r0 in the range

    -(a << 1) < r0 <= (a << 1)
    """
    rp = r % q
    r0 = reduce_mod_pm(rp, a)
    r1 = rp - r0
    if r1 == q - 1:
        return 0, r0 - 1
    r1 = r1 // a

    return r1, r0


def high_bits(r, a, q):
    r1, _ = decompose(r, a, q)
    return r1


def low_bits(r, a, q):
    _, r0 = decompose(r, a, q)
    return r0


# def __broken_make_hint(z, r, a, q):
#     r1 = high_bits(r, a, q)
#     v1 = high_bits(r + z, a, q)
#     return int(r1 != v1)


def make_hint(z0, r1, a, q):
    """
    The above function from the documentation
    fails sometimes, but this seems to work...

    This assumes that

    TODO: learn what the edge case is for the above function
    """
    gamma2 = a >> 1
    if z0 <= gamma2 or z0 > (q - gamma2) or (z0 == (q - gamma2) and r1 == 0):
        return 0
    return 1


def use_hint(h, r, a, q):
    m = (q - 1) // a
    r1, r0 = decompose(r, a, q)
    if h == 1:
        if r0 > 0:
            return (r1 + 1) % m
        return (r1 - 1) % m
    return r1


def check_norm_bound(n, b, q):
    """
    Norm bound is checked in the following four steps:
    x ∈ {0,        ...,                    ...,     q-1}
    x ∈ {-(q-1)/2, ...,       -1,       0, ..., (q-1)/2}
    x ∈ { (q-3)/2, ...,        0,       0, ..., (q-1)/2}
    x ∈ {0, 1,     ...,  (q-1)/2, (q-1)/2, ...,       1}
    """
    x = n % q
    x = ((q - 1) >> 1) - x
    x = x ^ (x >> 31)
    x = ((q - 1) >> 1) - x
    return x >= b


def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are
    of the same length
    """
    return bytes(a ^ b for a, b in zip(a, b))
