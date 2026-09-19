"""Deterministic AES attack recipes.

Two classic oracle attacks on misconfigured AES, both deterministic and
non-brute-force over the key space: they call an oracle once per secret
byte and reconstruct plaintext byte by byte.

- :func:`ecb_byte_at_a_time` — recovers the unknown suffix of an ECB
  encryption when the attacker controls data placed between a fixed
  (unknown) ``prefix`` and the ``secret``::

      oracle(data) == ECB(prefix + data + secret)

  Handles an arbitrary prefix length automatically.

- :func:`cbc_padding_oracle` — recovers plaintext block by block using a
  padding-validity oracle on CBC ciphertexts::

      oracle(previous || block) -> True if decrypting ``block`` against
      ``previous`` yields valid PKCS#7 padding
"""

from __future__ import annotations

BLOCK = 16


def _chunks(data: bytes, bs: int):
    return [data[i * bs:(i + 1) * bs] for i in range(len(data) // bs)]


def _detect_blocksize(oracle) -> int:
    base = len(oracle(b""))
    prev = base
    jumps = []
    for n in range(1, 256):
        cur = len(oracle(b"A" * n))
        if cur != prev:
            jumps.append(n)
            prev = cur
        if len(jumps) >= 2:
            return jumps[1] - jumps[0]
    raise ValueError("oracle output length never changes (no block size found)")


def _is_ecb(oracle, bs: int) -> bool:
    out = oracle(b"A" * (bs * 3))
    blocks = _chunks(out, bs)
    return len(set(blocks)) != len(blocks)


def _find_prefix_align(oracle, bs: int):
    """Return a list of candidate ``(q, j0)`` alignments.

    Feeding ``A^q + X^(2*bs)`` (for two independent byte values X = B, C)
    produces two consecutive identical ciphertext blocks iff
    ``(prefix_len + q) % bs == 0``.  The union of duplicate-pair indices
    across the two characters makes the detector robust against a prefix
    or secret that itself repeats bytes; the caller validates each
    candidate by attempting a full recovery.
    """
    pair_sets = []
    for byte_val in (0x42, 0x43):
        pairs = set()
        for q in range(bs):
            out = oracle(b"A" * q + bytes([byte_val]) * (bs * 2))
            blocks = _chunks(out, bs)
            for i in range(len(blocks) - 1):
                if blocks[i] == blocks[i + 1]:
                    pairs.add((q, i))
        pair_sets.append(pairs)
    cands = sorted(pair_sets[0] & pair_sets[1])
    if not cands:
        raise ValueError("could not align unknown prefix (no aligned run)")
    return cands


def _plaintext_len(oracle, bs: int) -> int:
    """Measure the oracle's total unpadded plaintext length.

    Let M be the plaintext length for an empty attacker input.  The oracle
    output for x attacker bytes is ``bs * ceil((M + x) / bs)`` (a full
    padding block when M + x is block-aligned, as PKCS#7 always pads), so
    the smallest x at which the length grows reveals ``M % bs``.
    """
    w = len(oracle(b"")) // bs
    prev = len(oracle(b""))
    jump = None
    for x in range(1, bs + 1):
        cur = len(oracle(b"A" * x))
        if cur > prev:
            jump = x
            break
        prev = cur
    if jump is None:
        raise ValueError("oracle length never changes; cannot detect plaintext len")
    return (w - 1) * bs + (bs - jump) % bs


def ecb_byte_at_a_time(oracle, secret_len=None, block_size=None):
    """Recover ``secret`` from ``oracle(data) == ECB(prefix+data+secret)``.

    Detects block size and ECB mode, measures an arbitrary unknown
    ``prefix`` (alignment + length), and reconstructs ``secret`` byte by
    byte with up to 256 oracle calls per byte plus a constant budget.
    """
    bs = _detect_blocksize(oracle) if block_size is None else block_size
    if not _is_ecb(oracle, bs):
        raise ValueError("oracle does not look like ECB (no duplicated block)")

    total_len = _plaintext_len(oracle, bs)
    candidates = _find_prefix_align(oracle, bs)
    failures = []
    best = None
    for q, j0 in candidates:
        try:
            prefix_len = j0 * bs - q
            if prefix_len < 0:
                raise ValueError("negative prefix length")
            slen = secret_len
            if slen is None:
                slen = total_len - prefix_len
            if slen < 0:
                raise ValueError("negative secret length")
            recovered = _recover_with_alignment(oracle, bs, q, j0, slen)
        except ValueError as exc:
            failures.append((q, j0, str(exc)))
            continue
        if best is None or len(recovered) > len(best):
            best = recovered
    if best is None:
        raise ValueError(
            "could not recover secret with any alignment (%s)" % failures[0][2])
    return best


def _recover_with_alignment(oracle, bs, q, j0, secret_len):
    """Run the byte-at-a-time recovery assuming aligned offset (q, j0).

    Reconstructs exactly ``secret_len`` bytes.  A candidate alignment is
    rejected when the probe byte never lands inside the compared block,
    which would silently recover zero bytes instead of the secret.
    """
    known = bytearray()
    for n in range(secret_len):
        a, r = divmod(n, bs)
        pad = bs - 1 - r
        base = oracle(b"A" * (q + pad))
        block = (j0 + a) * bs
        if block + bs > len(base):
            raise ValueError("target block out of range at byte %d" % n)
        target_block = base[block:block + bs]
        if n == 0:
            # Probe two values first: the probe byte sits at a fixed
            # position inside the compared block for a given alignment, so
            # a match for both means the probe never reached that block at
            # all (the alignment is degenerate) and the recovery would
            # silently produce zero bytes.
            zero = oracle(b"A" * (q + pad) + bytes([0]))
            one = oracle(b"A" * (q + pad) + bytes([1]))
            if (zero[block:block + bs] == target_block
                    and one[block:block + bs] == target_block):
                raise ValueError(
                    "ambiguous alignment q=%d,j0=%d" % (q, j0))
        found = None
        for c in range(256):
            cand = oracle(b"A" * (q + pad) + bytes(known) + bytes([c]))
            if cand[block:block + bs] == target_block:
                found = c
                break
        if found is None:
            raise ValueError(
                "byte %d not found with alignment q=%d,j0=%d"
                % (len(known), q, j0))
        known.append(found)
    return bytes(known)


def cbc_padding_oracle(block_decrypt, iv, ciphertext, block_size=BLOCK):
    """Recover the plaintext of a CBC ``ciphertext``.

    ``block_decrypt`` is the padding oracle: given ``previous || block`` it
    returns True iff decrypting ``block`` against ``previous`` yields a
    block with valid PKCS#7 padding.  No key material is required.

    Runs the classic block-by-block attack: each block is recovered by
    learning, byte by byte, the crafted previous block that makes the
    padding valid, then XORing the result with the real IV (or previous
    cipher block).
    """
    bs = block_size
    if len(ciphertext) % bs:
        raise ValueError("ciphertext must be a multiple of block size")
    ct_blocks = _chunks(ciphertext, bs)
    previous = iv
    out = bytearray()
    for block in ct_blocks:
        recovered = bytearray(bs)
        probe = bytearray(bs)
        for pos in range(bs - 1, -1, -1):
            pad_val = bs - pos
            for i in range(pos + 1, bs):
                probe[i] = recovered[i] ^ pad_val
            found = None
            for cand in range(256):
                probe[pos] = cand
                if block_decrypt(bytes(probe) + block):
                    found = cand
                    break
            if found is None:
                raise ValueError("padding oracle exhausted at pos %d" % pos)
            recovered[pos] = found ^ pad_val
        out += bytes(r ^ p for r, p in zip(recovered, previous))
        previous = block
    return bytes(out)
