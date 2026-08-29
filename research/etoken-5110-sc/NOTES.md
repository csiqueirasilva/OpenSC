# SafeNet eToken 5110 SC — protocol notes

Goal: drive this token with OpenSC, so users are not forced to install the
vendor's proprietary middleware (SafeNet Authentication Client) on every
machine. Windows has no inbox driver for it either — SAC is currently the only
way on any OS.

Status: **reconnaissance**. No driver code yet. Everything below is observed
behaviour, not documentation — the applet is proprietary and undocumented.

## Card identification

    ATR   3B D5 18 00 81 31 FE 7D 80 73 C8 21 10 F4
    Reader name  "SafeNet eToken 5100 [eToken 5110 SC]"

`smartcard_list.txt` maps this ATR to *Gemalto SafeNet eToken Java Based Cards*
and, sharing the same ATR, *Bank of Lithuania Identification card* — same Java
Card platform, different applet.

Not recognised by OpenSC master (a6f4fdc): the ATR appears nowhere in the tree,
and forcing each plausible driver fails.

    OPENSC_DRIVER={idprime,cardos,muscle,entersafe,epass2003,gemsafeV1,
                   iasecc,jacartapki,isoApplet} opensc-tool --name
    -> "Card is invalid or cannot be handled" for all nine

## No standard applet is present

SELECT by AID returns 6A82 (file not found) for every standard AID tried:

| AID | applet | result |
|---|---|---|
| `A0 00 00 00 63 50 4B 43 53 2D 31 35` | PKCS#15 | 6A82 |
| `A0 00 00 03 08 00 00 10 00` | PIV | 6A82 |
| `A0 00 00 03 97 42 54 46 59` | GIDS | 6A82 |
| `D2 76 00 01 24 01` | OpenPGP | 6A82 |
| `A0 00 00 01 51 00 00 00` | GlobalPlatform ISD | 6A82 |

`00 A4 00 0C 02 3F 00` (SELECT MF) returns 6A86 (incorrect P1/P2).

## How the traces were captured

`pcsc-spy` from pcsc-lite, no need to stop `pcscd`:

    pcsc-spy -n > trace.log &
    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libpcscspy.so.0 \
        pkcs11-tool --module /usr/lib/libeTPkcs11.so -O

`parse_spy.py` turns that into a readable APDU list.

## Observed command set

### Card identification — `80 1C 00 00 00`

    -> 80 1C 00 00 00
    <- 10 10 D6 E4 A5 5A 64 E7 4F D2 AC E1 51 5D F0 F4 16 E8   SW=9000

18 bytes. First command of every session. Content not yet understood; likely a
card/serial identifier.

### SELECT by path — `00 A4 08 04 <len> <path>`

Standard ISO 7816-4 SELECT, P1=08 (path from MF), P2=04 (return FCI). Paths are
proprietary and always start with `66 66`:

    66 66 50 00 00 0A            -> 9000
    66 66 50 00 00 0F            -> 9000
    66 66 50 00 02 20 50 01      -> 9000
    66 66 50 00 02 20 60 01 00 01
    66 66 50 00 02 20 10 02 00 01
    66 66 50 00 C0 00 00 01      -> 6A82 (probed, absent)

The FCI is 23 bytes of simple TLV:

    01 01 02        tag 01, len 1, value 02        (file type?)
    02 02 00 0A     tag 02, len 2, value 000A      (file id)
    03 02 00 09     tag 03, len 2, value 0009      (CONTENT LENGTH)
    04 08 00 FF ..  tag 04, len 8                  (ACL / flags?)

Tag 03 is confirmed as the content length: it always matches the length asked
for in the read that follows.

### Proprietary READ — `80 18 00 00 04 0E 02 00 00 <len>`

    -> 80 18 00 00 04 0E 02 00 00 09
    <- 05 01 08 00 0A 03 00 00 57   SW=9000

Reads the whole content of the currently selected file. The trailing byte is the
length taken from FCI tag 03. The `0E 02 00 00` prefix is constant in every read
seen so far — offset and/or a sub-command, still unknown.

### Object contents

Files under `66 66 50 00 02 20 50 xx` carry, among other things:

    06 08 2A 86 48 CE 3D 03 01 07     OID 1.2.840.10045.3.1.7 (prime256v1)

which matches the EC P-256 keys generated on this token. So this subtree is the
key/certificate object directory.

## Second trace: login and signature

Captured with `pkcs11-tool --login --sign --mechanism ECDSA-SHA256`. 51 APDUs.

### PIN is never sent in the clear

    36. -> 80 17 01 00 08          <- 22 D9 DC 5B 22 BA FF 5B      (8-byte challenge)
     9. -> 80 11 00 11 0A 10 08 <8 bytes>                   SW=9000

`80 17` is a proprietary GET CHALLENGE (P1 selects the purpose: 00 for the
authentication that precedes reads, 01 before signing). `80 11` carries the
response. So authentication is challenge/response — good news for privacy of the
traces, and bad news for anyone hoping to replay.

### Reads are in the clear, and fully decoded

    80 18 00 00 04 0E 02 <offset:2> <len:1>

Reads `len` bytes at `offset` from the selected file. Confirmed by the two-part
read of a 0x1C4-byte certificate: offset 0000 len F0, then offset 00F0 len D4.
Certificates come back as plain DER (`30 82 01 C0 ...`) and labels as plain
ASCII (`netbird-ca-intermediaria`, `csiqueira-estacao`).

### Object enumeration — `80 01 00 00 04 09 02 00 00 00`

    <- 0A 10 60 01 50 01 60 02 50 02 60 03 50 03 10 0...

A list of the object ids that also appear as path components: `6001/5001`,
`6002/5002`, `6003/5003`. This is the directory.

### 🔴 Signing is wrapped in secure messaging

    37. -> 84 0C 12 31 4C 32 ... (80 bytes)     <- 96 bytes
    38. -> 80 08 00 31 00                       <- 10 40 <64 bytes>

`CLA=0x84` sets the secure-messaging bit. The 64 bytes returned by `80 08` are
**not** the signature: the ECDSA signature written by `pkcs11-tool` in the same
run starts `21 CD 4A 05`, while the APDU returns `AC 2E 07 7E`. The payload is
encrypted under a session key derived from the challenge/response above.

## Where this leaves a driver

| capability | status |
|---|---|
| identify card, walk the file tree | **solved** — standard SELECT by path |
| read certificates and public objects | **solved** — `80 18` decoded, data in the clear |
| enumerate objects | **solved** — `80 01` |
| authenticate (PIN) | observed, not understood — challenge/response, key derivation unknown |
| **sign** | **blocked** — inside secure messaging |

A read-only driver is achievable with what is documented here: it would list and
read certificates without any crypto work. That is genuinely useful for
inspection, and useless for the case that motivated this — signing.

Getting to signing means reimplementing the secure-messaging layer: session key
derivation from the PIN authentication, cipher, MAC and padding. None of it is
documented, and inferring it from traces alone is not realistic. The remaining
path is static analysis of the vendor library, which is a different kind of
project — much larger, and on shakier legal ground than observing a protocol.

## Static analysis of the vendor stack

### Secure messaging on the response, confirmed by verification

Not an inference: the 64 bytes returned by `80 08` fail signature verification
against the token's public key, while the file `pkcs11-tool` wrote in the same
run verifies successfully.

    APDU 38 payload           -> Signature Verification Failure
    pkcs11-tool output file   -> Signature Verified Successfully

So the response really is protected, and the plaintext signature never appears
on the wire.

### No symmetric crypto tables anywhere in the vendor libraries

Scanned all ten shared objects shipped by the package for AES S-boxes (forward
and inverse), DES SP/PC1 tables, and MD5/SHA constants. Only the SHA-1 IV turns
up, in the two IDPrime engines. `libeToken.so` imports no crypto library either —
its only dependencies are pthread, dl, pcsclite and libc.

Either the symmetric implementation is table-free/obfuscated, or the session key
material is derived somewhere not yet located. All the libraries are stripped.

### 🟢 The vendor stack is built on OpenSC, and says so

`libeTPKCS15.so` exports **94 `sc_*` symbols** — `sc_pkcs15_bind`,
`sc_pkcs15_decode_cdf_entry`, `sc_asn1_decode`, `sc_pkcs15_change_pin` and so on.
It is OpenSC's own PKCS#15 layer, compiled into the product. The package's
copyright file states it plainly:

> The Open Source Software Component (OpenSC), whose PKCS#15 functionality is
> utilized within SafeNet's PKCS#11 and SafeNet SIS MD products, is used and
> distributed under the GNU Lesser General Public License 2.1

Two consequences.

**Legal.** LGPL-2.1 §6 explicitly permits reverse engineering for debugging
modifications of the covered work. For the OpenSC-derived portion, the grey area
noted earlier does not apply.

**Practical.** The licence obliges the distributor to make the source of the
covered component available. A source request is free and legitimate, and would
hand over their modified OpenSC instead of it having to be reconstructed.

Temper the expectation: the split of symbols suggests the interesting part is not
in the covered component. `libeTPKCS15.so` has 94 `sc_*` symbols; `libeToken.so`,
where the card protocol and the secure messaging almost certainly live, has 5.
The request is worth making, and is unlikely to deliver the SM implementation.

## Open questions

1. Key derivation for the secure-messaging session — the blocker.
2. Cipher, MAC and padding used by the `84` class commands.
3. Meaning of FCI tags 01 and 04.
4. Semantics of `80 1B` (16-byte payload after authentication) and `80 07`.
5. Whether the same applet is on the Bank of Lithuania card that shares this ATR
   — a second implementation would give a lot of signal for free.

## Method note

Traces are captured against a token owned by the person running the capture,
using their own PIN, for interoperability purposes only. No attempt is made to
extract key material — the private keys are marked non-extractable and stay in
the chip.
