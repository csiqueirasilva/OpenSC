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

## Open questions

1. PIN verification command — needs a trace with login.
2. Signature command (MSE + PSO, or a proprietary equivalent).
3. Meaning of FCI tags 01 and 04, and of the `0E 02 00 00` prefix in READ.
4. Full object directory format, to map onto OpenSC's PKCS#15 layer.
5. Whether writing (key generation, certificate import) is in scope at all — read
   and sign already cover the common case.

## Method note

Traces are captured against a token owned by the person running the capture,
using their own PIN, for interoperability purposes only. No attempt is made to
extract key material — the private keys are marked non-extractable and stay in
the chip.
