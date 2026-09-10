# Password Strength and Breach Auditor

Answers two separate questions about a password: how hard it is to guess, and
whether it has already leaked. No dependencies.

The strength check measures **entropy**, not whether it has a capital letter and
a symbol. `Password1!` passes every checklist and is still terrible. The breach
check uses **k-anonymity**, so the password never leaves your machine.

## Features

- Entropy in bits, from the character pool and length
- A rough crack-time estimate at a realistic guessing rate
- Detection of the patterns that make entropy lie: dictionary words, sequences,
  keyboard runs, the `Word2024!` shape
- Breach lookup against Have I Been Pwned using k-anonymity
- Hidden prompt when no password is given on the command line
- Exit code gates a script: non-zero for weak or breached

## Requirements

Python **3.10+**. The breach check needs internet; everything else is offline.

## Usage

```bash
# Prompt without echoing (the safest way; nothing lands in shell history)
python pwaudit.py

# Directly, if you accept it will be in your history
python pwaudit.py "correct horse battery staple"

# Strength only, no network
python pwaudit.py "hunter2" --no-breach-check
```

Exit codes: `0` strong and not breached, `1` weak or breached, `2` no password.

## Example output

```
$ python pwaudit.py Summer2024!

Password audit
========================================================
Length:       11
Character set: 95 possible characters
Entropy:      72.3 bits (strong)
Crack time:   ~9,218 years at 10 billion guesses/sec

Weaknesses (2):
  [!] Only 11 characters; 12 or more is the usual advice
  [!] Follows the predictable word-then-digits-then-symbol pattern

[!] Seen 3,614 time(s) in known breaches. Do not use it.
```

`Summer2024!` shows exactly why both checks are needed. Its entropy looks
strong, but it is a predictable pattern and it is already in the breach corpus.
Entropy alone would have passed it.

## How k-anonymity protects the password

The naive way to check a password against a breach database is to send it, or its
hash, to a server. Both are a bad idea. k-anonymity avoids both:

1. Hash the password with SHA-1: `password` becomes `5BAA6...D2E1F` (40 hex).
2. Send only the **first five characters** to the API: `5BAA6`.
3. The API returns every hash suffix it knows that starts with `5BAA6`, along
   with a breach count for each. Hundreds of them.
4. Match the rest of your hash against that list **locally**.

The server learns you were interested in one of ~800 hashes sharing a prefix,
which tells it nothing. It never sees your password and never sees your full
hash. SHA-1 being cryptographically broken does not matter here: the API is a
lookup table, not a security boundary. The privacy comes entirely from sending
only the prefix.

## Why entropy beats a checklist

The "one uppercase, one number, one symbol" rule optimises for the wrong thing.
It rewards `Password1!` and punishes `correcthorsebatterystaple`, when the
second is far stronger.

Entropy measures the actual search space: the size of the character pool raised
to the length, expressed in bits. Every extra character multiplies the work, so
length matters more than variety. A long passphrase from a large pool beats a
short password that ticks every box.

The catch is that entropy assumes every character is random. A dictionary word
drawn from a pool of 26 letters has nowhere near the entropy its length implies,
because an attacker guesses words, not letters. That is what the pattern
warnings exist to flag: the entropy number is an upper bound, and the warnings
say when the real figure is much lower.

## Design notes

**Strength and breach are independent.** A password can be high-entropy and
breached (someone else generated the same random string and it leaked), or
low-entropy and not yet in a corpus. The tool reports both and never collapses
them into one score, because they answer different questions.

**The crack-time estimate is deliberately rough.** Ten billion guesses a second
is a fair figure for one GPU against a fast hash. Real numbers depend on the
hashing scheme, and past the age of the universe the tool stops pretending to be
precise.

## What I learned

- What entropy actually measures, and why length beats character variety
- The k-anonymity construction, which is a genuinely elegant privacy trick
- Why SHA-1 being broken is irrelevant to how this API is used
- That a strong-looking password can still be breached, so both checks matter
- Reading a password without echoing it, and keeping it out of shell history

## Disclaimer

For education and for auditing your own passwords. Only the SHA-1 prefix is ever
transmitted.

## License

MIT, see [LICENSE](../../LICENSE).
