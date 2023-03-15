# SHA-256 in C
These are implementations of SHA-256 in C made according to the official standard ([FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)).

These implementations are not meant to be used in serious applications, but serve as reference for implementing SHA-256 in any programming language.

Please note that the algorithm used in these implementations deviate somewhat from the official standard in order to optimize parts of the algorithm. However, the implementations still produce only valid outputs.

## Usage
See sha256.h or sha256_malloc.h for more details about the implementations or how to use them.

## Testing
Included in this repository are the source code for C programs that test the validity of the SHA-256 functions. They contain simple tests that can be used to easily debug issues with the implementations. Keep in mind that a full validation test would require the implementations to be compliant with all test vectors from the [NIST](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing).
