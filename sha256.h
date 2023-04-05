/* SHA-256 implementation according to FIPS 180-4

   This implementation only uses static memory by allocating one block on the
   stack and compressing it into the next hash iteration when it fills up.

   SHA-256 algorithm optimizations:
   Current:
   - Pointer dereferences are kept to a minimum
   - Message schedule is prepared during main computation loop instead of
     separately
   - The size of the message schedule is shortened from 64 to 16 32-bit words
     and W is addressed modulo 16 in the main loop
   - Maj and Ch operators are optimized to use less instructions

   Possible:
   - Unroll main computation loops (preferrably with macros)


   This header file contains two different ways of using SHA-256:
   - Three different functions that allow you hash information if you have more
     than one pointer to the data.
   - An all-in-one function that just needs the message, its length, and a
     pointer to the hash array.

   All-in-one function:
   void sha256(const char* input, uint64_t input_len, uint32_t* hash_buffer)

   Three functions:
   void sha256_init(uint32_t* hash_buffer)
   uint8_t sha256_add_input(const char* input, uint64_t input_len,
                            uint32_t* hash_buffer, void* block,
                            uint8_t block_pos)
   void sha256_finish(uint64_t total_input_len, void* block, uint8_t block_pos,
                      uint32_t* hash_buffer)

   You must use the above three functions in the following order:
   - Allocate an array of 32 bytes and give it to sha256_init. This is your
     hash buffer.
   - Allocate an array of 64 bytes. This is your block.
   - Give a pointer to any data you want to hash to sha256_add_input along with
     the length of the data in bytes, the pointer to the block, the hash
     buffer, and the current block position (returned after every call to this
     function, pass 0 as the block position for the first call).
   - Repeat the above step for any other data you want to add to the message.
   - Call sha256_finish when you are finished adding data. Give it the block
     and hash buffer pointers, as well the length, in bytes, of the total
     message and the block position. The function will return the final hash in
     the hash buffer.
*/

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

/* Need to swap bytes sometimes if little endian
   This catches all modern GCCs (>= 4.6) and Clang (>=3.2)
*/
#if (defined __BYTE_ORDER__) && (defined __ORDER_LITTLE_ENDIAN__)
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define SWAP32(n) \
  (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#  define SWAP64(n) \
  (((n) << 56)                  \
   | (((n) & 0xff00) << 40)     \
   | (((n) & 0xff0000) << 24)   \
   | (((n) & 0xff000000) << 8)  \
   | (((n) >> 8) & 0xff000000)  \
   | (((n) >> 24) & 0xff0000)   \
   | (((n) >> 40) & 0xff00)     \
   | ((n) >> 56))
# else
#  define SWAP32(n) (n)
#  define SWAP64(n) (n)
# endif
#else
# error "Could not find endianness"
#endif


#define ROTR(w, s) ((w >> s) | (w << (32 - s)))

// Operators defined in FIPS 180-4: 4.1.2
#define Ch(x, y, z) (z ^ (x & (y ^ z))) // Same as (x & y) ^ (~x & z)
#define Maj(x, y, z) (x ^ ((x ^ y) & (x ^ z))) // Same as (x & y) ^ (x & z) ^ (y & z)
#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

// Constants for SHA-256 (FIPS 180-4: 4.2.2)
static const uint32_t K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/* Get hash ready with initial value (FIPS 180-4: 5.3.3)
   HASH_BUFFER must be an array of 32 bytes
*/
void sha256_init(uint32_t* hash_buffer)
{
	hash_buffer[0] = 0x6a09e667;
	hash_buffer[1] = 0xbb67ae85;
	hash_buffer[2] = 0x3c6ef372;
	hash_buffer[3] = 0xa54ff53a;
	hash_buffer[4] = 0x510e527f;
	hash_buffer[5] = 0x9b05688c;
	hash_buffer[6] = 0x1f83d9ab;
	hash_buffer[7] = 0x5be0cd19;
}

// Hash computation as outlined in FIPS 180-4: 6.2.2
static
void sha256_digest_block(const uint32_t* block, uint32_t* H)
{
	uint32_t a, b, c, d, e, f, g, h, T1, T2;
	uint32_t W[16];
	uint8_t t;

	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	for (t = 0; t < 16; t++) {
		T1 = SWAP32(block[t]);
		W[t] = T1;
		T1 += h + S1(e) + Ch(e, f, g) + K[t];
		T2 = S0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	for (; t < 64; t++) {
		T1 = s1(W[(t + 14) & 15]) + W[(t + 9) & 15]
		     + s0(W[(t + 1) & 15]) + W[t & 15];
		W[t & 15] = T1;
		T1 += h + S1(e) + Ch(e, f, g) + K[t];
		T2 = S0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;	
}

/* Adds input bytes to message block, performing one round
   of the hash computation when block is filled
   INPUT_LEN is length of INPUT in bytes
   HASH_BUFFER must be 32 bytes long and initialized before the first pass
   BLOCK must be 64 bytes long (doesn't have to be initialized)

   BLOCK_POS holds the position after the last byte that
   was written to BLOCK. This is updated and returned.
*/
uint8_t sha256_add_input(const char* input, uint64_t input_len,
                         uint32_t* hash_buffer, void* block, uint8_t block_pos)
{
	uint64_t i;

	for (i = 0; i < input_len; i++) {
		((char*)block)[block_pos] = input[i];
		block_pos++;
		if (block_pos == 64) {
			sha256_digest_block(block, hash_buffer);
			block_pos = 0;
		}
	}

	return block_pos;
}

/* Calculates final hash
   TOTAL_INPUT_LEN is in bytes
   HASH_BUFFER must be 32 bytes long
   BLOCK must be 64 bytes long
   Final hash is returned in HASH_BUFFER
*/
void sha256_finish(uint64_t total_input_len, void* block,
                    uint8_t block_pos, uint32_t* hash_buffer)
{
	// Append 1 bit to end of input
	((uint8_t*)block)[block_pos] = 0x80;
	block_pos++;

	// Pad with zeros if needed
	for (; block_pos < 56; block_pos++)
		((char*)block)[block_pos] = 0;

	if (block_pos > 56) {
		// Pad end of block
		for (; block_pos < 64; block_pos++)
			((char*)block)[block_pos] = 0;
        
		sha256_digest_block(block, hash_buffer);

		((uint64_t*)block)[0] = 0;
		((uint64_t*)block)[1] = 0;
		((uint64_t*)block)[2] = 0;
		((uint64_t*)block)[3] = 0;
		((uint64_t*)block)[4] = 0;
		((uint64_t*)block)[5] = 0;
		((uint64_t*)block)[6] = 0;
	}

	// Write message length in bits to end of block
	((uint64_t*)block)[7] = SWAP64(total_input_len << 3);

	sha256_digest_block(block, hash_buffer);

	// Need to swap bytes if little endian
	hash_buffer[0] = SWAP32(hash_buffer[0]);
	hash_buffer[1] = SWAP32(hash_buffer[1]);
	hash_buffer[2] = SWAP32(hash_buffer[2]);
	hash_buffer[3] = SWAP32(hash_buffer[3]);
	hash_buffer[4] = SWAP32(hash_buffer[4]);
	hash_buffer[5] = SWAP32(hash_buffer[5]);
	hash_buffer[6] = SWAP32(hash_buffer[6]);
	hash_buffer[7] = SWAP32(hash_buffer[7]);
}

/* All-in-one SHA-256 function
   Use when you have only one pointer to message
   INPUT_LEN is length of INPUT in bytes
   HASH_BUFFER must be an array of 32 bytes
   Final hash is returned in HASH_BUFFER
*/
void sha256(const char* input, uint64_t input_len, uint32_t* hash_buffer)
{
	char block[64];
	uint64_t i;
	uint8_t block_pos = 0;

	hash_buffer[0] = 0x6a09e667;
	hash_buffer[1] = 0xbb67ae85;
	hash_buffer[2] = 0x3c6ef372;
	hash_buffer[3] = 0xa54ff53a;
	hash_buffer[4] = 0x510e527f;
	hash_buffer[5] = 0x9b05688c;
	hash_buffer[6] = 0x1f83d9ab;
	hash_buffer[7] = 0x5be0cd19;	

	for (i = 0; i < input_len; i++) {
		block[block_pos] = input[i];
		block_pos++;
		if (block_pos == 64) {
			sha256_digest_block((uint32_t*)block, hash_buffer);
			block_pos = 0;
		}
	}

	// Append 1 bit to end of input
	block[block_pos] = 0x80;
	block_pos++;

	// Pad block with zeros if needed
	for (; block_pos < 56; block_pos++)
		block[block_pos] = 0;

	if (block_pos > 56) {
		// Pad end of block
		for (; block_pos < 64; block_pos++)
			block[block_pos] = 0;

		sha256_digest_block((uint32_t*)block, hash_buffer);

		((uint64_t*)block)[0] = 0;
		((uint64_t*)block)[1] = 0;
		((uint64_t*)block)[2] = 0;
		((uint64_t*)block)[3] = 0;
		((uint64_t*)block)[4] = 0;
		((uint64_t*)block)[5] = 0;
		((uint64_t*)block)[6] = 0;
	}

	// Write message length in bits to end of block
	((uint64_t*)block)[7] = SWAP64(input_len << 3);

	sha256_digest_block((uint32_t*)block, hash_buffer);

	// Need to swap bytes if little endian
	hash_buffer[0] = SWAP32(hash_buffer[0]);
	hash_buffer[1] = SWAP32(hash_buffer[1]);
	hash_buffer[2] = SWAP32(hash_buffer[2]);
	hash_buffer[3] = SWAP32(hash_buffer[3]);
	hash_buffer[4] = SWAP32(hash_buffer[4]);
	hash_buffer[5] = SWAP32(hash_buffer[5]);
	hash_buffer[6] = SWAP32(hash_buffer[6]);
	hash_buffer[7] = SWAP32(hash_buffer[7]);	
}

#endif
