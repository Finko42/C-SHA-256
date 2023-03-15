/* SHA-256 implementation according to FIPS 180-4

   This implementation uses malloc to allocate enough blocks for hashing the
   message.

   This header file contains one function:
   uint8_t sha256(const void* input, uint64_t input_len, uint32_t* hash_buffer)

   Call this function with INPUT being the array of data you want to hash,
   INPUT_LEN being the length of INPUT in bytes, and HASH_BUFFER being an
   array of 32 bytes. HASH_BUFFER will contain the final hash when the function
   returns. The function's return value will be 0 if successful or 1 if there
   was a memory error.

   See sha256.h for more details and an implementation that doesn't use malloc.
*/

#ifndef SHA256_MALLOC_H
#define SHA256_MALLOC_H

#include <stdint.h>
#include <stdlib.h>

/* Need to swap bytes sometimes if little endian
   This catches all modern GCCs (>= 4.6) and Clang (>=3.2) */
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
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
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


/* HASH_BUFFER must be an array of 32 bytes
   INPUT_LEN is length of INPUT in bytes
   Final hash is returned in HASH_BUFFER
   Returns 0 if successful, 1 if memory error
*/
uint8_t sha256_malloc(const void* input, uint64_t input_len, uint32_t* hash_buffer)
{       
	// Calculate number of bytes of blocks
	uint64_t blocks_size = 64 + ((input_len + 8) & ~63);
	void* blocks = malloc(blocks_size);
	if (!blocks)
		return 1;

	uint64_t i;

	// Write 64-bit words to blocks
	uint64_t t = input_len >> 3;
	for (i = 0; i < t; i++)
		((uint64_t*)blocks)[i] = ((uint64_t*)input)[i];

	// Write 32-bit word to blocks
	if ((input_len & 7) >= 4) {
		i = (input_len & ~7) >> 2;
		((uint32_t*)blocks)[i] = ((uint32_t*)input)[i];
	}

	// Write 16-bit word to blocks
	if ((input_len & 3) >= 2) {
		i = (input_len & ~3) >> 1;
		((uint16_t*)blocks)[i] = ((uint16_t*)input)[i];
	}

	// Write byte to blocks
	if (input_len & 1) {
		i = input_len & ~1;
		((uint8_t*)blocks)[i] = ((uint8_t*)input)[i];
	}

	// Append 1 bit to end of input
	((uint8_t*)blocks)[input_len] = 0x80;

	// Pad block with zeros if needed
	for (i = input_len + 1; (i & 63) != 56; i++)
		((uint8_t*)blocks)[i] = 0;

	// Write message length in bits to end of block
	((uint64_t*)blocks)[i >> 3] = SWAP64(input_len << 3);

	uint32_t a, b, c, d, e, f, g, h, T1, T2;
	uint32_t a_save, b_save, c_save, d_save, e_save, f_save, g_save, h_save;
	uint32_t W[16];

	// Initialize with constants from FIPS 180-4: 5.3.3
	a = 0x6a09e667;
	b = 0xbb67ae85;
	c = 0x3c6ef372;
	d = 0xa54ff53a;
	e = 0x510e527f;
	f = 0x9b05688c;
	g = 0x1f83d9ab;
	h = 0x5be0cd19;	

	// Main computation as outlined in FIPS 180-4: 6.2.2
	blocks_size >>= 2;
	for (i = 0; i < blocks_size; i += 16) {

		a_save = a;
		b_save = b;
		c_save = c;
		d_save = d;
		e_save = e;
		f_save = f;
		g_save = g;
		h_save = h;

		for (t = 0; t < 16; t++) {
			T1 = SWAP32(((uint32_t*)blocks)[i+t]);
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

		a += a_save;
		b += b_save;
		c += c_save;
		d += d_save;
		e += e_save;
		f += f_save;
		g += g_save;
		h += h_save;
	}

	free(blocks);

	hash_buffer[0] = SWAP32(a);
	hash_buffer[1] = SWAP32(b);
	hash_buffer[2] = SWAP32(c);
	hash_buffer[3] = SWAP32(d);
	hash_buffer[4] = SWAP32(e);
	hash_buffer[5] = SWAP32(f);
	hash_buffer[6] = SWAP32(g);
	hash_buffer[7] = SWAP32(h);

	return 0;
}

#endif
