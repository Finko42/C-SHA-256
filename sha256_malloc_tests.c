#include <stdio.h>
#include "sha256_malloc.h"

char str_cmp(const char* s1, const char* s2)
{
	unsigned char c1, c2;
	do {
		c1 = *s1++;
		c2 = *s2++;
	} while (c1 == c2 && c1);

	return c1 - c2;
}

void bin2hex(const uint8_t* buf, char* hex_str)
{
	const char* HEX_TABLE = "0123456789abcdef";

	uint8_t i;
	for (i = -32; i; i++) {
		*hex_str = HEX_TABLE[*buf >> 4];
		hex_str++;
		*hex_str = HEX_TABLE[*buf & 0xf];
		buf++;
		hex_str++;
	}
}

struct Test {
	char* mesg;
	uint64_t len;
	char* hash;
};

#define TEST_CNT 10

int main()
{
	uint8_t hash[32];
	char hex_buf[65];
	uint8_t i;
	hex_buf[64] = 0;

	const struct Test tests[TEST_CNT] =
	{
		{ "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "A", 1, "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd" },
		{ "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ "_w3o8<w3ZutTPuana|nuiu4evuetnveuyseiul*&*&r::KFSJ:WF:JA", 55, "75ef7ae4d9f3c26770e575ef178eb6e32ea94946513bd596c99d9c21b0dcef74" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
		{ "ciaurenutge+siuRwmiar38n4y7tw9pqKwant[.pm.,pe04p:94y5?m8$", 57, "2c3c74ba1118d7f78d31c1682cceb308897e033873197d6765be5567b7ce69d9" },
		{ "(*(&%i%_einuenisieue4[v4e,i[[.,.i[cubwtuewvneop4evmppoiwnai^&&^", 63, "3343de7d5f675634695b120278fccd89ad90f93a543cfa8585df40362ef32003" },
		{ "u~38w3903q930()*&ILULLL{YRDowinue#rwuoeNPIY^RM%ow*eteoGn;e[ese]!",
		   64, "101d8af68f58c935bc756a62c9ebb56d555b99b90b240d0c06b8cfcb14931b8f" },
		{ "c3n8t9t48n39w03'p4wtvnu4wpt9awpcrnopp9yunyjiqewoiTREYW#UK&O(:PP=?PU&PC@*Co;wvo4vnv",
		   82, "eb980bd51a4d6714a0b061ef5b1bc7c0bf30ce116ee947a487ed4ee5a33f138d" },
		{ "wo3avw4con84wtno4vwyon8u3vs&OT*TV^VE%U({M{awcam[5m[a;o}_+)}}){_qt7wparasDYRTVYVU<)IMNYIBTVRCWXZQ@#RCEVM)U{<o;visjhvdwm9a3(#&$GWH~10",
		  131, "edde2fd31212b9f94c4cbc2b62f300c887e4e504529eb4949c6e2a530c25aaa6" }
	};

	for (i=0; i<TEST_CNT; i++) {
		sha256_malloc(tests[i].mesg, tests[i].len, (uint32_t*)hash);

		bin2hex(hash, hex_buf);

		if (str_cmp(hex_buf, tests[i].hash)) {
			printf("Test %d failed:\nExpected: %s\nReceived: %s\n", i+1, tests[i].hash, hex_buf);
			return 1;
		}
	}

	puts("All tests successful.");
	return 0;
}
