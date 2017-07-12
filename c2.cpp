#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <getopt.h>
#include <cerrno>

using namespace std;

#define ROUNDS 32
#define BLOCK_LEN 16
#define KEY_LEN 32
#define GOLDEN_RATIO 0x9E3779B9L

#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define HI_NIBBLE(b) (((b) >> 4) & 0x0F)
#define LO_NIBBLE(b) ((b) & 0x0F)

typedef union _serpent_blk_t {
    uint8_t b[BLOCK_LEN];
    uint32_t w[BLOCK_LEN/4];
    uint64_t q[BLOCK_LEN/2];
} serpent_blk;

typedef uint32_t serpent_subkey_t[4];

typedef struct serpent_key_t {
    serpent_subkey_t x[ROUNDS+1];
} serpent_key;

void permute(serpent_blk* out, serpent_blk* in, bool initial) {
    uint8_t carry;

    for (int i = 0; i < BLOCK_LEN / 4; i++) {
        out->w[i] = 0;
    }

    if (initial) {
        for (int i = 0; i < BLOCK_LEN; i++) {
            for (int j = 0; j < BLOCK_LEN / 2; j++) {
                carry = in->w[j % 4] & 1;
                in->w[j % 4] >>= 1;
                out->b[i] = (carry << 7) | (out->b[i] >> 1);
            }
        }
    } else {
        for (int i = 0; i < BLOCK_LEN / 4; i++) {
            for (int j = 0; j < BLOCK_LEN * 2; j++) {
                carry = in->w[i] & 1;
                in->w[i] >>= 1;
                out->w[j % 4] = (carry << 31) | (out->w[j % 4] >> 1);
            }
        }
    }
}

void subbytes (serpent_blk *blk, uint32_t box_idx, bool encryption)
{
    serpent_blk tmp_blk, sb;
    uint8_t *sbp;
    uint8_t i, t;

    uint8_t sbox[8][8] =
        { { 0x83, 0x1F, 0x6A, 0xB5, 0xDE, 0x24, 0x07, 0xC9 },
          { 0xCF, 0x72, 0x09, 0xA5, 0xB1, 0x8E, 0xD6, 0x43 },
          { 0x68, 0x97, 0xC3, 0xFA, 0x1D, 0x4E, 0xB0, 0x25 },
          { 0xF0, 0x8B, 0x9C, 0x36, 0x1D, 0x42, 0x7A, 0xE5 },
          { 0xF1, 0x38, 0x0C, 0x6B, 0x52, 0xA4, 0xE9, 0xD7 },
          { 0x5F, 0xB2, 0xA4, 0xC9, 0x30, 0x8E, 0x6D, 0x17 },
          { 0x27, 0x5C, 0x48, 0xB6, 0x9E, 0xF1, 0x3D, 0x0A },
          { 0xD1, 0x0F, 0x8E, 0xB2, 0x47, 0xAC, 0x39, 0x65 }
        };

    uint8_t sbox_inv[8][8] =
        { { 0x3D, 0x0B, 0x6A, 0xC5, 0xE1, 0x74, 0x9F, 0x28 },
          { 0x85, 0xE2, 0x6F, 0x3C, 0x4B, 0x97, 0xD1, 0x0A },
          { 0x9C, 0x4F, 0xEB, 0x21, 0x30, 0xD6, 0x85, 0x7A },
          { 0x90, 0x7A, 0xEB, 0xD6, 0x53, 0x2C, 0x84, 0x1F },
          { 0x05, 0x38, 0x9A, 0xE7, 0xC2, 0x6B, 0xF4, 0x1D },
          { 0xF8, 0x92, 0x14, 0xED, 0x6B, 0x35, 0xC7, 0x0A },
          { 0xAF, 0xD1, 0x35, 0x06, 0x94, 0x7E, 0xC2, 0xB8 },
          { 0x03, 0xD6, 0xE9, 0x8F, 0xC5, 0x7B, 0x1A, 0x24 }
        };

    box_idx &= 7;

    if (encryption) {
      sbp=(uint8_t*)&sbox[box_idx][0];
    } else {
        sbp=(uint8_t*)&sbox_inv[box_idx][0];
    }

    for (i=0; i<16; i+=2) {
        t = sbp[i/2];
        sb.b[i+0] = LO_NIBBLE(t);
        sb.b[i+1] = HI_NIBBLE(t);
    }

    permute (&tmp_blk, blk, true);

    for (i = 0; i < BLOCK_LEN; i++) {
        t = tmp_blk.b[i];
        tmp_blk.b[i] = (sb.b[HI_NIBBLE(t)] << 4) | sb.b[LO_NIBBLE(t)];
    }

    permute (blk, &tmp_blk, false);
}

void whiten(serpent_blk *dst, serpent_key *key, int idx) {
    for (int i = 0; i < BLOCK_LEN / 4; i++) {
        dst->w[i] ^= key->x[idx][i];
    }
}

void linear_trans(serpent_blk* output, bool encryption) {
    uint32_t x0 = output->w[0];
    uint32_t x1 = output->w[1];
    uint32_t x2 = output->w[2];
    uint32_t x3 = output->w[3];

    if (encryption) {
        x2 = ROTL32(x2, 10);
        x0 = ROTR32(x0, 5);
        x2 ^= x3 ^ (x1 << 7);
        x0 ^= x1 ^ x3;
        x3 = ROTR32(x3, 7);
        x1 = ROTR32(x1, 1);
        x3 ^= x2 ^ (x0 << 3);
        x1 ^= x0 ^ x2;
        x2 = ROTR32(x2,  3);
        x0 = ROTR32(x0, 13);
    } else {
        x0 = ROTL32(x0, 13);
        x2 = ROTL32(x2,  3);
        x1 ^= x0 ^ x2;
        x3 ^= x2 ^ (x0 << 3);
        x1 = ROTL32(x1, 1);
        x3 = ROTL32(x3, 7);
        x0 ^= x1 ^ x3;
        x2 ^= x3 ^ (x1 << 7);
        x0 = ROTL32(x0, 5);
        x2 = ROTR32(x2, 10);
    }

    output->w[0] = x0;
    output->w[1] = x1;
    output->w[2] = x2;
    output->w[3] = x3;
}

uint32_t gen_w (uint32_t *b, uint32_t i) {
    uint32_t ret;
    ret = b[0] ^ b[3] ^ b[5] ^ b[7] ^ GOLDEN_RATIO ^ i;
    return ROTL32(ret, 11);
}

void key_setup (serpent_key *key, void *input)
{
    union {
        uint8_t b[32];
        uint32_t w[8];
    } s_ws;

    uint32_t i, j;

    // copy key input to local buffer
    memcpy (&s_ws.b[0], input, KEY_LEN);

    // expand the key
    for (i=0; i<=ROUNDS; i++) {
        for (j=0; j<4; j++) {
            key->x[i][j] = gen_w (s_ws.w, i*4+j);
            memmove (&s_ws.b, &s_ws.b[4], 7*4);
            s_ws.w[7] = key->x[i][j];
        }

        subbytes((serpent_blk*)&key->x[i], 3 - i, true);
    }
}

size_t hex2bin (void *bin, const char hex[]) {
    size_t len, i;
    int x;
    uint8_t *p=(uint8_t*)bin;

    len = strlen (hex);

    if ((len & 1) != 0) {
        return 0;
    }

    for (i=0; i<len; i++) {
        if (isxdigit((int)hex[i]) == 0) {
            return 0;
        }
    }

    for (i=0; i<len / 2; i++) {
        sscanf (&hex[i * 2], "%2x", &x);
        p[i] = (uint8_t)x;
    }
    return len / 2;
}

void dump_hex (uint8_t bin[], int len)
{
    for (int i = 0; i < len; i++) {
        printf ("%02x", bin[i]);
    }
}

void dump_str(uint8_t bin[], int len) {
    for (int i = 0; i < len; i++) {
        printf ("%c", bin[i]);
    }
}

void encrypt(serpent_blk* blk, serpent_key* key) {
    // repeat 32 rounds (0 - 31)
    for (int i = 0; i < ROUNDS; i++) {
        whiten(blk, key, i);
        subbytes(blk, i, true);
        if (i < ROUNDS - 1) {
            // final round, no linear trans
            linear_trans(blk, true);
        }
    }
    whiten(blk, key, ROUNDS);
}

void decrypt(serpent_blk* blk, serpent_key* key) {
    // round 31 - 0 (inverse)
    whiten(blk, key, ROUNDS);
    for (int i = ROUNDS - 1; i >= 0; i--) {
        subbytes(blk, i, false);
        whiten(blk, key, i);
        if (i != 0) {
            // final round (round 0)
            linear_trans(blk, false);
        }
    }
}

void generate(uint8_t key[64]) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 64; i++) {
        key[i] = rand() % 256;
    }
}

int main(int argc, char* argv[]) {
    char* message;
	char* key_input;
	int c;
    bool random_key_flag = false, key_flag = false, encrypt_flag = false, decrypt_flag = false;
    serpent_blk blk;
    uint8_t key[64];
    serpent_key skey;

	while (1) {
		static struct option long_options[] = {
            {"generate", no_argument, 0, 'g'},
            {"encrypt", required_argument, 0, 'e'},
            {"decrypt", required_argument, 0, 'd'},
            {"key", required_argument, 0, 'k'},
            {0, 0, 0, 0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "ge:d:k:", long_options, &option_index);
		if (c == -1)
			break;
		if (c == 'g') {
			random_key_flag = true;
		}
		if (c == 'e') {
			message = optarg;
			encrypt_flag = true;
		}
		if (c == 'd') {
			message = optarg;
			decrypt_flag = true;
		}
		if (c == 'k') {
            key_flag = true;
			key_input = optarg;
		}
	}

    if (random_key_flag) {
        generate(key);
        dump_hex(key, 32);
        return 0;
    }

    memset(key, 0, sizeof(key));
    if (key_flag) {
        if (strlen(key_input) % 64 != 0) {
            cout << "Key length must be 256-bit." << endl;
            return 0;
        } else {
            hex2bin(key, key_input);
        }
    } else {
        generate(key);
    }

    if (encrypt_flag) {
        key_setup(&skey, key);
        for (int i = 0; i < strlen(message); i += 16) {
            for (int j = 0; j < 16; j++) {
                if ((i + j) >= strlen(message)) {
                    blk.b[j] = 0;
                } else {
                    blk.b[j] = message[i + j];
                }
            }
            //dump_str(blk.b, 16);
            //cout << endl;
            //dump_hex(blk.b, 16);
            //cout << endl;
            encrypt(&blk, &skey);
            dump_hex(blk.b, 16);
            //cout << endl;
        }
        cout << endl;
    }

    if (decrypt_flag) {
        key_setup(&skey, key);
        for (int i = 0; i < strlen(message); i += 32) {
            for (int j = 0; j < 32; j += 2) {
                char c[3];
                c[0] = message[i + j];
                c[1] = message[i + j + 1];
                c[2] = '\0';
                blk.b[j / 2] = strtol(c, NULL, 16);
            }
            //dump_hex(blk.b, 16);
            decrypt(&blk, &skey);
            dump_str(blk.b, 16);
        }
        cout << endl;
    }
    return 0;
}
