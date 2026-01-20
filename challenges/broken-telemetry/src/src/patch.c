#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "patch.h"
#include "util.h"

extern unsigned char __executable_start[];
extern unsigned char __etext[];

// Mapped from file on first invocation
static unsigned char *pubkey;
#define PUBKEY_SIZE 32 // ed25519
#define SIGNATURE_SIZE 64 // ed25519
#define PUBKEY_FNAME "pubkey.bin"

void handle_patch(size_t offset, const unsigned char *data, size_t size,
		const unsigned char *signature)
{
	struct stat st;
	if (stat(PUBKEY_FNAME, &st) == -1) {
		perror_stdout("stat failed");
		return;
	}

	if (st.st_size != PUBKEY_SIZE) {
		// This should NOT happen!
		puts("internal error");
		return;
	}

	if (!pubkey) {
		// This will never get unmapped
		pubkey = map_file(PUBKEY_FNAME, st.st_size, 0);
		if (pubkey == NULL) {
			// Error mapping file: do nothing
			return;
		}
	}

	// Sanity check offset is within bounds (not that we really care, but still)
	const size_t mem_size = (size_t)(__etext - __executable_start);
	if (offset + size > mem_size) {
		puts("invalid patch offset");
		return;
	}

#ifdef DEBUG
	fputs("pubkey ", stdout);
	for (size_t i = 0; i < PUBKEY_SIZE; i++)
		printf("%02x", pubkey[i]);
	putchar('\n');

	fputs("patch  ", stdout);
	for (size_t i = 0; i < size; i++)
		printf("%02x", data[i]);
	putchar('\n');
#endif

	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, PUBKEY_SIZE);
	if (!pkey) {
		puts("internal crypto error 1");
		return;
	}

	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		puts("internal crypto error 2");
		goto err_free_pkey;
	}

	if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
		puts("internal crypto error 3");
		goto err_free_ctx;
	}

	if (EVP_DigestVerify(md_ctx, signature, SIGNATURE_SIZE, data, size) != 1) {
		puts("invalid patch signature");
		goto err_free_ctx;
	}

	// Patch passed signature check, apply it to memory
	unsigned char *const mem = __executable_start + ((offset / PAGE_SIZE) * PAGE_SIZE);
	const size_t page_offset = offset % PAGE_SIZE;

	// Make RWX, do not bother resetting prots later
	if (mprotect(mem, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
		perror_stdout("mprotect failed");

	// Cap size within page, couldn't be bothered to deal with special cases
	const size_t max_size = PAGE_SIZE - page_offset;
	if (size > max_size)
		size = max_size;

	fputs("base station applied system patch\n", stderr);
	memmove(&mem[page_offset], data, size);
	puts("patch applied");

err_free_ctx:
	EVP_MD_CTX_free(md_ctx);
err_free_pkey:
	EVP_PKEY_free(pkey);
}
