#include "commands.h"

/* Stack buffer size is tuned exactly to be able to ovrwrite 30 out of 32 bytes
 * of pub key with patch data, and the last 2 bytes with the first 2 bytes of
 * signature, so that a small 2-byte bruteforce is needed.
 */
#define STACK_FRAME_SIZE     (0x100 - 0x10) // 0x10 for retaddr + saved RBP
#define PATCH_SIGNATURE_SIZE 64
#define PATCH_MAX_SIZE       62
#define BUF_SIZE             PATCH_MAX_SIZE + PATCH_SIGNATURE_SIZE

.if PATCH_MAX_SIZE > 0xff
.error "bad max patch size"
.endif

.if BUF_SIZE > STACK_FRAME_SIZE
.error "bad stack frame setup"
.endif

/* Offsets from RSP */
#define BUF   0
#define PATCH (BUF + 0)
#define SIG   (BUF + PATCH_MAX_SIZE)

.macro _err fmt
	// strerror(-rax)
	neg  %rax
	mov  %rax, %rdi
	call strerror

	// errx(1, fmt, strerror(-rax))
	movl $1, %edi
	lea  \fmt(%rip), %rsi
	mov  %rax, %rdx
	xor  %eax, %eax
	call perror
	ud2
.endm

.macro _errx msg
	// errx(1, msg)
	movl $1, %edi
	lea  \msg(%rip), %rsi
	mov  %rax, %rdx
	xor  %eax, %eax
	call errx
	ud2
.endm

.section .rodata
msg_err_read:
	.asciz "read failed"
msg_err_invalid_cmd:
	.asciz "invalid command"
msg_err_invalid_patch_size:
	.asciz "invalid patch size"

.section .text

/**
 * void *worker(void *);
 *
 * Worker thread handling the main command loop. Need precise control of the
 * stack frame size, so let's have fun with some x86 asm...
 */
.globl worker
.type worker,@function
worker:
	push    %rbp
	mov     %rsp, %rbp
	sub     $STACK_FRAME_SIZE, %rsp
	and     $-0x10, %rsp

.Lnext:
	/* read(0, buf, 1) */
	mov     $0, %edi
	lea     BUF(%rsp), %rsi
	mov     $1, %edx
	call    read
	test    %rax, %rax
	js      .Lerr_read
	jz      .Lout /* EOF, bail out */

	/* Switch over command opcode (1 byte) */
	movb    BUF(%rsp), %al
	movzx   %al, %eax
	cmp     $CMD_TELEMETRY_MAX, %eax
	jbe     .Lcmd_telemetry
	cmp     $CMD_PATCH, %eax
	je      .Lcmd_patch
	cmp     $CMD_RESET, %eax
	je      .Lcmd_reset

	/* Invalid command, print error and bail out */
	lea     msg_err_invalid_cmd(%rip), %rdi
	call    puts
	jmp     .Lout

.Lcmd_telemetry:
	/* Save cmd in callee-saved reg */
	mov     %eax, %ebx

	/* Read in row index (4 bytes, big endian) */
	mov     $0, %edi
	lea     BUF(%rsp), %rsi
	mov     $4, %edx
	call    read
	test    %rax, %rax
	js      .Lerr_read
	jz      .Lout /* EOF, bail out */
	cmp     $4, %rax
	jne     .Lout /* short read, bail out */

	/* handle_telemetry(cmd, row_index) */
	mov     %ebx, %edi
	movl    BUF(%rsp), %esi
	bswap   %esi
	call    handle_telemetry
	jmp     .Lnext

.Lcmd_patch:
	/* Read in patch offset (4 bytes, big endian) */
	mov     $0, %edi
	lea     BUF(%rsp), %rsi
	mov     $4, %edx
	call    read
	test    %rax, %rax
	js      .Lerr_read
	jz      .Lout /* EOF, bail out */
	cmp     $4, %rax
	jne     .Lout /* short read, bail out */

	/* Save offset in callee-saved reg */
	movl    BUF(%rsp), %ebx
	bswap   %ebx

	/* Read in patch size (1 byte) */
	mov     $0, %edi
	lea     BUF(%rsp), %rsi
	mov     $1, %edx
	call    read
	test    %rax, %rax
	js      .Lerr_read
	jz      .Lout /* EOF, bail out */

	/* Validate size */
	movb    BUF(%rsp), %al
	cmp     $PATCH_MAX_SIZE, %al
	ja      .Lerr_invalid_patch_size

	/* Save size in callee-saved reg */
	movzx   %al, %r12d

	/* Read patch in stack buf (given user size) */
	mov     $0, %edi
	lea     PATCH(%rsp), %rsi
	mov     %r12, %rdx
	call    read
	test    %rax, %rax
	js      .Lerr_read
	jz      .Lout /* EOF, bail out */
	cmp     %r12, %rax
	jne     .Lout /* short read, bail out */

	/* Read signature in stack buf (PATCH_SIGNATURE_SIZE bytes) */
	mov     $0, %edi
	lea     SIG(%rsp), %rsi
	mov     $PATCH_SIGNATURE_SIZE, %edx
	call    read
	test    %rax, %rax
	js      .Lerr_read
	jz      .Lout /* EOF, bail out */
	cmp     $PATCH_SIGNATURE_SIZE, %rax
	jne     .Lout /* short read, bail out */

	/* handle_patch(offset, buf, size, signature) */
	mov     %rbx, %rdi
	lea     PATCH(%rsp), %rsi
	mov     %r12, %rdx
	lea     SIG(%rsp), %rcx
	call    handle_patch
	jmp    .Lnext

.Lcmd_reset:
	call    telemetry_reset
	/* BUG: re-invoke ourselves. This can cause a stack overflow. */
	xor    %edi, %edi
	call   worker
	jmp    .Lout

.Lerr_read:
	lea    msg_err_read(%rip), %rdi
	call   perror_stdout
	jmp    .Lout

.Lerr_invalid_patch_size:
	lea    msg_err_invalid_patch_size(%rip), %rdi
	call   puts

.Lout:
	xor    %eax, %eax
	leave
	ret
