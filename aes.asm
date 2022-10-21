section .text
global aes_encrypt_block
expand_key:
	vpshufd xmm2, xmm2, 0xff
	vpslldq xmm3, xmm1, 4
	vpxor xmm1, xmm1, xmm3
	vpslldq xmm3, xmm3, 4
	vpxor xmm1, xmm1, xmm3
	vpslldq xmm3, xmm3, 4
	vpxor xmm1, xmm1, xmm3
	vpxor xmm1, xmm1, xmm2
	ret

aes_encrypt_block:
	push rbx
	mov rbx, rdi
	vmovdqu xmm0, [rbx]
	vmovdqu xmm1, [rsi]
	vpxor xmm0, xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x01
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x02
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x04
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x08
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x10
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x20
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x40
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x80
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x1b
	call expand_key
	aesenc xmm0, xmm1
	vaeskeygenassist xmm2, xmm1, 0x36
	call expand_key
	aesenclast xmm0, xmm1
	vmovdqu [rbx], xmm0
	pop rbx
	ret
