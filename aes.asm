section .text
global aes_encrypt_block
; TODO: Implement expand (AES key expansion)
aes_encrypt_block:
	movss xmm0, [rdi]
	call expand
	; Implement rounds
