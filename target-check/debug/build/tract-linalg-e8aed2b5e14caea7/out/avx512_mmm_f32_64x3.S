



_text segment
avx512_mmm_f32_64x3_0_21_10 proc



    push        rbp
    mov         rbp, rsp


; https:;www.agner.org/optimize/calling_conventions.pdf xmm6-15 are not scratch
; https:;stackoverflow.com/questions/43358429/save-value-of-xmm-registers
    and rsp,-16
    lea rsp,[rsp-160]
    vmovaps [rsp], xmm6
    vmovaps [rsp+16*1],xmm7
    vmovaps [rsp+16*2],xmm8
    vmovaps [rsp+16*3],xmm9
    vmovaps [rsp+16*4],xmm10
    vmovaps [rsp+16*5],xmm11
    vmovaps [rsp+16*6],xmm12
    vmovaps [rsp+16*7],xmm13
    vmovaps [rsp+16*8],xmm14
    vmovaps [rsp+16*9],xmm15

    push        rdi
    push        rsi

    mov         rdi, rcx



    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15

    sub         rsp, 8


    stmxcsr     [rsp + 4]

    mov         rax, 1FC0h

    mov         [rsp], eax
    ldmxcsr     [rsp]

; vim: set syntax=asm :

non_linear:

non_linear_loop_enter:
    sub     rdi,    40
non_linear_loop:
    add     rdi,    40
    mov     rax,    [rdi]

    mov     r8, 29
    cmp     rax, 0
    cmovl   rax, r8
    cmp     rax, 29
    cmovg   rax, r8


    lea     r8, [ offset jmp_table ]

    movsxd  r9, dword ptr [ r8 + rax * 4 ]
    lea     r8, [ r8 + r9 ]
    jmp     r8

jmp_table:

    dd      done-jmp_table

    dd      clear-jmp_table

    dd      load_tile-jmp_table

    dd      scalar_min-jmp_table

    dd      scalar_max-jmp_table

    dd      scalar_add-jmp_table

    dd      scalar_mul-jmp_table

    dd      scalar_sub-jmp_table

    dd      scalar_sub_flipped-jmp_table

    dd      leaky_relu-jmp_table

    dd      per_row_min-jmp_table

    dd      per_row_max-jmp_table

    dd      per_row_add-jmp_table

    dd      per_row_mul-jmp_table

    dd      per_row_sub-jmp_table

    dd      per_row_sub_flipped-jmp_table

    dd      per_col_min-jmp_table

    dd      per_col_max-jmp_table

    dd      per_col_add-jmp_table

    dd      per_col_mul-jmp_table

    dd      per_col_sub-jmp_table

    dd      per_col_sub_flipped-jmp_table

    dd      q_scale-jmp_table

    dd      q_shr-jmp_table

    dd      q_shl-jmp_table

    dd      add_unicast-jmp_table

    dd      add_row_col_products-jmp_table

    dd      store-jmp_table

    dd      add_mat_mul-jmp_table

    dd      unsupported-jmp_table

unsupported:
    mov     rax,    1
    jmp     return


done:
    mov     rax, 0
    jmp     return


clear:
    vzeroall
    jmp     non_linear_loop

add_mat_mul:
    mov     rcx,    [rdi + 24]   ; B
    mov     rax,    [rdi + 16]   ; A

    mov     rbx,    [rdi + 8]    ; k
    test    rbx,    rbx
    jz      non_linear_loop

main_loop_packed_packed:
		; Tile size: 4x3
	; Accumulators: 0-11
	; Col regs: zmm12
	; Row regs: zmm13-15

	; Load col of A
	vmovaps			zmm12,	[rax]

	; Fill 3 cols of B
	vbroadcastss	zmm13,	dword ptr [rcx + 0]
	vbroadcastss	zmm14,	dword ptr [rcx + 4]
	vbroadcastss	zmm15,	dword ptr [rcx + 8]

	; N.B. Stepping cols in inner loop
	vfmadd231ps		zmm0,	zmm12, zmm13
	vfmadd231ps		zmm4,	zmm12, zmm14
	vfmadd231ps		zmm8,	zmm12, zmm15

	vmovaps			zmm12,	[rax+64]

	vfmadd231ps		zmm1,	zmm12, zmm13
	vfmadd231ps		zmm5,	zmm12, zmm14
	vfmadd231ps		zmm9,	zmm12, zmm15

	vmovaps			zmm12,	[rax+128]

	vfmadd231ps		zmm2,	zmm12, zmm13
	vfmadd231ps		zmm6,	zmm12, zmm14
	vfmadd231ps		zmm10,	 zmm12, zmm15

	vmovaps			zmm12,	[rax+192]

	vfmadd231ps		zmm3,	zmm12, zmm13
	vfmadd231ps		zmm7,	zmm12, zmm14
	vfmadd231ps		zmm11,	zmm12, zmm15

    add             rcx,    12
    add             rax,    256

    dec             rbx
    jnz             main_loop_packed_packed

    jmp             non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

scalar_min:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vminps          zmm0, zmm12, zmm0
        
            vminps          zmm1, zmm12, zmm1
        
            vminps          zmm2, zmm12, zmm2
        
            vminps          zmm3, zmm12, zmm3
        
            vminps          zmm4, zmm12, zmm4
        
            vminps          zmm5, zmm12, zmm5
        
            vminps          zmm6, zmm12, zmm6
        
            vminps          zmm7, zmm12, zmm7
        
            vminps          zmm8, zmm12, zmm8
        
            vminps          zmm9, zmm12, zmm9
        
            vminps          zmm10, zmm12, zmm10
        
            vminps          zmm11, zmm12, zmm11
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_max:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vmaxps          zmm0, zmm12, zmm0
        
            vmaxps          zmm1, zmm12, zmm1
        
            vmaxps          zmm2, zmm12, zmm2
        
            vmaxps          zmm3, zmm12, zmm3
        
            vmaxps          zmm4, zmm12, zmm4
        
            vmaxps          zmm5, zmm12, zmm5
        
            vmaxps          zmm6, zmm12, zmm6
        
            vmaxps          zmm7, zmm12, zmm7
        
            vmaxps          zmm8, zmm12, zmm8
        
            vmaxps          zmm9, zmm12, zmm9
        
            vmaxps          zmm10, zmm12, zmm10
        
            vmaxps          zmm11, zmm12, zmm11
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_add:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vaddps          zmm0, zmm12, zmm0
        
            vaddps          zmm1, zmm12, zmm1
        
            vaddps          zmm2, zmm12, zmm2
        
            vaddps          zmm3, zmm12, zmm3
        
            vaddps          zmm4, zmm12, zmm4
        
            vaddps          zmm5, zmm12, zmm5
        
            vaddps          zmm6, zmm12, zmm6
        
            vaddps          zmm7, zmm12, zmm7
        
            vaddps          zmm8, zmm12, zmm8
        
            vaddps          zmm9, zmm12, zmm9
        
            vaddps          zmm10, zmm12, zmm10
        
            vaddps          zmm11, zmm12, zmm11
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_mul:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vmulps          zmm0, zmm12, zmm0
        
            vmulps          zmm1, zmm12, zmm1
        
            vmulps          zmm2, zmm12, zmm2
        
            vmulps          zmm3, zmm12, zmm3
        
            vmulps          zmm4, zmm12, zmm4
        
            vmulps          zmm5, zmm12, zmm5
        
            vmulps          zmm6, zmm12, zmm6
        
            vmulps          zmm7, zmm12, zmm7
        
            vmulps          zmm8, zmm12, zmm8
        
            vmulps          zmm9, zmm12, zmm9
        
            vmulps          zmm10, zmm12, zmm10
        
            vmulps          zmm11, zmm12, zmm11
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vsubps          zmm0, zmm12, zmm0
        
            vsubps          zmm1, zmm12, zmm1
        
            vsubps          zmm2, zmm12, zmm2
        
            vsubps          zmm3, zmm12, zmm3
        
            vsubps          zmm4, zmm12, zmm4
        
            vsubps          zmm5, zmm12, zmm5
        
            vsubps          zmm6, zmm12, zmm6
        
            vsubps          zmm7, zmm12, zmm7
        
            vsubps          zmm8, zmm12, zmm8
        
            vsubps          zmm9, zmm12, zmm9
        
            vsubps          zmm10, zmm12, zmm10
        
            vsubps          zmm11, zmm12, zmm11
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub_flipped:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vsubps          zmm0, zmm0, zmm12
        
            vsubps          zmm1, zmm1, zmm12
        
            vsubps          zmm2, zmm2, zmm12
        
            vsubps          zmm3, zmm3, zmm12
        
            vsubps          zmm4, zmm4, zmm12
        
            vsubps          zmm5, zmm5, zmm12
        
            vsubps          zmm6, zmm6, zmm12
        
            vsubps          zmm7, zmm7, zmm12
        
            vsubps          zmm8, zmm8, zmm12
        
            vsubps          zmm9, zmm9, zmm12
        
            vsubps          zmm10, zmm10, zmm12
        
            vsubps          zmm11, zmm11, zmm12
        
    

    jmp    non_linear_loop

leaky_relu:
    ; can only use zmm12 to zmm15
    ; ymm15 <- alpha
    vbroadcastss    zmm15, dword ptr [rdi + 8]
    ; ymm14 <- all zero
    vpxorq          zmm14, zmm14, zmm14

    
        vcmpps      k1, zmm0, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm0 {k1}, zmm0, zmm15
    
        vcmpps      k1, zmm1, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm1 {k1}, zmm1, zmm15
    
        vcmpps      k1, zmm2, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm2 {k1}, zmm2, zmm15
    
        vcmpps      k1, zmm3, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm3 {k1}, zmm3, zmm15
    
        vcmpps      k1, zmm4, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm4 {k1}, zmm4, zmm15
    
        vcmpps      k1, zmm5, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm5 {k1}, zmm5, zmm15
    
        vcmpps      k1, zmm6, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm6 {k1}, zmm6, zmm15
    
        vcmpps      k1, zmm7, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm7 {k1}, zmm7, zmm15
    
        vcmpps      k1, zmm8, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm8 {k1}, zmm8, zmm15
    
        vcmpps      k1, zmm9, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm9 {k1}, zmm9, zmm15
    
        vcmpps      k1, zmm10, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm10 {k1}, zmm10, zmm15
    
        vcmpps      k1, zmm11, zmm14, 1 ; 1 means LT
        ; ymm12 <- alpha * x if < 0
        vmulps      zmm11 {k1}, zmm11, zmm15
    
    ; select muled of orginal

    jmp    non_linear_loop

q_scale:
q_shl:
q_shr:
    jmp unsupported
; vim: set syntax=asm :

; vim: set syntax=asm :

per_row_min:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm12,  [rax + 0]

    vmovups         zmm13,  [rax + 64]

    vmovups         zmm14,  [rax + 128]

    vmovups         zmm15,  [rax + 192]



    
        vminps zmm0, zmm12, zmm0
    
        vminps zmm1, zmm13, zmm1
    
        vminps zmm2, zmm14, zmm2
    
        vminps zmm3, zmm15, zmm3
    
        vminps zmm4, zmm12, zmm4
    
        vminps zmm5, zmm13, zmm5
    
        vminps zmm6, zmm14, zmm6
    
        vminps zmm7, zmm15, zmm7
    
        vminps zmm8, zmm12, zmm8
    
        vminps zmm9, zmm13, zmm9
    
        vminps zmm10, zmm14, zmm10
    
        vminps zmm11, zmm15, zmm11
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_max:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm12,  [rax + 0]

    vmovups         zmm13,  [rax + 64]

    vmovups         zmm14,  [rax + 128]

    vmovups         zmm15,  [rax + 192]



    
        vmaxps zmm0, zmm12, zmm0
    
        vmaxps zmm1, zmm13, zmm1
    
        vmaxps zmm2, zmm14, zmm2
    
        vmaxps zmm3, zmm15, zmm3
    
        vmaxps zmm4, zmm12, zmm4
    
        vmaxps zmm5, zmm13, zmm5
    
        vmaxps zmm6, zmm14, zmm6
    
        vmaxps zmm7, zmm15, zmm7
    
        vmaxps zmm8, zmm12, zmm8
    
        vmaxps zmm9, zmm13, zmm9
    
        vmaxps zmm10, zmm14, zmm10
    
        vmaxps zmm11, zmm15, zmm11
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_add:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm12,  [rax + 0]

    vmovups         zmm13,  [rax + 64]

    vmovups         zmm14,  [rax + 128]

    vmovups         zmm15,  [rax + 192]



    
        vaddps zmm0, zmm12, zmm0
    
        vaddps zmm1, zmm13, zmm1
    
        vaddps zmm2, zmm14, zmm2
    
        vaddps zmm3, zmm15, zmm3
    
        vaddps zmm4, zmm12, zmm4
    
        vaddps zmm5, zmm13, zmm5
    
        vaddps zmm6, zmm14, zmm6
    
        vaddps zmm7, zmm15, zmm7
    
        vaddps zmm8, zmm12, zmm8
    
        vaddps zmm9, zmm13, zmm9
    
        vaddps zmm10, zmm14, zmm10
    
        vaddps zmm11, zmm15, zmm11
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_mul:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm12,  [rax + 0]

    vmovups         zmm13,  [rax + 64]

    vmovups         zmm14,  [rax + 128]

    vmovups         zmm15,  [rax + 192]



    
        vmulps zmm0, zmm12, zmm0
    
        vmulps zmm1, zmm13, zmm1
    
        vmulps zmm2, zmm14, zmm2
    
        vmulps zmm3, zmm15, zmm3
    
        vmulps zmm4, zmm12, zmm4
    
        vmulps zmm5, zmm13, zmm5
    
        vmulps zmm6, zmm14, zmm6
    
        vmulps zmm7, zmm15, zmm7
    
        vmulps zmm8, zmm12, zmm8
    
        vmulps zmm9, zmm13, zmm9
    
        vmulps zmm10, zmm14, zmm10
    
        vmulps zmm11, zmm15, zmm11
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm12,  [rax + 0]

    vmovups         zmm13,  [rax + 64]

    vmovups         zmm14,  [rax + 128]

    vmovups         zmm15,  [rax + 192]



    
        vsubps zmm0, zmm12, zmm0
    
        vsubps zmm1, zmm13, zmm1
    
        vsubps zmm2, zmm14, zmm2
    
        vsubps zmm3, zmm15, zmm3
    
        vsubps zmm4, zmm12, zmm4
    
        vsubps zmm5, zmm13, zmm5
    
        vsubps zmm6, zmm14, zmm6
    
        vsubps zmm7, zmm15, zmm7
    
        vsubps zmm8, zmm12, zmm8
    
        vsubps zmm9, zmm13, zmm9
    
        vsubps zmm10, zmm14, zmm10
    
        vsubps zmm11, zmm15, zmm11
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub_flipped:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm12,  [rax + 0]

    vmovups         zmm13,  [rax + 64]

    vmovups         zmm14,  [rax + 128]

    vmovups         zmm15,  [rax + 192]



    
        vsubps zmm0, zmm0, zmm12
    
        vsubps zmm1, zmm1, zmm13
    
        vsubps zmm2, zmm2, zmm14
    
        vsubps zmm3, zmm3, zmm15
    
        vsubps zmm4, zmm4, zmm12
    
        vsubps zmm5, zmm5, zmm13
    
        vsubps zmm6, zmm6, zmm14
    
        vsubps zmm7, zmm7, zmm15
    
        vsubps zmm8, zmm8, zmm12
    
        vsubps zmm9, zmm9, zmm13
    
        vsubps zmm10, zmm10, zmm14
    
        vsubps zmm11, zmm11, zmm15
    


    jmp non_linear_loop
; vim: set syntax=asm :

; vim: set syntax=asm :

per_col_min:
    mov             rax, [ rdi + 8 ]








; 12 cols:3


    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vminps zmm0, zmm12, zmm0
        
    
        
        
            vminps zmm1, zmm12, zmm1
        
    
        
        
            vminps zmm2, zmm12, zmm2
        
    
        
        
            vminps zmm3, zmm12, zmm3
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vminps zmm4, zmm12, zmm4
        
    
        
        
            vminps zmm5, zmm12, zmm5
        
    
        
        
            vminps zmm6, zmm12, zmm6
        
    
        
        
            vminps zmm7, zmm12, zmm7
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vminps zmm8, zmm12, zmm8
        
    
        
        
            vminps zmm9, zmm12, zmm9
        
    
        
        
            vminps zmm10, zmm12, zmm10
        
    
        
        
            vminps zmm11, zmm12, zmm11
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_max:
    mov             rax, [ rdi + 8 ]








; 12 cols:3


    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmaxps zmm0, zmm12, zmm0
        
    
        
        
            vmaxps zmm1, zmm12, zmm1
        
    
        
        
            vmaxps zmm2, zmm12, zmm2
        
    
        
        
            vmaxps zmm3, zmm12, zmm3
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmaxps zmm4, zmm12, zmm4
        
    
        
        
            vmaxps zmm5, zmm12, zmm5
        
    
        
        
            vmaxps zmm6, zmm12, zmm6
        
    
        
        
            vmaxps zmm7, zmm12, zmm7
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmaxps zmm8, zmm12, zmm8
        
    
        
        
            vmaxps zmm9, zmm12, zmm9
        
    
        
        
            vmaxps zmm10, zmm12, zmm10
        
    
        
        
            vmaxps zmm11, zmm12, zmm11
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_add:
    mov             rax, [ rdi + 8 ]








; 12 cols:3


    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vaddps zmm0, zmm12, zmm0
        
    
        
        
            vaddps zmm1, zmm12, zmm1
        
    
        
        
            vaddps zmm2, zmm12, zmm2
        
    
        
        
            vaddps zmm3, zmm12, zmm3
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vaddps zmm4, zmm12, zmm4
        
    
        
        
            vaddps zmm5, zmm12, zmm5
        
    
        
        
            vaddps zmm6, zmm12, zmm6
        
    
        
        
            vaddps zmm7, zmm12, zmm7
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vaddps zmm8, zmm12, zmm8
        
    
        
        
            vaddps zmm9, zmm12, zmm9
        
    
        
        
            vaddps zmm10, zmm12, zmm10
        
    
        
        
            vaddps zmm11, zmm12, zmm11
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_mul:
    mov             rax, [ rdi + 8 ]








; 12 cols:3


    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmulps zmm0, zmm12, zmm0
        
    
        
        
            vmulps zmm1, zmm12, zmm1
        
    
        
        
            vmulps zmm2, zmm12, zmm2
        
    
        
        
            vmulps zmm3, zmm12, zmm3
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmulps zmm4, zmm12, zmm4
        
    
        
        
            vmulps zmm5, zmm12, zmm5
        
    
        
        
            vmulps zmm6, zmm12, zmm6
        
    
        
        
            vmulps zmm7, zmm12, zmm7
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmulps zmm8, zmm12, zmm8
        
    
        
        
            vmulps zmm9, zmm12, zmm9
        
    
        
        
            vmulps zmm10, zmm12, zmm10
        
    
        
        
            vmulps zmm11, zmm12, zmm11
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub:
    mov             rax, [ rdi + 8 ]








; 12 cols:3


    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm0, zmm12, zmm0
        
    
        
        
            vsubps zmm1, zmm12, zmm1
        
    
        
        
            vsubps zmm2, zmm12, zmm2
        
    
        
        
            vsubps zmm3, zmm12, zmm3
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm4, zmm12, zmm4
        
    
        
        
            vsubps zmm5, zmm12, zmm5
        
    
        
        
            vsubps zmm6, zmm12, zmm6
        
    
        
        
            vsubps zmm7, zmm12, zmm7
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm8, zmm12, zmm8
        
    
        
        
            vsubps zmm9, zmm12, zmm9
        
    
        
        
            vsubps zmm10, zmm12, zmm10
        
    
        
        
            vsubps zmm11, zmm12, zmm11
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub_flipped:
    mov             rax, [ rdi + 8 ]








; 12 cols:3


    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm0, zmm0, zmm12
        
    
        
        
            vsubps zmm1, zmm1, zmm12
        
    
        
        
            vsubps zmm2, zmm2, zmm12
        
    
        
        
            vsubps zmm3, zmm3, zmm12
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm4, zmm4, zmm12
        
    
        
        
            vsubps zmm5, zmm5, zmm12
        
    
        
        
            vsubps zmm6, zmm6, zmm12
        
    
        
        
            vsubps zmm7, zmm7, zmm12
        
    

    vbroadcastss    zmm12, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm8, zmm8, zmm12
        
    
        
        
            vsubps zmm9, zmm9, zmm12
        
    
        
        
            vsubps zmm10, zmm10, zmm12
        
    
        
        
            vsubps zmm11, zmm11, zmm12
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

load_tile:
    mov          r8, [rdi + 8]
    
        vmovups         zmm0, zmmword ptr [r8 + 0]
    
        vmovups         zmm1, zmmword ptr [r8 + 64]
    
        vmovups         zmm2, zmmword ptr [r8 + 128]
    
        vmovups         zmm3, zmmword ptr [r8 + 192]
    
        vmovups         zmm4, zmmword ptr [r8 + 256]
    
        vmovups         zmm5, zmmword ptr [r8 + 320]
    
        vmovups         zmm6, zmmword ptr [r8 + 384]
    
        vmovups         zmm7, zmmword ptr [r8 + 448]
    
        vmovups         zmm8, zmmword ptr [r8 + 512]
    
        vmovups         zmm9, zmmword ptr [r8 + 576]
    
        vmovups         zmm10, zmmword ptr [r8 + 640]
    
        vmovups         zmm11, zmmword ptr [r8 + 704]
    

    jmp    non_linear_loop

add_unicast:

    mov     r10,    [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     rbx,    [rdi + 24]          ; col stride

    mov     eax,    0


    pinsrd  xmm14, eax, 0
    add     eax,    esi

    pinsrd  xmm14, eax, 1
    add     eax,    esi

    pinsrd  xmm14, eax, 2
    add     eax,    esi

    pinsrd  xmm14, eax, 3
    add     eax,    esi


    pinsrd  xmm15, eax, 0
    add     eax,    esi

    pinsrd  xmm15, eax, 1
    add     eax,    esi

    pinsrd  xmm15, eax, 2
    add     eax,    esi

    pinsrd  xmm15, eax, 3
    add     eax,    esi


    pinsrd  xmm12, eax, 0
    add     eax,    esi

    pinsrd  xmm12, eax, 1
    add     eax,    esi

    pinsrd  xmm12, eax, 2
    add     eax,    esi

    pinsrd  xmm12, eax, 3
    add     eax,    esi


    pinsrd  xmm13, eax, 0
    add     eax,    esi

    pinsrd  xmm13, eax, 1
    add     eax,    esi

    pinsrd  xmm13, eax, 2
    add     eax,    esi

    pinsrd  xmm13, eax, 3
    add     eax,    esi


    vperm2f128      ymm14,  ymm14, ymm15,         32 ; ymm14 <- xmm14::xmm15
    vperm2f128      ymm13,  ymm12, ymm13,         32 ; ymm12 <- xmm12::xmm13
    vinsertf32x8    zmm14, zmm14, ymm13, 1


    kxnorw k1,k1,k1
    vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
    add     r10, rbx
    vaddps          zmm0,   zmm0,   zmm12

    kxnorw k1,k1,k1
    vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
    add     r10, rbx
    vaddps          zmm4,   zmm4,   zmm12

    kxnorw k1,k1,k1
    vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
    add     r10, rbx
    vaddps          zmm8,   zmm8,   zmm12


    imul    esi,    16
    vpbroadcastd    zmm15, esi


    mov     r10,    [rdi + 8]
    vpaddd          zmm14, zmm14, zmm15

    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm1,   zmm1,   zmm12
    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm5,   zmm5,   zmm12
    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm9,   zmm9,   zmm12
    

    mov     r10,    [rdi + 8]
    vpaddd          zmm14, zmm14, zmm15

    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm2,   zmm2,   zmm12
    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm6,   zmm6,   zmm12
    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm10,   zmm10,   zmm12
    

    mov     r10,    [rdi + 8]
    vpaddd          zmm14, zmm14, zmm15

    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm3,   zmm3,   zmm12
    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm7,   zmm7,   zmm12
    
        kxnorw k1,k1,k1
        vgatherdps      zmm12{k1},  [ r10 + zmm14 ]
        add     r10, rbx
        vaddps          zmm11,   zmm11,   zmm12
    


    jmp    non_linear_loop

add_row_col_products:
    mov             rax, [ rdi + 8 ]
    mov             rbx, [ rdi + 16 ]

    vbroadcastss    zmm13, dword ptr [rbx]
    vbroadcastss    zmm14, dword ptr [rbx+4]
    vbroadcastss    zmm15, dword ptr [rbx+8]


    vmovups         zmm12, zmmword ptr [rax+0]
    vfmadd231ps     zmm0, zmm12, zmm13
    vfmadd231ps     zmm4, zmm12, zmm14
    vfmadd231ps     zmm8, zmm12, zmm15

    vmovups         zmm12, zmmword ptr [rax+64]
    vfmadd231ps     zmm1, zmm12, zmm13
    vfmadd231ps     zmm5, zmm12, zmm14
    vfmadd231ps     zmm9, zmm12, zmm15

    vmovups         zmm12, zmmword ptr [rax+128]
    vfmadd231ps     zmm2, zmm12, zmm13
    vfmadd231ps     zmm6, zmm12, zmm14
    vfmadd231ps     zmm10, zmm12, zmm15

    vmovups         zmm12, zmmword ptr [rax+192]
    vfmadd231ps     zmm3, zmm12, zmm13
    vfmadd231ps     zmm7, zmm12, zmm14
    vfmadd231ps     zmm11, zmm12, zmm15


    jmp    non_linear_loop

store:
    mov     r8,     [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     rbx,    [rdi + 24]          ; col stride

    ; tops of cols
    lea     r9,     [ r8 + rbx ]
    lea     r10,    [ r8 + 2 * rbx ]
    lea     r11,    [ r10 + rbx ]

    
        
            
                vextractf32x4 xmm12, zmm0, 0
            
                vextractf32x4 xmm13, zmm4, 0
            
                vextractf32x4 xmm14, zmm8, 0
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm0, 1
            
                vextractf32x4 xmm13, zmm4, 1
            
                vextractf32x4 xmm14, zmm8, 1
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm0, 2
            
                vextractf32x4 xmm13, zmm4, 2
            
                vextractf32x4 xmm14, zmm8, 2
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm0, 3
            
                vextractf32x4 xmm13, zmm4, 3
            
                vextractf32x4 xmm14, zmm8, 3
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
    
        
            
                vextractf32x4 xmm12, zmm1, 0
            
                vextractf32x4 xmm13, zmm5, 0
            
                vextractf32x4 xmm14, zmm9, 0
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm1, 1
            
                vextractf32x4 xmm13, zmm5, 1
            
                vextractf32x4 xmm14, zmm9, 1
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm1, 2
            
                vextractf32x4 xmm13, zmm5, 2
            
                vextractf32x4 xmm14, zmm9, 2
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm1, 3
            
                vextractf32x4 xmm13, zmm5, 3
            
                vextractf32x4 xmm14, zmm9, 3
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
    
        
            
                vextractf32x4 xmm12, zmm2, 0
            
                vextractf32x4 xmm13, zmm6, 0
            
                vextractf32x4 xmm14, zmm10, 0
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm2, 1
            
                vextractf32x4 xmm13, zmm6, 1
            
                vextractf32x4 xmm14, zmm10, 1
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm2, 2
            
                vextractf32x4 xmm13, zmm6, 2
            
                vextractf32x4 xmm14, zmm10, 2
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm2, 3
            
                vextractf32x4 xmm13, zmm6, 3
            
                vextractf32x4 xmm14, zmm10, 3
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
    
        
            
                vextractf32x4 xmm12, zmm3, 0
            
                vextractf32x4 xmm13, zmm7, 0
            
                vextractf32x4 xmm14, zmm11, 0
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm3, 1
            
                vextractf32x4 xmm13, zmm7, 1
            
                vextractf32x4 xmm14, zmm11, 1
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm3, 2
            
                vextractf32x4 xmm13, zmm7, 2
            
                vextractf32x4 xmm14, zmm11, 2
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
            
                vextractf32x4 xmm12, zmm3, 3
            
                vextractf32x4 xmm13, zmm7, 3
            
                vextractf32x4 xmm14, zmm11, 3
            
            
                
                    vextractps  dword ptr [r8], xmm12, 0
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 0
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 0
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 1
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 1
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 1
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 2
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 2
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 2
                    add         r10, rsi
                
            
                
                    vextractps  dword ptr [r8], xmm12, 3
                    add         r8, rsi
                
                    vextractps  dword ptr [r9], xmm13, 3
                    add         r9, rsi
                
                    vextractps  dword ptr [r10], xmm14, 3
                    add         r10, rsi
                
            
        
        

    jmp     non_linear_loop

return:
    ldmxcsr     [rsp + 4]
    add         rsp, 8

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx


    pop rsi
    pop rdi

    vmovaps xmm15, [rsp+16*9]
    vmovaps xmm14, [rsp+16*8]
    vmovaps xmm13, [rsp+16*7]
    vmovaps xmm12, [rsp+16*6]
    vmovaps xmm11, [rsp+16*5]
    vmovaps xmm10, [rsp+16*4]
    vmovaps xmm9, [rsp+16*3]
    vmovaps xmm8, [rsp+16*2]
    vmovaps xmm7, [rsp+16*1]
    vmovaps xmm6, [rsp]


    mov rsp, rbp
    pop rbp
    ret


avx512_mmm_f32_64x3_0_21_10 endp
_text ends
end


