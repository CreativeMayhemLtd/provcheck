




_text segment
fma_mmm_f32_40x2_0_21_10 proc



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
    	; Tile size: 5x2
	; Accumulators: 0-9
	; Col regs: ymm10-13
	; Row regs: ymm14-15

	vmovaps			ymm10,	[rax]
	vbroadcastss	ymm14,	dword ptr [rcx + 0]
	vbroadcastss	ymm15,	dword ptr [rcx + 4]
	vmovaps			ymm11,	[rax + 32]

	; NB stepping column-wise
	vfmadd231ps		ymm0,	ymm10, ymm14
	vfmadd231ps		ymm5,	ymm10, ymm15

	vmovaps			ymm12,	[rax + 64]

	vfmadd231ps		ymm1,	ymm11, ymm14
	vfmadd231ps		ymm6,	ymm11, ymm15

	vmovaps			ymm13,	[rax + 96]

	vfmadd231ps		ymm2,	ymm12, ymm14
	vfmadd231ps		ymm7,	ymm12, ymm15

	vmovaps			ymm11,	[rax + 128]

	vfmadd231ps		ymm3,	ymm13, ymm14
	vfmadd231ps		ymm8,	ymm13, ymm15

	vfmadd231ps		ymm4,	ymm11, ymm14
	vfmadd231ps		ymm9,	ymm11, ymm15

	add rax, 160
	add rcx, 8

    dec             rbx
    jnz             main_loop_packed_packed

    jmp             non_linear_loop

; NON LINEAR / ADDC

; vim: set syntax=asm :

; vim: set syntax=asm :

scalar_min:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vminps          ymm0, ymm12, ymm0
        
            vminps          ymm1, ymm12, ymm1
        
            vminps          ymm2, ymm12, ymm2
        
            vminps          ymm3, ymm12, ymm3
        
            vminps          ymm4, ymm12, ymm4
        
            vminps          ymm5, ymm12, ymm5
        
            vminps          ymm6, ymm12, ymm6
        
            vminps          ymm7, ymm12, ymm7
        
            vminps          ymm8, ymm12, ymm8
        
            vminps          ymm9, ymm12, ymm9
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_max:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vmaxps          ymm0, ymm12, ymm0
        
            vmaxps          ymm1, ymm12, ymm1
        
            vmaxps          ymm2, ymm12, ymm2
        
            vmaxps          ymm3, ymm12, ymm3
        
            vmaxps          ymm4, ymm12, ymm4
        
            vmaxps          ymm5, ymm12, ymm5
        
            vmaxps          ymm6, ymm12, ymm6
        
            vmaxps          ymm7, ymm12, ymm7
        
            vmaxps          ymm8, ymm12, ymm8
        
            vmaxps          ymm9, ymm12, ymm9
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_add:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vaddps          ymm0, ymm12, ymm0
        
            vaddps          ymm1, ymm12, ymm1
        
            vaddps          ymm2, ymm12, ymm2
        
            vaddps          ymm3, ymm12, ymm3
        
            vaddps          ymm4, ymm12, ymm4
        
            vaddps          ymm5, ymm12, ymm5
        
            vaddps          ymm6, ymm12, ymm6
        
            vaddps          ymm7, ymm12, ymm7
        
            vaddps          ymm8, ymm12, ymm8
        
            vaddps          ymm9, ymm12, ymm9
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_mul:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vmulps          ymm0, ymm12, ymm0
        
            vmulps          ymm1, ymm12, ymm1
        
            vmulps          ymm2, ymm12, ymm2
        
            vmulps          ymm3, ymm12, ymm3
        
            vmulps          ymm4, ymm12, ymm4
        
            vmulps          ymm5, ymm12, ymm5
        
            vmulps          ymm6, ymm12, ymm6
        
            vmulps          ymm7, ymm12, ymm7
        
            vmulps          ymm8, ymm12, ymm8
        
            vmulps          ymm9, ymm12, ymm9
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vsubps          ymm0, ymm12, ymm0
        
            vsubps          ymm1, ymm12, ymm1
        
            vsubps          ymm2, ymm12, ymm2
        
            vsubps          ymm3, ymm12, ymm3
        
            vsubps          ymm4, ymm12, ymm4
        
            vsubps          ymm5, ymm12, ymm5
        
            vsubps          ymm6, ymm12, ymm6
        
            vsubps          ymm7, ymm12, ymm7
        
            vsubps          ymm8, ymm12, ymm8
        
            vsubps          ymm9, ymm12, ymm9
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub_flipped:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vsubps          ymm0, ymm0, ymm12
        
            vsubps          ymm1, ymm1, ymm12
        
            vsubps          ymm2, ymm2, ymm12
        
            vsubps          ymm3, ymm3, ymm12
        
            vsubps          ymm4, ymm4, ymm12
        
            vsubps          ymm5, ymm5, ymm12
        
            vsubps          ymm6, ymm6, ymm12
        
            vsubps          ymm7, ymm7, ymm12
        
            vsubps          ymm8, ymm8, ymm12
        
            vsubps          ymm9, ymm9, ymm12
        
    

    jmp    non_linear_loop

leaky_relu:
    ; can only use ymm12 to ymm15
    ; ymm15 <- alpha
    
        vbroadcastss    ymm15, dword ptr [rdi + 8]
    

    ; ymm14 <- all zero
    vpxor           ymm14, ymm14, ymm14

    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm0, ymm15
        vcmpps     ymm13, ymm14, ymm0, 1 ; 1 means LT
        vblendvps   ymm0, ymm12, ymm0, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm1, ymm15
        vcmpps     ymm13, ymm14, ymm1, 1 ; 1 means LT
        vblendvps   ymm1, ymm12, ymm1, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm2, ymm15
        vcmpps     ymm13, ymm14, ymm2, 1 ; 1 means LT
        vblendvps   ymm2, ymm12, ymm2, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm3, ymm15
        vcmpps     ymm13, ymm14, ymm3, 1 ; 1 means LT
        vblendvps   ymm3, ymm12, ymm3, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm4, ymm15
        vcmpps     ymm13, ymm14, ymm4, 1 ; 1 means LT
        vblendvps   ymm4, ymm12, ymm4, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm5, ymm15
        vcmpps     ymm13, ymm14, ymm5, 1 ; 1 means LT
        vblendvps   ymm5, ymm12, ymm5, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm6, ymm15
        vcmpps     ymm13, ymm14, ymm6, 1 ; 1 means LT
        vblendvps   ymm6, ymm12, ymm6, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm7, ymm15
        vcmpps     ymm13, ymm14, ymm7, 1 ; 1 means LT
        vblendvps   ymm7, ymm12, ymm7, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm8, ymm15
        vcmpps     ymm13, ymm14, ymm8, 1 ; 1 means LT
        vblendvps   ymm8, ymm12, ymm8, ymm13
    
        ; ymm12 <- alpha * x
        vmulps      ymm12, ymm9, ymm15
        vcmpps     ymm13, ymm14, ymm9, 1 ; 1 means LT
        vblendvps   ymm9, ymm12, ymm9, ymm13
    
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





    
        vmovups         ymm10,  [rax + 0]
    
        vmovups         ymm11,  [rax + 32]
    
        vmovups         ymm12,  [rax + 64]
    
        vmovups         ymm13,  [rax + 96]
    
        vmovups         ymm14,  [rax + 128]
    



    
        vminps ymm0, ymm10, ymm0
    
        vminps ymm1, ymm11, ymm1
    
        vminps ymm2, ymm12, ymm2
    
        vminps ymm3, ymm13, ymm3
    
        vminps ymm4, ymm14, ymm4
    
        vminps ymm5, ymm10, ymm5
    
        vminps ymm6, ymm11, ymm6
    
        vminps ymm7, ymm12, ymm7
    
        vminps ymm8, ymm13, ymm8
    
        vminps ymm9, ymm14, ymm9
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_max:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm10,  [rax + 0]
    
        vmovups         ymm11,  [rax + 32]
    
        vmovups         ymm12,  [rax + 64]
    
        vmovups         ymm13,  [rax + 96]
    
        vmovups         ymm14,  [rax + 128]
    



    
        vmaxps ymm0, ymm10, ymm0
    
        vmaxps ymm1, ymm11, ymm1
    
        vmaxps ymm2, ymm12, ymm2
    
        vmaxps ymm3, ymm13, ymm3
    
        vmaxps ymm4, ymm14, ymm4
    
        vmaxps ymm5, ymm10, ymm5
    
        vmaxps ymm6, ymm11, ymm6
    
        vmaxps ymm7, ymm12, ymm7
    
        vmaxps ymm8, ymm13, ymm8
    
        vmaxps ymm9, ymm14, ymm9
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_add:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm10,  [rax + 0]
    
        vmovups         ymm11,  [rax + 32]
    
        vmovups         ymm12,  [rax + 64]
    
        vmovups         ymm13,  [rax + 96]
    
        vmovups         ymm14,  [rax + 128]
    



    
        vaddps ymm0, ymm10, ymm0
    
        vaddps ymm1, ymm11, ymm1
    
        vaddps ymm2, ymm12, ymm2
    
        vaddps ymm3, ymm13, ymm3
    
        vaddps ymm4, ymm14, ymm4
    
        vaddps ymm5, ymm10, ymm5
    
        vaddps ymm6, ymm11, ymm6
    
        vaddps ymm7, ymm12, ymm7
    
        vaddps ymm8, ymm13, ymm8
    
        vaddps ymm9, ymm14, ymm9
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_mul:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm10,  [rax + 0]
    
        vmovups         ymm11,  [rax + 32]
    
        vmovups         ymm12,  [rax + 64]
    
        vmovups         ymm13,  [rax + 96]
    
        vmovups         ymm14,  [rax + 128]
    



    
        vmulps ymm0, ymm10, ymm0
    
        vmulps ymm1, ymm11, ymm1
    
        vmulps ymm2, ymm12, ymm2
    
        vmulps ymm3, ymm13, ymm3
    
        vmulps ymm4, ymm14, ymm4
    
        vmulps ymm5, ymm10, ymm5
    
        vmulps ymm6, ymm11, ymm6
    
        vmulps ymm7, ymm12, ymm7
    
        vmulps ymm8, ymm13, ymm8
    
        vmulps ymm9, ymm14, ymm9
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm10,  [rax + 0]
    
        vmovups         ymm11,  [rax + 32]
    
        vmovups         ymm12,  [rax + 64]
    
        vmovups         ymm13,  [rax + 96]
    
        vmovups         ymm14,  [rax + 128]
    



    
        vsubps ymm0, ymm10, ymm0
    
        vsubps ymm1, ymm11, ymm1
    
        vsubps ymm2, ymm12, ymm2
    
        vsubps ymm3, ymm13, ymm3
    
        vsubps ymm4, ymm14, ymm4
    
        vsubps ymm5, ymm10, ymm5
    
        vsubps ymm6, ymm11, ymm6
    
        vsubps ymm7, ymm12, ymm7
    
        vsubps ymm8, ymm13, ymm8
    
        vsubps ymm9, ymm14, ymm9
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub_flipped:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm10,  [rax + 0]
    
        vmovups         ymm11,  [rax + 32]
    
        vmovups         ymm12,  [rax + 64]
    
        vmovups         ymm13,  [rax + 96]
    
        vmovups         ymm14,  [rax + 128]
    



    
        vsubps ymm0, ymm0, ymm10
    
        vsubps ymm1, ymm1, ymm11
    
        vsubps ymm2, ymm2, ymm12
    
        vsubps ymm3, ymm3, ymm13
    
        vsubps ymm4, ymm4, ymm14
    
        vsubps ymm5, ymm5, ymm10
    
        vsubps ymm6, ymm6, ymm11
    
        vsubps ymm7, ymm7, ymm12
    
        vsubps ymm8, ymm8, ymm13
    
        vsubps ymm9, ymm9, ymm14
    


    jmp non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

per_col_min:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vminps ymm0, ymm10, ymm0
        
    
        
        
            vminps ymm1, ymm10, ymm1
        
    
        
        
            vminps ymm2, ymm10, ymm2
        
    
        
        
            vminps ymm3, ymm10, ymm3
        
    
        
        
            vminps ymm4, ymm10, ymm4
        
    

    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vminps ymm5, ymm10, ymm5
        
    
        
        
            vminps ymm6, ymm10, ymm6
        
    
        
        
            vminps ymm7, ymm10, ymm7
        
    
        
        
            vminps ymm8, ymm10, ymm8
        
    
        
        
            vminps ymm9, ymm10, ymm9
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_max:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vmaxps ymm0, ymm10, ymm0
        
    
        
        
            vmaxps ymm1, ymm10, ymm1
        
    
        
        
            vmaxps ymm2, ymm10, ymm2
        
    
        
        
            vmaxps ymm3, ymm10, ymm3
        
    
        
        
            vmaxps ymm4, ymm10, ymm4
        
    

    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vmaxps ymm5, ymm10, ymm5
        
    
        
        
            vmaxps ymm6, ymm10, ymm6
        
    
        
        
            vmaxps ymm7, ymm10, ymm7
        
    
        
        
            vmaxps ymm8, ymm10, ymm8
        
    
        
        
            vmaxps ymm9, ymm10, ymm9
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_add:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vaddps ymm0, ymm10, ymm0
        
    
        
        
            vaddps ymm1, ymm10, ymm1
        
    
        
        
            vaddps ymm2, ymm10, ymm2
        
    
        
        
            vaddps ymm3, ymm10, ymm3
        
    
        
        
            vaddps ymm4, ymm10, ymm4
        
    

    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vaddps ymm5, ymm10, ymm5
        
    
        
        
            vaddps ymm6, ymm10, ymm6
        
    
        
        
            vaddps ymm7, ymm10, ymm7
        
    
        
        
            vaddps ymm8, ymm10, ymm8
        
    
        
        
            vaddps ymm9, ymm10, ymm9
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_mul:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vmulps ymm0, ymm10, ymm0
        
    
        
        
            vmulps ymm1, ymm10, ymm1
        
    
        
        
            vmulps ymm2, ymm10, ymm2
        
    
        
        
            vmulps ymm3, ymm10, ymm3
        
    
        
        
            vmulps ymm4, ymm10, ymm4
        
    

    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vmulps ymm5, ymm10, ymm5
        
    
        
        
            vmulps ymm6, ymm10, ymm6
        
    
        
        
            vmulps ymm7, ymm10, ymm7
        
    
        
        
            vmulps ymm8, ymm10, ymm8
        
    
        
        
            vmulps ymm9, ymm10, ymm9
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vsubps ymm0, ymm10, ymm0
        
    
        
        
            vsubps ymm1, ymm10, ymm1
        
    
        
        
            vsubps ymm2, ymm10, ymm2
        
    
        
        
            vsubps ymm3, ymm10, ymm3
        
    
        
        
            vsubps ymm4, ymm10, ymm4
        
    

    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vsubps ymm5, ymm10, ymm5
        
    
        
        
            vsubps ymm6, ymm10, ymm6
        
    
        
        
            vsubps ymm7, ymm10, ymm7
        
    
        
        
            vsubps ymm8, ymm10, ymm8
        
    
        
        
            vsubps ymm9, ymm10, ymm9
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub_flipped:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vsubps ymm0, ymm0, ymm10
        
    
        
        
            vsubps ymm1, ymm1, ymm10
        
    
        
        
            vsubps ymm2, ymm2, ymm10
        
    
        
        
            vsubps ymm3, ymm3, ymm10
        
    
        
        
            vsubps ymm4, ymm4, ymm10
        
    

    
        vbroadcastss    ymm10, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vsubps ymm5, ymm5, ymm10
        
    
        
        
            vsubps ymm6, ymm6, ymm10
        
    
        
        
            vsubps ymm7, ymm7, ymm10
        
    
        
        
            vsubps ymm8, ymm8, ymm10
        
    
        
        
            vsubps ymm9, ymm9, ymm10
        
    


    jmp non_linear_loop

; vim: set syntax=asm :

load_tile:
    mov          r8, [rdi + 8]
    
        vmovups         ymm0, ymmword ptr [r8 + 0]
    
        vmovups         ymm1, ymmword ptr [r8 + 32]
    
        vmovups         ymm2, ymmword ptr [r8 + 64]
    
        vmovups         ymm3, ymmword ptr [r8 + 96]
    
        vmovups         ymm4, ymmword ptr [r8 + 128]
    
        vmovups         ymm5, ymmword ptr [r8 + 160]
    
        vmovups         ymm6, ymmword ptr [r8 + 192]
    
        vmovups         ymm7, ymmword ptr [r8 + 224]
    
        vmovups         ymm8, ymmword ptr [r8 + 256]
    
        vmovups         ymm9, ymmword ptr [r8 + 288]
    

    jmp    non_linear_loop

add_unicast:
    mov     r8,    [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     rbx,    [rdi + 24]          ; col stride

    cmp rsi, 4
    jne unicast_generic

    lea             r9,  [ r8 + rbx ]
    lea             r10, [ r9 + rbx]
    lea             r11, [ r10 + rbx ]
    lea             r12, [ r11 + rbx ]



    
        vmovups ymm12,  [ r8 ]
        add		r8, 32
        vaddps 	ymm0, ymm0, ymm12
    
        vmovups ymm12,  [ r8 ]
        add		r8, 32
        vaddps 	ymm1, ymm1, ymm12
    
        vmovups ymm12,  [ r8 ]
        add		r8, 32
        vaddps 	ymm2, ymm2, ymm12
    
        vmovups ymm12,  [ r8 ]
        add		r8, 32
        vaddps 	ymm3, ymm3, ymm12
    
        vmovups ymm12,  [ r8 ]
        add		r8, 32
        vaddps 	ymm4, ymm4, ymm12
    

    
        vmovups ymm12,  [ r9 ]
        add		r9, 32
        vaddps 	ymm5, ymm5, ymm12
    
        vmovups ymm12,  [ r9 ]
        add		r9, 32
        vaddps 	ymm6, ymm6, ymm12
    
        vmovups ymm12,  [ r9 ]
        add		r9, 32
        vaddps 	ymm7, ymm7, ymm12
    
        vmovups ymm12,  [ r9 ]
        add		r9, 32
        vaddps 	ymm8, ymm8, ymm12
    
        vmovups ymm12,  [ r9 ]
        add		r9, 32
        vaddps 	ymm9, ymm9, ymm12
    

    jmp    non_linear_loop

unicast_generic:
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


    vperm2f128      ymm14,  ymm14, ymm15,         32 ; ymm14 <- xmm14::xmm15

    lea             r9,  [ r8 + rsi * 8]
    lea             r10, [ r9 + rsi * 8]
    lea             r11, [ r10 + rsi * 8]
    lea             r12, [ r11 + rsi * 8]


   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r8 + ymm14 ], ymm15
      add 			  r8, 	rbx
      vaddps 		  ymm0, ymm0, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r9 + ymm14 ], ymm15
      add 			  r9, 	rbx
      vaddps 		  ymm1, ymm1, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
      add 			  r10, 	rbx
      vaddps 		  ymm2, ymm2, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r11 + ymm14 ], ymm15
      add 			  r11, 	rbx
      vaddps 		  ymm3, ymm3, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r12 + ymm14 ], ymm15
      add 			  r12, 	rbx
      vaddps 		  ymm4, ymm4, ymm12
   

   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r8 + ymm14 ], ymm15
      add 			  r8, 	rbx
      vaddps 		  ymm5, ymm5, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r9 + ymm14 ], ymm15
      add 			  r9, 	rbx
      vaddps 		  ymm6, ymm6, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
      add 			  r10, 	rbx
      vaddps 		  ymm7, ymm7, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r11 + ymm14 ], ymm15
      add 			  r11, 	rbx
      vaddps 		  ymm8, ymm8, ymm12
   
      vpcmpeqd        ymm15, ymm15, ymm15
      vgatherdps      ymm12, [ r12 + ymm14 ], ymm15
      add 			  r12, 	rbx
      vaddps 		  ymm9, ymm9, ymm12
   


    jmp    non_linear_loop

add_row_col_products:
    mov             rax, [ rdi + 8 ]
    mov             rbx, [ rdi + 16 ]

    vbroadcastss    ymm10, dword ptr [rbx]
    vbroadcastss    ymm11, dword ptr [rbx + 4]

    vmovups         ymm12,  [rax + 0]
    vfmadd231ps     ymm0, ymm12, ymm10
    vfmadd231ps     ymm5, ymm12, ymm11

    vmovups         ymm12,  [rax + 32]
    vfmadd231ps     ymm1, ymm12, ymm10
    vfmadd231ps     ymm6, ymm12, ymm11

    vmovups         ymm12,  [rax + 64]
    vfmadd231ps     ymm2, ymm12, ymm10
    vfmadd231ps     ymm7, ymm12, ymm11

    vmovups         ymm12,  [rax + 96]
    vfmadd231ps     ymm3, ymm12, ymm10
    vfmadd231ps     ymm8, ymm12, ymm11

    vmovups         ymm12,  [rax + 128]
    vfmadd231ps     ymm4, ymm12, ymm10
    vfmadd231ps     ymm9, ymm12, ymm11

    jmp    non_linear_loop


store:
    mov     r8,     [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     rbx,    [rdi + 24]          ; col stride

    lea     r9,     [ r8  +     rbx ]
    lea     r10,    [ r8  + 2 * rbx ]
    lea     r11,    [ r10 +     rbx ]
    lea     r12,    [ r10 + 2 * rbx ]

    cmp         rsi, 4
    jne         store_strides_generic

    
       
            vmovups ymmword ptr [r8], ymm0
            add 	r8, 32
       
            vmovups ymmword ptr [r8], ymm1
            add 	r8, 32
       
            vmovups ymmword ptr [r8], ymm2
            add 	r8, 32
       
            vmovups ymmword ptr [r8], ymm3
            add 	r8, 32
       
            vmovups ymmword ptr [r8], ymm4
            add 	r8, 32
       
    
       
            vmovups ymmword ptr [r9], ymm5
            add 	r9, 32
       
            vmovups ymmword ptr [r9], ymm6
            add 	r9, 32
       
            vmovups ymmword ptr [r9], ymm7
            add 	r9, 32
       
            vmovups ymmword ptr [r9], ymm8
            add 	r9, 32
       
            vmovups ymmword ptr [r9], ymm9
            add 	r9, 32
       
    

    jmp     non_linear_loop

store_strides_generic:
    
       
           
                vextractps  dword ptr [r8], xmm0, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm0, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm0, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm0, 3
                add         r8, rsi
           
           vperm2f128  ymm0, ymm0, ymm0, 1
           
                vextractps  dword ptr [r8], xmm0, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm0, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm0, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm0, 3
                add         r8, rsi
           
       
           
                vextractps  dword ptr [r8], xmm1, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm1, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm1, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm1, 3
                add         r8, rsi
           
           vperm2f128  ymm1, ymm1, ymm1, 1
           
                vextractps  dword ptr [r8], xmm1, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm1, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm1, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm1, 3
                add         r8, rsi
           
       
           
                vextractps  dword ptr [r8], xmm2, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm2, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm2, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm2, 3
                add         r8, rsi
           
           vperm2f128  ymm2, ymm2, ymm2, 1
           
                vextractps  dword ptr [r8], xmm2, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm2, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm2, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm2, 3
                add         r8, rsi
           
       
           
                vextractps  dword ptr [r8], xmm3, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm3, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm3, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm3, 3
                add         r8, rsi
           
           vperm2f128  ymm3, ymm3, ymm3, 1
           
                vextractps  dword ptr [r8], xmm3, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm3, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm3, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm3, 3
                add         r8, rsi
           
       
           
                vextractps  dword ptr [r8], xmm4, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm4, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm4, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm4, 3
                add         r8, rsi
           
           vperm2f128  ymm4, ymm4, ymm4, 1
           
                vextractps  dword ptr [r8], xmm4, 0
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm4, 1
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm4, 2
                add         r8, rsi
           
                vextractps  dword ptr [r8], xmm4, 3
                add         r8, rsi
           
       
    
       
           
                vextractps  dword ptr [r9], xmm5, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm5, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm5, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm5, 3
                add         r9, rsi
           
           vperm2f128  ymm5, ymm5, ymm5, 1
           
                vextractps  dword ptr [r9], xmm5, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm5, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm5, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm5, 3
                add         r9, rsi
           
       
           
                vextractps  dword ptr [r9], xmm6, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm6, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm6, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm6, 3
                add         r9, rsi
           
           vperm2f128  ymm6, ymm6, ymm6, 1
           
                vextractps  dword ptr [r9], xmm6, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm6, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm6, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm6, 3
                add         r9, rsi
           
       
           
                vextractps  dword ptr [r9], xmm7, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm7, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm7, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm7, 3
                add         r9, rsi
           
           vperm2f128  ymm7, ymm7, ymm7, 1
           
                vextractps  dword ptr [r9], xmm7, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm7, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm7, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm7, 3
                add         r9, rsi
           
       
           
                vextractps  dword ptr [r9], xmm8, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm8, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm8, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm8, 3
                add         r9, rsi
           
           vperm2f128  ymm8, ymm8, ymm8, 1
           
                vextractps  dword ptr [r9], xmm8, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm8, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm8, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm8, 3
                add         r9, rsi
           
       
           
                vextractps  dword ptr [r9], xmm9, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm9, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm9, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm9, 3
                add         r9, rsi
           
           vperm2f128  ymm9, ymm9, ymm9, 1
           
                vextractps  dword ptr [r9], xmm9, 0
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm9, 1
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm9, 2
                add         r9, rsi
           
                vextractps  dword ptr [r9], xmm9, 3
                add         r9, rsi
           
       
    
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


fma_mmm_f32_40x2_0_21_10 endp
_text ends
end

