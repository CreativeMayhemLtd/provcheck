




_text segment
fma_mmm_f32_32x1_0_21_10 proc



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
    mov     r8,    [rdi + 32]   ; packing
    test    rbx,    rbx
    jz      non_linear_loop

    cmp     r8, 1
    jz      q40f32

    cmp     r8, 2
    jz      q40f16

    cmp     r8, 3
    jz      f16f16

align 16
main_loop_packed_packed:
    vbroadcastss    ymm15,  dword ptr [rcx]

    vmovaps     ymm8, [rax]
    vmovaps     ymm9, [rax + 32]
    vmovaps     ymm10, [rax + 64]
    vmovaps     ymm11, [rax + 96]

    vfmadd231ps     ymm0, ymm15, ymm8
    vfmadd231ps     ymm1, ymm15, ymm9
    vfmadd231ps     ymm2, ymm15, ymm10
    vfmadd231ps     ymm3, ymm15, ymm11

    add             rcx, 4
	add             rax, 128
    sub             rbx, 1
    jnz             main_loop_packed_packed

    jmp             non_linear_loop


q40f32_mask:
    dd 0F0F0F0Fh
q40f32_eight:
    dd 08h


q40f32:
    ; ymm0-3: acc
    ; ymm4-7: scales
    ; ymm13: 8
    ; ymm14: mask
    ; ymm15: b value
    vbroadcastss    ymm14, dword ptr [offset q40f32_mask]
    vbroadcastss    ymm13, dword ptr [offset q40f32_eight]

q40f32_outerloop:
    ; scales
    vmovaps         xmm4, [rax]
    vmovaps         xmm5, [rax + 16]
    vmovaps         xmm6, [rax + 32]
    vmovaps         xmm7, [rax + 48]
    vcvtph2ps       ymm4, xmm4
    vcvtph2ps       ymm5, xmm5
    vcvtph2ps       ymm6, xmm6
    vcvtph2ps       ymm7, xmm7
    add             rax, 64

    mov             rdx, 32

q40f32_innerloop:
    vbroadcastss    ymm15, dword ptr [rcx]
    vmovaps         xmm8, [rax]            ; 32 nibbles

    vpand           xmm10, xmm8, xmm14      ; 16 bytes

    vpmovzxbd       ymm9, xmm10            ; 8 u32

    vpermilpd       xmm10, xmm10, 1        ; swap 64bit halves
    vpmovzxbd       ymm10, xmm10            ; 8 u32

    vpsrlw          xmm8, xmm8, 4
    vpand           xmm12, xmm8, xmm14      ; 16 bytes
    vpmovzxbd       ymm11, xmm12            ; 8 u32
    vpermilpd       xmm12, xmm12, 1        ; swap 64bit halves
    vpmovzxbd       ymm12, xmm12            ; 8 u32

    vpsubd          ymm9, ymm9, ymm13
    vpsubd          ymm10, ymm10, ymm13
    vpsubd          ymm11, ymm11, ymm13
    vpsubd          ymm12, ymm12, ymm13

    vcvtdq2ps       ymm9, ymm9
    vcvtdq2ps       ymm10, ymm10
    vcvtdq2ps       ymm11, ymm11
    vcvtdq2ps       ymm12, ymm12

    vmulps          ymm9, ymm9, ymm4
    vmulps          ymm10, ymm10, ymm5
    vmulps          ymm11, ymm11, ymm6
    vmulps          ymm12, ymm12, ymm7

    vfmadd231ps     ymm0, ymm15, ymm9
    vfmadd231ps     ymm1, ymm15, ymm10
    vfmadd231ps     ymm2, ymm15, ymm11
    vfmadd231ps     ymm3, ymm15, ymm12

    add             rax, 16
    add             rcx, 4
    sub             rdx, 1
    jnz             q40f32_innerloop

    sub             rbx, 32
    jnz             q40f32_outerloop

    jmp             non_linear_loop

q40f16:
    ; ymm0-3: acc
    ; ymm4-7: scales
    ; ymm13: 8
    ; ymm14: mask
    ; ymm15: b value
    vbroadcastss    ymm14, dword ptr [offset q40f32_mask]
    vbroadcastss    ymm13, dword ptr [offset q40f32_eight]

q40f16_outerloop:
    ; scales
    vmovaps         xmm4, [rax]
    vmovaps         xmm5, [rax + 16]
    vmovaps         xmm6, [rax + 32]
    vmovaps         xmm7, [rax + 48]
    vcvtph2ps       ymm4, xmm4
    vcvtph2ps       ymm5, xmm5
    vcvtph2ps       ymm6, xmm6
    vcvtph2ps       ymm7, xmm7
    add             rax, 64

    mov             rdx, 32

q40f16_innerloop:
    vpbroadcastw    ymm15, word ptr [rcx]
    vcvtph2ps       ymm15, xmm15

    vmovaps         xmm8, [rax]            ; 32 nibbles

    vpand           xmm10, xmm8, xmm14      ; 16 bytes

    vpmovzxbd       ymm9, xmm10            ; 8 u32

    vpermilpd       xmm10, xmm10, 1        ; swap 64bit halves
    vpmovzxbd       ymm10, xmm10            ; 8 u32

    vpsrlw          xmm8, xmm8, 4
    vpand           xmm12, xmm8, xmm14      ; 16 bytes
    vpmovzxbd       ymm11, xmm12            ; 8 u32
    vpermilpd       xmm12, xmm12, 1        ; swap 64bit halves
    vpmovzxbd       ymm12, xmm12            ; 8 u32

    vpsubd          ymm9, ymm9, ymm13
    vpsubd          ymm10, ymm10, ymm13
    vpsubd          ymm11, ymm11, ymm13
    vpsubd          ymm12, ymm12, ymm13

    vcvtdq2ps       ymm9, ymm9
    vcvtdq2ps       ymm10, ymm10
    vcvtdq2ps       ymm11, ymm11
    vcvtdq2ps       ymm12, ymm12

    vmulps          ymm9, ymm9, ymm4
    vmulps          ymm10, ymm10, ymm5
    vmulps          ymm11, ymm11, ymm6
    vmulps          ymm12, ymm12, ymm7

    vfmadd231ps     ymm0, ymm15, ymm9
    vfmadd231ps     ymm1, ymm15, ymm10
    vfmadd231ps     ymm2, ymm15, ymm11
    vfmadd231ps     ymm3, ymm15, ymm12

    add             rax, 16
    add             rcx, 2
    sub             rdx, 1
    jnz             q40f16_innerloop

    sub             rbx, 32
    jnz             q40f16_outerloop

    jmp             non_linear_loop

f16f16:
align 16
    vpbroadcastw    ymm15, word ptr [rcx]

    vmovaps     xmm4, [rax]
    vmovaps     xmm5, [rax + 16]
    vmovaps     xmm6, [rax + 32]
    vmovaps     xmm7, [rax + 48]

    vcvtph2ps       ymm15, xmm15
    vcvtph2ps       ymm4, xmm4
    vcvtph2ps       ymm5, xmm5
    vcvtph2ps       ymm6, xmm6
    vcvtph2ps       ymm7, xmm7

    vfmadd231ps     ymm0, ymm15, ymm4
    vfmadd231ps     ymm1, ymm15, ymm5
    vfmadd231ps     ymm2, ymm15, ymm6
    vfmadd231ps     ymm3, ymm15, ymm7

    add             rcx, 2
	add             rax, 64
    sub             rbx, 1
    jnz             f16f16

    jmp             non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

scalar_min:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vminps          ymm0, ymm12, ymm0
        
            vminps          ymm1, ymm12, ymm1
        
            vminps          ymm2, ymm12, ymm2
        
            vminps          ymm3, ymm12, ymm3
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_max:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vmaxps          ymm0, ymm12, ymm0
        
            vmaxps          ymm1, ymm12, ymm1
        
            vmaxps          ymm2, ymm12, ymm2
        
            vmaxps          ymm3, ymm12, ymm3
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_add:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vaddps          ymm0, ymm12, ymm0
        
            vaddps          ymm1, ymm12, ymm1
        
            vaddps          ymm2, ymm12, ymm2
        
            vaddps          ymm3, ymm12, ymm3
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_mul:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vmulps          ymm0, ymm12, ymm0
        
            vmulps          ymm1, ymm12, ymm1
        
            vmulps          ymm2, ymm12, ymm2
        
            vmulps          ymm3, ymm12, ymm3
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vsubps          ymm0, ymm12, ymm0
        
            vsubps          ymm1, ymm12, ymm1
        
            vsubps          ymm2, ymm12, ymm2
        
            vsubps          ymm3, ymm12, ymm3
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub_flipped:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vsubps          ymm0, ymm0, ymm12
        
            vsubps          ymm1, ymm1, ymm12
        
            vsubps          ymm2, ymm2, ymm12
        
            vsubps          ymm3, ymm3, ymm12
        
    

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





    
        vmovups         ymm4,  [rax + 0]
    
        vmovups         ymm5,  [rax + 32]
    
        vmovups         ymm6,  [rax + 64]
    
        vmovups         ymm7,  [rax + 96]
    



    
        vminps ymm0, ymm4, ymm0
    
        vminps ymm1, ymm5, ymm1
    
        vminps ymm2, ymm6, ymm2
    
        vminps ymm3, ymm7, ymm3
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_max:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm4,  [rax + 0]
    
        vmovups         ymm5,  [rax + 32]
    
        vmovups         ymm6,  [rax + 64]
    
        vmovups         ymm7,  [rax + 96]
    



    
        vmaxps ymm0, ymm4, ymm0
    
        vmaxps ymm1, ymm5, ymm1
    
        vmaxps ymm2, ymm6, ymm2
    
        vmaxps ymm3, ymm7, ymm3
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_add:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm4,  [rax + 0]
    
        vmovups         ymm5,  [rax + 32]
    
        vmovups         ymm6,  [rax + 64]
    
        vmovups         ymm7,  [rax + 96]
    



    
        vaddps ymm0, ymm4, ymm0
    
        vaddps ymm1, ymm5, ymm1
    
        vaddps ymm2, ymm6, ymm2
    
        vaddps ymm3, ymm7, ymm3
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_mul:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm4,  [rax + 0]
    
        vmovups         ymm5,  [rax + 32]
    
        vmovups         ymm6,  [rax + 64]
    
        vmovups         ymm7,  [rax + 96]
    



    
        vmulps ymm0, ymm4, ymm0
    
        vmulps ymm1, ymm5, ymm1
    
        vmulps ymm2, ymm6, ymm2
    
        vmulps ymm3, ymm7, ymm3
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm4,  [rax + 0]
    
        vmovups         ymm5,  [rax + 32]
    
        vmovups         ymm6,  [rax + 64]
    
        vmovups         ymm7,  [rax + 96]
    



    
        vsubps ymm0, ymm4, ymm0
    
        vsubps ymm1, ymm5, ymm1
    
        vsubps ymm2, ymm6, ymm2
    
        vsubps ymm3, ymm7, ymm3
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub_flipped:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm4,  [rax + 0]
    
        vmovups         ymm5,  [rax + 32]
    
        vmovups         ymm6,  [rax + 64]
    
        vmovups         ymm7,  [rax + 96]
    



    
        vsubps ymm0, ymm0, ymm4
    
        vsubps ymm1, ymm1, ymm5
    
        vsubps ymm2, ymm2, ymm6
    
        vsubps ymm3, ymm3, ymm7
    


    jmp non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

per_col_min:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm4, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vminps ymm0, ymm4, ymm0
        
    
        
        
            vminps ymm1, ymm4, ymm1
        
    
        
        
            vminps ymm2, ymm4, ymm2
        
    
        
        
            vminps ymm3, ymm4, ymm3
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_max:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm4, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vmaxps ymm0, ymm4, ymm0
        
    
        
        
            vmaxps ymm1, ymm4, ymm1
        
    
        
        
            vmaxps ymm2, ymm4, ymm2
        
    
        
        
            vmaxps ymm3, ymm4, ymm3
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_add:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm4, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vaddps ymm0, ymm4, ymm0
        
    
        
        
            vaddps ymm1, ymm4, ymm1
        
    
        
        
            vaddps ymm2, ymm4, ymm2
        
    
        
        
            vaddps ymm3, ymm4, ymm3
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_mul:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm4, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vmulps ymm0, ymm4, ymm0
        
    
        
        
            vmulps ymm1, ymm4, ymm1
        
    
        
        
            vmulps ymm2, ymm4, ymm2
        
    
        
        
            vmulps ymm3, ymm4, ymm3
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm4, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vsubps ymm0, ymm4, ymm0
        
    
        
        
            vsubps ymm1, ymm4, ymm1
        
    
        
        
            vsubps ymm2, ymm4, ymm2
        
    
        
        
            vsubps ymm3, ymm4, ymm3
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub_flipped:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm4, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vsubps ymm0, ymm0, ymm4
        
    
        
        
            vsubps ymm1, ymm1, ymm4
        
    
        
        
            vsubps ymm2, ymm2, ymm4
        
    
        
        
            vsubps ymm3, ymm3, ymm4
        
    


    jmp non_linear_loop

; vim: set syntax=asm :

load_tile:
    mov          r8, [rdi + 8]
    
        vmovups         ymm0, ymmword ptr [r8 + 0]
    
        vmovups         ymm1, ymmword ptr [r8 + 32]
    
        vmovups         ymm2, ymmword ptr [r8 + 64]
    
        vmovups         ymm3, ymmword ptr [r8 + 96]
    

    jmp    non_linear_loop

add_unicast:
    mov     r10,    [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride

	cmp rsi, 4
	jne add_unicast_generic

    
        vaddps ymm0, ymm0, [ r10 + 0 ]
    
        vaddps ymm1, ymm1, [ r10 + 32 ]
    
        vaddps ymm2, ymm2, [ r10 + 64 ]
    
        vaddps ymm3, ymm3, [ r10 + 96 ]
    
    jmp    non_linear_loop


    jmp    non_linear_loop

add_unicast_generic:
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


    vpcmpeqd        ymm15,  ymm15, ymm15
    vgatherdps      ymm12,  [ r10 + ymm14 ], ymm15

    vaddps          ymm0,   ymm0,   ymm12
    lea             r10, [ r10 + rsi * 8 ]

    vpcmpeqd        ymm15,  ymm15, ymm15
    vgatherdps      ymm12,  [ r10 + ymm14 ], ymm15

    vaddps          ymm1,   ymm1,   ymm12
    lea             r10, [ r10 + rsi * 8 ]

    vpcmpeqd        ymm15,  ymm15, ymm15
    vgatherdps      ymm12,  [ r10 + ymm14 ], ymm15

    vaddps          ymm2,   ymm2,   ymm12
    lea             r10, [ r10 + rsi * 8 ]

    vpcmpeqd        ymm15,  ymm15, ymm15
    vgatherdps      ymm12,  [ r10 + ymm14 ], ymm15

    vaddps          ymm3,   ymm3,   ymm12
    lea             r10, [ r10 + rsi * 8 ]


    jmp    non_linear_loop

add_row_col_products:
    mov             rax, [ rdi + 8 ]
    mov             rbx, [ rdi + 16 ]

    vbroadcastss    ymm14, dword ptr [rbx]


    vmovups         ymm12,  [rax + 0]
    vfmadd231ps     ymm0, ymm12, ymm14

    vmovups         ymm12,  [rax + 32]
    vfmadd231ps     ymm1, ymm12, ymm14

    vmovups         ymm12,  [rax + 64]
    vfmadd231ps     ymm2, ymm12, ymm14

    vmovups         ymm12,  [rax + 96]
    vfmadd231ps     ymm3, ymm12, ymm14

    jmp    non_linear_loop

store:
    mov     r8,     [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     r11,    [rdi + 32]          ; item size

    cmp     r11, 2
    je      store_f16

	cmp rsi, 4
	jne store_generic

	
        vmovups [r8 + 0], ymm0
    
        vmovups [r8 + 32], ymm1
    
        vmovups [r8 + 64], ymm2
    
        vmovups [r8 + 96], ymm3
    

    jmp     non_linear_loop

store_generic:

    
        
            
                movaps xmm9, xmm0
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
            
                vperm2f128 ymm9, ymm0, ymm0, 1
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
    
        
            
                movaps xmm9, xmm1
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
            
                vperm2f128 ymm9, ymm1, ymm1, 1
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
    
        
            
                movaps xmm9, xmm2
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
            
                vperm2f128 ymm9, ymm2, ymm2, 1
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
    
        
            
                movaps xmm9, xmm3
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
            
                vperm2f128 ymm9, ymm3, ymm3, 1
            
            
                vextractps  dword ptr [r8], xmm9, 0
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 1
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 2
                add         r8, rsi
            
                vextractps  dword ptr [r8], xmm9, 3
                add         r8, rsi
            
        
    

    jmp    non_linear_loop

store_f16:

    vcvtps2ph   xmm0, ymm0, 0
    vcvtps2ph   xmm1, ymm1, 0
    vcvtps2ph   xmm2, ymm2, 0
    vcvtps2ph   xmm3, ymm3, 0

    cmp         rsi, 2
	jne store_generic_f16

	
        vmovups [r8 + 0], xmm0
    
        vmovups [r8 + 16], xmm1
    
        vmovups [r8 + 32], xmm2
    
        vmovups [r8 + 48], xmm3
    

    jmp     non_linear_loop
    
store_generic_f16:

    
        
            vextractps  dword ptr [r8], xmm0, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 3
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 4
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 5
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 6
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm0, 7
            add         r8, rsi
        
    
        
            vextractps  dword ptr [r8], xmm1, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 3
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 4
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 5
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 6
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm1, 7
            add         r8, rsi
        
    
        
            vextractps  dword ptr [r8], xmm2, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 3
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 4
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 5
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 6
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm2, 7
            add         r8, rsi
        
    
        
            vextractps  dword ptr [r8], xmm3, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 3
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 4
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 5
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 6
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm3, 7
            add         r8, rsi
        
    

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


fma_mmm_f32_32x1_0_21_10 endp
_text ends
end

