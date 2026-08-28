



_text segment
avx2_mmm_i32_8x8_0_21_10 proc



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
    mov     r12,    [rdi + 32]   ; packing
    mov     rbx,    [rdi + 24]   ; B
    mov     rax,    [rdi + 16]   ; A

    mov     rcx,    [rdi + 8]    ; k
    test    rcx,    rcx
    jz      non_linear_loop

    cmp     r12, 1
    je      main_loop_packed_packed_i8i8

main_loop_packed_packed:
    vmovaps         ymm12,  [rax]

    
        vbroadcastss    ymm14, dword ptr [rbx + 0 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm0, ymm0, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 1 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm1, ymm1, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 2 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm2, ymm2, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 3 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm3, ymm3, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 4 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm4, ymm4, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 5 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm5, ymm5, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 6 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm6, ymm6, ymm13
    
        vbroadcastss    ymm14, dword ptr [rbx + 7 * 4]
        vpmulld         ymm13, ymm12, ymm14
        vpaddd          ymm7, ymm7, ymm13
    

    add             rax,    32
    add             rbx,    32
    dec             rcx
    jnz             main_loop_packed_packed

    jmp             non_linear_loop

main_loop_packed_packed_i8i8:
    movq            xmm8, qword ptr [rax]          ; read 8 bytes
    vpmovsxbw       ymm8, xmm8                     ; promote byte to i32x8

    vpbroadcastb    ymm9, byte ptr [rbx]           ; broadcast 1 byte from B
    vpbroadcastb    ymm10, byte ptr [rbx + 1]      ; broadcast 1 byte from B
    vpbroadcastb    ymm11, byte ptr [rbx + 2]      ; broadcast 1 byte from B
    vpbroadcastb    ymm12, byte ptr [rbx + 3]      ; broadcast 1 byte from B
    vpmovsxbw       ymm9, xmm9                     ; promote byte to i32x8
    vpmovsxbw       ymm10, xmm10                   ; promote byte to i32x8
    vpmovsxbw       ymm11, xmm11                   ; promote byte to i32x8
    vpmovsxbw       ymm12, xmm12                   ; promote byte to i32x8

    vpmullw         ymm9, ymm9, ymm8
    vpmullw         ymm10, ymm10, ymm8
    vpmullw         ymm11, ymm11, ymm8
    vpmullw         ymm12, ymm12, ymm8
    vpmovsxwd       ymm9, xmm9                     ; promote byte to i32x8
    vpmovsxwd       ymm10, xmm10                   ; promote byte to i32x8
    vpmovsxwd       ymm11, xmm11                   ; promote byte to i32x8
    vpmovsxwd       ymm12, xmm12                   ; promote byte to i32x8
    vpaddd          ymm0, ymm0, ymm9
    vpaddd          ymm1, ymm1, ymm10
    vpaddd          ymm2, ymm2, ymm11
    vpaddd          ymm3, ymm3, ymm12

    vpbroadcastb    ymm9, byte ptr [rbx + 4]
    vpbroadcastb    ymm10, byte ptr [rbx + 5]
    vpbroadcastb    ymm11, byte ptr [rbx + 6]
    vpbroadcastb    ymm12, byte ptr [rbx + 7]
    vpmovsxbw       ymm9, xmm9
    vpmovsxbw       ymm10, xmm10
    vpmovsxbw       ymm11, xmm11
    vpmovsxbw       ymm12, xmm12

    vpmullw         ymm9, ymm9, ymm8
    vpmullw         ymm10, ymm10, ymm8
    vpmullw         ymm11, ymm11, ymm8
    vpmullw         ymm12, ymm12, ymm8
    vpmovsxwd       ymm9, xmm9                     ; promote byte to i32x8
    vpmovsxwd       ymm10, xmm10                   ; promote byte to i32x8
    vpmovsxwd       ymm11, xmm11                   ; promote byte to i32x8
    vpmovsxwd       ymm12, xmm12                   ; promote byte to i32x8
    vpaddd          ymm4, ymm4, ymm9
    vpaddd          ymm5, ymm5, ymm10
    vpaddd          ymm6, ymm6, ymm11
    vpaddd          ymm7, ymm7, ymm12

    add             rbx,    8
    add             rax,    8
    dec             rcx
    jnz             main_loop_packed_packed_i8i8

    jmp             non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

scalar_min:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vpminsd          ymm0, ymm12, ymm0
        
            vpminsd          ymm1, ymm12, ymm1
        
            vpminsd          ymm2, ymm12, ymm2
        
            vpminsd          ymm3, ymm12, ymm3
        
            vpminsd          ymm4, ymm12, ymm4
        
            vpminsd          ymm5, ymm12, ymm5
        
            vpminsd          ymm6, ymm12, ymm6
        
            vpminsd          ymm7, ymm12, ymm7
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_max:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vpmaxsd          ymm0, ymm12, ymm0
        
            vpmaxsd          ymm1, ymm12, ymm1
        
            vpmaxsd          ymm2, ymm12, ymm2
        
            vpmaxsd          ymm3, ymm12, ymm3
        
            vpmaxsd          ymm4, ymm12, ymm4
        
            vpmaxsd          ymm5, ymm12, ymm5
        
            vpmaxsd          ymm6, ymm12, ymm6
        
            vpmaxsd          ymm7, ymm12, ymm7
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_mul:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vpmulld          ymm0, ymm12, ymm0
        
            vpmulld          ymm1, ymm12, ymm1
        
            vpmulld          ymm2, ymm12, ymm2
        
            vpmulld          ymm3, ymm12, ymm3
        
            vpmulld          ymm4, ymm12, ymm4
        
            vpmulld          ymm5, ymm12, ymm5
        
            vpmulld          ymm6, ymm12, ymm6
        
            vpmulld          ymm7, ymm12, ymm7
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_add:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vpaddd          ymm0, ymm12, ymm0
        
            vpaddd          ymm1, ymm12, ymm1
        
            vpaddd          ymm2, ymm12, ymm2
        
            vpaddd          ymm3, ymm12, ymm3
        
            vpaddd          ymm4, ymm12, ymm4
        
            vpaddd          ymm5, ymm12, ymm5
        
            vpaddd          ymm6, ymm12, ymm6
        
            vpaddd          ymm7, ymm12, ymm7
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vpsubd          ymm0, ymm12, ymm0
        
            vpsubd          ymm1, ymm12, ymm1
        
            vpsubd          ymm2, ymm12, ymm2
        
            vpsubd          ymm3, ymm12, ymm3
        
            vpsubd          ymm4, ymm12, ymm4
        
            vpsubd          ymm5, ymm12, ymm5
        
            vpsubd          ymm6, ymm12, ymm6
        
            vpsubd          ymm7, ymm12, ymm7
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub_flipped:
    
        vbroadcastss    ymm12, dword ptr [rdi + 8]
    
    
    
        
            vpsubd          ymm0, ymm0, ymm12
        
            vpsubd          ymm1, ymm1, ymm12
        
            vpsubd          ymm2, ymm2, ymm12
        
            vpsubd          ymm3, ymm3, ymm12
        
            vpsubd          ymm4, ymm4, ymm12
        
            vpsubd          ymm5, ymm5, ymm12
        
            vpsubd          ymm6, ymm6, ymm12
        
            vpsubd          ymm7, ymm7, ymm12
        
    

    jmp    non_linear_loop

leaky_relu:
    ; can only use ymm12 to ymm15
    ; ymm15 <- alpha
    vbroadcastss    ymm15, dword ptr [rdi + 8]
    ; ymm14 <- all zero
    vpxor          ymm14, ymm14, ymm14

    
        vpmulld     ymm12, ymm0, ymm15
        vpcmpgtd    ymm13, ymm14, ymm0
        vblendvps   ymm0, ymm0, ymm12, ymm13
    
        vpmulld     ymm12, ymm1, ymm15
        vpcmpgtd    ymm13, ymm14, ymm1
        vblendvps   ymm1, ymm1, ymm12, ymm13
    
        vpmulld     ymm12, ymm2, ymm15
        vpcmpgtd    ymm13, ymm14, ymm2
        vblendvps   ymm2, ymm2, ymm12, ymm13
    
        vpmulld     ymm12, ymm3, ymm15
        vpcmpgtd    ymm13, ymm14, ymm3
        vblendvps   ymm3, ymm3, ymm12, ymm13
    
        vpmulld     ymm12, ymm4, ymm15
        vpcmpgtd    ymm13, ymm14, ymm4
        vblendvps   ymm4, ymm4, ymm12, ymm13
    
        vpmulld     ymm12, ymm5, ymm15
        vpcmpgtd    ymm13, ymm14, ymm5
        vblendvps   ymm5, ymm5, ymm12, ymm13
    
        vpmulld     ymm12, ymm6, ymm15
        vpcmpgtd    ymm13, ymm14, ymm6
        vblendvps   ymm6, ymm6, ymm12, ymm13
    
        vpmulld     ymm12, ymm7, ymm15
        vpcmpgtd    ymm13, ymm14, ymm7
        vblendvps   ymm7, ymm7, ymm12, ymm13
    

    jmp    non_linear_loop
; vim: set syntax=asm :

; vim: set syntax=asm :

per_row_min:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm8,  [rax + 0]
    



    
        vpminsd ymm0, ymm8, ymm0
    
        vpminsd ymm1, ymm8, ymm1
    
        vpminsd ymm2, ymm8, ymm2
    
        vpminsd ymm3, ymm8, ymm3
    
        vpminsd ymm4, ymm8, ymm4
    
        vpminsd ymm5, ymm8, ymm5
    
        vpminsd ymm6, ymm8, ymm6
    
        vpminsd ymm7, ymm8, ymm7
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_max:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm8,  [rax + 0]
    



    
        vpmaxsd ymm0, ymm8, ymm0
    
        vpmaxsd ymm1, ymm8, ymm1
    
        vpmaxsd ymm2, ymm8, ymm2
    
        vpmaxsd ymm3, ymm8, ymm3
    
        vpmaxsd ymm4, ymm8, ymm4
    
        vpmaxsd ymm5, ymm8, ymm5
    
        vpmaxsd ymm6, ymm8, ymm6
    
        vpmaxsd ymm7, ymm8, ymm7
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_add:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm8,  [rax + 0]
    



    
        vpaddd ymm0, ymm8, ymm0
    
        vpaddd ymm1, ymm8, ymm1
    
        vpaddd ymm2, ymm8, ymm2
    
        vpaddd ymm3, ymm8, ymm3
    
        vpaddd ymm4, ymm8, ymm4
    
        vpaddd ymm5, ymm8, ymm5
    
        vpaddd ymm6, ymm8, ymm6
    
        vpaddd ymm7, ymm8, ymm7
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_mul:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm8,  [rax + 0]
    



    
        vpmulld ymm0, ymm8, ymm0
    
        vpmulld ymm1, ymm8, ymm1
    
        vpmulld ymm2, ymm8, ymm2
    
        vpmulld ymm3, ymm8, ymm3
    
        vpmulld ymm4, ymm8, ymm4
    
        vpmulld ymm5, ymm8, ymm5
    
        vpmulld ymm6, ymm8, ymm6
    
        vpmulld ymm7, ymm8, ymm7
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm8,  [rax + 0]
    



    
        vpsubd ymm0, ymm8, ymm0
    
        vpsubd ymm1, ymm8, ymm1
    
        vpsubd ymm2, ymm8, ymm2
    
        vpsubd ymm3, ymm8, ymm3
    
        vpsubd ymm4, ymm8, ymm4
    
        vpsubd ymm5, ymm8, ymm5
    
        vpsubd ymm6, ymm8, ymm6
    
        vpsubd ymm7, ymm8, ymm7
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub_flipped:
    mov             rax, [ rdi + 8 ]





    
        vmovups         ymm8,  [rax + 0]
    



    
        vpsubd ymm0, ymm0, ymm8
    
        vpsubd ymm1, ymm1, ymm8
    
        vpsubd ymm2, ymm2, ymm8
    
        vpsubd ymm3, ymm3, ymm8
    
        vpsubd ymm4, ymm4, ymm8
    
        vpsubd ymm5, ymm5, ymm8
    
        vpsubd ymm6, ymm6, ymm8
    
        vpsubd ymm7, ymm7, ymm8
    


    jmp non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

per_col_min:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm0, ymm8, ymm0
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm1, ymm8, ymm1
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm2, ymm8, ymm2
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm3, ymm8, ymm3
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm4, ymm8, ymm4
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm5, ymm8, ymm5
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm6, ymm8, ymm6
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpminsd ymm7, ymm8, ymm7
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_max:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm0, ymm8, ymm0
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm1, ymm8, ymm1
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm2, ymm8, ymm2
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm3, ymm8, ymm3
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm4, ymm8, ymm4
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm5, ymm8, ymm5
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm6, ymm8, ymm6
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmaxsd ymm7, ymm8, ymm7
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_add:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm0, ymm8, ymm0
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm1, ymm8, ymm1
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm2, ymm8, ymm2
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm3, ymm8, ymm3
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm4, ymm8, ymm4
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm5, ymm8, ymm5
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm6, ymm8, ymm6
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpaddd ymm7, ymm8, ymm7
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_mul:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm0, ymm8, ymm0
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm1, ymm8, ymm1
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm2, ymm8, ymm2
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm3, ymm8, ymm3
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm4, ymm8, ymm4
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm5, ymm8, ymm5
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm6, ymm8, ymm6
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpmulld ymm7, ymm8, ymm7
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm0, ymm8, ymm0
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm1, ymm8, ymm1
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm2, ymm8, ymm2
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm3, ymm8, ymm3
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm4, ymm8, ymm4
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm5, ymm8, ymm5
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm6, ymm8, ymm6
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm7, ymm8, ymm7
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub_flipped:
    mov             rax, [ rdi + 8 ]











    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm0, ymm0, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm1, ymm1, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm2, ymm2, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm3, ymm3, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm4, ymm4, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm5, ymm5, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm6, ymm6, ymm8
        
    

    
        vbroadcastss    ymm8, dword ptr [ rax ]
        add             rax, 4
    
    
        
        
            vpsubd ymm7, ymm7, ymm8
        
    


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
    

    jmp    non_linear_loop

add_unicast:

    mov     r10,    [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     rbx,    [rdi + 24]          ; col stride
    mov     r8,     [rdi + 32]          ; item size

    cmp     r8,    4
    je      non_linear_addc_i32



    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm0, ymm0, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm1, ymm1, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm2, ymm2, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm3, ymm3, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm4, ymm4, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm5, ymm5, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm6, ymm6, ymm10
        add r10, rbx
    
        mov r8, r10
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 0
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 1
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 2
            
                mov al, [ r8 ]
                add r8, rsi
                movsx eax, al
                pinsrd xmm10, eax, 3
            
            vperm2f128  ymm10,   ymm10,   ymm10,  1
        
        vpaddd ymm7, ymm7, ymm10
        add r10, rbx
    

    jmp    non_linear_loop

non_linear_addc_i32:

    mov     eax,    0

    pinsrd  xmm14, eax, 0
    add     eax,    esi

    pinsrd  xmm14, eax, 1
    add     eax,    esi

    pinsrd  xmm14, eax, 2
    add     eax,    esi

    pinsrd  xmm14, eax, 3
    add     eax,    esi

    vpermq          ymm14, ymm14, 78 ; 0b01001110

    pinsrd  xmm14, eax, 0
    add     eax,    esi

    pinsrd  xmm14, eax, 1
    add     eax,    esi

    pinsrd  xmm14, eax, 2
    add     eax,    esi

    pinsrd  xmm14, eax, 3
    add     eax,    esi

    vpermq          ymm14, ymm14, 78 ; 0b01001110



    vpbroadcastd    ymm10, dword ptr [ offset byte_shuffle ]
    vmovups         ymm11, dword ptr [ offset i128_shuffle ]



    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm0,   ymm0,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm1,   ymm1,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm2,   ymm2,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm3,   ymm3,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm4,   ymm4,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm5,   ymm5,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm6,   ymm6,   ymm12
    add             r10, rbx

    vpcmpeqd        ymm15, ymm15, ymm15
    vgatherdps      ymm12, [ r10 + ymm14 ], ymm15
    vpaddd          ymm7,   ymm7,   ymm12
    add             r10, rbx


    jmp    non_linear_loop


.data
byte_shuffle dd              201851904 ; 0x0c080400
i128_shuffle dd              0, 4
.code


add_row_col_products:
    mov             rax, [ rdi + 8 ]
    mov             rbx, [ rdi + 16 ]

    vmovups         ymm12,  [rax]


    vbroadcastss    ymm14, dword ptr [rbx + 0 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm0, ymm0, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 4 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm1, ymm1, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 8 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm2, ymm2, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 12 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm3, ymm3, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 16 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm4, ymm4, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 20 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm5, ymm5, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 24 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm6, ymm6, ymm15

    vbroadcastss    ymm14, dword ptr [rbx + 28 ]
    vpmulld         ymm15, ymm12, ymm14
    vpaddd          ymm7, ymm7, ymm15

    jmp    non_linear_loop

q_scale:
    mov             r8, [ rdi + 16 ]        ; policy
    vbroadcastss    ymm8, dword ptr [rdi + 24] ; multi

    mov             rax, 1
    movq            xmm9, rax
    vpbroadcastq    ymm9, xmm9              ; ymm9 <- 1

    mov             rax, [ rdi + 8 ]        ; xmm10 <- shift + 31
    add             rax, 31
    movq            xmm10, rax
    vpbroadcastq    ymm10, xmm10

    mov             rax, 1
    movq            xmm11, rax
    vpsubq          ymm12, ymm10, ymm9      ; shift+31 - 1
    vpsllq          ymm11, ymm9, xmm12      ; ymm11 <- 1 << (shift + 31 - 1)

    cmp     r8, 1
    je      q_scale_rounding_zero
    cmp     r8, 2
    je      q_scale_rounding_away
    cmp     r8, 3
    je      q_scale_rounding_minus_inf
    cmp     r8, 4
    je      q_scale_rounding_plus_inf
    cmp     r8, 5
    je      q_scale_rounding_even
    cmp     r8, 6
    je      q_scale_rounding_odd

    jmp    unsupported

q_scale_rounding_zero:           ; signum * ( (abs + nudge) >> shift )

    vpabsd      ymm14, ymm0
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsubq      ymm14, ymm14, ymm9
    vpsubq      ymm15, ymm15, ymm9

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm7, ymm14, ymm7


    jmp    non_linear_loop

q_scale_rounding_away:           ; signum * ( (abs + nudge) >> shift )

    vpabsd      ymm14, ymm0
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm7, ymm14, ymm7


    jmp    non_linear_loop

q_scale_rounding_minus_inf:           ; signum * ( (abs << 32 + 1<<30+shift) >> shift )

    vpabsd      ymm14, ymm0
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm0, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm1, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm2, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm3, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm4, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm5, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm6, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    ; sign extract for nudging in the right direction
    vpxor       ymm13, ymm13, ymm13
    vpcmpgtd    ymm13, ymm7, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpsrld      ymm13, ymm13, 31            ; then just 0 or 1

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm7, ymm14, ymm7


    jmp    non_linear_loop

q_scale_rounding_plus_inf:           ; signum * ( (abs << 32 + 1<<30+shift) >> shift )

    vpbroadcastd ymm9, xmm9


    vpabsd      ymm14, ymm0
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm0, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm1, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm2, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm3, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm4, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm5, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm6, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpxor       ymm13, ymm13, ymm13

    ; sign extract for nudging in the right direction
    vpcmpgtd    ymm13, ymm7, ymm13      ; ymm13 <- s0, s1, ..s8 (signums, as all ones or all zeros)
    vpaddd      ymm13, ymm13, ymm9          ; if val >= 0 { 0i32 } else { 1i32 }

    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    ; reinterpret ymm13=s0i32..s7 as i64 and blend with zero to pick the even ones as i64
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm14, ymm14, ymm12

    vpsrldq     ymm13, ymm13, 4             ; ymm13 <- s1, s2, .., s7, 0
    vpxor       ymm12, ymm12, ymm12
    vpblendd    ymm12, ymm12, ymm13, 85     ; 0x55
    vpsubq      ymm15, ymm15, ymm12

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm7, ymm14, ymm7


    jmp    non_linear_loop

q_scale_rounding_even:           ; signum * ( (abs + nudge) >> shift )

    vpabsd      ymm14, ymm0
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm14, ymm14, ymm12
    vpsubq      ymm14, ymm14, ymm9

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpaddq      ymm15, ymm15, ymm12
    vpsubq      ymm15, ymm15, ymm9

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm7, ymm14, ymm7

    jmp    non_linear_loop

q_scale_rounding_odd:           ; signum * ( (abs + nudge) >> shift )

    vpabsd      ymm14, ymm0
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsrldq     ymm15, ymm14, 4             ; ymm15 <- a1, a2, a3, a4, a5, a6, a7, 0
    vpmuldq     ymm14, ymm14, ymm8          ; ymm14  <- a0*c, a2*c, a4*c, a6*c
    vpmuldq     ymm15, ymm15, ymm8          ; ymm15 <- a1*c, a3*c, a5*c, a7*c

    vpsrlq      ymm12, ymm14, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm14, ymm14, ymm12

    vpsrlq      ymm12, ymm15, xmm10
    vpand       ymm12, ymm12, ymm9
    vpsubq      ymm15, ymm15, ymm12

    vpaddq      ymm14, ymm14, ymm11
    vpaddq      ymm15, ymm15, ymm11

    vpsrlq      ymm14, ymm14, xmm10
    vpsrlq      ymm15, ymm15, xmm10

    vpslldq     ymm15, ymm15, 4
    vpblendd    ymm14, ymm15, ymm14, 85     ; 0x55
    vpsignd     ymm7, ymm14, ymm7


    jmp    non_linear_loop

q_shl:
    mov             eax, [ rdi + 8 ]        ; xmm10 <- -shift (8 times)
    movd            xmm10, eax
    vpbroadcastd    ymm10, xmm10


    vpsllvd     ymm0, ymm0, ymm10

    vpsllvd     ymm1, ymm1, ymm10

    vpsllvd     ymm2, ymm2, ymm10

    vpsllvd     ymm3, ymm3, ymm10

    vpsllvd     ymm4, ymm4, ymm10

    vpsllvd     ymm5, ymm5, ymm10

    vpsllvd     ymm6, ymm6, ymm10

    vpsllvd     ymm7, ymm7, ymm10

    jmp     non_linear_loop

q_shr:
    mov             r8, [ rdi + 16 ]        ; policy

    mov             eax, 1
    movd            xmm9, eax
    vpbroadcastd    ymm9, xmm9              ; ymm9 <- 1u32 (8 times)

    mov             eax, [ rdi + 8 ]        ; xmm10 <- shift (8 times)
    movd            xmm10, eax
    vpbroadcastd    ymm10, xmm10

    mov             ebx, 1
    mov             cl, al
    sub             cl, 1                  ; rcx <- shift -1
    sal             ebx, cl                ; rbx <- (1 << (shift - 1))
    movd            xmm11, ebx
    vpbroadcastd    ymm11, xmm11            ; ymm11 <- "half"

    vpxor           ymm12, ymm12, ymm12     ; ymm12 <- zeroes

    cmp     r8, 1
    je      q_shr_rounding_zero
    cmp     r8, 2
    je      q_shr_rounding_away
    cmp     r8, 3
    je      q_shr_rounding_minus_inf
    cmp     r8, 4
    je      q_shr_rounding_plus_inf
    cmp     r8, 5
    je      q_shr_rounding_even
    cmp     r8, 6
    je      q_shr_rounding_odd

    jmp    unsupported

q_shr_rounding_zero:

    vpabsd      ymm14, ymm0
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsubd      ymm14, ymm14, ymm9
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm7, ymm14, ymm7

    jmp     non_linear_loop

q_shr_rounding_away:

    vpabsd      ymm14, ymm0
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpaddd      ymm14, ymm14, ymm11
    vpsravd     ymm14, ymm14, ymm10
    vpsignd     ymm7, ymm14, ymm7

    jmp     non_linear_loop

q_shr_rounding_minus_inf:

    vpsubd  ymm0, ymm0, ymm9
    vpaddd  ymm0, ymm0, ymm11
    vpsravd ymm0, ymm0, ymm10

    vpsubd  ymm1, ymm1, ymm9
    vpaddd  ymm1, ymm1, ymm11
    vpsravd ymm1, ymm1, ymm10

    vpsubd  ymm2, ymm2, ymm9
    vpaddd  ymm2, ymm2, ymm11
    vpsravd ymm2, ymm2, ymm10

    vpsubd  ymm3, ymm3, ymm9
    vpaddd  ymm3, ymm3, ymm11
    vpsravd ymm3, ymm3, ymm10

    vpsubd  ymm4, ymm4, ymm9
    vpaddd  ymm4, ymm4, ymm11
    vpsravd ymm4, ymm4, ymm10

    vpsubd  ymm5, ymm5, ymm9
    vpaddd  ymm5, ymm5, ymm11
    vpsravd ymm5, ymm5, ymm10

    vpsubd  ymm6, ymm6, ymm9
    vpaddd  ymm6, ymm6, ymm11
    vpsravd ymm6, ymm6, ymm10

    vpsubd  ymm7, ymm7, ymm9
    vpaddd  ymm7, ymm7, ymm11
    vpsravd ymm7, ymm7, ymm10

    jmp     non_linear_loop

q_shr_rounding_plus_inf:

    vpaddd  ymm0, ymm0, ymm11
    vpsravd ymm0, ymm0, ymm10

    vpaddd  ymm1, ymm1, ymm11
    vpsravd ymm1, ymm1, ymm10

    vpaddd  ymm2, ymm2, ymm11
    vpsravd ymm2, ymm2, ymm10

    vpaddd  ymm3, ymm3, ymm11
    vpsravd ymm3, ymm3, ymm10

    vpaddd  ymm4, ymm4, ymm11
    vpsravd ymm4, ymm4, ymm10

    vpaddd  ymm5, ymm5, ymm11
    vpsravd ymm5, ymm5, ymm10

    vpaddd  ymm6, ymm6, ymm11
    vpsravd ymm6, ymm6, ymm10

    vpaddd  ymm7, ymm7, ymm11
    vpsravd ymm7, ymm7, ymm10

    jmp     non_linear_loop

q_shr_rounding_even:

    vpabsd      ymm14, ymm0
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm13, ymm9          ; nudge = ((abs >>l shift) & 0x01) - 1
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm7, ymm14, ymm7

    jmp     non_linear_loop

q_shr_rounding_odd:

    vpabsd      ymm14, ymm0
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm0, ymm14, ymm0

    vpabsd      ymm14, ymm1
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm1, ymm14, ymm1

    vpabsd      ymm14, ymm2
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm2, ymm14, ymm2

    vpabsd      ymm14, ymm3
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm3, ymm14, ymm3

    vpabsd      ymm14, ymm4
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm4, ymm14, ymm4

    vpabsd      ymm14, ymm5
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm5, ymm14, ymm5

    vpabsd      ymm14, ymm6
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm6, ymm14, ymm6

    vpabsd      ymm14, ymm7
    vpsravd ymm13, ymm14, ymm10
    vpand   ymm13, ymm13, ymm9
    vpsubd  ymm13, ymm12, ymm13          ; nudge = - ((abs >>l shift) & 0x01)
    vpaddd  ymm14, ymm14, ymm13         ; add nudge
    vpaddd  ymm14, ymm14, ymm11         ; add half
    vpsravd ymm14, ymm14, ymm10
    vpsignd     ymm7, ymm14, ymm7

    jmp     non_linear_loop

store:
    mov     r8,     [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride
    mov     rdx,    [rdi + 24]          ; col stride
    mov     rcx,    [rdi + 32]          ; item size

    cmp     rcx,    4
    je      store_strides_i32

    
        mov r10, r8
        
            extractps   ebx, xmm0, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm0, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm0, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm0, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm0,   ymm0,   ymm0,  1
        
            extractps   ebx, xmm0, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm0, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm0, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm0, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm1, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm1, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm1, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm1, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm1,   ymm1,   ymm1,  1
        
            extractps   ebx, xmm1, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm1, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm1, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm1, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm2, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm2, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm2, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm2, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm2,   ymm2,   ymm2,  1
        
            extractps   ebx, xmm2, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm2, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm2, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm2, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm3, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm3, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm3, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm3, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm3,   ymm3,   ymm3,  1
        
            extractps   ebx, xmm3, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm3, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm3, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm3, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm4, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm4, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm4, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm4, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm4,   ymm4,   ymm4,  1
        
            extractps   ebx, xmm4, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm4, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm4, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm4, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm5, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm5, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm5, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm5, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm5,   ymm5,   ymm5,  1
        
            extractps   ebx, xmm5, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm5, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm5, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm5, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm6, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm6, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm6, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm6, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm6,   ymm6,   ymm6,  1
        
            extractps   ebx, xmm6, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm6, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm6, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm6, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    
        mov r10, r8
        
            extractps   ebx, xmm7, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm7, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm7, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm7, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        vperm2f128  ymm7,   ymm7,   ymm7,  1
        
            extractps   ebx, xmm7, 0
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm7, 1
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm7, 2
            mov         byte ptr [r10], bl
            add         r10, rsi
        
            extractps   ebx, xmm7, 3
            mov         byte ptr [r10], bl
            add         r10, rsi
        
        add r8, rdx
    

    jmp     non_linear_loop

store_strides_i32:
    
        mov r10,    r8
        
            extractps   ebx, xmm0, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm0, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm0, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm0, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm0,   ymm0,   ymm0,  1
        
            extractps   ebx, xmm0, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm0, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm0, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm0, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm1, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm1, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm1, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm1, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm1,   ymm1,   ymm1,  1
        
            extractps   ebx, xmm1, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm1, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm1, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm1, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm2, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm2, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm2, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm2, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm2,   ymm2,   ymm2,  1
        
            extractps   ebx, xmm2, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm2, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm2, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm2, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm3, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm3, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm3, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm3, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm3,   ymm3,   ymm3,  1
        
            extractps   ebx, xmm3, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm3, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm3, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm3, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm4, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm4, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm4, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm4, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm4,   ymm4,   ymm4,  1
        
            extractps   ebx, xmm4, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm4, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm4, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm4, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm5, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm5, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm5, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm5, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm5,   ymm5,   ymm5,  1
        
            extractps   ebx, xmm5, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm5, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm5, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm5, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm6, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm6, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm6, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm6, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm6,   ymm6,   ymm6,  1
        
            extractps   ebx, xmm6, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm6, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm6, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm6, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    
        mov r10,    r8
        
            extractps   ebx, xmm7, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm7, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm7, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm7, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        vperm2f128  ymm7,   ymm7,   ymm7,  1
        
            extractps   ebx, xmm7, 0
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm7, 1
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm7, 2
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
            extractps   ebx, xmm7, 3
            mov         dword ptr [r10], ebx
            add         r10, rsi
        
        add r8, rdx
    

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


one_32bit:

    dd      1



avx2_mmm_i32_8x8_0_21_10 endp
_text ends
end
