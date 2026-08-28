




_text segment
avx512_mmm_f32_16x1_0_21_10 proc



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

	cmp rbx, 8
	jl main_loop_packed_packed_tail

align 16
main_loop_packed_packed:
		; slow
	vbroadcastss xmm16, dword ptr [rcx]
	vbroadcastss xmm17, dword ptr [rcx + 4]
	vbroadcastss xmm18, dword ptr [rcx + 8]
	vbroadcastss xmm19, dword ptr [rcx + 12]

	; fast
	vmovups	   		xmm31, [rcx]
	vbroadcastss 	zmm16, xmm31
	valignd 		xmm17, xmm31, xmm31, 1
	vbroadcastss 	zmm17, xmm17
	valignd 		xmm18, xmm31, xmm31, 2
	vbroadcastss 	zmm18, xmm18
	valignd 		xmm19, xmm31, xmm31, 3
	vbroadcastss 	zmm19, xmm19

	; commmon
	vfmadd231ps		zmm0, zmm16, [rax + 0]
	vfmadd231ps		zmm1, zmm17, [rax + 64]
	vfmadd231ps		zmm2, zmm18, [rax + 128]
	vfmadd231ps		zmm3, zmm19, [rax + 192]

	add rcx, 16
	add rax, 256

    sub             rbx, 4
	cmp rbx,        4
	jge              main_loop_packed_packed

	
	   vaddps zmm0, zmm0, zmm1
	
	   vaddps zmm0, zmm0, zmm2
	
	   vaddps zmm0, zmm0, zmm3
	

    test    rbx, rbx
    jz      non_linear_loop

align 16
main_loop_packed_packed_tail:
		vbroadcastss    zmm15, dword ptr [rcx]

    vmovups         zmm8, [rax]
    vfmadd231ps     zmm0, zmm15, zmm8

    add rcx, 4
	add rax, 64

	sub             rbx, 1
    jnz				main_loop_packed_packed_tail

    jmp      non_linear_loop

; vim: set syntax=asm :

; vim: set syntax=asm :

scalar_min:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vminps          zmm0, zmm12, zmm0
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_max:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vmaxps          zmm0, zmm12, zmm0
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_add:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vaddps          zmm0, zmm12, zmm0
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_mul:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vmulps          zmm0, zmm12, zmm0
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vsubps          zmm0, zmm12, zmm0
        
    

    jmp    non_linear_loop
; vim: set syntax=asm :

scalar_sub_flipped:
    vbroadcastss    zmm12, dword ptr [rdi + 8]
    
        
            vsubps          zmm0, zmm0, zmm12
        
    

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





    vmovups         zmm1,  [rax + 0]



    
        vminps zmm0, zmm1, zmm0
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_max:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm1,  [rax + 0]



    
        vmaxps zmm0, zmm1, zmm0
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_add:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm1,  [rax + 0]



    
        vaddps zmm0, zmm1, zmm0
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_mul:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm1,  [rax + 0]



    
        vmulps zmm0, zmm1, zmm0
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm1,  [rax + 0]



    
        vsubps zmm0, zmm1, zmm0
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_row_sub_flipped:
    mov             rax, [ rdi + 8 ]





    vmovups         zmm1,  [rax + 0]



    
        vsubps zmm0, zmm0, zmm1
    


    jmp non_linear_loop
; vim: set syntax=asm :

; vim: set syntax=asm :

per_col_min:
    mov             rax, [ rdi + 8 ]








; 1 cols:1


    vbroadcastss    zmm1, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vminps zmm0, zmm1, zmm0
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_max:
    mov             rax, [ rdi + 8 ]








; 1 cols:1


    vbroadcastss    zmm1, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmaxps zmm0, zmm1, zmm0
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_add:
    mov             rax, [ rdi + 8 ]








; 1 cols:1


    vbroadcastss    zmm1, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vaddps zmm0, zmm1, zmm0
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_mul:
    mov             rax, [ rdi + 8 ]








; 1 cols:1


    vbroadcastss    zmm1, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vmulps zmm0, zmm1, zmm0
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub:
    mov             rax, [ rdi + 8 ]








; 1 cols:1


    vbroadcastss    zmm1, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm0, zmm1, zmm0
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

per_col_sub_flipped:
    mov             rax, [ rdi + 8 ]








; 1 cols:1


    vbroadcastss    zmm1, dword ptr [ rax ]
    add             rax, 4

    
        
        
            vsubps zmm0, zmm0, zmm1
        
    


    jmp non_linear_loop
; vim: set syntax=asm :

load_tile:
    mov          r8, [rdi + 8]
    
        vmovups         zmm0, zmmword ptr [r8 + 0]
    

    jmp    non_linear_loop

add_unicast:
    mov     r10,    [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride

	cmp rsi, 4
	jne add_unicast_generic

	vaddps zmm0, zmm0, [r10]

    jmp    non_linear_loop

add_unicast_generic:
    mov r8, [0]
;     mov     eax,    0
; 
;     pinsrd  xmm14, eax, 0
;     add     eax,    esi
; 
;     pinsrd  xmm14, eax, 1
;     add     eax,    esi
; 
;     pinsrd  xmm14, eax, 2
;     add     eax,    esi
; 
;     pinsrd  xmm14, eax, 3
;     add     eax,    esi
; 
; 
;     pinsrd  xmm15, eax, 0
;     add     eax,    esi
; 
;     pinsrd  xmm15, eax, 1
;     add     eax,    esi
; 
;     pinsrd  xmm15, eax, 2
;     add     eax,    esi
; 
;     pinsrd  xmm15, eax, 3
;     add     eax,    esi
; 
;
;     vperm2f128      zmm14,  zmm14, zmm15,         32 ; zmm14 <- xmm14::xmm15
;
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm0,   zmm0,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm1,   zmm1,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm2,   zmm2,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm3,   zmm3,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm4,   zmm4,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm5,   zmm5,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm6,   zmm6,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;     vpcmpeqd        zmm15,  zmm15, zmm15
;     vgatherdps      zmm12,  [ r10 + zmm14 ], zmm15
;
;     vaddps          zmm7,   zmm7,   zmm12
;     lea             r10, [ r10 + rsi * 8 ]
; 
;
    jmp    non_linear_loop

add_row_col_products:
    mov             rax, [ rdi + 8 ]
    mov             rbx, [ rdi + 16 ]

    vbroadcastss    zmm14, dword ptr [rbx]


    vmovups         zmm12,  [rax + 0]
    vfmadd231ps     zmm0, zmm12, zmm14

    jmp    non_linear_loop

store:
    mov     r8,     [rdi + 8]           ; c ptr
    mov     rsi,    [rdi + 16]          ; row stride

    cmp     rsi, 4
    jne      store_noncontiguous

	test r8, 63
	jnz store_unaligned

    vmovaps [r8], zmm0
    jmp     non_linear_loop

store_unaligned:
	vmovups [r8], zmm0
    jmp     non_linear_loop

store_noncontiguous:
    
        vextractf32x4 xmm8, zmm0, 0
        
            vextractps  dword ptr [r8], xmm8, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 3
            add         r8, rsi
        
    
        vextractf32x4 xmm8, zmm0, 1
        
            vextractps  dword ptr [r8], xmm8, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 3
            add         r8, rsi
        
    
        vextractf32x4 xmm8, zmm0, 2
        
            vextractps  dword ptr [r8], xmm8, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 3
            add         r8, rsi
        
    
        vextractf32x4 xmm8, zmm0, 3
        
            vextractps  dword ptr [r8], xmm8, 0
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 1
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 2
            add         r8, rsi
        
            vextractps  dword ptr [r8], xmm8, 3
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


avx512_mmm_f32_16x1_0_21_10 endp
_text ends
end

