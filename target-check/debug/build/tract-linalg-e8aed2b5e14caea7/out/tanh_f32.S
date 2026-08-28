



_text segment
avx512_tanh_f32_0_21_10 proc



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

    ; move around arguments to mimick SysV rdi,rsi passing
    push        rdi
    push        rsi
    mov         rdi, rcx
    mov         rsi, rdx



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
; ----------------------------------------------------------------------



    cmp     rsi, 0
    je      done

    cmp     rsi, 32
    jl      loop_1

loop_4:

    vmovaps         zmm4, [rdi]
    vmovaps         zmm5, [rdi + 64]
    vmovaps         zmm6, [rdi + 128]
    vmovaps         zmm7, [rdi + 192]

    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_low]
    vbroadcastss    zmm1, dword ptr [ offset   coeffs_num_high]
    vbroadcastss    zmm2, dword ptr [ offset   coeffs_num_alpha_13]
    vbroadcastss    zmm3, dword ptr [ offset   coeffs_num_alpha_11]

    vmaxps          zmm4, zmm4, zmm0
    vmaxps          zmm5, zmm5, zmm0
    vmaxps          zmm6, zmm6, zmm0
    vmaxps          zmm7, zmm7, zmm0
    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_alpha_9]

    vminps          zmm4, zmm4, zmm1
    vminps          zmm5, zmm5, zmm1
    vminps          zmm6, zmm6, zmm1
    vminps          zmm7, zmm7, zmm1        ; zmm4..7 <- x
    vbroadcastss    zmm1, dword ptr [ offset   coeffs_num_alpha_7]

    vmulps          zmm8, zmm4, zmm4
    vmulps          zmm9, zmm5, zmm5
    vmulps          zmm10, zmm6, zmm6
    vmulps          zmm11, zmm7, zmm7        ; zmm8..11 <- x^2

    vmovaps         zmm12, zmm2
    vmovaps         zmm13, zmm2
    vmovaps         zmm14, zmm2
    vmovaps         zmm15, zmm2
    vbroadcastss    zmm2, dword ptr [ offset   coeffs_num_alpha_5]
    vfmadd132ps     zmm12, zmm3, zmm8
    vfmadd132ps     zmm13, zmm3, zmm9
    vfmadd132ps     zmm14, zmm3, zmm10
    vfmadd132ps     zmm15, zmm3, zmm11
    vbroadcastss    zmm3, dword ptr [ offset   coeffs_num_alpha_3]
    vfmadd132ps     zmm12, zmm0, zmm8
    vfmadd132ps     zmm13, zmm0, zmm9
    vfmadd132ps     zmm14, zmm0, zmm10
    vfmadd132ps     zmm15, zmm0, zmm11
    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_alpha_1]
    vfmadd132ps     zmm12, zmm1, zmm8
    vfmadd132ps     zmm13, zmm1, zmm9
    vfmadd132ps     zmm14, zmm1, zmm10
    vfmadd132ps     zmm15, zmm1, zmm11
    vbroadcastss    zmm1, dword ptr [ offset   coeffs_num_beta_6]
    vfmadd132ps     zmm12, zmm2, zmm8
    vfmadd132ps     zmm13, zmm2, zmm9
    vfmadd132ps     zmm14, zmm2, zmm10
    vfmadd132ps     zmm15, zmm2, zmm11
    vbroadcastss    zmm2, dword ptr [ offset   coeffs_num_beta_4]
    vfmadd132ps     zmm12, zmm3, zmm8
    vfmadd132ps     zmm13, zmm3, zmm9
    vfmadd132ps     zmm14, zmm3, zmm10
    vfmadd132ps     zmm15, zmm3, zmm11
    vbroadcastss    zmm3, dword ptr [ offset   coeffs_num_beta_2]
    vfmadd132ps     zmm12, zmm0, zmm8
    vfmadd132ps     zmm13, zmm0, zmm9
    vfmadd132ps     zmm14, zmm0, zmm10
    vfmadd132ps     zmm15, zmm0, zmm11
    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_beta_0]
    vmulps          zmm4, zmm4, zmm12
    vmulps          zmm5, zmm5, zmm13
    vmulps          zmm6, zmm6, zmm14
    vmulps          zmm7, zmm7, zmm15   ; zmm4..7 <- num

    vmovaps         zmm12, zmm1
    vmovaps         zmm13, zmm1
    vmovaps         zmm14, zmm1
    vmovaps         zmm15, zmm1
    vfmadd132ps     zmm12, zmm2, zmm8
    vfmadd132ps     zmm13, zmm2, zmm9
    vfmadd132ps     zmm14, zmm2, zmm10
    vfmadd132ps     zmm15, zmm2, zmm11
    vfmadd132ps     zmm12, zmm3, zmm8
    vfmadd132ps     zmm13, zmm3, zmm9
    vfmadd132ps     zmm14, zmm3, zmm10
    vfmadd132ps     zmm15, zmm3, zmm11
    vfmadd132ps     zmm12, zmm0, zmm8
    vfmadd132ps     zmm13, zmm0, zmm9
    vfmadd132ps     zmm14, zmm0, zmm10
    vfmadd132ps     zmm15, zmm0, zmm11  ; zmm12..14 <- denum

    vdivps          zmm4, zmm4, zmm12
    vdivps          zmm5, zmm5, zmm13
    vdivps          zmm6, zmm6, zmm14
    vdivps          zmm7, zmm7, zmm15

    vmovaps [rdi], zmm4
    vmovaps [rdi + 64], zmm5
    vmovaps [rdi + 128], zmm6
    vmovaps [rdi + 192], zmm7

    add     rdi, 256
    sub     rsi, 32
    cmp     rsi, 32
    jg      loop_4

    cmp     rsi, 0
    je      done

loop_1:
    vmovaps         zmm4, [rdi]

    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_low]
    vbroadcastss    zmm1, dword ptr [ offset   coeffs_num_high]
    vbroadcastss    zmm2, dword ptr [ offset   coeffs_num_alpha_13]
    vbroadcastss    zmm3, dword ptr [ offset   coeffs_num_alpha_11]

    vmaxps          zmm4, zmm4, zmm0
    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_alpha_9]

    vminps          zmm4, zmm4, zmm1        ; zmm4 <- x
    vbroadcastss    zmm1, dword ptr [ offset   coeffs_num_alpha_7]

    vmulps          zmm8, zmm4, zmm4        ; zmm8 <- x^2

    vmovaps         zmm12, zmm2
    vbroadcastss    zmm2, dword ptr [ offset   coeffs_num_alpha_5]
    vfmadd132ps     zmm12, zmm3, zmm8
    vbroadcastss    zmm3, dword ptr [ offset   coeffs_num_alpha_3]
    vfmadd132ps     zmm12, zmm0, zmm8
    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_alpha_1]
    vfmadd132ps     zmm12, zmm1, zmm8
    vbroadcastss    zmm1, dword ptr [ offset   coeffs_num_beta_6]
    vfmadd132ps     zmm12, zmm2, zmm8
    vbroadcastss    zmm2, dword ptr [ offset   coeffs_num_beta_4]
    vfmadd132ps     zmm12, zmm3, zmm8
    vbroadcastss    zmm3, dword ptr [ offset   coeffs_num_beta_2]
    vfmadd132ps     zmm12, zmm0, zmm8
    vbroadcastss    zmm0, dword ptr [ offset   coeffs_num_beta_0]
    vmulps          zmm4, zmm4, zmm12

    vmovaps         zmm12, zmm1
    vfmadd132ps     zmm12, zmm2, zmm8
    vfmadd132ps     zmm12, zmm3, zmm8
    vfmadd132ps     zmm12, zmm0, zmm8

    vdivps          zmm4, zmm4, zmm12

    vmovaps [rdi], zmm4
    add     rdi, 32
    sub     rsi, 8
    jnz     loop_1

done:

; ----------------------------------------------------------------------

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



coeffs_num_low:
     real4  -9.0                     ; low
coeffs_num_high:
     real4  9.0                      ; high

coeffs_num_alpha_13:
     real4  -2.76076847742355e-16    ; alpha_13
coeffs_num_alpha_11:
     real4  2.00018790482477e-13     ; alpha_11
coeffs_num_alpha_9:
     real4  -8.60467152213735e-11    ; alpha_9
coeffs_num_alpha_7:
     real4  5.12229709037114e-08     ; alpha_7
coeffs_num_alpha_5:
     real4  1.48572235717979e-05     ; alpha_5
coeffs_num_alpha_3:
     real4  6.37261928875436e-04     ; alpha_3
coeffs_num_alpha_1:
     real4  4.89352455891786e-03     ; alpha_1

coeffs_num_beta_6:
     real4  1.19825839466702e-06     ; beta_6
coeffs_num_beta_4:
     real4  1.18534705686654e-04     ; beta_4
coeffs_num_beta_2:
     real4  2.26843463243900e-03     ; beta_2
coeffs_num_beta_0:
     real4  4.89352518554385e-03     ; beta_0


avx512_tanh_f32_0_21_10 endp
_text ends
end
