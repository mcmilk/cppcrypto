;
;Copyright (c) 2007 Robert W. Waite <winstonwaite@gmail.com>
;
;Permission to use, copy, modify, and distribute this software for any
;purpose with or without fee is hereby granted, provided that the above
;copyright notice and this permission notice appear in all copies.
;
;THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
;WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
;MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
;ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
;WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
;ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
;OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

;The novel method of using sboxes used in this code is entirely not
;my idea. I borrowed the sboxes from Dag Arne Osvik. I will put his
;paper in the documentation in the not too distant future.

; Modified by kerukuro for use in cppcrypto.

%macro      xorKey   4

        xor %1, [ebp]
        xor %2, [ebp+4]
        xor %3, [ebp+8]
        xor %4, [ebp+12]
        add ebp, 16 
        
%endmacro

%macro      xorKeyInverse   4

        xor %1, [ebp]
        xor %2, [ebp+4]
        xor %3, [ebp+8]
        xor %4, [ebp+12]
        sub ebp, 16 

%endmacro

%macro      sbox0    5

        mov %5, %4
        or  %4, %1
        xor %1, %5
        xor %5, %3
        not %5
        xor %4, %2
        and %2, %1
        xor %2, %5
        xor %3, %1
        xor %1, %4
        or  %5, %1
        xor %1, %3
        and %3, %2
        xor %4, %3
        not %2
        xor %3, %5
        xor %2, %3
        
%endmacro

%macro      sbox0Inverse     5

        mov %5, %4
        xor %2, %1
        or  %4, %2
        xor %5, %2
        not %1
        xor %3, %4
        xor %4, %1
        and %1, %2
        xor %1, %3
        and %3, %4
        xor %4, %5
        xor %3, %4
        xor %2, %4
        and %4, %1
        xor %2, %1
        xor %1, %3
        xor %5, %4
        
%endmacro

%macro      sbox1    5

        mov %5, %2
        xor %2, %1
        xor %1, %4
        not %4
        and %5, %2
        or  %1, %2
        xor %4, %3
        xor %1, %4
        xor %2, %4
        xor %4, %5
        or  %2, %5
        xor %5, %3
        and %3, %1
        xor %3, %2
        or  %2, %1
        not %1
        xor %1, %3
        xor %5, %2
        
%endmacro

%macro      sbox1Inverse     5

        xor %2, %4
        mov %5, %1
        xor %1, %3
        not %3
        or  %5, %2
        xor %5, %4
        and %4, %2
        xor %2, %3
        and %3, %5
        xor %5, %2
        or  %2, %4
        xor %4, %1
        xor %3, %1
        or  %1, %5
        xor %3, %5
        xor %2, %1
        xor %5, %2
        
%endmacro

%macro      sbox2    5

        not %4
        xor %2, %1
        mov %5, %1
        and %1, %3
        xor %1, %4
        or  %4, %5
        xor %3, %2
        xor %4, %2
        and %2, %1
        xor %1, %3
        and %3, %4
        or  %4, %2
        not %1
        xor %4, %1
        xor %5, %1
        xor %1, %3
        or  %2, %3
        
%endmacro

%macro      sbox2Inverse     5

        xor %3, %2
        mov %5, %4
        not %4
        or  %4, %3
        xor %3, %5
        xor %5, %1
        xor %4, %2
        or  %2, %3
        xor %3, %1
        xor %2, %5
        or  %5, %4
        xor %3, %4
        xor %5, %3
        and %3, %2
        xor %3, %4
        xor %4, %5
        xor %5, %1
        
%endmacro

%macro      sbox3    5

        mov %5, %2
        xor %2, %4
        or  %4, %1
        and %5, %1
        xor %1, %3
        xor %3, %2
        and %2, %4
        xor %3, %4
        or  %1, %5
        xor %5, %4
        xor %2, %1
        and %1, %4
        and %4, %5
        xor %4, %3
        or  %5, %2
        and %3, %2
        xor %5, %4
        xor %1, %4
        xor %4, %3
        
%endmacro

%macro      sbox3Inverse     5

        xor %3, %2
        mov %5, %2
        and %2, %3
        xor %2, %1
        or  %1, %5
        xor %5, %4
        xor %1, %4
        or  %4, %2
        xor %2, %3
        xor %2, %4
        xor %1, %3
        xor %3, %4
        and %4, %2
        xor %2, %1
        and %1, %3
        xor %5, %4
        xor %4, %1
        xor %1, %2
        
%endmacro

%macro      sbox4    5

        
        mov %5, %4
        and %4, %1
        xor %1, %5
        xor %4, %3
        or  %3, %5
        xor %1, %2
        xor %5, %4
        or  %3, %1
        xor %3, %2
        and %2, %1
        xor %2, %5
        and %5, %3
        xor %3, %4
        xor %5, %1
        or  %4, %2
        not %2
        xor %4, %1
        
%endmacro

%macro      sbox4Inverse     5

        xor %3, %4
        mov %5, %1
        and %1, %2
        xor %1, %3
        or  %3, %4
        not %5
        xor %2, %1
        xor %1, %3
        and %3, %5
        xor %3, %1
        or  %1, %5
        xor %1, %4
        and %4, %3
        xor %5, %4
        xor %4, %2
        and %2, %1
        xor %5, %2
        xor %1, %4
        
%endmacro

%macro      sbox5    5

        mov %5, %2
        or  %2, %1
        xor %3, %2
        not %4
        xor %5, %1
        xor %1, %3
        and %2, %5
        or  %5, %4
        xor %5, %1
        and %1, %4
        xor %2, %4
        xor %4, %3
        xor %1, %2
        and %3, %5
        xor %2, %3
        and %3, %1
        xor %4, %3
        
%endmacro

%macro      sbox5Inverse     5

        mov %5, %2
        or  %2, %3
        xor %3, %5
        xor %2, %4
        and %4, %5
        xor %3, %4
        or  %4, %1
        not %1
        xor %4, %3
        or  %3, %1
        xor %5, %2
        xor %3, %5
        and %5, %1
        xor %1, %2
        xor %2, %4
        and %1, %3
        xor %3, %4
        xor %1, %3
        xor %3, %5
        xor %5, %4
        
%endmacro

%macro      sbox6    5

        mov %5, %2
        xor %4, %1
        xor %2, %3
        xor %3, %1
        and %1, %4
        or  %2, %4
        not %5
        xor %1, %2
        xor %2, %3
        xor %4, %5
        xor %5, %1
        and %3, %1
        xor %5, %2
        xor %3, %4
        and %4, %2
        xor %4, %1
        xor %2, %3
        
%endmacro

%macro      sbox6Inverse     5

        xor %1, %3
        mov %5, %1
        and %1, %4
        xor %3, %4
        xor %1, %3
        xor %4, %2
        or  %3, %5
        xor %3, %4
        and %4, %1
        not %1
        xor %4, %2
        and %2, %3
        xor %5, %1
        xor %4, %5
        xor %5, %3
        xor %1, %2
        xor %3, %1
        
%endmacro

%macro      sbox7    5

        not %2
        mov %5, %2
        not %1
        and %2, %3
        xor %2, %4
        or  %4, %5
        xor %5, %3
        xor %3, %4
        xor %4, %1
        or  %1, %2
        and %3, %1
        xor %1, %5
        xor %5, %4
        and %4, %1
        xor %5, %2
        xor %3, %5
        xor %4, %2
        or  %5, %1
        xor %5, %2
        
%endmacro

%macro      sbox7Inverse     5

        mov %5, %4
        and %4, %1
        xor %1, %3
        or  %3, %5
        xor %5, %2
        not %1
        or  %2, %4
        xor %5, %1
        and %1, %3
        xor %1, %2
        and %2, %3
        xor %4, %3
        xor %5, %4
        and %3, %4
        or  %4, %1
        xor %2, %5
        xor %4, %5
        and %5, %1
        xor %5, %3
        
%endmacro

%macro      linearTrans     5

        rol %1, 13
        rol %3, 3
        xor %2, %1
        xor %2, %3
        mov %5, %1
        sal %5, 3
        xor %4, %5
        xor %4, %3
        rol %2, 1
        rol %4, 7
        xor %1, %2
        xor %1, %4
        mov %5, %2
        sal %5, 7
        xor %3, %5
        xor %3, %4
        rol %1, 5
        rol %3, 22
        
%endmacro   

%macro      linearTransInverse      5

        ror %3, 22
        ror %1, 5
        mov %5, %2
        xor %3, %4
        xor %1, %4
        sal %5, 7
        xor %1, %2
        ror %2, 1
        xor %3, %5
        ror %4, 7
        mov %5, %1
        sal %5, 3
        xor %2, %1
        xor %4, %5      
        xor %2, %3
        xor %4, %3
        ror %3, 3
        ror %1, 13
        
%endmacro

%macro      firstKeyRound   0

mov eax, [esp]          
mov ebx, [esp+12]       
mov ecx, [esp+20]       
mov edx, [esp+28]       
xor eax, ebx
xor eax, ecx
xor eax, edx
xor eax, 0x9e3779b9
xor eax, 0
rol eax, 11             
mov [esp], eax

mov edi, [esp+4]        
mov esi, [esp+16]       
mov ebp, [esp+24]       
xor edi, esi
xor edi, ebp
xor edi, eax
xor edi, 0x9e3779b9
xor edi, 1
rol edi, 11             
mov [esp+4], edi

mov ebx, [esp+8]                
xor ebx, ecx             
xor ebx, edx             
xor ebx, edi             
xor ebx, 0x9e3779b9      
xor ebx, 2               
rol ebx, 11              
mov [esp+8], ebx
         
mov esi, [esp+12]        
xor esi, ebp             
xor esi, eax             
xor esi, ebx             
xor esi, 0x9e3779b9      
xor esi, 3               
rol esi, 11              
mov [esp+12], esi 
       
mov ecx, [esp+16]        
xor ecx, edx             
xor ecx, edi             
xor ecx, esi             
xor ecx, 0x9e3779b9      
xor ecx, 4               
rol ecx, 11              
mov [esp+16], ecx  
      
mov ebp, [esp+20]        
xor ebp, eax             
xor ebp, ebx             
xor ebp, ecx             
xor ebp, 0x9e3779b9      
xor ebp, 5               
rol ebp, 11              
mov [esp+20], ebp  
      
mov edx, [esp+24]        
xor edx, edi             
xor edx, esi             
xor edx, ebp             
xor edx, 0x9e3779b9      
xor edx, 6               
rol edx, 11              
mov [esp+24], edx  
      
mov eax, [esp+28]        
xor eax, ebx             
xor eax, ecx             
xor eax, edx             
xor eax, 0x9e3779b9      
xor eax, 7               
rol eax, 11              
mov [esp+28], eax        
mov edi, [esp]

%endmacro

%macro      normalKeyRound      3

%assign rnd %1
%assign inky %2
%assign outky %3    
     
xor edi, esi             
xor edi, ebp             
xor edi, eax             
xor edi, 0x9e3779b9      
xor edi, rnd               
rol edi, 11              
mov [esp+outky], edi        
mov ebx, [esp+inky] 

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
         
xor ebx, ecx                                      
xor ebx, edx                                      
xor ebx, edi           
xor ebx, 0x9e3779b9    
xor ebx, rnd             
rol ebx, 11                  
mov [esp+outky], ebx      
mov esi, [esp+inky]

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
             
xor esi, ebp           
xor esi, eax           
xor esi, ebx           
xor esi, 0x9e3779b9    
xor esi, rnd            
rol esi, 11                  
mov [esp+outky], esi      
mov ecx, [esp+inky] 

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
        
xor ecx, edx           
xor ecx, edi           
xor ecx, esi           
xor ecx, 0x9e3779b9
xor ecx, rnd            
rol ecx, 11                  
mov [esp+outky], ecx            
mov ebp, [esp+inky] 

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
        
xor ebp, eax           
xor ebp, ebx           
xor ebp, ecx           
xor ebp, 0x9e3779b9    
xor ebp, rnd            
rol ebp, 11                  
mov [esp+outky], ebp      
mov edx, [esp+inky]     

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
    
xor edx, edi           
xor edx, esi           
xor edx, ebp           
xor edx, 0x9e3779b9    
xor edx, rnd            
rol edx, 11                  
mov [esp+outky], edx      
mov eax, [esp+inky]     

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
    
xor eax, ebx           
xor eax, ecx           
xor eax, edx           
xor eax, 0x9e3779b9    
xor eax, rnd            
rol eax, 11                  
mov [esp+outky], eax            
mov edi, [esp+inky]     

%endmacro

%macro      finalKeyRound   3

%assign rnd %1
%assign inky %2
%assign outky %3    
     
xor edi, esi             
xor edi, ebp             
xor edi, eax             
xor edi, 0x9e3779b9      
xor edi, rnd               
rol edi, 11              
mov [esp+outky], edi        
mov ebx, [esp+inky] 

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
         
xor ebx, ecx                                      
xor ebx, edx                                      
xor ebx, edi           
xor ebx, 0x9e3779b9    
xor ebx, rnd             
rol ebx, 11                  
mov [esp+outky], ebx      
mov esi, [esp+inky]

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
             
xor esi, ebp           
xor esi, eax           
xor esi, ebx           
xor esi, 0x9e3779b9    
xor esi, rnd            
rol esi, 11                  
mov [esp+outky], esi      
mov ecx, [esp+inky] 

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
        
xor ecx, edx           
xor ecx, edi           
xor ecx, esi           
xor ecx, 0x9e3779b9 
xor ecx, rnd            
rol ecx, 11                  
mov [esp+outky], ecx            
mov ebp, [esp+inky] 

%assign rnd rnd+1
%assign inky inky+4
%assign outky outky+4
        
xor ebp, eax           
xor ebp, ebx           
xor ebp, ecx           
xor ebp, 0x9e3779b9    
xor ebp, rnd            
rol ebp, 11                  
mov [esp+outky], ebp      
mov edx, [esp+inky]

%endmacro

%macro      sboxKeyRound    6

%assign w %1
%assign x w+4
%assign y w+8
%assign z w+12

mov eax, [esp+w]
mov ebx, [esp+x]
mov ecx, [esp+y]
mov edx, [esp+z]

%6  eax, ebx, ecx, edx, edi

mov [ebp+w], %2
mov [ebp+x], %3
mov [ebp+y], %4
mov [ebp+z], %5

%endmacro


section .text
    global _serpentEncrypt
    global _serpentDecrypt
    global _serpentGenKeyAsm
    global serpentEncrypt
    global serpentDecrypt
    global serpentGenKeyAsm

    _serpentEncrypt:
    serpentEncrypt:
    
        push ebp                    ;save value of registers, we use them all
        push ebx                    ;save register
        push esi                    ;save register
        push edi                    ;save register
        
        mov esi, [esp+20]           ;move pointer to plaintext (first arg of function) to ESI   
        mov eax, [esi+12]           ;put first int in EAX
        mov ebx, [esi+8]            ;second int in EBX
        mov ecx, [esi+4]            ;third in ECX
        mov edx, [esi]              ;fourth in EDX
        mov ebp, [esp+24]           ;move pointer to key (second arg of function) to EBP
              
        xorKey      eax, ebx, ecx, edx
        sbox0       eax, ebx, ecx, edx, edi
        
        linearTrans ecx, ebx, edx, eax, edi
        xorKey      ecx, ebx, edx, eax
        sbox1       ecx, ebx, edx, eax, edi
        
        linearTrans edi, edx, eax, ecx, ebx
        xorKey      edi, edx, eax, ecx
        sbox2       edi, edx, eax, ecx, ebx
        
        linearTrans ebx, edx, edi, ecx, eax
        xorKey      ebx, edx, edi, ecx
        sbox3       ebx, edx, edi, ecx, eax
        
        linearTrans ecx, eax, edx, ebx, edi
        xorKey      ecx, eax, edx, ebx
        sbox4       ecx, eax, edx, ebx, edi
        
        linearTrans eax, edx, ebx, edi, ecx
        xorKey      eax, edx, ebx, edi
        sbox5       eax, edx, ebx, edi, ecx
        
        linearTrans ecx, eax, edx, edi, ebx
        xorKey      ecx, eax, edx, edi
        sbox6       ecx, eax, edx, edi, ebx
        
        linearTrans edx, ebx, eax, edi, ecx
        xorKey      edx, ebx, eax, edi
        sbox7       edx, ebx, eax, edi, ecx
        
        linearTrans ecx, eax, edi, edx, ebx
        xorKey      ecx, eax, edi, edx
        sbox0       ecx, eax, edi, edx, ebx
        
        linearTrans edi, eax, edx, ecx, ebx
        xorKey      edi, eax, edx, ecx
        sbox1       edi, eax, edx, ecx, ebx
        
        linearTrans ebx, edx, ecx, edi, eax
        xorKey      ebx, edx, ecx, edi
        sbox2       ebx, edx, ecx, edi, eax
        
        linearTrans eax, edx, ebx, edi, ecx
        xorKey      eax, edx, ebx, edi
        sbox3       eax, edx, ebx, edi, ecx
        
        linearTrans edi, ecx, edx, eax, ebx
        xorKey      edi, ecx, edx, eax
        sbox4       edi, ecx, edx, eax, ebx
        
        linearTrans ecx, edx, eax, ebx, edi
        xorKey      ecx, edx, eax, ebx
        sbox5       ecx, edx, eax, ebx, edi
        
        linearTrans edi, ecx, edx, ebx, eax
        xorKey      edi, ecx, edx, ebx
        sbox6       edi, ecx, edx, ebx, eax
        
        linearTrans edx, eax, ecx, ebx, edi
        xorKey      edx, eax, ecx, ebx
        sbox7       edx, eax, ecx, ebx, edi
        
        linearTrans edi, ecx, ebx, edx, eax
        xorKey      edi, ecx, ebx, edx
        sbox0       edi, ecx, ebx, edx, eax
        
        linearTrans ebx, ecx, edx, edi, eax
        xorKey      ebx, ecx, edx, edi
        sbox1       ebx, ecx, edx, edi, eax
        
        linearTrans eax, edx, edi, ebx, ecx
        xorKey      eax, edx, edi, ebx
        sbox2       eax, edx, edi, ebx, ecx
        
        linearTrans ecx, edx, eax, ebx, edi
        xorKey      ecx, edx, eax, ebx
        sbox3       ecx, edx, eax, ebx, edi
        
        linearTrans ebx, edi, edx, ecx, eax
        xorKey      ebx, edi, edx, ecx
        sbox4       ebx, edi, edx, ecx, eax
        
        linearTrans edi, edx, ecx, eax, ebx
        xorKey      edi, edx, ecx, eax
        sbox5       edi, edx, ecx, eax, ebx
        
        linearTrans ebx, edi, edx, eax, ecx
        xorKey      ebx, edi, edx, eax
        sbox6       ebx, edi, edx, eax, ecx
        
        linearTrans edx, ecx, edi, eax, ebx
        xorKey      edx, ecx, edi, eax
        sbox7       edx, ecx, edi, eax, ebx
        
        linearTrans ebx, edi, eax, edx, ecx
        xorKey      ebx, edi, eax, edx
        sbox0       ebx, edi, eax, edx, ecx
        
        linearTrans eax, edi, edx, ebx, ecx
        xorKey      eax, edi, edx, ebx
        sbox1       eax, edi, edx, ebx, ecx
        
        linearTrans ecx, edx, ebx, eax, edi
        xorKey      ecx, edx, ebx, eax
        sbox2       ecx, edx, ebx, eax, edi
        
        linearTrans edi, edx, ecx, eax, ebx
        xorKey      edi, edx, ecx, eax
        sbox3       edi, edx, ecx, eax, ebx
        
        linearTrans eax, ebx, edx, edi, ecx
        xorKey      eax, ebx, edx, edi
        sbox4       eax, ebx, edx, edi, ecx
        
        linearTrans ebx, edx, edi, ecx, eax
        xorKey      ebx, edx, edi, ecx
        sbox5       ebx, edx, edi, ecx, eax
        
        linearTrans eax, ebx, edx, ecx, edi
        xorKey      eax, ebx, edx, ecx
        sbox6       eax, ebx, edx, ecx, edi
        
        linearTrans edx, edi, ebx, ecx, eax
        xorKey      edx, edi, ebx, ecx
        sbox7       edx, edi, ebx, ecx, eax
        
        xorKey      eax, ebx, ecx, edx
                                       
        mov esi, [esp+20]           ;save values of columns
        mov [esi+12], eax
        mov [esi+8], ebx
        mov [esi+4], ecx
        mov [esi], edx       
        
        pop edi                     ;restore registers to their values before the call
        pop esi
        pop ebx
        pop ebp

        ret
        
    _serpentDecrypt:
    serpentDecrypt:
    
        push ebp                    ;save value of registers, we use them all
        push ebx                    ;save register
        push esi                    ;save register
        push edi                    ;save register
        
        mov esi, [esp+20]           ;move pointer to data (first arg of function) to ESI   
        mov eax, [esi+12]           ;put first int in EAX
        mov ebx, [esi+8]            ;second int in EBX
        mov ecx, [esi+4]            ;third in ECX
        mov edx, [esi]              ;fourth in EDX
        mov ebp, [esp+24]           ;move pointer to key (second arg of function) to EBP
        
        add ebp, 512                ;move to end of key since we are decrypting
                 
        xorKeyInverse       eax, ebx, ecx, edx
        sbox7Inverse        eax, ebx, ecx, edx, edi
        
        xorKeyInverse       ebx, edx, eax, edi
        linearTransInverse  ebx, edx, eax, edi, ecx
        sbox6Inverse        ebx, edx, eax, edi, ecx
        
        xorKeyInverse       eax, ecx, edi, ebx
        linearTransInverse  eax, ecx, edi, ebx, edx
        sbox5Inverse        eax, ecx, edi, ebx, edx
        
        xorKeyInverse       ecx, edx, eax, edi
        linearTransInverse  ecx, edx, eax, edi, ebx
        sbox4Inverse        ecx, edx, eax, edi, ebx
        
        xorKeyInverse       ecx, eax, ebx, edi
        linearTransInverse  ecx, eax, ebx, edi, edx
        sbox3Inverse        ecx, eax, ebx, edi, edx
        
        xorKeyInverse       ebx, ecx, edx, edi
        linearTransInverse  ebx, ecx, edx, edi, eax
        sbox2Inverse        ebx, ecx, edx, edi, eax
        
        xorKeyInverse       ecx, eax, edi, edx
        linearTransInverse  ecx, eax, edi, edx, ebx
        sbox1Inverse        ecx, eax, edi, edx, ebx
        
        xorKeyInverse       ebx, eax, edi, edx
        linearTransInverse  ebx, eax, edi, edx, ecx
        sbox0Inverse        ebx, eax, edi, edx, ecx
        
        xorKeyInverse       edi, ecx, eax, ebx
        linearTransInverse  edi, ecx, eax, ebx, edx
        sbox7Inverse        edi, ecx, eax, ebx, edx
        
        xorKeyInverse       ecx, ebx, edi, edx
        linearTransInverse  ecx, ebx, edi, edx, eax
        sbox6Inverse        ecx, ebx, edi, edx, eax
        
        xorKeyInverse       edi, eax, edx, ecx
        linearTransInverse  edi, eax, edx, ecx, ebx
        sbox5Inverse        edi, eax, edx, ecx, ebx
        
        xorKeyInverse       eax, ebx, edi, edx
        linearTransInverse  eax, ebx, edi, edx, ecx
        sbox4Inverse        eax, ebx, edi, edx, ecx
        
        xorKeyInverse       eax, edi, ecx, edx
        linearTransInverse  eax, edi, ecx, edx, ebx
        sbox3Inverse        eax, edi, ecx, edx, ebx
        
        xorKeyInverse       ecx, eax, ebx, edx
        linearTransInverse  ecx, eax, ebx, edx, edi
        sbox2Inverse        ecx, eax, ebx, edx, edi
        
        xorKeyInverse       eax, edi, edx, ebx
        linearTransInverse  eax, edi, edx, ebx, ecx
        sbox1Inverse        eax, edi, edx, ebx, ecx
        
        xorKeyInverse       ecx, edi, edx, ebx
        linearTransInverse  ecx, edi, edx, ebx, eax
        sbox0Inverse        ecx, edi, edx, ebx, eax
        
        xorKeyInverse       edx, eax, edi, ecx
        linearTransInverse  edx, eax, edi, ecx, ebx
        sbox7Inverse        edx, eax, edi, ecx, ebx
        
        xorKeyInverse       eax, ecx, edx, ebx
        linearTransInverse  eax, ecx, edx, ebx, edi
        sbox6Inverse        eax, ecx, edx, ebx, edi
        
        xorKeyInverse       edx, edi, ebx, eax
        linearTransInverse  edx, edi, ebx, eax, ecx
        sbox5Inverse        edx, edi, ebx, eax, ecx
        
        xorKeyInverse       edi, ecx, edx, ebx
        linearTransInverse  edi, ecx, edx, ebx, eax
        sbox4Inverse        edi, ecx, edx, ebx, eax
        
        xorKeyInverse       edi, edx, eax, ebx
        linearTransInverse  edi, edx, eax, ebx, ecx
        sbox3Inverse        edi, edx, eax, ebx, ecx
        
        xorKeyInverse       eax, edi, ecx, ebx
        linearTransInverse  eax, edi, ecx, ebx, edx
        sbox2Inverse        eax, edi, ecx, ebx, edx
        
        xorKeyInverse       edi, edx, ebx, ecx
        linearTransInverse  edi, edx, ebx, ecx, eax
        sbox1Inverse        edi, edx, ebx, ecx, eax
        
        xorKeyInverse       eax, edx, ebx, ecx
        linearTransInverse  eax, edx, ebx, ecx, edi
        sbox0Inverse        eax, edx, ebx, ecx, edi
        
        xorKeyInverse       ebx, edi, edx, eax
        linearTransInverse  ebx, edi, edx, eax, ecx
        sbox7Inverse        ebx, edi, edx, eax, ecx
        
        xorKeyInverse       edi, eax, ebx, ecx
        linearTransInverse  edi, eax, ebx, ecx, edx
        sbox6Inverse        edi, eax, ebx, ecx, edx
        
        xorKeyInverse       ebx, edx, ecx, edi
        linearTransInverse  ebx, edx, ecx, edi, eax
        sbox5Inverse        ebx, edx, ecx, edi, eax
        
        xorKeyInverse       edx, eax, ebx, ecx
        linearTransInverse  edx, eax, ebx, ecx, edi
        sbox4Inverse        edx, eax, ebx, ecx, edi
        
        xorKeyInverse       edx, ebx, edi, ecx
        linearTransInverse  edx, ebx, edi, ecx, eax
        sbox3Inverse        edx, ebx, edi, ecx, eax
        
        xorKeyInverse       edi, edx, eax, ecx
        linearTransInverse  edi, edx, eax, ecx, ebx
        sbox2Inverse        edi, edx, eax, ecx, ebx
        
        xorKeyInverse       edx, ebx, ecx, eax
        linearTransInverse  edx, ebx, ecx, eax, edi
        sbox1Inverse        edx, ebx, ecx, eax, edi
        
        xorKeyInverse       edi, ebx, ecx, eax
        linearTransInverse  edi, ebx, ecx, eax, edx
        sbox0Inverse        edi, ebx, ecx, eax, edx
        
        xorKeyInverse       ecx, edx, ebx, edi
                                
        mov esi, [esp+20]           ;save values of columns
        mov [esi+12], ecx
        mov [esi+8], edx
        mov [esi+4], ebx
        mov [esi], edi       
        
        pop edi                     ;restore registers to their values before the call
        pop esi
        pop ebx
        pop ebp

        ret
        
    _serpentGenKeyAsm:
    serpentGenKeyAsm:
    
        push ebp                    ;save value of registers, we use them all
        push ebx                    ;save register
        push esi                    ;save register
        push edi                    ;save register

        mov esi, [esp+20]           ;pntr to input key
        sub esp, 528                ;pntr to bottom of local stack
        
        mov edi, [esi]              ;load key into local stack, to free a register
        mov [esp], edi
        mov edi, [esi+4]
        mov [esp+4], edi
        mov edi, [esi+8]
        mov [esp+8], edi
        mov edi, [esi+12]
        mov [esp+12], edi
        mov edi, [esi+16]
        mov [esp+16], edi
        mov edi, [esi+20]
        mov [esp+20], edi
        mov edi, [esi+24]
        mov [esp+24], edi
        mov edi, [esi+28]
        mov [esp+28], edi
                
        firstKeyRound
        normalKeyRound       8,    4,   32
        normalKeyRound      15,   32,   60
        normalKeyRound      22,   60,   88
        normalKeyRound      29,   88,  116
        normalKeyRound      36,  116,  144
        normalKeyRound      43,  144,  172
        normalKeyRound      50,  172,  200
        normalKeyRound      57,  200,  228
        normalKeyRound      64,  228,  256
        normalKeyRound      71,  256,  284
        normalKeyRound      78,  284,  312
        normalKeyRound      85,  312,  340
        normalKeyRound      92,  340,  368
        normalKeyRound      99,  368,  396
        normalKeyRound     106,  396,  424
        normalKeyRound     113,  424,  452
        normalKeyRound     120,  452,  480
        finalKeyRound      127,  480,  508
        
        mov ebp, [esp+552]                  ;mov pointer to output key into EBX
        
        sboxKeyRound          0, edx, edi, ebx, eax, sbox3
        sboxKeyRound         16, edi, ebx, eax, edx, sbox2
        sboxKeyRound         32, edi, ecx, edx, eax, sbox1
        sboxKeyRound         48, ecx, ebx, edx, eax, sbox0
        sboxKeyRound         64, edi, ecx, edx, eax, sbox7
        sboxKeyRound         80, ecx, edi, ebx, edx, sbox6
        sboxKeyRound         96, edi, eax, ebx, edx, sbox5
        sboxKeyRound        112, ebx, ecx, edx, edi, sbox4
        sboxKeyRound        128, edx, edi, ebx, eax, sbox3
        sboxKeyRound        144, edi, ebx, eax, edx, sbox2
        sboxKeyRound        160, edi, ecx, edx, eax, sbox1
        sboxKeyRound        176, ecx, ebx, edx, eax, sbox0
        sboxKeyRound        192, edi, ecx, edx, eax, sbox7
        sboxKeyRound        208, ecx, edi, ebx, edx, sbox6
        sboxKeyRound        224, edi, eax, ebx, edx, sbox5
        sboxKeyRound        240, ebx, ecx, edx, edi, sbox4
        sboxKeyRound        256, edx, edi, ebx, eax, sbox3
        sboxKeyRound        272, edi, ebx, eax, edx, sbox2
        sboxKeyRound        288, edi, ecx, edx, eax, sbox1
        sboxKeyRound        304, ecx, ebx, edx, eax, sbox0
        sboxKeyRound        320, edi, ecx, edx, eax, sbox7
        sboxKeyRound        336, ecx, edi, ebx, edx, sbox6
        sboxKeyRound        352, edi, eax, ebx, edx, sbox5
        sboxKeyRound        368, ebx, ecx, edx, edi, sbox4
        sboxKeyRound        384, edx, edi, ebx, eax, sbox3
        sboxKeyRound        400, edi, ebx, eax, edx, sbox2
        sboxKeyRound        416, edi, ecx, edx, eax, sbox1
        sboxKeyRound        432, ecx, ebx, edx, eax, sbox0
        sboxKeyRound        448, edi, ecx, edx, eax, sbox7
        sboxKeyRound        464, ecx, edi, ebx, edx, sbox6
        sboxKeyRound        480, edi, eax, ebx, edx, sbox5
        sboxKeyRound        496, ebx, ecx, edx, edi, sbox4
        sboxKeyRound        512, edx, edi, ebx, eax, sbox3
                
        add esp, 528                ;destroy local stack
        pop edi                     ;restore registers to their values before the call
        pop esi
        pop ebx
        pop ebp

        ret
