---
title: HackCon2019 rev Writeup
published: true
---

# [](#header-1)HackCon 2019 Writeup

한국시간 23일 00시에 열린 [HackCon 2019](https://hackcon.online/)에 참여하여 리버싱 문제를 중점으로 진행했습니다.

## [](#header-2)babyrev

> babyrev (score: 100 / solvers: 101)
>
> What comes before main , I wonder .... Note: flag format : flag{XXXXXXX}

문제형식은 ELF x86-64입니다. 로직도 굉장히 심플하면서 어려움 없이 풀이가 가능합니다. 하지만 main을 보면 입력 외에 별다른 작업을 하지 않습니다.
하지만 함수목록을 보면 `begin, check, end`와 같은 함수들이 존재합니다.

```c
   result = result | *pbVar1 ^ *pbVar2 ^ 0x41 | ruser[lVar3] ^ pass[lVar4] ^ 0x41 |
           ruser[lVar5] ^ pass[lVar6] ^ 0x41 | ruser[lVar7] ^ pass[lVar8] ^ 0x41 |
           ruser[lVar9] ^ pass[lVar10] ^ 0x41 | ruser[lVar11] ^ pass[lVar12] ^ 0x41 |
           ruser[lVar13] ^ pass[lVar14] ^ 0x41 | ruser[lVar15] ^ pass[lVar16] ^ 0x41 |
           ruser[lVar17] ^ pass[lVar18] ^ 0x41;
```

그중 end함수를 확인해보면 위와 같이 0x41을 XOR하여 어떤 값을 유도한다는 걸 알 수 있습니다. 그렇다면 어떤 값을 0x41과 XOR을 하는지 찾아보면
begin함수에서 pass에 대해서 write작업을 한다는 걸 알 수 있습니다.

```c
                             pass
         00301450 00 00 00 00      undefined
                 00 00 00 00 
                 00 00 00 0
            00301450 00              undefined100h                     [0]                               XREF[4]:     Entry Point(*), end:00100747(*), 
                                                                                                                     end:00100756(R), begin:001008e6(W)  
            00301451 00              undefined100h                     [1]                               XREF[1]:     end:0010076b(R)  
            00301452 00              undefined100h                     [2]                               XREF[1]:     end:00100780(R)  
            00301453 00              undefined100h                     [3]                               XREF[1]:     end:00100798(R)  
            00301454 00              undefined100h                     [4]                               XREF[2]:     end:001007b0(R), begin:001008e6(W)  
            00301455 00              undefined100h                     [5]                               XREF[1]:     end:001007c8(R)  
            00301456 00              undefined100h                     [6]                               XREF[1]:     end:001007df(R)  
            00301457 00              undefined100h                     [7]                               XREF[1]:     end:001007f5(R)  
            00301458 00              undefined100h                     [8]                               XREF[2]:     end:0010080d(R), begin:001008e6(W)  
            00301459 00              undefined100h                     [9]                               XREF[1]:     end:00100825(R)  
            0030145a 00              undefined100h                     [10]                              XREF[1]:     end:0010076b(R)  
            0030145b 00              undefined100h                     [11]                              XREF[1]:     end:00100780(R)  
            0030145c 00              undefined100h                     [12]                              XREF[2]:     end:00100798(R), begin:001008e6(W)  
            0030145d 00              undefined100h                     [13]                              XREF[1]:     end:001007b0(R)  
            0030145e 00              undefined100h                     [14]                              XREF[1]:     end:001007c8(R)  
            0030145f 00              undefined100h                     [15]                              XREF[1]:     end:001007df(R)  
            00301460 00              undefined100h                     [16]                              XREF[2]:     end:001007f5(R), begin:001008d8(W)  
            00301461 00              undefined100h                     [17]                              XREF[2]:     end:0010080d(R), begin:001008df(W)  
            00301462 00              undefined100h                     [18]                              XREF[2]:     end:00100825(R), begin:001008ed(W)  
```

write하는 값을 모두 모아 0x41과 XOR하게 되면 flag가 출력됩니다.

`flag{Th15_15_Cr4zy}`

## [](#header-3)Break It Baby

> Break It Baby (score: 304 / solvers: 71)
>
> Just break the password and submit in the flag format: d4rk{PASSWORD}c0de

이 문제도 처음 문제와 같이 단순한 형태의 main을 가지고 있습니다. 입력을 받고 XOR하여 최종적으로 "Congratulations!"을 만드는 게 목적입니다.
입력을 받고 호출되는 `test`함수는 `0x1673660-input`한 값에 의해 switch문을 수행합니다. switch문에 따라 호출되는 함수는 동일하며 마지막 default만 예외적으로
rand()함수에 의해 생성된 난수를 인자로 넘겨줍니다.

```c
 local_21 = 0x757c7d51;
 local_1d = 0x67667360;
 local_19 = 0x7b66737e;
 local_15 = 0x33617c7d;
 local_11 = 0;
 sVar1 = strlen((char *)&local_21);
 local_2c = 0;
 while (local_2c < sVar1) {
   *(byte *)((int)&local_21 + local_2c) = (byte)ctx ^ *(byte *)((int)&local_21 + local_2c);
   local_2c = local_2c + 1;
 }
 iVar2 = strcmp((char *)&local_21,"Congratulations!");
 if (iVar2 == 0) {
   puts("Submit!");
 }
```

마지막으로 `decrypt`함수를 분석하면 인자로 넘어온 숫자와 hard coding된 상수값과 xor하게 되며 최종적으로 "Congratulations!"와 비교하게 됩니다.
그러면 간단한 파이선 스크립트를 작성해 brute forcing하면 해당 숫자를 구할 수 있습니다.

```python
>>> f2 = bytearray('757c7d51676673607b66737e33617c7d'.decode('hex'))
>>> for n in range(0, 255):
…     flag = ''
…     for ch in f2:
…             flag += chr(ch ^ n)
…     print(n, flag)
… 
(0, 'u|}Qgfs`{fs~3a|}')
(1, 't}|Pfgrazgr\x7f2`}|')
(2, 'w~\x7fSedqbydq|1c~\x7f')
(3, 'v\x7f~Rdepcxep}0b\x7f~')
(4, 'qxyUcbwd\x7fbwz7exy')
(5, 'pyxTbcve~cv{6dyx')
(6, 'sz{Wa`uf}`ux5gz{')
(7, 'r{zV`atg|aty4f{z')
(8, '}tuYon{hsn{v;itu')
(9, '|utXnozirozw:hut')
(10, '\x7fvw[mlyjqlyt9kvw')
(11, '~wvZlmxkpmxu8jwv')
(12, 'ypq]kj\x7flwj\x7fr?mpq')
(13, 'xqp\\jk~mvk~s>lqp')
(14, '{rs_ih}nuh}p=ors')
(15, 'zsr^hi|oti|q<nsr')
(16, 'elmAwvcpkvcn#qlm')
(17, 'dml@vwbqjwbo"pml')
(18, 'gnoCutarital!sno')    <-- HERE!
(19, 'fonBtu`shu`m ron')
```

상숫값이 little-endian으로 표시된걸 고려하여 보면 18과 XOR한 결과가 목적인 "Congratulations!"와 같다는걸 알 수 있습니다.

`d4rk{23541326}c0de`

## [](#header-4)OpenMePloxx

> OpenMePloxx (score: 490 / solvers: 17)
>
> Can you find my key

키값을 찾는 문제입니다. main이 조금 복잡해 보이지만 사실 3개의 영역으로 구분하면 별로 어렵지 않습니다.

* key format check
* hex to dec
* bit calculation

```c
         001006a3 48 8b 5e 08      MOV        RBX,qword ptr [RSI + 0x8]
         001006a7 48 89 df        MOV        RDI,RBX
         001006aa e8 81 ff ff      CALL       strlen                                           size_t strlen(char * __s)
                 ff
         001006af 48 83 f8 36      CMP        RAX,0x36
         001006b3 0f 85 44 02      JNZ        wrong_message
                 00 00
```

실행 인자가 2개인지 검사한 후 가장 먼저 key의 길이를 검사합니다.

```c
         001006e9 48 8d 3d 81      LEA        RDI,[s_d4rk{_00100d71]                             = "d4rk{"
                 06 00 00
         001006f0 8b 6b 31        MOV        EBP,dword ptr [RBX + 0x31]
         001006f3 f3 a6           CMPSB.REPE RDI=>s_d4rk{_00100d71,RSI                          = "d4rk{"
...
         00100714 48 8d 3d 5c      LEA        RDI,[s_}c0de_00100d77]                             = "}c0de"
                 06 00 00
         0010071b 4c 89 c6        MOV        RSI,R8
         0010071e 4c 89 d1        MOV        RCX,R10
         00100721 f3 a6           CMPSB.REPE RDI=>s_}c0de_00100d77,RSI                          = "}c0de"

```

다음으로 키의 양 끝이 `d4rk{, }c0de`인지 검사합니다.
계속해서 strtok를 통해 `-`를 기준으로 조각을 만드는데 이때 조각된 문자열의 길이는 **0xe**입니다. 또한 첫 2글자는 `0x`여야 하며 총 3번의 연산을 수행합니다.
그러면 지금까지 분석한 Key의 모양은 다음과 같습니다.

```c
d4rk{0xxxxxxxxxxxxx-0xxxxxxxxxxxxx-0xxxxxxxxxxxxx}c0de
```

0x를 보면 예상할 수 있듯 3개의 문자열은 16진수 형태로 되어야 합니다. 이후 분석을 통해서 알 수 있지만, 이 값을 Atoi와 같이 문자열에서 정숫값으로 변화하기 때문입니다.
세 부분을 정수화한 이후에 비트 연산을 하게 됩니다.

비트 연산은 첫번째 조각을 이용해 두 번째 조각을 만들고 두 번째 조각을 이용해 **0x6ff76dfeb3f4**를 만들게 됩니다. 하지만 단순한 계산으로는 힘들며 숫자 또한 크기 때문에 단순한 brute forcing은 무리라고
생각되었을 때 [rev3rs3r](mailto:rev3rs3r@gmail.com) 님이 z3 이용하는 게 아니냐는 아이디어에 급하게 작성하여 정답을 출력하게 했습니다.

```python
from z3 import *

# https://stackoverflow.com/questions/11867611/z3py-checking-all-solutions-for-equation
def get_models(F, M):
    s = Solver()
    count = 0
    s.add(F)
    while count < M and s.check() == sat:
        m = s.model()
        count += 1
        yield m
        # Create a new constraint the blocks the current model
        block = []
        for d in m:
            # d is a declaration
            if d.arity() > 0:
                raise Z3Exception("uninterpreted functions are not supported")
            # create a constant from declaration
            c = d()
            if is_array(c) or c.sort().kind() == Z3_UNINTERPRETED_SORT:
                raise Z3Exception("arrays and uninterpreted sorts are not supported")
            block.append(c != m[d])
        s.add(Or(block))

def main():
    s = []
    d = [BitVec('i%d' % i, 64) for i in xrange(4)]

    s.append(And(d[0] > 0x100000000000, d[0] < 0xFFFFFFFFFFFF))
    s.append(And(d[2] > 0x100000000000, d[2] < 0xFFFFFFFFFFFF))

    s.append((((d[2] & 0x1fff) << d[3]) | (d[2] >> 0xd)) == d[0])
    s.append((((d[0] & 0x1FFFFFFF) << d[1]) | (d[0] >> 0x1d)) == 0x6FF76DFEB3F4)

    for A in get_models(s, 20):
        for i in d:
            print(hex(int(str(A[i]))))

if __name__ == '__main__':
    main()
```

이때 여러 답이 나오는데 첫 번째에서 두 번째를 만드는 과정은 대부분 맞지만 두 번째에서 세 번째를 만드는 과정에서는 shift left가 13인 경우를 찾아서 정답을 인증하면 됩니다.

`d4rk{0x567e9bfddb7f-0xdbfab3f4dfee-0x6ff76dfeb3f4}c0de`
