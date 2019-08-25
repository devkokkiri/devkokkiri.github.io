---
title: Inc0gnitoCTF 2019 rev Writeup
published: true
---

# [](#header-1)Inc0gnitoCTF 2019 rev Writeup

Inc0gnito가 주최한 세미나에서 진행된 CTF를 풀어봤습니다.

## [](#header-2)powerpc

> powerpc (score: 400 / solves: 0)
>
> Get flag!

사실 3문제중 가장 간단한 문제입니다. 먼저 문제파일을 열면 UPX로 패킹이 된걸 알 수 있습니다. 

```c
cou9ar@ubuntu:~/upx-3.94-amd64_linux$ ./upx -d ../powerpc
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2017
UPX 3.94        Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: ../powerpc: Exception: compressed data violation

Unpacked 1 file: 0 ok, 1 error.
```

그렇다면 바론 upx의 `-d` 옵션으로 언패킹을 시도했지만 역시 error... 그리고 시도한게 바이너리 내부에 존재하는 문자열을 조금 더 자세하게 살펴보기 위해서 `strings` 명령어를 통해서 출력했습니다.

```c
cou9ar@ubuntu:~$ strings powerpc
...
/{flag:H
av4e_y0u_ev8er_hEar1d_a3b$t_P
o6w(PC?^%f
...
```

놀랍게도 내부에 flag로 추측되는 문자열이 존재하고 이를 적절히 조합해서 인증을 했지만 역시 실패.. 마지막으로 왜 UPX가 정상적으로 언패킹이 안되는지 고민을 해보다가 ELF format에 어떤 트릭을 만든게 아닐까 라는 생각이 들었습니다.

```bash
cou9ar@ubuntu:~$ readelf -h powerpc
ELF Header:
  Magic:   7f 45 4c 46 01 02 01 03 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, big endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - GNU
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386             <-- WHAT THE HECK!
  Version:                           0x1
  Entry point address:               0x13c940
  Start of program headers:          52 (bytes into file)
  Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         3
  Size of section headers:           40 (bytes)
  Number of section headers:         0
  Section header string table index: 0
```

`readelf`로 확인해보면 문제이름의 힌트에서 powerpc라는걸 쉽게 추측할 수 있지만 Machine에는 엉뚱한 **`Intel 80386`**이 있습니다. 그래서 [해당 부분](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)을 PowerPC로 수정하여 UPX로 언패킹을 시도하면 정상적으로 언팩이 가능합니다. 이후에 qemu와 같은 에뮬레이터를 통해서 실행하면 flag가 출력됩니다.

```bash
cou9ar@ubuntu:~$ qemu-ppc64abi32-static ./powerpc_moe
{flag:Hav4e_y0u_ev8er_hEar1d_a3b0ut_Po6werPC?}
3.333333
```

## [](#header-3)Reversing #2

> Reversing #2 (score: 395 / solves: 5)
>
> Get flag!

```c
 while( true ) {
   while( true ) {
     while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            while( true ) {
             while( true ) {
               while (if_case == -0x4c7d98a0) {
```

문제를 열고 디컴파일을 해보면 딥딥한 while을 볼 수 있습니다. 로직은 임의로 이름을 정한 `if_case`에는 상수값이 들어가고 이 값에 따라서 분기가 이뤄집니다. 이걸 염두하고 코드를 분석하면 저희가 분석해야할 부분은 총 3곳이 되는데 다음과 같습니다.

```c
1. local_218[(long)(int)inc_index] = local_218[(long)(int)inc_index] ^ s_SECRET_00602060[(long)((int)inc_index % 5)];
2. local_218[(long)(int)inc_index2] = (&DAT_00400c20)[(long)(int)((long)(ulong)input_buffer[(long)(int)inc_index2] / 0x10) * 0x10];
3. iVar1 = memcmp(local_218,&maybe_flag,0x1e);
```

`1번`의 경우 문자열 `SECRET`을 통해서 배열의 현재 위치의 값과 XOR하며 암호화하게 됩니다. 중요한건 SECRET중 SECRE만으로 XOR을 하게 됩니다.
`2번`의 경우는 입력한 문자를 가지고 `DAT_00400c20`에서 값을 가져오는데 예를 들어 1을 입력하면 DAT_00400c20['1']의 값을 가져오게됩니다.
`3번`의 경우 최종적으로 만들어진 값이 두 번째 인자값으로 들어온 데이터와 비교하는데 이때 만들어야하는 데이터를 알 수 있습니다.

그러면 최종적으로 만들어야하는 데이터를 역으로 접근하여 SECRE으로 XOR한 뒤 해당 데이터를 DAT_00400c20에서 찾으며, 찾은 위치의 인덱스값을 문자로 바꾸면 flag가 출력되게 됩니다.

```python
f = bytearray('6015acd76457ef70cfd3a85dd1d6059c5f5bcd659cd36356169ca680ad2200'.decode('hex'))
k = bytearray('SECRET')
ff = bytearray()
fff = bytearray('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'.decode('hex'))

for n in range(0, len(f)):
    ff.append(f[n]^k[n%5])

flag = ''
for n in ff:
    for pos in range(0, len(fff)):
        if n == fff[pos]:
            flag += chr(pos)

print(repr(flag))
```
