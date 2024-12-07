---
title: Reversing.kr
widgets:
  - type: toc
    position: left
    index: true
    collapsed: true
    depth: 3
toc: true
abbrlink: 3671
date: 2024-08-24 23:27:53
tags:
- Reverse
- Writeup
cover: /gallery/covers/reversing_kr.png
---

# 題目總覽

* Easy Crack
* Easy Keygen
* Easy Unpack

<!--more-->

---


# Easy Crack: 100

## 分析
打開之後會彈出一個視窗，要使用者輸入文字

## 逆向
開啟ghidra分析，使用search->strings

![](/gallery/photo/reversing_easy_crackme.png)

可以看到在00406044位置有一個Congratulation!!字串 跟進去看使用他的函示
```cpp

void FUN_00401080(HWND param_1)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  char *pcVar4;
  undefined4 *puVar5;
  bool bVar6;
  char local_64;
  char local_63;
  char cStack_62;
  byte abStack_61 [97];
  
  local_64 = '\0';
  puVar5 = (undefined4 *)&local_63;
  for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  GetDlgItemTextA(param_1,1000,&local_64,100);
  if (local_63 == 'a') {
    iVar3 = _strncmp(&local_63 + 1,&DAT_00406078,2);
    if (iVar3 == 0) {
      pcVar4 = s_AGR3versing_0040606a;
      pbVar2 = (byte *)(&local_63 + 3);
      do {
        pcVar4 = (char *)((byte *)pcVar4 + 2);
        bVar1 = *pbVar2;
        bVar6 = bVar1 < (byte)*pcVar4;
        if (bVar1 != *pcVar4) {
LAB_00401102:
          iVar3 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
          goto LAB_00401107;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar2[1];
        bVar6 = bVar1 < ((byte *)pcVar4)[1];
        if (bVar1 != ((byte *)pcVar4)[1]) goto LAB_00401102;
        pbVar2 = pbVar2 + 2;
      } while (bVar1 != 0);
      iVar3 = 0;
LAB_00401107:
      if ((iVar3 == 0) && (local_64 == 'E')) {
        MessageBoxA(param_1,s_Congratulation_!!_00406044,s_EasyCrackMe_00406058,0x40);
        EndDialog(param_1,0);
        return;
      }
    }
  }
  MessageBoxA(param_1,s_Incorrect_Password_00406030,s_EasyCrackMe_00406058,0x10);
  return;
}

```
發現他是在拿我們使用著的輸入去比對，輸入正確會使用MessageBoxA出現Congratulation!!
將函示整理一下
可以先將
```cpp
char local_64;
  char local_63;
  char cStack_62;
  byte abStack_61 [97];
```
合併成

```cpp
char user_input [100];
```

另外原反編譯s_AGR3versing_0040606a跟反組譯過後是不同的，因此需要將0040606a位置的資料手動更新

[GetDlgItemTextA](https://learn.microsoft.com/zh-tw/windows/win32/api/winuser/nf-winuser-getdlgitemtexta) : 擷取對話方塊中控制項相關聯的標題或文字。
```
UINT GetDlgItemTextA(
  [in]  HWND  hDlg,
  [in]  int   nIDDlgItem,
  [out] LPSTR lpString,
  [in]  int   cchMax
);  
```

```cpp

void FUN_00401080(HWND param_1)

{
  byte bVar1;
  byte *pbVar2;
  int i;
  char *pcVar3;
  undefined4 *puVar4;
  bool bVar5;
  char user_input [100];
  
  user_input[0] = '\0';
  puVar4 = (undefined4 *)(user_input + 1);
  for (i = 0x18; i != 0; i = i + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  GetDlgItemTextA(param_1,1000,user_input,100);
  if (user_input[1] == 'a') {
    i = _strncmp(user_input + 2,5y_DAT_00406078,2);
    if (i == 0) {
      pcVar3 = s_R3versing_0040606c;
      pbVar2 = (byte *)(user_input + 4);
      do {
        bVar1 = *pbVar2;
        bVar5 = bVar1 < (byte)*pcVar3;
        if (bVar1 != *pcVar3) {
LAB_00401102:
          i = (1 - (uint)bVar5) - (uint)(bVar5 != 0);
          goto LAB_00401107;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar2[1];
        bVar5 = bVar1 < ((byte *)pcVar3)[1];
        if (bVar1 != ((byte *)pcVar3)[1]) goto LAB_00401102;
        pbVar2 = pbVar2 + 2;
        pcVar3 = (char *)((byte *)pcVar3 + 2);
      } while (bVar1 != 0);
      i = 0;
LAB_00401107:
      if ((i == 0) && (user_input[0] == 'E')) {
        MessageBoxA(param_1,s_Congratulation_!!_00406044,s_EasyCrackMe_00406058,0x40);
        EndDialog(param_1,0);
        return;
      }
    }
  }
  MessageBoxA(param_1,s_Incorrect_Password_00406030,s_EasyCrackMe_00406058,0x10);
  return;
}


```


因此可以推斷user input內容會是
user_input[0] = 'E'
user_input[1] = 'a'
user_input[2-3] = "5y"
user_input[4-12] = "R3versing"
驗證之後即為答案

>flag : Ea5yR3versing

---

# Easy Keygen: 100  
## 分析
有一個Readme.txt，內容為
```
ReversingKr KeygenMe
Find the Name when the Serial is 5B134977135E7D13
```
Easy Keygen.exe執行後需要輸入一個input 與serial

## 逆向
使用ida 分析exe
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v3; // ebp
  int i; // esi
  char v6; // [esp+Ch] [ebp-130h]
  char v7[2]; // [esp+Dh] [ebp-12Fh] BYREF
  char v8[100]; // [esp+10h] [ebp-12Ch] BYREF
  char Buffer[197]; // [esp+74h] [ebp-C8h] BYREF
  __int16 v10; // [esp+139h] [ebp-3h]
  char v11; // [esp+13Bh] [ebp-1h]

  memset(v8, 0, sizeof(v8));
  memset(Buffer, 0, sizeof(Buffer));
  v10 = 0;
  v11 = 0;
  v6 = 16;
  qmemcpy(v7, " 0", sizeof(v7));
  sub_4011B9((int)aInputName);
  scanf("%s", v8);
  v3 = 0;
  for ( i = 0; v3 < (int)strlen(v8); ++i )
  {
    if ( i >= 3 )
      i = 0;
    sprintf(Buffer, "%s%02X", Buffer, v8[v3++] ^ v7[i - 1]);  // v7[i - 1]有解錯應為v7[i]
  }
  memset(v8, 0, sizeof(v8));
  sub_4011B9((int)aInputSerial);
  scanf("%s", v8);
  if ( !strcmp(v8, Buffer) )
    sub_4011B9((int)aCorrect);
  else
    sub_4011B9((int)aWrong);
  return 0;
}
```
可以觀察到他先將使用者輸入的文字一個一個取出來對一個keys[0x10,0x20,0x30]做xor，最後再取得用者輸入的serial比對是否相同，因為題目有提供正確答案xor後的serial，因此可以使用xor性質a^b=c,b^c=a反寫回去得到答案

chal.py
```python
def generate_correct_serial(input_name):
    v7 = [0x10,0x20,0x30]
    Buffer = "" 
    i = 0
    v3 = 0
    result = [input_name[i:i+2] for i in range(0, len(input_name), 2)]

    for h in result:
        Buffer += chr(int(h,16) ^ v7[i])
        i+=1
        if(i >=3):
            i = 0
    print(Buffer)
input_name = "5B134977135E7D13"  # 假設這是我們的輸入名稱
generate_correct_serial(input_name)
```

> flag:K3yg3nm3

---

# Easy Unpack: 100
根據題目名稱應該是一個需要脫殼的題目，先丟入PEiD看看

![Easy_unpack_PEiD.png](/gallery/photo/Easy_unpack_PEiD.png)

發現到有加殼，但不知道是什麼殼，另外在Readme.txt中有說要找到OEP(Orginal Entry Point)，因此可以用ida 或 gdb 分析。

![Easy_unpack_ida.png](/gallery/photo/Easy_unpack_ida.png)

可以看到loc_40A1FB，有一個大跳越，跳到loc_401150，這很像脫殼後的樣子，可以猜測0x00401150就是Original Entry Point。可以用x32dbg驗證，在0040A1FB下斷點

![Easy_unpack_breakpoint.png](/gallery/photo/Easy_unpack_breakpoint.png)

F7追進去之後發現在0x00401150的地方有55(push ebp)，因此0x00401150就是OEP

![Easy_unpack_entrypoint.png](/gallery/photo/Easy_unpack_entrypoint.png)

> flag : 00401150