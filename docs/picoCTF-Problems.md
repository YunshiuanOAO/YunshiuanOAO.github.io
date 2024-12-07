---
title: PicoCTF-reverse-allproblems
type: tags
tags: 
- picoCTF
- Reverse
- Writeup
widgets:
- type: toc
  position: left
  index: true
  collapsed: true
  depth: 3
abbrlink: 16364
date: 2024-08-11 00:39:15
toc : true
cover: /gallery/covers/picoctf.png
---


EASY :
* [Transformation](#transformation)
* [vault-door-training](#vault-door-training)

HARD : 
* [not crypto](#not-crypto)
* [No-Way_Out](#no_way_out)

<!--more-->
---

# Transformation
Difficulty : Easy
[picoCTF連結](https://play.picoctf.org/practice/challenge/104)
Description
>I wonder what this really is... enc ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

## 觀察
```python
enc ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
```

這段程式碼看起來將一段文字編成了其他編碼，丟進去CyberChef選擇magic自偵測的方式即可拿到flag
[CyberChef](https://gchq.github.io/CyberChef/#recipe=Magic(3,true,false,'')&input=54Gp5o2v5I2U5Jm744S25b2i5qW0542f5qWu542044y05pGf5r2m5by45by345Wk45C446S45om9&oenc=65001)

flag:
>picoCTF{16_bits_inst34d_of_8_75d4898b}

---

# vault-door-training
Difficulty : Easy


[picoCTF連結](https://play.picoctf.org/practice/challenge/7)
Description
> Your mission is to enter Dr. Evil's laboratory and retrieve the blueprints for his Doomsday Project. The laboratory is protected by a series of locked vault doors. Each door is controlled by a computer and requires a password to open. Unfortunately, our undercover agents have not been able to obtain the secret passwords for the vault doors, but one of our junior agents obtained the source code for each vault's computer! You will need to read the source code for each level to figure out what the password is for that vault door. As a warmup, we have created a replica vault in our training facility. The source code for the training vault is here: VaultDoorTraining.java

## 觀察
打開VaultDoorTraining.java後發現他在checkPassword函式中直接將玩家的輸入與w4rm1ng_Up_w1tH_jAv4_3808d338b46做比對，相同救回傳Access granted
```
public boolean checkPassword(String password) {
	return password.equals("w4rm1ng_Up_w1tH_jAv4_3808d338b46");
}
```

因此可以直接組出flag

flag:
> picoCTF{w4rm1ng_Up_w1tH_jAv4_3808d338b46}


---

# not crypto
Difficulty : hard

[picoCTF連結](https://play.picoctf.org/practice/challenge/222)
Description
> there's crypto in here but the challenge is not crypto... 🤔


## 觀察
執行過後會要使用者輸入東西，丟入ida發現到中間有一大串的操作，最後有一個memcmp去比較兩個字串，有可能是比較我們輸入的字串與程式操作過後的字串做比較，因此可以下斷點在memcpy上面並觀察傳入的參數

## solve

![no-crypto.png](/gallery/photo/no-crypto.png)

flag:
> picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}


---

# No_Way_Out
Difficulty : hard

[picoCTF連結](https://play.picoctf.org/practice/challenge/361)
Description
>Put this flag in standard picoCTF format before submitting. If the flag was h1_1m_7h3_f14g submit picoCTF{h1_1m_7h3_f14g} to the platform.Windows game, Mac game Use password `picoctf` to unzip archives.


## 觀察
先用detect it easy 觀察一下
![NoWayOut_die](/gallery/photo/NoWayOut_DIE.png)
沒殼 使用C/C++

進入遊戲後在畫面的最上方有hint提示:Escape to find the flag
![NoWayOut_Game](/gallery/photo/NoWayOut_Game.png)
爬上梯子後被牆擋住，因此目標是要**通過牆前往旗子的地方**
可能可以考慮以下解法
* 更改玩家跳躍的功能
* 更改觸發flag的條件
* 瞬移到牆壁外面
## Solve
### 解法一: dnspy
逛一下遊戲資料夾，發現有一個檔案名為

> /pico_Data/Managed/Assembly-Csharp.dll

看檔案名可以猜測主要的遊戲程式內容，我們需要改的內容會在這裡
打開dnspy 並將Assembly-Csharp.dll丟進去

目標是要改變玩家的**跳躍功能** 因此要在裡面找到處理跳躍功能的程式碼
翻找一下會發現是在EvolveGames->PlayerController的update()函式中

![NoWayOut_dnspy](/gallery/photo/NoWayOut_dnspy.png)

其中有一個條件很明顯是處理跳躍功能
```cpp
if (Input.GetButton("Jump") && this.canMove && this.characterController.isGrounded && !this.isClimbing)
{
    this.moveDirection.y = this.jumpSpeed;
}
else
{
    this.moveDirection.y = y;
}
```
這裡有兩個解法
1. 增加跳躍數值

code:
```cpp
if (Input.GetButton("Jump") && this.canMove && this.characterController.isGrounded && !this.isClimbing)
{
    this.moveDirection.y = this.jumpSpeed + 20f;
}
else
{
    this.moveDirection.y = y;
}
```
讓玩家一跳就跳很高

DEMO:
![](/gallery/photo/NoWayOut_sol1.gif)

2. 刪除限制條件

```cpp
if (Input.GetButton("Jump"))
{
    this.moveDirection.y = this.jumpSpeed;
}
else
{
    this.moveDirection.y = y;
}
```

讓玩家可以在空中連續跳

DEMO:
![](/gallery/photo/NoWayOut_sol2.gif)


另外，也可以注意到在APTX的 class中有一個條件
```cpp
if (collision.gameObject == this.player)
{
    this.Mysterious.SetActive(true);
}
```
這個條件的感覺很像是如果一個東西碰到玩家後，會將一個Mysterious設成true
可以猜測是如果玩家碰到旗子之後的程式
因此可以編輯這個class 新增一個start函式，讓遊戲執行的時候就將Mysterious設成true
```cpp
using System;
using UnityEngine;

// Token: 0x02000002 RID: 2
public class APTX : MonoBehaviour
{
	// Token: 0x06000001 RID: 1
	private void OnTriggerEnter(Collider collision)
	{
		if (collision.gameObject == this.player)
		{
			this.Mysterious.SetActive(true);
		}
	}

	// Token: 0x06000002 RID: 2
	public APTX()
	{
	}

	// Token: 0x0600003A RID: 58
	public void Start()
	{
		this.Mysterious.SetActive(true);
	}

	// Token: 0x04000001 RID: 1
	public GameObject player;

	// Token: 0x04000002 RID: 2
	public GameObject Mysterious;
}

```

DEMO:
![](/gallery/photo/NoWayOut_sol3.gif)

## 解法二: CheatEngine
使用cheatEngin獲得玩家位置的記憶體位置，修改掉數值達成穿牆
[參考影片](https://youtu.be/QgF4PQjeG-o?si=qvckIAU1Cr03s50d&t=604)


flag:
> picoCTF{WELCOME_TO_UNITY!!}