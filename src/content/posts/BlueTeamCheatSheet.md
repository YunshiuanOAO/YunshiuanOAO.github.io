---
title: 🛡️ BlueTeam CheatSheet
description: Blue Team 常用事件代碼、Sysmon 事件與 IDS/IPS 工具速查
published: 2025-08-12
category: Blog
tags:
- BlueTeam
- Forensic
---

In this note, I organize the commons blue team skill
## Event code

### Winlog 

| Event ID | 說明                                                         |
| -------- | ------------------------------------------------------------ |
| 4104     | Windows powershell 執行日記                                  |
| 4624     | 登入成功                                                     |
| 4625     | 登入失敗                                                     |
| 4648     | 明確帳號登入（如 RunAs）                                     |
| 4672     | 特權登入（如 admin 登入）                                    |
| 4634     | 使用者登出                                                   |
| 4662     | Active Directory (AD) 物件上執行了某項操作 ( 偵測 Dscync ，尤其是一般使用者存取時) |
| 4688     | 建立新程序（程式啟動）                                       |
| 4689     | 程式結束                                                     |
| 4697     | 安裝新服務（常用於惡意持久化）                               |
| 4720     | 建立新帳號                                                   |
| 4722     | 啟用帳戶                                                     |
| 4723     | 嘗試變更自己的密碼                                           |
| 4724     | 嘗試為他人變更密碼                                           |
| 4725     | 停用帳戶                                                     |
| 4726     | 刪除帳戶                                                     |
| 4728     | 使用者被加入**全域**群組                                     |
| 4732     | 使用者被加入**本機**群組                                     |
| 4768     | Kerberos TGT 請求                                            |
| 4769     | Kerberos 服務票證請求                                        |
| 4776     | NTLM 驗證請求                                                |
| 5140     | 存取共用資料夾                                               |
| 5156     | 防火牆允許的網路連線（NetConn 事件）                         |
| 7045     | 安裝服務（System log，也可監控持久化）                       |

## [Sysmon](https://learn.microsoft.com/zh-tw/sysinternals/downloads/sysmon)

* 可以看到更底層的資訊，包含檔案的更新或者創建等等
* 可以用 [Sysmon view](https://github.com/nshalabi/SysmonTools) 查看

| Event ID | 說明                                             |
| -------- | ------------------------------------------------ |
| 1        | Process Create（程式啟動）                       |
| 2        | File creation time changed（時間戳被修改）       |
| 3        | Network connection（TCP 連線）                   |
| 5        | Process Terminate（程式終止）                    |
| 6        | Driver Loaded（驅動載入）                        |
| 7        | Image Loaded（DLL載入）                          |
| 8        | CreateRemoteThread（遠端執行緒注入）             |
| 9        | RawAccessRead（磁碟原始存取）                    |
| 10       | ProcessAccess（程式存取他人記憶體）              |
| 11       | File Create（檔案建立）                          |
| 12       | Registry Key Create（註冊表鍵建立）              |
| 13       | Registry Value Set（註冊表值修改）               |
| 14       | Registry Key Delete（註冊表鍵刪除）              |
| 15       | FileCreateStreamHash（建立 ADS）                 |
| 22       | DNS Query（DNS 查詢事件）                        |
| 23       | File Delete（檔案刪除）                          |
| 25       | Process Tampering（程式記憶體被修改）            |
| 26       | File Deleted and Overwritten（防止取證）         |
| 29       | FileExecutableDetected (新的 .exe .dll 產出偵測) |
| 255      | Sysmon 設定被修改（Config change）               |



## IDS/IPS

* [OSSEC](https://www.ossec.net/)
    * HIDS

* [Suricata](https://suricata.io/)
    * Suricata 是一個開源的入侵偵測系統（IDS）與入侵防禦系統（IPS），以深度封包檢測、流量分析與威脅偵測聞名。能使用 Suricata 的龐大規則集快速評估網路資料並辨識異常。
    
      
    
      指令如下

      ```
      suricata -r B33F50up_blog.pcapng 
      ```
    
      他會產生四個檔案
    
      * eve.json : Suricata的結構化日誌檔案，包含多種事件類型的詳細記錄
      * fast.log : Suricata 快速警報日誌，包含檢測到的安全威脅警報
      * stats.log : Suricata 運行統計資料，包含詳細的系統運行統計
      * suricata.log : Suricata 主要運行日誌，包含系統啟動和運行資訊
    
      ![](assets/5LROwbAnig-tGtRpsi7V6Ig8OL3X9F9e3CxpqHcjWvs=.png)
    
      以下是 fast.log 資訊
    
      ```
      08/09/2025-02:53:47.165861  [**] [1:2019284:3] ET ATTACK_RESPONSE Output of id command from HTTP server [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.125:5000 -> 100.112.165.2:60865
      08/09/2025-02:56:49.767871  [**] [1:2002034:13] ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style) [**] [Classification: Information Leak] [Priority: 2] {TCP} 192.168.1.125:5000 -> 100.112.165.2:61207
      ```
    
    * `ls -lah /etc/suricata/rules/` see all rulus
    * `suricata -r test.pcap` create various logs(etc eve.json,fast.log...)
    * `suricata --pcap=ens160 -vv`  Suricata's (Live) LibPCAP mod
    * `cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http")' | head -1 | jq `quury example 
    
* [RITA](https://github.com/activecm/rita)
    * detect C2
    * ``
    * [simple tour](https://cn-sec.com/archives/1901157.html)
    * [simple tour2](https://ithelp.ithome.com.tw/m/articles/10209273)

* [Snort](https://www.snort.org/)
    * example:
    ```bash
    sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/cerber.pcap -A cmg
    ```

    ``` bash
    sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq \
    -r XXX.pcap
    ```

    ```bash
    sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq \
    -i ens160
    ```

* Zeek 
    * Zeek 是一個開源的網路安全監控工具，以強大的資料記錄功能聞名。它能將原始的 pcap 封包檔轉換成結構化的日誌，方便在 Zeek 內查詢與分析，快速提供網路行為的概覽。
    
      指令如下
    
      ```bash
      zeek -C -r B33F50up_blog.pcapng
      ```
    
      他會產生以下檔案
    
      * conn.log  : 記錄了所有的網路連接
      * dns.log：記錄了所有的 DNS查詢活動
      * files.log：記錄了通過 HTTP 傳輸的檔案
      * http.log：這是一個 HTTP 協議的流量日誌，記錄了網頁瀏覽和API 請求
      * packet\_filter.log：記錄了封包過濾器的配置
    
      ![](assets/wEXC7MUEGLZqmjPBWvXxb9gL4cWzTN2L6JHdh9dc1cA=.png)
    
      以下是http.log 的形式
    
      ```bash
      #separator \x09
      #set_separator	,
      #empty_field	(empty)
      #unset_field	-
      #path	http
      #open	2025-09-27-22-26-52
      #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
      #types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
      1754678828.272075	CAuRo91flufxXutAke	100.112.165.2	60665	192.168.1.125	5000	1	GET	192.168.1.125:5000	/	-	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	-	0	24859	200	OK	-	-	(empty)	-	-	-	-	-	-	FA9Bk7Ikrr1LVrys	-	text/html
      1754678857.820963	CIRhMK1X97Z1MzFRD1	100.112.165.2	60676	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	15	727	200	OK	-	-	(empty)	-	-	-	FIUrzJ3sbt6deYBXf3	-	text/plain	FyILV9CHbcmUMGtc6	-	text/json
      1754678865.293310	CZnidTF5LIgaMzbRe	100.112.165.2	60677	192.168.1.125	5000	1	POST	192.168.1.125:5000	/system	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	141	185	200	OK	-	-	(empty)	-	-	-	Fvs6lg41SIyuYsReh2	-	-	FqFYD91bNrEWRNR501	-	text/json
      1754679070.738945	CWlCIn4qK2ntw6CuJl	100.112.165.2	60757	192.168.1.125	5000	1	GET	192.168.1.125:5000	/	-	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	-	0	24859	200	OK	-	-	(empty)	-	-	-	-	-	-	FG2QH72aF2jeG9CYC9	-	text/html
      1754679165.228123	C5V1Fn3nYAvFuSQeE	100.112.165.2	60778	192.168.1.125	5000	1	POST	192.168.1.125:5000	/system	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	141	287	200	OK	-	-	(empty)	-	-	-	FnwtMr2TZ1qIS6LLmj	-	-	Fq827u4xABcX563I21	-	text/json
      1754679173.669096	CWXpsv3zrBE7Lx66Sg	100.112.165.2	60779	192.168.1.125	5000	1	POST	192.168.1.125:5000	/system	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	144	13177	200	OK	-	-	(empty)	-	-	-	FxvTqN3Pid7VWQP7y3	-	-	Fi4rGH32Y4P77kznf3	-	text/json
      1754679180.268390	Co6odn3WTbf9HKGcO6	100.112.165.2	60780	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	15	728	200	OK	-	-	(empty)	-	-	-	FYW00SjDihqYC30xe	-	text/plain	FQGbYm3SH1rsO8o9ng	-	text/json
      1754679196.383809	CGjLWoznypKV0Pgt	100.112.165.2	60809	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	16	738	200	OK	-	-	(empty)	-	-	-	FVCJDglco6ai9lzi4	-	text/plain	FB2a4L3x3ZELSSdCQ1	-	text/json
      1754679223.696243	C0s1KA7ZrfQvnIpj	100.112.165.2	60865	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	30	851	200	OK	-	-	(empty)	-	-	-	FA2p79sD6MkhyaCEb	-	text/plain	FwUGICEULGQRyBs78	-	text/json
      1754679257.891805	CtwrhY2Kw9bscBOsX7	100.112.165.2	60874	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	34	755	200	OK	-	-	(empty)	-	-	-	FybSTDKXBk5dCiaYl	-	text/plain	F55jsD1S1vWW8IVBY4	-	text/json
      1754679265.650887	CFgfqH2IasZxXsovkd	100.112.165.2	60875	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	30	869	200	OK	-	-	(empty)	-	-	-	FtvRcZ3D5kRIP1ijy5	-	text/plain	FTYdr5iKtJX11Efma	-	text/json
      1754679315.090163	CEAuN63ly0lHS2zRrj	100.112.165.2	60895	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	30	869	200	OK	-	-	(empty)	-	-	-	Fyt7jP30AEKPs4C0Uj	-	text/plain	F0zHt852ycC25Gpkf	-	text/json
      1754679319.217264	CRWcyt2bda4K3g6Xub	100.112.165.2	60912	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	36	900	200	OK	-	-	(empty)	-	-	-	FUAgus1sr4pPeGnidg	-	text/plain	FqnOWw20dfXD0koyIi	-	text/json
      1754679354.845803	CulPOq3A9IP8ab4Zqd	100.112.165.2	60981	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	48	769	200	OK	-	-	(empty)	-	-	-	FZw17aZHAnZltVkJ	-	text/plain	FQvAYSOVPIbUCfRm7	-	text/json
      1754679406.575000	C9iy0scrJKJuDpi07	100.112.165.2	61207	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	49	2621	200	OK	-	-	(empty)	-	-	-	FiejrYnJjwTaJ5db7	-	text/plain	FKZoSb4yddnL4uzkZf	-	text/json
      1754679827.575533	CV2dqm3aNuGOi4EC0h	100.112.165.2	63113	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	36	912	200	OK	-	-	(empty)	-	-	-	FDaXYp2bh8hJpHMYCi	-	text/plain	FdsBU41nDrcCQ9mTV9	-	text/json
      1754679851.757452	CWSzgl4AsTyJVyRpJf	100.112.165.2	63213	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	44	800	200	OK	-	-	(empty)	-	-	-	FAGwfWDdjCLhcrZX2	-	text/plain	F89dhl1uFy7r4oRtf	-	text/json
      1754679859.655497	C0LErP2jTxCqKmUESd	100.112.165.2	63216	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	47	781	200	OK	-	-	(empty)	-	-	-	FoNYJj2QlLyZkd9tEe	-	text/plain	FUaGCH2RbcOlDQcaOi	-	text/json
      1754679875.655339	CqC0qj2SMoQnSfaju6	100.112.165.2	63217	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	31	762	200	OK	-	-	(empty)	-	-	-	FRGjia4iHeyPzIDRC3	-	text/plain	FwGgDTGi2gHDik2P5	-	text/json
      1754679999.499748	CtN1Vk4RrwIRGOgwHc	100.112.165.2	63280	192.168.1.125	5000	1	POST	192.168.1.125:5000	/ping	http://192.168.1.125:5000/	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36	http://192.168.1.125:5000	142	836	200	OK	-	-	(empty)	-	-	-	FFJx4j4PnbpIi0mfD6	-	text/plain	FYpDmc37JMpCuz4Zac	-	text/json
      #close	2025-09-27-22-26-52
      
      ```
    
      另外他也會根據 pcap 檔產生其他log ，參考網址：https://docs.zeek.org/en/master/logs/index.html 


xml filter example
``` xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[
        System[
          (EventID=3)
          and TimeCreated[
            @SystemTime >= '2022-01-01T07:41:36.000Z'
            and @SystemTime <= '2022-10-02T07:41:36.999Z'
          ]
        ]
        and EventData[
          Data[@Name='ProcessGuid']='a79137ec-af0f-6338-b702-00000000e901'
        ]
      ]
    </Select>
  </Query>
</QueryList>
```




## SIEM

Continuously, for ongoing detection and alerting

### [ELK Stack](https://www.elastic.co/elastic-stack)

直接用 docker 架起來的方式 : [連結](https://hackmd.io/@CHW/S1vy8V8ca#Elastic-stackELK-%E5%AE%89%E8%A3%9D-on-docker-%E4%B8%80%E9%8D%B5%E5%AE%89%E8%A3%9D)  

#### Elastic Common Schema (ECS)
| 字段類型 | 描述 | KQL 範例 |
|---------|------|---------|
| event.category | 將事件按大型邏輯類別分組，通常與"event.category"字段結合使用進行過濾搜索 | • event.category: authentication<br>• event.category: process<br>• event.category: file<br>• event.category: malware<br>• event.category: network |
| event.type | 作為子分類，通常與"event.category"字段結合使用過濾搜索 | • event.type: creation<br>• event.type: deletion<br>• event.type: access |
| event.outcome | 指示事件是否成功或失敗 | • event.outcome: success<br>• event.outcome: failure |

#### Common Search Fields
| 字段 | KQL 範例 | 輸出 |
|------|----------|------|
| @timestamp | @timestamp: 2023-01-25 | 事件發生時間的時間戳（事件來源於該時間而非更早或更晚） |
| agent.name | agent.name: "DESKTOP*" | 從代理名稱中搜索指定字符並顯示結果 |
| message | message: powershell | 在任何含有"powershell"字符的消息中搜索 |

#### Process Related Fields
| 字段 | KQL 範例 | 輸出 |
|------|----------|------|
| process.name | event.category: process and process.name: svchost | 尋找進程名為svchost的所有進程 |
| process.command_line | process.command_line: (cmd or "/c") | 尋找使用cmd並且含有命令行參數為"/c"的進程 |
| process.pid | event.category: process and process.pid: 4360 | 尋找PID為4360的進程 |
| process.parent.name | event.category: process and process.parent.name: cmd.exe and process.name: powershell.exe | 尋找父進程為cmd.exe且該進程名為powershell的進程；尋找由cmd.exe父進程啟動的PowerShell進程 |
| process.parent.pid | event.category: process and process.parent.pid: 1240 | 尋找父進程PID為1240的進程 |

#### Network Related Fields
| 字段 | KQL 範例 | 輸出 |
|------|----------|------|
| source.ip | source.ip: 127.0.0.1 | 尋找源IP地址中的任何出站流量 |
| destination.ip | destination.ip: 23.184.192.62 | 尋找目的IP地址中的任何入站流量 |
| destination.port | destination.port: 443 | 尋找目的端口中的任何入站流量，例如目的端口443 |
| dns.question.name | dns.question.name: "www.youtube.com" | 尋找DNS查詢記錄查看DNS解析，包括網站youtube.com |
| dns.response_code | dns.response_code: "NXDOMAIN" | 尋找DNS響應代碼的返回碼，包含NXDOMAIN |
| destination.geo.country_name | destination.geo.country_name: "Canada" | 尋找目的地理國家欄位，例如Canada |

#### Authentication Related Fields
| 字段 | KQL 範例 | 輸出 |
|------|----------|------|
| user.name | event.category: "authentication" and user.name: john | 尋找用戶名john的登錄嘗試 |
| winlog.logon.type | event.category: "authentication" and winlog.logon.type: 3 | 尋找logon type為3（網路登錄）的驗證事件 |
| winlog.event_data.AuthenticationPackageName | event.category: "authentication" and winlog.event_data.AuthenticationPackageName: "NTLM" | 尋找使用NTLM驗證包的驗證事件 |

#### 常用查詢語法
```bash
event.provider: "Microsoft-Windows-Sysmon" and event.code: 11  and winlog.event_data.TargetFilename  : *.aspx

# DNS相關查詢
agent.type : "packetbeat" and type:"dns"  
dns.question.registered_domain : "XXX"

# 程序監控
event.category: process and process.name: powershell.exe
process.command_line: *encoded* and event.category: process

# 網路流量分析
source.ip: 192.168.1.0/24 and destination.port: (443 or 80)
event.category: network and destination.geo.country_name: "China"

# 驗證事件
event.category: authentication and event.outcome: failure
winlog.event_id: 4625 and user.name: administrator

# 檔案操作
event.category: file and event.type: creation
file.extension: (exe or dll) and file.path: *temp*
```


* [splunk](https://www.splunk.com/zh_tw)

* chainsaw
    * use sigma 


## DFIR

after an incident has occurred 

* [Velociraptor](https://docs.velociraptor.app/)




## CTI
* [MISP]()
* [YETI](https://yeti-platform.io/)
* [openCTI](https://github.com/OpenCTI-Platform/opencti)


## Malware Analysis
* [Noriben](https://github.com/Rurik/Noriben)
    * Noriben is a Python-based script that works in conjunction with Sysinternals Procmon to automatically collect, analyze, and report on runtime indicators of malware.
    * `python Noriben.py` launch the script

* [VirusTotal](https://www.virustotal.com/gui/home/upload)

    VirusTotal 是一個線上服務，讓使用者可以上傳檔案、URL、Domain、IP 或 Hash 進行分析，以檢測是否含有惡意軟體、惡意連結、釣魚等威脅，VirusTotal 內把多個防毒引擎、網頁掃描器、威脅情報來源彙整在一起，並且裡面會跑沙箱獲得惡意程式行為

    ![](assets/gMfDOnx2P7vfSTa0t39KTSF4X51TsNEZ1JieQp1GN9Y=.png)

    使用方式是在上方的搜尋欄輸入 Hash、IP、Domain，或至上傳頁面上傳惡意程式

    ![](assets/wVcdSKbGTJgrc4GYZeCk1VWOvjD2NKPOKSYt9_s5xPg=.png)

    這裡介紹一下 VirusTotal 分析完後提供的頁面資訊

    ### Detection

    這個頁面提供了多家的 antivirus 引擎的偵測結果，會顯示出辨識的惡意程式家族與標籤

    ![](assets/z3PpmUJlTskTOc-_l2CYf5VAZNTDMKlxMQ3i28g1sos=.png)

    ### Details

    這個頁面會列出惡意程式的大小、型態、雜湊，以及編譯、修改時間

    ![](assets/tvFgDnMjsBkHGBDXWKh2CtBid7nsv75o1We8A6U8X1E=.png)

    PE 結構（Sections、Imports/Exports）、簽章資訊、字串等

    ![](assets/-yTNwLT3_1naezKvF3WWA6if8ccs7-ctpuBf63FxELQ=.png)

    ### Relations

    這個頁面會列出惡意程式連線的 IP、Domain 

    ![](assets/rGfLfkJ0NLPqqubsITDG8YcSD_oXKpVZ90nQ10vh7T0=.png)

    以及執行惡意程式時產生的檔案

    ![](assets/hNljM3GQjeIAib7Jbc6JH5X6n9aESH8pVix3NyaGWp4=.png)

    ### Behavior

    這裡會列出惡意程式跑在多種沙箱中的行為

    ![](assets/FbaXPCeyc1-V85aF3NNLqvM8J-bA8NuaXak9nMfQ4d8=.png)

    當中會有 Network 的分析

    ![](assets/OhyS62SmzrqyOeKDsNXGOIr1k3M7VSM5kGmzncOPy9M=.png)

    當中也有檔案的操作，包含檔案開啟、修改、刪除、創建

    ![](assets/6-oZNV1IMKjgu5wbtjl5TjhnAu7kPSfdVJ4m-kjurNA=.png)

    Process 的創建以及 Command 的記錄

    ![](assets/zJdkjUtwInk-OW6R7zFKZaWdJmPniYZuo9vIRsHfHsk=.png)

    ### Community

    這個頁面大多數會有人分享其他惡意程式檢測平台的 Report 

    ![](assets/KXXwfCJI5ITKqJD8oFD6YiINevnuM8DAk7YjVPM9kG0=.png)

* [ANY.RUN](https://any.run/)

    ANY.RUN 是一個互動式線上惡意程式沙箱，允許使用者在受控的虛擬環境中動態執行可疑檔案或網址，觀察其行為、網路活動、檔案／登錄表操作等等

    ![](assets/-ipWo-VWZ1bBq9M0ip9AO1AW3ijwawfUVE_86kzXMPU=.png)

    如果要使用它的沙箱功能，就像 VirusTotal 一樣可以直接丟惡意程式進去分析的話，會需要先註冊帳戶，如果不想註冊的話，可以直接前往 https://app.any.run/submissions 並使用 Hash 查詢有沒有人之前丟過的惡意程式

    假設我查詢 hash 為 `ced525930c76834184b4e194077c8c4e7342b3323544365b714943519a0f92af` 的惡意程式

    ![](assets/wf3oQc9EpL8An_hXnvPKekdTlcrO5clXLA2HHXto9Gs=.png)

    然後點選其中一個，也可以進入到沙箱分析結果頁面

    ![](assets/rgOQ9BgqW3CpsBVaEnONX00EBqyz8ce9z1Eoq5GmGQE=.png)

    這邊介紹一下 Report 介面，首先可以先看右邊的功能列，功能包含你可以下載這個惡意程式，以及在惡意程式啟動時執行了什麼行為

    ![](assets/Pb8iPUJignS3owgETQh_oKV0DrQJy8eDm7t2yfmFQx0=.png)

    

    如果想要詳細分析其中一個檔案，點擊他就會出現詳細訊息

    ![](assets/uDYCE6z7kaaGJyXNgruAqM7W3SB-CmNOx9XFiV8wLcY=.png)

    點選 More Info 之後就會進入到這個程式的完整分析內容

    ![](assets/TuHLpPHsOnJkkZGA_e4CjCrF45L98ZXRK9mWvHOIq9s=.png)

    這個頁面有一個很方便的功能，它會列出惡意程式行為的嚴重程度，假設我想要了解 `T1053.005 Scheduled Task (1)` 這個行為，並且想要知道它下的 Cmdline，可以點擊下方的 `Uses Task Scheduler to run other applications` 就會跳出視窗並顯示詳細內容

    ![](assets/ZL3yijW5pBAeEDHXbe6EVXN0sc9pld1JxCrkcPeBQDo=.png)

    

    回到分析主頁，下方是顯示 Network 相關分析結果，也有看檔案操作的頁面

    ![](assets/yyT6D73zz3KtGYHdOElmGIztskP0I4j4MQNd2N0-Rj8=.png)

* [MalwareBazaar](https://bazaar.abuse.ch/browse/)

    MalwareBazaar 是由 abuse.ch 所運營的惡意軟體樣本分享平台，旨在讓資安研究人員、antivirus 廠商、威脅情報團隊能夠更容易地交換與取得惡意軟體樣本，如果有想要查詢的惡意程式可以來這個網站查

    ![](assets/WjzEU8V90NjOlZCZa8f61be1PPxTNpUIJ-_39gDptlo=.png)

    它有一個查詢的語法，需要照著它的語法不然會找不到

    ```
    Search syntax is as follow: keyword:search_term
    
    Following is a list of accepted keywords along with an example search_term
    
    md5:1b109efade90ace7d953507adb1f1563 ( run)
    sha256:11b16ba733f2f4f10ac58021eecaf5668551a73e2a1acfae99745c50bfccbb44 ( run)
    signature:CobaltStrike ( run)
    tag:TA505 ( run)
    file_type:rtf ( run)
    user:malware_traffic ( run)
    clamav:SecuriteInfo.com.Artemis1FBB04F6EAF7.17086.UNOFFICIAL ( run)
    yara:win_asyncrat_j1 ( run)
    serial_number:51CD5393514F7ACE2B407C3DBFB09D8D ( run)
    issuer_cn:Sectigo RSA Code Signing CA ( run)
    imphash:756fdea446bc618b4804509775306c0d ( run)
    tlsh:8DD484F440EF10A2F25F852936ADBE9401B2B1C7DBDA5E08137DE5311BBDA633A0564D ( run)
    telfhash:52d0a7c198b4972c99e60578ed5c5bb29106216620070b20cf10a5d4d83b440f40db59 ( run)
    gimphash:b43f35a8610180bcb184238555a0858a6c160a2d872566e7e9633221308b34fd ( run)
    dhash_icon:f8dcbeffbffecee8 ( run)
    ```


    假設我現在要查sha256 是`ced525930c76834184b4e194077c8c4e7342b3323544365b714943519a0f92af` 的惡意程式
    
    ![](assets/h5BRvZtDGV6UzkjnyWHJoiFVyPj1qiOAVfCeJ7KTCa8=.png)
    
    這樣就成功找到了，首先會列出基本的訊息
    
    ![](assets/dhEkCdxVv7tqQkAy65vx9ZPsWCww_ZVAfR4ES2eojPM=.png)
    
    這個網站不錯的地方是它會去整理各大惡意程式檢測平台的 Report，並列出來 Report 網址或者檢測結果
    
    ![](assets/MPS_tDeEXUcke389E3C6h51m7s3_fHIANLYQh00okQ=.png)

* [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)

    Malpedia 是由 Fraunhofer FKIE所維運的一個「惡意軟體百科 + 參考樣本集」平台，惡意軟體家族百科與研究資源，提供家族描述、別名、已知樣本參考、YARA 規則、相關研究連結。

    ![](assets/2dvHSIedbNMendmEHvAO8F2RepgjV8q_V2Of8pGfZi0=.png)

    假設我們剛剛的 XWorm 惡意程式，可以直接在搜尋欄打上 XWorm

    ![](assets/QbiEpyzJnEPDzDRdwNEz7JdUil3UzOlx_OD_1ug3E_8=.png)

    這些皆是針對於 XWorm 的研究，可以點進去參考

    

    另外也可以尋找這是哪個組織發出來的

    可以在 Family 頁面中搜尋 XWorm

    ![](assets/NSHxGJOQdrVMnCIB7qpIba_49beBljRTv3kp9hmIss=.png)

    點進去後可以看到這隻惡意程式相關的訊息，包含 Actor

    ![](assets/w6h7nMg7-aII3T313yGWoVOqf72mqCKIPX7RPRfIQZU=.png)

    那這邊就可以看到 Actor 是 `Hive0137` 

    點擊後可以看到該 Actor 的相關資訊

    ![](assets/QzHW9EOxvKz5xMAcFYHqeUAO6nFinJiYTmo4Tdfx9cc=.png)

* [Triage](https://tria.ge/reports/public)

    Triage 是由 Hatching 提供的線上惡意程式沙箱台，用來自動執行、分析可疑檔案並生成行為報告，協助安全分析師快速篩選與分類威脅樣本。

    ![](assets/tur58FvV11eeExk1BKcPqd2fqstHnhwZd39997p7hCI=.png)

    它可以像 VirusTotal 一樣上傳惡意程式並分析或者搜尋之前已經上傳過的惡意程式

    搜尋的方式就是點選右上角的 Search 後也是可以用 Hash 搜尋

    ![](assets/fgbYNIkhdgIgR5syn8hEHZAzsxh33-q_IKZMooswMmI=.png)

    點進去後就會出現分析報告

    ![](assets/LSq6C5CnL3srr-davFhRkk2fxAeZAvhPQnt6kGkVyAk=.png)

    而如果是要上傳惡意程式，需要先進行登入，登入後上面列的 Submit 是上傳惡意程式的頁面

    ![](assets/XLiYnj_Z4f0BPL-Azp2DnSM75KXVZGJUKYSCCspUbus=.png)

    上傳完後也會出現 Report 的頁面

    Report 頁面有包含

    * 環境與 metadata
    * 樣本基本資訊（雜湊、大小、評分、標籤）
    * 提取出的惡意設定（C2、安裝位置、檔案名）
    * 偵測簽章 / 行為標記
    * 進程行為
    * 網路行為
    * MITRE ATT\&CK 對應技術
    * 可下載的記憶體 / 生成檔案

## Memory Forensics

### Volatility Framework
記憶體取證分析工具，用於分析記憶體映像檔案

### pslist/pstree 

可以幫助我們去查看這台電腦跑了什麼process，他們分析的方式是會根據Symbol Table 找到Windows Kernel的 PsActiveProcessHead 的位址，然後從那個鏈表開始沿 ActiveProcessLinks 指標逐一讀出 EPROCESS 結構並解析必要欄位，如：ImageFileName、UniqueProcessId、CreateTime、ExitTime 等

![](assets/cghIGl_AaCJnL5zsvyk6TDeHL4Zf5T7ugVayuyE-uDo=.png "source:https://www.tophertimzen.com/resources/cs407/slides/week02_02-Processes.html#slide13")

另外的pstree 以 pslist 的結果為基礎，轉成父子樹狀。

那如果參考 https://ithelp.ithome.com.tw/m/articles/10321120 或者 https://ithelp.ithome.com.tw/articles/10335699 的其中一個方式， 可以發現其實惡意程式是可以去將process 隱藏起來的，並且讓pslist 與 pstree 無法偵測，因此我們可以使用 psscan 嘗試去偵測

### psscan

首先要說明，Windows kernel 在為許多核心物件（例如 EPROCESS、ETHREAD、FILE\_OBJECT）分配記憶體時，會在 `_POOL_HEADER` 中放置一個 4-byte 的 pool tag，用來標示該分配的用途或來源。

psscan是一個使用 pool-tag scanning 的掃描器：它會在 memory dump 中搜尋`_POOL_HEADER` 與 pool tag，並且對找到的候選區塊做結構一致性檢查（例如欄位範圍、指標是否指向可讀記憶體、ProcessName 是否可讀等），來判定該區塊是否為一個有效的 EPROCESS／ETHREAD。因此，即使該程序物件已被從 kernel 的 active list unlink（例如被某些 rootkit 隱藏），只要其 pool 分配尚存在記憶體且尚未被覆寫，psscan 通常可以把它找到。

### psxview 

這個plugin 會將我們剛剛提到的pslist/pstree與psscan以及其他thrdscan、csrss作比較，如果沒有出現在相對應的掃描上就會出現 False， 否則就會出現 true，因此如果有一個process 他在pslist 出現False 但在psscan出現True 那就可以嘗試去分析看看是不是rootkit

#### System Profiling
| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 識別作業系統版本 | imageinfo | `python vol.py -f memory.dump imageinfo` |
| 分析KDBG結構 | kdbgscan | `python vol.py -f memory.dump --profile=Win7SP1x64 kdbgscan` |

#### Processes Analysis
| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 程序列表 | pslist | `python vol.py -f memory.dump --profile=Win7SP1x64 pslist` |
| 程序父子關係 | pstree | `python vol.py -f memory.dump --profile=Win7SP1x64 pstree` |
| 掃描程序 (含隱藏/終止) | psscan | `python vol.py -f memory.dump --profile=Win7SP1x64 psscan` |
| 隱藏程序檢查 | psxview | `python vol.py -f memory.dump --profile=Win7SP1x64 psxview` |
| 程序詳細資訊 | psinfo | `python vol.py -f memory.dump --profile=Win7SP1x64 psinfo -p 1640` |
| 程序權限 | privs | `python vol.py -f memory.dump --profile=Win7SP1x64 privs -p 1640` |
| 程序執行緒 | threads | `python vol.py -f memory.dump --profile=Win7SP1x64 threads -p 1640` |
| 程序SID | getsids | `python vol.py -f memory.dump --profile=Win7SP1x64 getsids -p 1640` |
| 程序令牌 | tokens | `python vol.py -f memory.dump --profile=Win7SP1x64 tokens -p 1640` |
| 轉儲程序執行檔 | procdump | `python vol.py -f memory.dump --profile=Win7SP1x64 procdump -p 1640 --dump-dir=./` |
| 虛擬位址描述符 | vadinfo | `python vol.py -f memory.dump --profile=Win7SP1x64 vadinfo -p 1640` |
| VAD樹結構 | vadtree | `python vol.py -f memory.dump --profile=Win7SP1x64 vadtree -p 1640` |
| 遍歷VAD | vadwalk | `python vol.py -f memory.dump --profile=Win7SP1x64 vadwalk -p 1640` |

#### Network Connections
| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 網路連線/網路活動 | netscan | `python vol.py -f memory.dump --profile=Win7SP1x64 netscan` |

#### Persistence Techniques
| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 註冊表鍵值 | printkey | `python vol.py -f memory.dump --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"` |
| 查找所有持久化機制 | autoruns | `python vol.py -f memory.dump --profile=Win7SP1x64 autoruns` |

#### Filesystem
| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 解析MFT項目 | mftparser | `python vol.py -f memory.dump --profile=Win7SP1x64 mftparser` |
| 掃描檔案物件 | filescan | `python vol.py -f memory.dump --profile=Win7SP1x64 filescan` |
| 轉儲檔案 | dumpfiles | `python vol.py -f memory.dump --profile=Win7SP1x64 dumpfiles -Q 0x000000007e410890 --dump-dir=./` |

#### Advanced Analysis
| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 掃描DLL | dlllist | `python vol.py -f memory.dump --profile=Win7SP1x64 dlllist -p 1640` |
| 檢查處理程序句柄 | handles | `python vol.py -f memory.dump --profile=Win7SP1x64 handles -p 1640 -t Process,Thread` |
| 命令行歷史 | cmdline | `python vol.py -f memory.dump --profile=Win7SP1x64 cmdline` |
| 環境變數 | envars | `python vol.py -f memory.dump --profile=Win7SP1x64 envars` |
| 記憶體字串搜尋 | strings | `strings memory.dump \| grep -i password` |
| 轉儲程序記憶體 | memdump | `python vol.py -f memory.dump --profile=Win7SP1x64 memdump -p 1640 --dump-dir=./` |

透過 Volatility 拿到 evtx

## Volatility 2

```
vol.py -f ./memory.dmp --profile=Win10x64_14393 -g 0xf8004a000b20 filescan | grep '.evtx'
```

## Volatility 3

```
vol -f memory.dmp windows.filescan | grep '.evtx'
```

![](assets/2lVDyAjMs3yOlsZxMikXlj2nIgpeJqE_tenYg-RGAog=.png)

我們可以利用 FileScan 的 pugin 幫助我們檢查是否有我們想要的檔案，圖片中可以得知到說確實有，接下來就可以將他們dump下來，Volatility 2 以及Volatility 3 的 Dumpfile 支援 regex ，可以使用它幫助我們找到所有我們需要的 evtx

## Volatility 2 

```
vol.py -f ./memory.dmp --profile=Win10x64_14393 -g 0xf8004a000b20  dumpfiles --regex .evtx$ --ignore-case --dump-dir output
```

## Volatility 3

```
vol -f memory.dmp windows.dumpfiles.DumpFiles --filter .evtx$
```

這個指令簡單來說就是從memory.dump 中 將結尾為.evtx的檔案全部抓出來，也可以指定看你想要看什麼evtx，再去更改regex即可。

假設我想要dump Security.evtx下來看

## Volatility 2 

```
vol.py -f ./memory.dmp --profile=Win10x64_14393 -g 0xf8004a000b20 --regex Security.evtx$ --ignore-case --dump-dir output
```

## Volatility 3

```
vol -f memory.dmp windows.dumpfiles.DumpFiles --filter Security.evtx$
```

![](assets/n11TvjQIvmkx_EM-nMo45tSov2D461awpBgTU_khL3o=.png)

圖片中發現成功Dump出來東西了，但是怎麼會有兩個檔案，而且這兩個檔案一個是 vacb ，一個是 dat，跟 evtx 的關係不是說沒有感覺是一點關係都沒有，那什麼是 vacb，什麼是 dat ?

* vacb : Caching Data
* dat : Less Fragile File

簡單來說這兩個都儲存了 evtx 的資料，只是 dat 的儲存方式比較穩定可靠

因此其實也可以直接把 vacb 或 dat 副檔名直接改成 evtx ，就可以直接用內建的 Event viewer 查看

![](assets/Chv6PtoCP5Pxr6ytsdD9dJ-t5cpcGlqVz_joyxsW87c=.png)

但另外其實也可以用Evtxcmd 將它變成 CSV 檔查看

根據 https://github.com/EricZimmerman/evtx?tab=readme-ov-file 官方給的使用說明，可以使用以下指令將我們的 evtx 轉換成 csv 

```powershell
.\EvtxECmd.exe -f "..\..\file.0xca82b31c5990.0xca82b3848c70.SharedCacheMap.Security.evtx.vacb" --csv ./
```

接下來就可以獲得一個csv檔，並且裡面的內容是evtx的內容

```powershell
PS C:\Users\yunshiuan\Desktop\net9\EvtxeCmd > .\EvtxECmd.exe -f "..\..\file.0xca82b31c5990.0xca82b3848c70.SharedCacheMap.Security.evtx.vacb" --csv ./
EvtxECmd version 1.5.2.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/evtx

Command line: -f ..\..\file.0xca82b31c5990.0xca82b3848c70.SharedCacheMap.Security.evtx.vacb --csv ./

Warning: Administrator privileges not found!

CSV output will be saved to ./20250904074916_EvtxECmd_Output.csv

Maps loaded: 453

Processing C:\Users\yunshiuan\Desktop\file.0xca82b31c5990.0xca82b3848c70.SharedCacheMap.Security.evtx.vacb...
Chunk count: 30, Iterating records...
Record # 68 (Event Record Id: 68): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 68 (Event Record Id: 68): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 69 (Event Record Id: 69): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 69 (Event Record Id: 69): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 70 (Event Record Id: 70): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 70 (Event Record Id: 70): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 71 (Event Record Id: 71): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 71 (Event Record Id: 71): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 72 (Event Record Id: 72): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 72 (Event Record Id: 72): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 73 (Event Record Id: 73): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 73 (Event Record Id: 73): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 78 (Event Record Id: 78): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 78 (Event Record Id: 78): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 79 (Event Record Id: 79): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 79 (Event Record Id: 79): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 83 (Event Record Id: 83): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessName"] not found! Replacing with empty string
Record # 83 (Event Record Id: 83): In map for event 4718, Property /Event/EventData/Data[@Name="ProcessId"] not found! Replacing with empty string
Record # 2529 (Event Record Id: 2529): In map for event 1100, Property /Event/UserData[@Name="ServiceShutdown"] not found! Replacing with empty string

Event log details
Flags: IsDirty
Chunk count: 30
Stored/Calculated CRC: B5FC0719/B5FC0719
Earliest timestamp: 2024-01-31 23:47:41.1765022
Latest timestamp:   2024-02-01 19:48:31.0253493
Total event log records found: 246

Records included: 246 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1100            1
4608            2
4624            58
4625            1
4647            1
4648            7
4672            51
4688            23
4696            2
4717            10
4718            9
4720            1
4725            2
4728            1
4731            11
4732            3
4735            11
4738            6
4739            1
4797            5
4798            7
4799            3
4826            2
4902            2
4907            1
5024            1
5033            1
5379            23

Processed 1 file in 1.8517 seconds
```

之後就可以用Timeline Explorer 或其他可以開 csv 的軟體去做想要的Event ID查詢或者字串的搜尋。

![](assets/M9NLjmdw8XqYgsflY7NZPbn3tEQ6x0CqxY7Zf7XbbPU=.png)

#### Malware Detection

| 分析項目 | 插件 | 命令行 |
|---------|------|--------|
| 檢查程序注入 | malfind | `python vol.py -f memory.dump --profile=Win7SP1x64 malfind` |
| Hook檢測 | apihooks | `python vol.py -f memory.dump --profile=Win7SP1x64 apihooks` |
| SSDT Hook檢測 | ssdt | `python vol.py -f memory.dump --profile=Win7SP1x64 ssdt` |
| 驅動程式掃描 | driverscan | `python vol.py -f memory.dump --profile=Win7SP1x64 driverscan` |

### Cookie

如果你在 Win10 的記憶體 dump 使用 Volatility 2 的 psscan 時，有可能會出現以下的錯誤

```
$ vol.py -f MemoryDump.mem --profile=Win10x64_19041 psscan

Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Name                PID   PPID PDB                Time created                   Time exited
------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
WARNING : volatility.debug    : Cannot find nt!ObGetObjectType
WARNING : volatility.debug    : Cannot find nt!ObGetObjectType
Traceback (most recent call last):
  File "/usr/local/bin/vol.py", line 192, in <module>
    main()
  File "/usr/local/bin/vol.py", line 183, in main
    command.execute()
  File "/usr/local/lib/python2.7/dist-packages/volatility/commands.py", line 147, in execute
    func(outfd, data)
  File "/usr/local/lib/python2.7/dist-packages/volatility/plugins/filescan.py", line 428, in render_text
    for eprocess in data:
  File "/usr/local/lib/python2.7/dist-packages/volatility/poolscan.py", line 252, in scan
    skip_type_check = skip_type_check)
  File "/usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/windows/windows.py", line 1258, in get_object
    return self.get_object_top_down(struct_name, object_type, skip_type_check)
  File "/usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/windows/windows.py", line 1231, in get_object_top_down
    header.get_object_type() == object_type):
  File "/usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/windows/win7.py", line 155, in get_object_type
    return self.type_map.get(int(self.TypeIndex), '')
  File "/usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/windows/win10.py", line 334, in TypeIndex
    return ((addr >> 8) ^ cook ^ indx) & 0xFF
TypeError: unsupported operand type(s) for ^: 'int' and 'NoneType'
```

這個錯誤是因為win10.py 中在執行時在`return ((addr >> 8) ^ cook ^ indx) & 0xFF`這段程式出現了 NoneType 的變數。

#### nt!ObGetObjectType 是什麼？

根據[這篇文章](https://medium.com/%40ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a)的分析，可以知道說 Win 10 的 TypeInde&#x78;**&#x20;**&#x88AB;混淆過，並且是根據

```
Index = TypeIndex ^ 2nd least significate byte of OBJECT_HEADER address ^ nt!ObHeaderCookie
```

這樣的公式進行混淆，nt!ObGetObjectType 的功用就是將TypeIndex 進行解混淆並回傳解混淆的TypeIndex。

因為 Volatility 2 是開源的，可以去看一下 win10.py 的[sourcecode](https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/overlays/windows/win10.py)

```python
class _OBJECT_HEADER_10(win8._OBJECT_HEADER):
        
    @property
    def TypeIndex(self):
        """Wrap the TypeIndex member with a property that decodes it 
        with the nt!ObHeaderCookie value."""

        cook = obj.VolMagic(self.obj_vm).ObHeaderCookie.v()
        addr = self.obj_offset 
        indx = int(self.m("TypeIndex"))

        return ((addr >> 8) ^ cook ^ indx) & 0xFF
```

這邊就可以明顯的看到這三個變數分別代表什麼，並且利用這三個變數解混淆

* addr : OBJECT\_HEADER\_address
* cook : nt!ObHeaderCookie 讀出的cookie 值，Windows 10 是每次開機隨機生成的
* indx : 混淆過後的TypeIndex

那這邊就是因為 Volatlity2 讀不到 nt!ObHeaderCookie，因此 cook 會是NoneType ， 而如果你有在Volatility 2下過 `-h` 有可能會看過可以下`--cookie`。

```
$ vol.py -h

Volatility Foundation Volatility Framework 2.6.1
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/home/yunshiuan/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/home/yunshiuan/.cache/volatility
                        Directory where cache files are stored
  --cache               Use caching
  --tz=TZ               Sets the (Olson) timezone for displaying timestamps
                        using pytz (if installed) or tzset
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --profile=WinXPSP2x86
                        Name of the profile to load (use --info to see a list
                        of supported profiles)
  -l LOCATION, --location=LOCATION
                        A URN location from which to load an address space
  -w, --write           Enable write support
  --dtb=DTB             DTB Address
  --shift=SHIFT         Mac KASLR shift address
  --output=text         Output in this format (support is module specific, see
                        the Module Output Options below)
  --output-file=OUTPUT_FILE
                        Write output in this file
  -v, --verbose         Verbose information
  --physical_shift=PHYSICAL_SHIFT
                        Linux kernel physical shift address
  --virtual_shift=VIRTUAL_SHIFT
                        Linux kernel virtual shift address
  -g KDBG, --kdbg=KDBG  Specify a KDBG virtual address (Note: for 64-bit
                        Windows 8 and above this is the address of
                        KdCopyDataBlock)
  --force               Force utilization of suspect profile
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address
  --cookie=COOKIE       Specify the address of nt!ObHeaderCookie (valid for
                        Windows 10 only)
```

那這個就是讓我們放 nt!ObHeaderCookie 的 address 給 Volatility 2 ， 因此接下來只要獲取到nt!ObHeaderCookie 位置的 cookie 應該就可以解決這個問題了。而 nt!ObHeaderCookie 在 ntoskrnl.exe 中可以找到。



因此我們現在要把memory 中的ntoskrnl.exe dump出來，volatility 2 有一個很猛的 `moddump` Plugin ，他可以將 Kernel Driver 全部 dump 出來

```bash
$ vol.py -f MemoryDump.mem --profile=Win10x64_19041 moddump --dump-dir ./

Volatility Foundation Volatility Framework 2.6.1
Module Base        Module Name          Result
------------------ -------------------- ------
0xfffff8076221a000 ntoskrnl.exe         OK: driver.fffff8076221a000.sys
0xfffff80762070000 hal.dll              OK: driver.fffff80762070000.sys
0xfffff80767340000 ucx01000.sys         OK: driver.fffff80767340000.sys
0xfffff80764530000 NETIO.SYS            OK: driver.fffff80764530000.sys
0xfffff80767570000 UsbHub3.sys          OK: driver.fffff80767570000.sys
0xfffff80767020000 USBPORT.SYS          OK: driver.fffff80767020000.sys
0xfffff80767db0000 vm3dmp.sys           OK: driver.fffff80767db0000.sys
0xfffff807643c0000 ndis.sys             OK: driver.fffff807643c0000.sys
0xfffff807679d0000 cldflt.sys           OK: driver.fffff807679d0000.sys
0xfffff80767a80000 bindflt.sys          OK: driver.fffff80767a80000.sys
0xfffff80763fe0000 EhStorClass.sys      OK: driver.fffff80763fe0000.sys
0xfffff807635f0000 CI.dll               OK: driver.fffff807635f0000.sys
0xfffff80763c00000 pdc.sys              OK: driver.fffff80763c00000.sys
0xfffff80767af0000 rspndr.sys           OK: driver.fffff80767af0000.sys
0xfffff80767210000 e1i65x64.sys         OK: driver.fffff80767210000.sys
0xfffff80763e00000 vsock.sys            OK: driver.fffff80763e00000.sys
0xfffff80767440000 rdpbus.sys           OK: driver.fffff80767440000.sys
0xfffff80774a50000 tcpipreg.sys         OK: driver.fffff80774a50000.sys
0xfffff8077a5f0000 ad_driver.10.sys     OK: driver.fffff8077a5f0000.sys
0xfffff80765670000 cdrom.sys            OK: driver.fffff80765670000.sys
0xfffff80774c80000 mpsdrv.sys           OK: driver.fffff80774c80000.sys
0xfffff80763eb0000 storahci.sys         OK: driver.fffff80763eb0000.sys
0xfffff8077a4c0000 condrv.sys           OK: driver.fffff8077a4c0000.sys
0xfffff80765ad0000 watchdog.sys         OK: driver.fffff80765ad0000.sys
0xfffff807656f0000 Beep.SYS             OK: driver.fffff807656f0000.sys
0xfffff80764b70000 mup.sys              OK: driver.fffff80764b70000.sys
0xfffff80767d90000 serenum.sys          OK: driver.fffff80767d90000.sys
0xfffff80763b50000 msisadrv.sys         OK: driver.fffff80763b50000.sys
0xfffff80762160000 FLTMGR.SYS           OK: driver.fffff80762160000.sys
0xfffff80767390000 vmgencounter.sys     OK: driver.fffff80767390000.sys
0xfffff80763fb0000 stornvme.sys         OK: driver.fffff80763fb0000.sys
0xfffff807635c0000 werkernel.sys        OK: driver.fffff807635c0000.sys
0xfffff80765720000 dxgkrnl.sys          OK: driver.fffff80765720000.sys
0xfffff807637f0000 WMILIB.SYS           OK: driver.fffff807637f0000.sys
0xfffff80763d90000 volmgrx.sys          Error: Cannot acquire AS
0xfffff80774a20000 Ndu.sys              OK: driver.fffff80774a20000.sys
0xfffff80763ef0000 storport.sys         OK: driver.fffff80763ef0000.sys
0xfffff80767990000 wcifs.sys            OK: driver.fffff80767990000.sys
0xfffff80763c50000 partmgr.sys          OK: driver.fffff80763c50000.sys
0xfffff80767870000 dxgmms2.sys          OK: driver.fffff80767870000.sys
0xfffff80766e80000 kdnic.sys            OK: driver.fffff80766e80000.sys
0xfffff80767b70000 peauth.sys           OK: driver.fffff80767b70000.sys
0xfffff80764aa0000 volsnap.sys          OK: driver.fffff80764aa0000.sys
0xfffff80763b10000 IntelTA.sys          OK: driver.fffff80763b10000.sys
0xfffff807676c0000 HIDPARSE.SYS         OK: driver.fffff807676c0000.sys
0xfffff80767cd0000 umbus.sys            OK: driver.fffff80767cd0000.sys
0xfffff80767720000 dump_storport.sys    OK: driver.fffff80767720000.sys
0xfffff807673b0000 BATTC.SYS            OK: driver.fffff807673b0000.sys
0xfffff80766da0000 dfsc.sys             OK: driver.fffff80766da0000.sys
0xfffff80763b20000 WindowsTr...roxy.sys OK: driver.fffff80763b20000.sys
0xfffff80764b10000 rdyboost.sys         OK: driver.fffff80764b10000.sys
0xfffff80763d50000 PCIIDEX.SYS          OK: driver.fffff80763d50000.sys
0xfffff80766f80000 afunix.sys           OK: driver.fffff80766f80000.sys
0xfffff80767da0000 vm3dmp_loader.sys    OK: driver.fffff80767da0000.sys
0xfffff80764ba0000 iorate.sys           OK: driver.fffff80764ba0000.sys
0xfffff80767420000 NdisVirtualBus.sys   OK: driver.fffff80767420000.sys
0xfffff80766dd0000 CompositeBus.sys     OK: driver.fffff80766dd0000.sys
0xfffff80774a00000 mmcss.sys            OK: driver.fffff80774a00000.sys
0xfffff80764000000 fileinfo.sys         OK: driver.fffff80764000000.sys
0xfffff80764610000 tcpip.sys            OK: driver.fffff80764610000.sys
0xfffff807637a0000 WDFLDR.SYS           OK: driver.fffff807637a0000.sys
0xfffff80766c20000 rdbss.sys            OK: driver.fffff80766c20000.sys
0xfffff80762080000 kdcom.dll            OK: driver.fffff80762080000.sys
0xfffff80766ca0000 csc.sys              OK: driver.fffff80766ca0000.sys
0xfffffb54a32b0000 win32k.sys           Error: Cannot acquire AS
0xfffff807674e0000 USBD.SYS             OK: driver.fffff807674e0000.sys
0xfffffb54a2c00000 win32kbase.sys       OK: driver.fffffb54a2c00000.sys
0xfffff80763af0000 WindowsTrustedRT.sys OK: driver.fffff80763af0000.sys
0xfffff80774ca0000 mrxsmb.sys           OK: driver.fffff80774ca0000.sys
0xfffff80767d20000 kbdclass.sys         OK: driver.fffff80767d20000.sys
0xfffff80766d40000 nsiproxy.sys         OK: driver.fffff80766d40000.sys
0xfffff80767560000 ksthunk.sys          OK: driver.fffff80767560000.sys
0xfffff80765b70000 crashdmp.sys         OK: driver.fffff80765b70000.sys
0xfffff80763b30000 pcw.sys              OK: driver.fffff80763b30000.sys
0xfffff807643b0000 Fs_Rec.sys           Error: Cannot acquire AS
0xfffff807649c0000 fvevol.sys           OK: driver.fffff807649c0000.sys
0xfffff807635e0000 ntosext.sys          OK: driver.fffff807635e0000.sys
0xfffff80764c00000 CLASSPNP.SYS         OK: driver.fffff80764c00000.sys
0xfffff80766bf0000 winhvr.sys           OK: driver.fffff80766bf0000.sys
0xfffff80762130000 PSHED.dll            OK: driver.fffff80762130000.sys
0xfffff80763e20000 vmci.sys             OK: driver.fffff80763e20000.sys
0xfffff80767430000 swenum.sys           OK: driver.fffff80767430000.sys
0xfffff80767660000 hidusb.sys           OK: driver.fffff80767660000.sys
0xfffff80766b20000 netbios.sys          OK: driver.fffff80766b20000.sys
0xfffff80766ea0000 CimFS.SYS            OK: driver.fffff80766ea0000.sys
0xfffff80774ac0000 HTTP.sys             OK: driver.fffff80774ac0000.sys
0xfffff80767ab0000 lltdio.sys           OK: driver.fffff80767ab0000.sys
0xfffff807670d0000 portcls.sys          OK: driver.fffff807670d0000.sys
0xfffff807656e0000 Null.SYS             Error: Cannot acquire AS
0xfffff80767cf0000 i8042prt.sys         OK: driver.fffff80767cf0000.sys
0xfffff80763910000 mssecflt.sys         OK: driver.fffff80763910000.sys
0xfffff80766f20000 netbt.sys            OK: driver.fffff80766f20000.sys
0xfffff80766b40000 Vid.sys              OK: driver.fffff80766b40000.sys
0xfffff80762150000 BOOTVID.dll          OK: driver.fffff80762150000.sys
0xfffff80767760000 dump_stornvme.sys    OK: driver.fffff80767760000.sys
0xfffff80763d70000 volmgr.sys           OK: driver.fffff80763d70000.sys
0xfffff80763990000 ACPI.sys             OK: driver.fffff80763990000.sys
0xfffff807636e0000 cng.sys              OK: driver.fffff807636e0000.sys
0xfffff80766fa0000 ahcache.sys          OK: driver.fffff80766fa0000.sys
0xfffff80774d90000 vmmemctl.sys         OK: driver.fffff80774d90000.sys
0xfffff80767b10000 msquic.sys           OK: driver.fffff80767b10000.sys
0xfffff807621d0000 cmimcext.sys         OK: driver.fffff807621d0000.sys
0xfffff80766df0000 fastfat.SYS          OK: driver.fffff80766df0000.sys
0xfffff80763400000 clipsp.sys           OK: driver.fffff80763400000.sys
0xfffff807637c0000 SleepStudyHelper.sys OK: driver.fffff807637c0000.sys
0xfffff80764020000 Wof.sys              OK: driver.fffff80764020000.sys
0xfffff80763e70000 ataport.SYS          OK: driver.fffff80763e70000.sys
0xfffff80764a90000 volume.sys           OK: driver.fffff80764a90000.sys
0xfffff807670a0000 HDAudBus.sys         OK: driver.fffff807670a0000.sys
0xfffff807656b0000 filecrypt.sys        OK: driver.fffff807656b0000.sys
0xfffff807638e0000 acpiex.sys           OK: driver.fffff807638e0000.sys
0xfffff80766ef0000 TDI.SYS              OK: driver.fffff80766ef0000.sys
0xfffff8077a4e0000 vmhgfs.sys           OK: driver.fffff8077a4e0000.sys
0xfffff80765b10000 BasicRender.sys      OK: driver.fffff80765b10000.sys
0xfffff80767d50000 mouclass.sys         OK: driver.fffff80767d50000.sys
0xfffff80763d40000 intelide.sys         OK: driver.fffff80763d40000.sys
0xfffffb54a3350000 cdd.dll              Error: Cannot acquire AS
0xfffff80767960000 luafv.sys            OK: driver.fffff80767960000.sys
0xfffff80774c50000 bowser.sys           OK: driver.fffff80774c50000.sys
0xfffff807676e0000 mouhid.sys           OK: driver.fffff807676e0000.sys
0xfffff807677b0000 dump_dumpfve.sys     OK: driver.fffff807677b0000.sys
0xfffff807673d0000 intelppm.sys         OK: driver.fffff807673d0000.sys
0xfffff80765be0000 Msfs.SYS             OK: driver.fffff80765be0000.sys
0xfffff8077a550000 WdFilter.sys         OK: driver.fffff8077a550000.sys
0xfffff80766ff0000 tap0901.sys          OK: driver.fffff80766ff0000.sys
0xfffff80774da0000 srvnet.sys           OK: driver.fffff80774da0000.sys
0xfffff807640d0000 Ntfs.sys             OK: driver.fffff807640d0000.sys
0xfffff80763e40000 mountmgr.sys         OK: driver.fffff80763e40000.sys
0xfffff80767450000 usbhub.sys           OK: driver.fffff80767450000.sys
0xfffff80767a60000 storqosflt.sys       OK: driver.fffff80767a60000.sys
0xfffff80767680000 HIDCLASS.SYS         OK: driver.fffff80767680000.sys
0xfffff80763c90000 spaceport.sys        OK: driver.fffff80763c90000.sys
0xfffff807672a0000 USBXHCI.SYS          OK: driver.fffff807672a0000.sys
0xfffff80766ec0000 tdx.sys              OK: driver.fffff80766ec0000.sys
0xfffff80766ad0000 pacer.sys            OK: driver.fffff80766ad0000.sys
0xfffff80765700000 vmrawdsk.sys         OK: driver.fffff80765700000.sys
0xfffff80767000000 usbuhci.sys          OK: driver.fffff80767000000.sys
0xfffff80763550000 msrpc.sys            Error: Cannot acquire AS
0xfffff80763b60000 pci.sys              OK: driver.fffff80763b60000.sys
0xfffff80767ad0000 mslldp.sys           OK: driver.fffff80767ad0000.sys
0xfffff80767170000 ks.sys               OK: driver.fffff80767170000.sys
0xfffff80766d90000 gpuenergydrv.sys     OK: driver.fffff80766d90000.sys
0xfffff807673a0000 CmBatt.sys           OK: driver.fffff807673a0000.sys
0xfffff807645d0000 ksecpkg.sys          OK: driver.fffff807645d0000.sys
0xfffff80763be0000 vdrvroot.sys         OK: driver.fffff80763be0000.sys
0xfffff807671f0000 usbehci.sys          OK: driver.fffff807671f0000.sys
0xfffff80763800000 Wdf01000.sys         OK: driver.fffff80763800000.sys
0xfffff80764be0000 disk.sys             OK: driver.fffff80764be0000.sys
0xfffff80766d70000 mssmbios.sys         OK: driver.fffff80766d70000.sys
0xfffff80774d40000 mrxsmb20.sys         OK: driver.fffff80774d40000.sys
0xfffff807677d0000 dxgmms1.sys          OK: driver.fffff807677d0000.sys
0xfffff80767d70000 serial.sys           OK: driver.fffff80767d70000.sys
0xfffff80766ab0000 vwififlt.sys         OK: driver.fffff80766ab0000.sys
0xfffff807620c0000 CLFS.SYS             OK: driver.fffff807620c0000.sys
0xfffff807656d0000 tbs.sys              OK: driver.fffff807656d0000.sys
0xfffff80764900000 fwpkclnt.sys         OK: driver.fffff80764900000.sys
0xfffff80766f10000 ws2ifsl.sys          OK: driver.fffff80766f10000.sys
0xfffff80763520000 ksecdd.sys           OK: driver.fffff80763520000.sys
0xfffff80765b30000 Npfs.SYS             OK: driver.fffff80765b30000.sys
0xfffff80767140000 drmk.sys             OK: driver.fffff80767140000.sys
0xfffff80766d60000 npsvctrig.sys        OK: driver.fffff80766d60000.sys
0xfffff80764980000 wfplwfs.sys          OK: driver.fffff80764980000.sys
0xfffff80767d40000 vmmouse.sys          OK: driver.fffff80767d40000.sys
0xfffff807637d0000 WppRecorder.sys      OK: driver.fffff807637d0000.sys
0xfffff80761de0000 mcupdate.dll         OK: driver.fffff80761de0000.sys
0xfffff8077a3f0000 srv2.sys             OK: driver.fffff8077a3f0000.sys
0xfffff80766a00000 afd.sys              OK: driver.fffff80766a00000.sys
0xfffff80763970000 SgrmAgent.sys        OK: driver.fffff80763970000.sys
0xfffff80767620000 usbccgp.sys          OK: driver.fffff80767620000.sys
0xfffff80763c30000 CEA.sys              OK: driver.fffff80763c30000.sys
0xfffff80767700000 vmusbmouse.sys       OK: driver.fffff80767700000.sys
0xfffff80767850000 monitor.sys          OK: driver.fffff80767850000.sys
0xfffff80763e60000 atapi.sys            OK: driver.fffff80763e60000.sys
0xfffff80763a80000 intelpep.sys         OK: driver.fffff80763a80000.sys
0xfffff80762090000 tm.sys               OK: driver.fffff80762090000.sys
0xfffff80766e60000 bam.sys              OK: driver.fffff80766e60000.sys
0xfffffb54a2ee0000 win32kfull.sys       Error: Cannot acquire AS
0xfffff807674f0000 HdAudio.sys          OK: driver.fffff807674f0000.sys
0xfffff80766b00000 ndiscap.sys          OK: driver.fffff80766b00000.sys
0xfffff80765af0000 BasicDisplay.sys     OK: driver.fffff80765af0000.sys
```

&#x20;第一個就是ntoskrnl.exe ，把它拿去反編譯之後找到 ObGetObjectType 接下來把前面的8 bytes 的 opcode 記住

![](assets/TvYuVt1MEA0AH8i7s_0FELoY5njlVr0iMo2in0PMfRc=.png)

接下來用yarascan 把他從記憶體中的位置抓出來 

```bash
$ sudo python2.7 vol.py -f ../temp_extract_dir/MemoryDump.mem --profile=Win10x64_19041 yarascan -K -Y "{48 8D 41 D0 0F B6 49 E8}"

Volatility Foundation Volatility Framework 2.6.1
Rule: r1
Owner: ntoskrnl.exe
0xf8076291d470  48 8d 41 d0 0f b6 49 e8 48 c1 e8 08 0f b6 c0 48   H.A...I.H......H
0xf8076291d480  33 c1 0f b6 0d a3 92 5f 00 48 33 c1 48 8d 0d ed   3......_.H3.H...
0xf8076291d490  99 5f 00 48 8b 04 c1 c3 cc cc cc cc cc cc cc cc   ._.H............
0xf8076291d4a0  48 83 ec 58 8a 84 24 a0 00 00 00 c7 44 24 48 01   H..X..$.....D$H.
0xf8076291d4b0  00 00 00 88 44 24 40 8b 84 24 98 00 00 00 89 44   ....D$@..$.....D
0xf8076291d4c0  24 38 8b 84 24 90 00 00 00 89 44 24 30 48 8b 84   $8..$.....D$0H..
0xf8076291d4d0  24 88 00 00 00 48 89 44 24 28 48 8b 84 24 80 00   $....H.D$(H..$..
0xf8076291d4e0  00 00 48 89 44 24 20 e8 14 00 00 00 48 83 c4 58   ..H.D$......H..X
0xf8076291d4f0  c3 cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc   ................
0xf8076291d500  4c 8b dc 49 89 5b 08 49 89 73 10 4d 89 4b 20 4d   L..I.[.I.s.M.K.M
0xf8076291d510  89 43 18 57 41 54 41 55 41 56 41 57 48 83 ec 70   .C.WATAUAVAWH..p
0xf8076291d520  48 8b da 48 8b f9 45 33 ed 4d 89 6b b0 4d 89 6b   H..H..E3.M.k.M.k
0xf8076291d530  b8 65 48 8b 04 25 88 01 00 00 48 89 44 24 60 44   .eH..%....H.D$`D
0xf8076291d540  8a b8 32 02 00 00 45 84 ff 0f 84 07 94 12 00 49   ..2...E........I
0xf8076291d550  8b 4b 28 48 b8 00 00 ff ff ff 7f 00 00 48 3b c8   .K(H.........H;.
0xf8076291d560  48 0f 43 c8 8b 01 89 01 44 8b a4 24 d0 00 00 00   H.C.....D..$....
```

接下來知道 ntoskrnl.exe 的位置在`0xf8076291d470`後我們就可以寫 script 幫我我們提取ObHeaderCookie

回去看反編譯出來的ObGetObjectType，我們的目標是`movzx   ecx, byte [rel ObHeaderCookie]` 這段

```bash
$ sudo python2.7 vol.py -f ../temp_extract_dir/MemoryDump.mem --profile=Win10x64_19041 volshell
Volatility Foundation Volatility Framework 2.6.1
Current context: System @ 0xffffad8185883180, pid=4, ppid=0 DTB=0x1ad002
Welcome to volshell! Current memory image is:
file:///home/yunshiuan/temp_extract_dir/MemoryDump.mem
To get help, type 'hh()'
>>> addr = 0xf8076291d470
>>> for m in getmods():
...     nt_mod = m
...     break
...
>>> mode = distorm3.Decode64Bits
>>> data = nt_mod.obj_vm.read(addr, 100)
>>> ops = distorm3.Decompose(addr, data, mode)
>>> for op in reversed(ops):
...     if (op.size == 7 and 'FLAG_RIP_RELATIVE' in op.flags and len(op.operands) == 2 and op.operands[0].type == 'Register' and op.operands[1].type == 'AbsoluteMemory' and op.operands[1].size == 8):
...         addr2 = op.address + op.size + op.operands[1].disp
...
>>> cookie = obj.Object("unsigned int", offset = addr2, vm = nt_mod.obj_vm)
>>> hex(cookie)
'0x9be88324L'
>>> exit()
```

這個script 簡單來說

* 首先先獲取到addr 的第一個函數，那因為我們直接定位的關係，所以這邊nt\_mod = ObGetObjectType
* 接下來分別是設定64 位元反組譯模式、讀取100 位元組的機器碼、進行反組譯得到指令列表
* 下一部分是尋找`movzx ecx, byte [rel ObHeaderCookie]`指令
  * `op.size == 7`：指令長度為 7 位元組
  * `'FLAG_RIP_RELATIVE' in op.flags`：使用 RIP相對定址
  * `len(op.operands) == 2`：有 2 個運算元
  * `op.operands[0].type== 'Register'`：第一個運算元是暫存器
  * `op.operands[1].type == 'AbsoluteMemory'`：第二個運算元是記憶體位址
  * `op.operands[1].size== 8`：記憶體運算元大小為 8 位元組
* 找到後計算ObHeaderCookie的實際記憶體位置
  * `addr2 = op.address + op.size + op.operands[1].disp`
    * op.address：指令地址
    * op.size：指令大小（7 位元組）
    * op.operands\[1].disp：RIP 相對位移
* 最後提取cookie 的值



提取後我們知道cookie 的值為`0x9be88324`，最後再下一次 psscan 帶上剛剛抓的cookie

```bash
sudo python2.7 vol.py -f ../temp_extract_dir/MemoryDump.mem --profile=Win10x64_19041 --cookie=0x9be88324 psscan
```

發現成功執行

![](assets/itW3xFS6UvPW_Na9YNcMa0hzXSp3BMdpHgJ7ig0oANU=.png)

---

## Network Forensics

* wireshark

    ### 解密封包

    Wireshark 支援可以匯入key ，將加密過後的HTTPS 流量還原成明文

    因為HTTPS 多了一層SSL/TLS，他會將封包進行加密保護傳輸內容不被竊聽

    

    解密流程如下：

    假設我們要分析一個HTTPS網站的登入過程，將加解密的key 先存在一個檔案中

    ```shellscript
    export SSLKEYLOGFILE="/home/user/ssl-keys.log"
    ```

    然後再Preferences-> Prorocols 裡面找到TLS ，接下來把剛剛儲存的key 路徑丟進去最底下`(Pre)-Master-Screct log filename`裡面

    ![](assets/CeYJy0OyLQdOSSNNFOSwGR4xwqu41W5ftRSrnPAi5Lg=.png)

    另外wireshark 支援的解密為

    1. **SSL/TLS解密**：最常見的HTTPS流量解密
    2. **WEP/WPA/WPA2解密**：WiFi加密流量
    3. **IPsec解密**：VPN流量
    4. **Kerberos解密**：Windows認證流量
    5. **自定義加密**：透過Lua腳本支援

    ### 匯出物件

    wireshark 提供了可以將封包傳輸的物件(如：圖片、檔案、網頁......) dump 下來的功能

    ![](assets/3ddxe9oKXt86KtV1SU35U9aQ4UFkfBXaD7uXQ3UaAbA=.png)

    ***

* NetworkMiner 

    目前只支援 Windows 作業系統，但是也可以使用其他工具讓它在 Linux 或 Mac 上執行。它可以將 pcap 內的封包拆開、解析、重組，嘗試把裡面的檔案、圖片、郵件、憑證／SSL 證書、使用者帳號密碼等直接還原出來，另外它也可以即時監聽封包並分析

    ![](assets/BJmkNL7Wg-jT87SnETdJ3A595Aq2fIzDb_OTbU6yD3A=.png)

    但是，NetworkMiner 免費版只能分析 pcap 檔案，如果是 pcapng 格式則需要付費才能分析，付費版本需要 1300 USD 

    > pcapng 也是一種用來儲存網路封包捕捉資料的檔案格式，是舊的 pcap 格式的進化版，它會比 pcap 儲存的資料還要多，可以分析的資訊也越多。目前 Wireshark 從 v1.8 開始，預設就把封包儲存格式改成 pcapng

* Zui 
    * Zui 它的前身是Brim ， 是一款用於網路流量分析的工具，它提供了使用者友善的圖形化介面，可以讓使用者能夠快速分析與視覺化大量網路流量
    
      ![](assets/aEB_E59Bb6Ghcjk57wLkzd5kCFR_ATktueWQUMrKugE=.png)
    
      這個工具裡面整合了兩個網路封包分析工具，分別是Zeek、Suricata，先用 [brimcap](https://github.com/brimdata/brimcap) 將 pcap 送到 Zeek/Suricata 做 summary/log，再在 Zui 內用 correlation view、alert 視窗、或 detail pane 分析事件與原始封包。
    
      所以只要將pcap 封包丟進去 zeek ，他就會開始進行分析
    
      ![](assets/gyCnmYGl_VfYEuqKAOa8TyKLnNYYC6tohyAziYN13Ck=.png)
    
      分析完後按下`Query Pool` 就可以看到視覺化的頁面
    
      ![](assets/aEB_E59Bb6Ghcjk57wLkzd5kCFR_ATktueWQUMrKugE=.png)
    
      另外 Zui 使用 Zed（或稱 Zed query / SuperSQL）來做過濾與轉換查詢可以更快處理大量資料
    
      以下分享幾個操作
    
      首先可以篩選出Suricata 警報
    
      ```
      event_type=="alert" #可篩選出 Suricata 警報
      ```
    
      ![](assets/s_W7IAAYyK-10fAyW9KpXLDpZhCSm8jgPMVAQABdehY=.png)
    
      也有像wireshark 一樣可以篩選 ip scr or ip dst 
    
      ```
      id.orig_h==100.112.165.2 and id.resp_p==53 #來源ip = 100.112.165.2 目標port = 53
      ```
    
      ![](assets/tWu_XB4kP452AJbgpcIQ0vOiRSROoPhmTNH13gBxRPg=.png)
    
      另外他也可以進行統計與排序
    
      ```
      count() by id.resp_p | sort -r  # 對目標port 進行統計，並降冪排序
      ```
    
      ![](assets/mq6sPm0cAJqgKEiREZUwTYXNAvnegIR2DAfkVtRs4GQ=.png)
    
      對你想要篩選的資料按右鍵可以自動生成查詢指令
    
      ![](assets/T2wzAhndl8-IWt4PObDgOI8JbPrlO9uiPokk5yl27do=.png)
    
      最後也可以下載官方提供預先寫好的查詢
    
      連結：[https://github.com/brimdata/brimcap?tab=readme-ov-file#brimcap-queries
    
    
      ](https://github.com/brimdata/brimcap?tab=readme-ov-file#brimcap-queries)下載後queries.json 後按下+的藍色按鈕，點選Import Queries
    
      ![](assets/777onBmZHXrrhqyTl2BNjPp328hH_BsS0lh761qK6Aw=.png)
    
      把剛剛下載的json 檔丟進去，就會匯入預先寫好的query 
    
      ![](assets/kndUjYMJJCjbP4n4KenQWusY9yA4lv4sKzYL_6Ke0lA=.png)
    
      

## Disk Forensics

winlog 路徑 : `C:\Windows\System32\winevt\Logs`

Register 路徑 ：`C:\Windows\System32`

常見 Registry 路徑

| **Registry 路徑**                                            | **說明**               |
| ------------------------------------------------------------ | ---------------------- |
| HKLM\SYSTEM\CurrentControlSet\Services                       | 系統服務與驅動程式資訊 |
| HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName | 電腦名稱               |
| HKLM\SYSTEM\MountedDevices                                   | 磁碟/USB 裝置掛載資訊  |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run           | 系統啟動時自動執行程式 |
| HKLM\SAM\SAM\Domains\Account\Users                           | 本機帳號資訊           |

* SAM：儲存本地使用者帳號與群組的資訊，例如使用者名稱、建立時間、最後登入時間。
  * Domain 帳號資訊在 Domain Controller 的 NTDS.dit

* SECURITY：包含使用者帳號的安全相關資訊，例如密碼政策。
* SOFTWARE：紀錄所有已安裝軟體（包含 Windows 內建與第三方軟體）。
* SYSTEM：儲存系統層級的組態資訊，例如事件日誌設定、硬體（像是 USB 裝置）相關的設定。

### \$MFT

路徑：`<Volume_Root>\$MFT`

\$MFT 是 NTFS 檔案系統的核心元件，儲存所有檔案和目錄的metadata（如名稱、大小、時間戳、權限等）。
由一系列固定大小的檔案記錄組成，每個記錄包含一個檔案或目錄的所有屬性。

下方圖片是使用 [MFT Explorer](https://ericzimmerman.github.io/#!index.md) 把 MFT 內的資料視覺化顯示出來

![](assets/LKoPSOtJbxLBBf-25Wy6a6Pdf2PagV_pacqey3WPJBw=.png)

### \$UsnJrnl

路徑：`<Volume_Root>\$Extend\$UsnJrnl:$J`

\$UsnJrnl 的主要功能是追蹤 NTFS 上所有文件與目錄的變更。每當文件被創建、修改、刪除、重命名、移動，或其屬性／安全描述符發生變化時，\$UsnJrnl 都會記錄一條對應條目。這些條目包括變更類型、發生時間、關聯的 USN（更新序列號）、文件 ID、父目錄 ID、文件名稱、屬性與大小等資訊，但因為紀錄的比較詳細，所以大約只會記錄到1~2天的資訊。

![](assets/cQfi8Udc0DTBsNYPvThawCXqM082PrXrodQAtZ_VH8Q=.png)

### \$LogFile

路徑：`<Volume_Root>\$LogFile`

\$LogFile 與 \$UsnJrnl 紀錄的內容差不多，但是紀錄的是更底層的操作，其功能是作為 NTFS 的 transaction log，記錄對 metadata 所做的各種操作（如 MFT 新增／修改／刪除、目錄索引更新、Bitmap Allocation、\$UsnJrnl 本身的更新等）。在進行 metadata 變更前，系統會先將這些交易寫入 \$LogFile，以確保即便系統意外中斷，也可利用日誌進行回滾或重做操作，以保持文件系統的一致性與完整性。

![](assets/0rdT1ORbwNlebwEt7OXnRopij-tFJVEr5PXan4DQRoA=.png)

### \$I30

在 NTFS 檔案系統中，每一個 Directory 都維護一個 Index，用來快速查找該目錄下的檔案與子目錄，當目錄內容改變 (如新增、刪除、重命名) 時，對應的 index entry 也會被修改或標記為已刪除 (Flags 欄位)，因為是標記的關係，所以可以在`$I30` 中找到被刪除的檔案。

![](assets/CGFDolSOV19jk_scmOtNOnpFMABkF3YeLx_g2mG76Lw=.png)

### Amcache.hve

路徑位置：`%WinDir%\AppCompat\Programs\Amcache.hve`

![](assets/Ybc_QgFK9UsOKi7pW8blJhLBDXDmoh5zkDgOjPsqhkw=.png)

自 Windows 8 起引入，記錄了已執行應用程式的詳細資訊，包括檔案路徑、SHA-1 雜湊值、時間戳記等。

**若惡意程式本體被刪除或遭清除，無法從映像直接看到該檔案本身時**，可以透過 Amcache 的記錄去驗證是否存在

### NTUSER.DAT

路徑位置：`C:\Users\<username>\NTUSER.DAT`

![](assets/HbBDSu1lraXx3pIgsNxHGOqZHdhNnyuWDrcCEMR8-1A=.png)

NTUSER.DAT 是 Windows 每個使用者帳戶在其使用者設定檔底下的一個檔案，用來儲存與該帳戶相關的 Registry 設定與使用者偏好，在使用者登入時，系統會將這個檔案對應到註冊表的 HKEY\_CURRENT\_USER（HKCU） 分支，讓該使用者的作業與應用程式可以讀寫其個人設定；在登出或關機時，這些變更會回寫到 NTUSER.DAT。



可以直接用 [RegistryExplorer](https://ericzimmerman.github.io/#!index.md) 查看。

![](assets/RIvMLfCdh5rrb81bTPyBEaPuSO1d-zFoxpUOjAMwYo8=.png)

這邊重點提兩個比較特別的 key

### UserAssist

key 路徑：`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

UserAssist 是 Windows 用來追蹤使用者透過圖形介面啟動應用程式或捷徑的統計記錄機制，裡面會包含程式的執行次數、最後執行時間、**Focus Count、Focus Time**

![](assets/EX1XBHpXaNJ2rj-3d0M_GUZyaVjDpWQwmaKNE1NvYuY=.png)

### ShellBags

ShellBags 是 Windows 用於記錄使用者在檔案總管中瀏覽**資料夾**時的設定偏好與檔案夾訪問紀錄，包括資料夾的視窗配置 / 檢視樣式 / 排列方式 / 大小 / 位置等，代表如有刪除或存取資料夾的操作會被記錄在 ShellBags 當中。

它會依照作業系統存在不同地方

* `<NTUSER.DAT>\Software\Microsoft\Windows\Shell\BagMRU `
* `<NTUSER.DAT>\Software\Microsoft\Windows\Shell\Bags`
* 在較新 Windows 版本（如 Windows 7 之後），部分 ShellBags 資料會存於 `C:\Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat`
* 在某些 Windows 版本或使用者設定中，部分 ShellBags 條目只存在於 UsrClass.dat 而非 NTUSER.DAT

![](assets/pnKEJ4vqw21ZBolGw34xhCg7XGai0iP7POjOr8NtI2I=.png)

如果直接使用 RegistryExplorer 會很難閱讀，建議使用 Eric Zimmerman's tools 中的 ShellBags Explorer 查看

### Prefetch

位置：`%WinDir%\prefetch`

Prefetch（.pf）是 Windows 為了加速程式啟動而維護的快取檔案。系統會在 `%WinDir%\prefetch` 路徑下為執行過的可執行檔建立 .pf 檔，裡面包含：



1. **執行時間戳**：Windows 8 以後的 Prefetch 能記錄多達 8 個執行時間點，可用來建立事件時間線，另外 Prefetch 的時間戳在精確到秒時通常要減掉 10 秒，在做精細時間對帳時要留意此差異，[參考網址](https://www.thedfirspot.com/post/artifacts-of-execution-i-know-what-you-did-last-incident?utm_source=chatqpt.com)。 
2. **Run count**：表示該程式被執行了多少次。 
3. **可執行檔名稱與路徑**：指出實際被執行的檔案與來源路徑，對判斷惡意軟體的落點很重要。 
4. **程式啟動時存取過的檔案清單**：有時會列出其他被呼叫或載入的 DLL、路徑，可用來找出程式的行為鏈，例如開啟哪些檔。 
5. **volume / system info、執行檔雜湊等元資料**：可用來確認是在哪個 volume / 機器上被執行

檔名通常會長得像 PROGRAM.EXE-XXXXXXXX.pf，後面的 8 字元為路徑雜湊，用來區分相同名稱但路徑不同的執行檔。

![](assets/Kq6MvDG5ev05EwQcxGDnrfk7YXkBzYtWCCX0F1_nnas=.png)

為了讀取裡面的資料，可以使用 Eric Zimmerman's tools 當中的 PECmd 轉換成 CSV 檔

### Shimcache

位置：

紀錄系統曾「看過/存取」的可執行檔資訊，但**不保證不一定執行**，更新的時間是寫入 Register 的時間，通常是關機/重啟時，

紀錄的是檔案修改時間 Last Modify Time ，

會有一個 Cache Entry ，數字越大代表越早出現，這樣可以知道有哪些程式比惡意程式更早或更晚出現

### BAM/DAM

Windows 10+ 用於管理背景應用程式資源使用機制，紀錄程式最後執行時間與完整路徑

* 快速確認程式最近一次執行時間

### SRUM 

路徑：C:\windows\system32\sru\SRUDB.dat

* 紀錄這隻程式使用了多少**網路流量**

注意資料約每 60 分鐘更新一次，不是即時紀錄

### PSReadLine

路徑：C:\Users\\<Users>\\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine\ConsoleHost_history.txt

Powershell 命令歷史紀錄，檔案為純文字，紀錄使用者之前下過的 powershell 指令



## 工具：

* AutoSpy

* R-studio
    * $MFT viewer

* [NTFS Log Tracker]( https://sites.google.com/site/forensicnote/ntfs-log-tracker)

    NTFS Log Tracker 是一款專門用來解析 NTFS 上 \$LogFile 和 UsnJrnl:\$J 的工具。 它可以從交易日誌與變更日誌中挑出檔案／目錄操作的記錄。

    ![](assets/icAM7IWI3LvNSrDBmhOmy5cGEzp09GpK-dinwOSbtyU=.png)

    填上對應檔案的路徑

    ![](assets/hFcjva1sejXuwvwZjLaD60MFdZe6FS2HDJgTsNGphjE=.png)

    按下右上角的 Parse 之後會先把資料都儲存成一個 DB，這邊幫它取名以及輸出的路徑

    ![](assets/EOWJWa9jI9Oo_YlfKFZjHfHSsssQj7qrHWYUPRjkGao=.png)

    選擇好後就會開始進行分析

    ![](assets/DG2D3gmzJq6Xs7ar_F0kw4LThRBfLuUG7aIE9lyk8oE=.png)

    結束後就會出現 \$LogFile 以及 UsnJrnl:\$J 的內容

    ![](assets/0m_erXlMLOZR4CnCdmW7tevpuuIOkLZCdUxp95dTunY=.png)

    另外也可以把它們匯出成 CSV 檔案

    ![](assets/-QjIqTFArdJExEa85qymNdtSPPa_HZOrYVz2fmOQOWc=.png)

    同樣可以使用 [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) 或者其他查看 CSV 檔案的軟體查看

    ![](assets/g1tx-sJ6dvFR19b2NJ-SlCuIZDWt8F5_Ajg0pKzuXH4=.png)


### [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)

* MFTECmd

  MFTECmd 是由數位鑑識專家 Eric Zimmerman 開發的 Windows command-line 工具，

  用來解析 NTFS 檔案系統中由 \$MFT 與其衍生紀錄，例如：

  * \$MFT
  * \$LogFile
  * \$UsnJrnl
  * \$Boot
  * \$Secure
  * \$Extend\\\$UsnJrnl
  * \$I30

  並將其轉成 CSV 檔案

  首先找到要鑑識的目錄，並提取其 `$I30` 內容

  ![](assets/pWkdQsp10SNyj8hJ5rJ2V_jEM1SYnI-z8-Hak-LF6N0=.png)

  接下來下指令將它轉換成 CSV 檔案

  ![](assets/FPsRisIYrXMyG_LyDIXtF63__b0J8jlG8LpqAm0sPQ0=.png)

  轉換後可以使用 [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) 或者其他查看 CSV 檔案的軟體查看

  ![](assets/XM56jj6p4EatiIDTljlbRIsJ-SHMJj8bBHFqZ69r9RI=.png)

* [SIDR](https://github.com/strozfriedberg/sidr)

    * windows Search Index Database Reporter
    * detect the delete file 
* [shellbagsexplorer](https://ericzimmerman.github.io/#!index.md)

    ShellBags Explorer 是由 Eric Zimmerman 所開發的一款專門用來瀏覽與解析 Windows ShellBags 資料的工具，將 BagMRU / Bags 的註冊表資料解析為資料夾層級樹狀視圖，可以看到使用者曾瀏覽過哪些資料夾

    它的介面跟 RegistryExplorer 差不多，一樣需要匯入 hive，看作業系統版本匯入 `NTUSER.DAT` 或者 `UsrClass.dat`

    ![](assets/MvUItWpVpa5jnJsYBxUDs0mF7EWLYanjudpkwnoJOs8=.png)

    匯入後就可以看到 ShellBags 資訊

    ![](assets/wVsOpk-GTmT9mXzGHEOn72qufR43sE350d2ofw13oh4=.png)
* LECmd
    * to see link file
    `LECmd.exe -d "C:\Users\Administrator\Desktop\Start Here\Artifacts" --csvf lnk.csv --csv "C:\Users\Administrator\Desktop\lnk-files"`
* jumpLists Explorer

* USB Forensics tracker 
* WxTCMD
    * analyze timeline data base to csv file 
    * "C:\Users\ <user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db"
* RegistryExplorer

    ![](assets/U_Af3Nuy6jkoJVOBYMEK0JxMY0oldryrcEpKqJiiFYg=.png)

    另外有時候匯入 Hive 時會出現這樣的警告

    ![](assets/1R6SsxPjf6RH4H9TTieYwGk_l_SPDaEw3IEEwytPx7U=.png)

    此警告表示主 hive 檔案與其 transaction logs (.LOG) 的序號不一致，代表 transaction log 中存在尚未同步到主檔案的變更。

    Windows Registry 採用 write-ahead logging 機制：修改時先寫入記憶體快取，再記錄到 transaction log，最後才定期 flush 到主 hive 檔案。而當 log 檔案的序號大於主檔案時，這個 hive 就會被稱為 **Dirty Hive** 

    按下 Yes 之後就會開始進行與 transaction logs 的合併

    ![](assets/aMqvxrwhRPljyqQ9q7YZGnDq-qwqUj9tamap8pHlCCI=.png)

    選擇 transaction logs

    ![](assets/vV7W6Z8NLSy3_PqzONNNI-lZkXLVGK3gjQLIHimlGyA=.png)

    選擇後它就會幫你合併，合併完後先儲存到一個地方

    ![](assets/zWmyczb4k7Jxotypg0j4NvhrhaU-1uXbQ3tgONIuTxo=.png)

    存完後就可以看這個合併過後的 Hive 

    ![](assets/-Nlg6ItibiOChztpvL-_Bj38i8jwo1N9KOo1v6D0c30=.png)

    Registry Explorer 工具除了可以查看之外它還有預設書籤可以使用，快速定位到想要看的 key 

    ![](assets/ias4TQfhKvlTF0pKOS0CDMBbNHwjRZQ8-186lYojnGA=.png)

* WinPrefetchView

* SrumECmd

* AmcacheParser

  AmcacheParser 是由數位鑑識專家 Eric Zimmerman 所開發的一款命令列工具，專門用於解析 Windows 系統中的 Amcache.hve 註冊檔，支援將解析結果輸出為 CSV 格式，方便後續分析與處理

  ```powershell
  PS C:\Users\yunshiuan\Desktop\net9 > .\AmcacheParser.exe -f C:\Users\yunshiuan\Desktop\Amcache.hve_clean --csv C:\Users\yunshiuan\Desktop
  AmcacheParser version 1.5.2.0
  
  Author: Eric Zimmerman (saericzimmerman@gmail.com)
  https://github.com/EricZimmerman/AmcacheParser
  
  Command line: -f C:\Users\yunshiuan\Desktop\Amcache.hve_clean --csv C:\Users\yunshiuan\Desktop
  
  Warning: Administrator privileges not found!
  
  Unknown value name when processing DevicePnp at path {11517B7C-E79D-4e20-961B-75A811715ADD}\Root\InventoryDevicePnp\display/default_monitor/1&1f0c3c2f&0&uid256: ManifestPath
  
  C:\Users\yunshiuan\Desktop\Amcache.hve_clean is in new format!
  
  Total file entries found: 240
  Total shortcuts found: 51
  Total device containers found: 13
  Total device PnPs found: 94
  Total drive binaries found: 373
  Total driver packages found: 4
  
  Found 123 unassociated file entry
  
  Results saved to: C:\Users\yunshiuan\Desktop
  
  Total parsing time: 0.909 seconds
  ```

  它的輸出會有很多 CSV 檔，可能會出現下面檔案

  | **Amcache\_ProgramEntries.csv**          | 程式條目（Programs Entry）         | 描述註冊在 Amcache “Programs” 分支下的應用程式資訊，如安裝資訊或註冊的程式條目。 |
  | ---------------------------------------- | ---------------------------------- | ------------------------------------------------------------ |
  | **Amcache\_AssociatedFileEntries.csv**   | 關聯的檔案條目                     | 指那些能夠被對應（或關聯）到程式條目的檔案條目（File entries）。即那些被安裝程式所擁有或管理的檔案。 |
  | **Amcache\_UnassociatedFileEntries.csv** | 無關聯的檔案條目                   | 指那些沒有被關聯到任何程式條目的檔案條目，也就是那些孤立的可執行檔 / 檔案。這是很多調查中重點查看的部分，因為可能是惡意工具或獨立執行檔。 |
  | **Amcache\_Shortcuts.csv**               | 快捷方式 / 連結資訊                | 描述系統或應用程式捷徑（.lnk 或類似連結）相關的資訊，例如快捷目標、路徑等。 |
  | **Amcache\_DeviceContainers.csv**        | 裝置容器 (Device Container)        | 與裝置（例如 USB 裝置、硬體裝置）或其容器有關的條目。        |
  | **Amcache\_DevicePnps.csv**              | 裝置 PnP 條目 (Plug-and-Play 裝置) | 描述插拔裝置 (PnP 裝置) 的資訊，例如硬體 ID、裝置名稱、相關時間等。 |
  | **Amcache\_DriveBinaries.csv**           | 驅動程式二進位檔                   | 涉及驅動程式（driver binaries）或在磁碟上可執行但屬驅動程式範疇的條目。 |
  | **Amcache\_DriverPackages.csv**          | 驅動套件 (Driver Packages)         | 關於驅動程式套件安裝、驅動套件版本、封裝資訊等。             |

  接下來就可以用 [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) 或者其他可以查看 CSV 檔的程式查看內容

  ![](assets/mPcDCME75qRv_jdBbz7s7O_MXQtHhoV6h36PvLThoFc=.png)

  假設想要知道 notepad.exe 的實際路徑以及它的 SHA-1 值，按照上面的步驟並在 `<XXX_UnassociatedFileEntries.csv>` 搜尋 notepad.exe

  ![](assets/x-tZ0wFWbbmTkDMDwjC0KcLnXum2pc_9t6A4oT2z3Bg=.png)

  可以馬上就看到相關資訊

* PECmd

  PECmd 是由 Eric Zimmerman 開發的一個命令行工具，它的目的是解析 Windows 的 Prefetch 檔案（.pf），抽取其中的 metadata（如執行時間戳、執行次數、被參照的檔案清單等），以便用於鑑識分析

  有一個很方便的功能是可以使用以下指令批量處理 Prefetch 裡面的所有檔案，並把它們合成一個 CSV 檔

  ```bash
  .\PECmd.exe -d C:\Users\yunshiuan\Desktop\The_Enduring_Echo\C\Windows\prefetch --csv "C:\Users\yunshiuan\Desktop\output"
  ```

  ![](assets/YZQ4eHTHNW2nzsMq1S9CPq9H7CPp6_8kzmD9OzCkXTM=.png)

  如果想要單獨轉換某個 .pf 檔的話可以使用 `-f` 

  接下來就會在 output 中出現轉換好的 CSV 檔

  ![](assets/vN3s7s5Ir8f6bWh_K-OBrUFXzhTtEFEzoj7px-EMmh8=.png)

  可以使用 [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) 或者其他查看 CSV 檔的軟體查看

  ![](assets/IZtn-xPIIX5IwNcA-FIRxiwXk3Aqu-eJfzpZnmt-W-Q=.png)

  假設我想要知道 cmd.exe 執行了幾次，直接按照剛剛的步驟並搜尋 cmd.exe，發現它執行了 26 次

  ![](assets/EWcRoavCJbqZQ7VouNsE-FHXlJrmgvL1A8hxDCCG750=.png)


### Zone Identifier
當從瀏覽器（如 Edge、Chrome、IE）下載檔案時，Windows 會建立一個 NTFS 區段資料（ADS） 來記錄檔案來源，例如：
```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.com
HostUrl=https://example.com/download/file.exe
```
這通常儲存在 Zone.Identifier 流裡。

要查看可以從FTK imager 中點擊下載的檔案看有沒有附加的Zone.Identifier

## 瀏覽器紀錄

Windows 系統中，應用程式的使用者資料通常儲存在 `AppData` 目錄下：

```
C:\Users\<username>\AppData\
├── Local\
├── Roaming\        
└── LocalLow\       
```

* Local : 儲存大容量，臨時或易刪除的資料
* Roaming : 跨裝置同步資料，會跟著使用者帳戶移動到其他電腦
* LocalLow：與 Local 類似，但是應用程式被授予的權限較低



以下介紹一些常用的瀏覽器的資料儲存位置以及可以分析的檔案

### Google Chrome

**位置：** `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default`

```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\
├── History               # 瀏覽歷史和下載記錄
├── Network\Cookies       # Cookie 資料
├── Login Data            # 儲存的密碼
├── Web Data              # 自動填入資料
├── Bookmarks             # 書籤
├── Preferences           # 使用者偏好設定
├── Cache\                # 快取資料
├── Local Storage\        # 本地儲存
├── Session Storage\      # 會話儲存
└── IndexedDB\            # 索引資料庫
```

![](assets/t3wC0oXhNjW5IAY58wESdbEguCnaBPvkbUMzF7wKS0w=.png)

### Microsoft Edge 

**位置：** `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default`

```
C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\
├── History               # 瀏覽歷史和下載記錄
├── Cookies               # Cookie 資料
├── Login Data            # 儲存的密碼
├── Web Data              # 自動填入資料
├── Preferences           # 使用者偏好設定
├── Cache\                # 快取資料
├── Local Storage\        # 本地儲存
├── Session Storage\      # 會話儲存
└── IndexedDB\            # 索引資料庫
```

![](assets/c8YUdhLtLG-xs03GspLLfxg5lXWwJaANvvFQ00ftp9E=.png)

### Mozilla Firefox

**位置：** `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>`

`<profile>` 常常會以xxxx.default-release 表示

```
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\
├── places.sqlite        # 瀏覽歷史、書籤、下載記錄
├── cookies.sqlite       # Cookie 資料
├── logins.json          # 儲存的密碼
├── formhistory.sqlite   # 表單歷史
├── permissions.sqlite   # 網站權限
├── prefs.js            # 使用者偏好設定
├── user.js             # 使用者自訂設定
└── storage\            # 本地儲存
```

![](assets/MH-kVAb81up_baCG59UVWSc7VpFwFHxrAKgKZVGoG5c=.png)

有些檔案會是 SQLite 儲存的，這邊推薦一個 GUI 應用程式可以查看 SQLite 資料庫內的內容：**DB Browser for SQLite**

### DB Browser for SQLite

下載連結：https://sqlitebrowser.org/

DB Browser for SQLite 是一款開源的、跨平台的視覺化 SQLite 資料庫管理工具。它讓使用者不用深入指令列就能開啟、瀏覽、查詢、修改 SQLite 資料庫檔案。它支援標準的 SQLite 檔案（.sqlite, .db, .sqlite3 等），也支援匯入／匯出 CSV、SQL dump 等格式



假設我要查看使用者在 Google Chrome 的瀏覽與下載紀錄

首先先把 `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History` dump 下來

![](assets/9FgyVU4gE0qZHD_cPbKAPnJZwqx-YWgxBiESlAA1ZAI=.png)

然後開啟 DB Browser for SQLite，將剛剛 dump 下來的 history 資料丟進 DB Browser for SQLite 內

![](assets/jev_UQgFrTH7os7vKMbXlqQFHHDiJf7N7AUvGTDCoto=.png)

下面可以看到資料庫內的 Table，如果想要看裡面的資料就點選瀏覽資料的頁面

![](assets/E_xTSK3RQjQUtRC4oW8-bFfy_f8KdXiWu4GJ3viGkWs=.png)

如果是要看瀏覽記錄就選擇 `urls`，如果要看下載紀錄的話就看 `downloads` Table

![](assets/Wy19Ca-3LR-VWh2fqEcZKglEGOWIsqVcTY9cYyQt-8I=.png)

## Acquision
* Dumpit.exe
    * windows memory image
* [LiME](https://github.com/504ensicsLabs/LiME)
    * Linux memory image
* [EDD](https://www.magnetforensics.com/resources/encrypted-disk-detector/)
    * check disk wheather has been encrypted
* KAPE
    * triage image
* CyLR
    * inux triage image

if windwos memory dead Acquision

* hiberfil.sys C:/

* pagefile.sys C:/

---

## Android 

#### ALEAPP

下載連結：

ALEAPP : [ https://github.com/abrignoni/ALEAPP](https://github.com/abrignoni/ALEAPP)

是由 Alexis Brignoni 開發的一個開源工具，用來做 Android 裝置的 證據檔案分析（forensic artifacts parsing）。其目的在於整理 Android 裝置中常見的 log、事件、Protobuf（如 Google Play Services 或其他使用 Protobuf 的 apps）等資料，協助數位鑑識與 incident response 調查人員快速取出與分析有用資料。

***

今天的Android 的 dumpfiles 會以今年初剛結束的 MVS CTF 2025 中的Android 分類來分享

下載連結 ： https://drive.google.com/file/d/1Ay-T4kE8J3NX-XLh0krarFvE9j8SK_LT/view

這個連結下載會給一個Android 手機的 data 資料夾內容，並且是壓縮過後的。

這邊可以分享一下在Android 11 後，沒有 root 的權限是沒有辦法去存取到 data 資料夾的，因此會需要一些第三方的工具才可以把它 dump 下來。

我的猜測，這個 dump 的製作是使用一個[Magisk](https://github.com/topjohnwu/Magisk) 工具安裝到裝置上，這個工具可以讓你獲得到 root 權限並無需修改系統分區，[參考連結](https://izaka.tw/magisk-tutorial-and-installation-guide/)



ALEAPP 只支援 tar/zip/gz 檔案，因此我是先從連結上下載後解壓再重新壓縮成 zip 一次

得到檔案之後就可以丟給 ALEAPP，上面是填題目給的檔案，下面是選它產生的分析結果要輸出到哪裡的資料夾

下面的 Module 可以全選

![](assets/mDASlDFj6hHZvVJoPZZZ210DAqwMwVXbJ-mrViOr-w4=.png)

接下來按左下角的 Process 它就會開始做分析，分析完之後它會在你跟剛剛填的路徑下新增一個資料夾

![](assets/lDtakJToWuHInXS9qc6ldb-xieSy0NSlWyeQBwburCs=.png)

這些就是它將分析的結果轉成 HTML，類似生成一個報告，主要的頁面會在 `index.html`，點開之後會進入到這個頁面

![](assets/IvCPZq8bj5obL1jWJ0mLYUYg_gNCe6EhCRZm-CpzJGE=.png)

之後就可以開始去翻有沒有什麼可疑的東西

其中的功能很多，這邊介紹其中一部分的內容

### Home page 

首頁就會顯示一些手機的名稱、SIM卡資訊等等

![](assets/Z2AoWqFIXBkawKwp5jiAnGuJy122aa8Tyd-SZjcOsOc=.png)



## APP

### APP Icons

這邊可以查看使用者在裝置上安裝了什麼app

![](assets/5hibQen43Jn1ThRdY0x2r67KBkQ_yTAxbqaeRzwTUNA=.png)

### Packages

它會解析 `packages.xml`，記錄了裝置上安裝過的所有套件（應用程式），包含：

•	系統應用（隨 ROM 出廠）

•	OEM 廠商附加應用

•	使用者自行安裝的應用（例如從 Google Play Store、adb sideload 等）

![](assets/lE9NediFoYvRMhSRjJrXjxl-wX8-nBMapXtwwlAYmJM=.png)



### Bluetooth 

#### Bluetooth Adapter Information 

這邊可以看到藍牙的一些設定

![](assets/Jl_I6EruZUlSFYviq3RPTFNfNMnoUY4vPQckU9-sKpc=.png)

#### Bluetooth Connections

這邊可以看藍牙裝置連線紀錄

![](assets/tTj3bI9f-yMf1GKbRGqfxsjClNGrxo9di4EThFU7qTw=.png)

---

## IOS

### ILEAPP

下載連結： https://github.com/abrignoni/iLEAPP

iLEAPP 是 Alexis Brignoni 開發的開源工具，用來解析 iOS 裝置（與備份）中的日誌、事件與 plist 等常見鑑識 artefacts，協助快速整理出可供鑑識與調查的資訊。此工具可以快速 triage iOS 欄位：例如系統與應用 logs、通知（notifications）、build / 設備資訊、行動網路資料、應用狀態資料庫（ApplicationState.db）等，將原始檔案轉成可讀的表格/HTML 報告或 timeline，便於調查人員閱讀與分析

***

今天的IOS 的 dumpfiles 檔會以今年初剛結束的 MVS CTF 2025 檔中的 IOS 分類來分享

檔案下載網址：https://drive.google.com/drive/folders/1yaMc--Va2u2IJzQKci4yBaeftjDGRDya

網址下載下來後應該會是iOS 系統的Applications、private、System 資料夾的壓縮檔



將下載的檔案丟給iLEAPP，上面是填題目給的檔案，下面是選他產生的分析結果要輸出到哪裡的資料夾

下面的Module可以全選

![](assets/pN_MLRInXD93sGXMtwoxxnvG6LiVZAyfxuDtWOxSxF4=.png)

接下來按左下角的 Process 程式就會開始分析

結束之後會產生分析的結果並產生html，

![](assets/OzFeLiwH1qYq5CZbvm7R8tR14Pxz_wcfw2JjuQ82SY0=.png)

報告的主頁會產生在\_HTML 底下的 `index.html` 打開之後會出現這樣的頁面

![](assets/9oHLDoZAR8rpHPWI5a65Wj2LDRsWts9dnS1ABtfelbM=.png)

之後就可以在左側的功能列翻想要尋找的東西。

這邊介紹幾個我覺得比較特別的分析結果



## Home Page 

在首頁的Device details 中有顯示裝置基本資訊（型號、序號、iOS 版本）

![](assets/fXGB2uwjc5BZY9TvJLQPPKzqzsdhCceqbkQM1yNVhBw=.png)



### Keyboard Usage Stats

這邊會顯示

* `tium.totalWordsTyped` → 使用者總共輸入的字數
* `tium.totalWordsFromCandidateBar` → 從鍵盤候選列選字的次數
* `tium.totalWordsAutocorrected` → 自動更正的字數

![](assets/nMTSMholF589UNss0wwNX1RI3f9GH22jovCeBZGWRZ0=.png)

## Itunes Metadata

&#x20;Itunes Metadata 這邊會列出一些裝置上安裝的APP 

![](assets/mT5LK33BqV_BBiDqV8WyiXbqmUKXcCQe4lEyVllEug4=.png)

---

## Email Security

一個 Email 帳號的組成，會由一個小老鼠`@` 將左右隔開

* 左半部分是依照使用者設定的字串，因此可以取名為`aaaabbbccc123` 、 `admin` 、`me` 皆可
* 右半部分是組織的 Domain Name，像是常見的 `gmail.com`；如果自己有架設 Email Server，就會是自己的 domain，如：`yunshiuan.com` 

![](assets/RrromGCNVsSXy7dWVTw1aLyjocOQzZtGr4ggahqd7Fs=.png)

`source: https://flickr.com/photos/jameschen1/24160994516/`

到這邊就會有一個偽造正常信件的方式：如果攻擊者註冊了一個與正常組織幾乎相同、只差一個字的 domain，甚至直接冒用正常組織的 Domain Name 來欺騙使用者，只要使用者一個不注意就可能把它當成正常信件而被釣到，這個攻擊被稱為 **Email Spoofing**

### Email Spoofing

攻擊者會試圖使用與常見組織相似或相同的 email 欺騙使用者認為是正常郵件。

ex : 可以透過 [這個網頁](https://emkei.cz/)  偽造 Email 傳給使用者，這邊將 Email 偽造成`support@paypal.com` 並傳一封帳號異常的信給使用者

![](assets/PiPU_SyMgnQoKCb7bRDCvsyttMnbLm9Dt8RXKp7TKBk=.png)

那這樣只單看 Email 是很難分辨是否為釣魚信件，所以會透過郵件驗證協定 **DMARC** 來偵測郵件偽造攻擊。

### DMARC 

DMARC 是一種郵件驗證協定，它讓郵件網域擁有者能聲明當收到未通過驗證的郵件時該如何處理。

我在 demo 時寄到我個人的信箱，使用 Cloudflare 的 Email Routing 功能轉發郵件；因此當我把釣魚信寄到自己的信箱時，因未通過 DMARC 驗證而被拒收。

![](assets/aeeOF3FAMAlT_FXaTinD9zx6HRYzvPoellic9cvMBvM=.png)

如果DMARC 驗證通過的話會像下方圖示的一樣。

![](assets/cOeVnUSdeBGztRM6cfg0XEqzFCD75DgvYr24PX0TF7g=.png)

可以看到主要的驗證方式會使用到 SPF 以及 DKIM。

### SPF

SPF 是一種電子郵件驗證協定，它讓網域擁有者能夠指定哪些郵件伺服器有權代表該網域寄送郵件。這份「授權清單」會以 DNS TXT 記錄 的形式公開發布，接收方的郵件伺服器則可在收信時檢查寄件伺服器是否被授權，以判斷郵件是否可信。


可以使用 `dig` 指令查看 SPF

```BASH
$ dig yunshiuan.com  TXT | grep spf
yunshiuan.com.		377	IN	TXT	"v=spf1 include:_spf.mx.cloudflare.net ~all"
```

* v=spf1：指定 SPF 協定版本
* include:\_spf.mx.cloudflare.net：授權清單由 Cloudflare 維護
* ~all：非授權來源標記為 SoftFail（可疑）
  （若設定 -all 則代表 Fail，非授權來源應被拒絕）

### DKIM 

DKIM 是電子郵件驗證機制之一，讓收件方可以驗證一封郵件是否真正由該網域授權寄出，並確認郵件在傳送過程中是否被篡改；它透過數位簽章機制實現。寄件方使用私鑰對郵件內容進行簽名，收件方則從 DNS 查出對應的公鑰來驗證。

DKIM 的公鑰會被發布在 DNS TXT 紀錄中，格式如下：

```
<selector>._domainkey.<domain>
```

以 Cloudflare 舉例，它的 selector 是 `cf2024-1`，查詢 DKIM 也可使用 `dig` 指令

```bash
$ dig cf2024-1._domainkey.yunshiuan.com TXT | grep DKIM
cf2024-1._domainkey.yunshiuan.com. 377 IN TXT	"v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiweykoi+o48IOGuP7GR3X0MOExCUDY/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hEQVsgVRQP4DcnQDVjGMbASQtrY4WmB1VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq35yIo4sdlmtZGV+i0H4cpYH9+3JJ78k" "m4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dkNDVAS3gioCvELryh1TxKGiVTkg4wqHTyHfWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58bTixDSJwIDAQAB"
```

總結來說 DMARC 驗證流程會是：接收方收到郵件後，先檢查 SPF 和 DKIM 認證，再根據 DMARC 政策決定郵件的處理方式（放行、隔離或拒絕）。

DMARC 記錄可以在 `_dmarc.<domain>` 找到

```bash
$ dig _dmarc.any.run TXT                                                                             


; <<>> DiG 9.10.6 <<>> _dmarc.any.run TXT
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31385
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;_dmarc.any.run.			IN	TXT

;; ANSWER SECTION:
_dmarc.any.run.		377	IN	TXT	"v=DMARC1; p=quarantine; sp=quarantine;"

;; Query time: 226 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Oct 09 20:09:24 CST 2025
;; MSG SIZE  rcvd: 94
```

* v=DMARC1 : DMARC 版本
* p=quarantine : 主要政策，對主域名認證失敗的郵件進行隔離
* sp=quarantine : 子域名政策，對子域名認證失敗的郵件也進行隔離

### Gophish

下載連結：https://github.com/gophish/gophish/releases

Gophish 是一個開源的釣魚模擬平台，用於進行社交工程演練，可以快速建立和發送釣魚郵件，追蹤點擊率和提交率，幫助組織測試員工的資安意識並提供教育訓練。

`source : https://ui-code.com/archives/779`

安裝很簡單，將 ZIP 下載之後執行裡面的執行檔就能架起

![](assets/9yIIcEGIjBtwp2TUs8hEn1hT_Il_Buo1FbIYSVM9nP0=.png)

如果要遠端也可以登入admin 介面，要去config.json 將admin 網址改成`0.0.0.0:3333`

若要遠端也能登入 Admin 介面，請在 config.json 將 Admin 位址改成 `0.0.0.0:3333`

架起來後會給你帳號密碼，網頁進入`0.0.0.0:3333`後登入就可以開始使用了

![](assets/gI4Up0C79FNgdPy_IY4j4hZSu3scYdFss05qVW5NJb8=.png)


裡面的功能非常豐富，包括

* **活動管理**: 建立/排程釣魚活動，指定目標群組、郵件模板、登入頁與寄件設定，並即時監控結果。
* **目標群組**: 管理收件人清單，支援手動新增與 CSV 匯入。
* **郵件模板**: 視覺化編輯與變數插入（如 &#123;&#123;.FirstName&#125;&#125;），可預覽與測試寄送。
* **登入頁**: 匯入/客製 HTML，選擇是否擷取提交資料，支援點擊後/提交後導向。
* **寄件設定**: 設定 SMTP（主機、帳密、TLS/SSL、自訂寄件者/標頭），支援測試連線。
* **即時追蹤**: 記錄寄送、開啟、點擊、提交資料（含 IP、User-Agent）；可選「回報」事件。
* **儀表板與報表**: 活動概況、成效趨勢，結果支援 CSV 匯出。
* **REST API**: 提供完整 API 以自動化建立活動、上傳模板/名單、擷取結果。
* **網域與證書**: 自訂追蹤/寄送網域與 TLS 憑證配置，提升可信度與達投遞率。


![](assets/2xWCIDOeOd16WAYIllSS5iysk0uLCS1ibgVpO_vFsy4=.png)

`source : https://ui-code.com/archives/779`

---

## OSINT

### WaybackMachine 

網站連結：http://web.archive.org/

這個網站是由 Internet Archive 維護的一個線上服務。它可以定期將網站的網頁內容 snapshot 存檔，讓人們能夠查看某個網站在過去不同時間點的樣子



例如我想要看一下 https://yunshiuan.com/ 網站之前的樣子，就可以將網址輸入進去後看看。

![](assets/1XCkWh3EsZrt_VK1tm_gQRoafiqcVr9vfBjomnlVdBQ=.png)



發現它在 8/15 有被打了一個 snapshot，點進去看看後就可以看到在 8/15 這個網頁時的樣子

![](assets/DgnhK5fhsurE8l2P3XwB4UKENppv9MiZ4XfVIDMUv1o=.png)

### Recon-ng 

下載方式

```
apt-get update && apt-get install recon-ng
```

Recon-ng 是一個用 Python 寫成、以模組化、指令列互動介面為設計的 OSINT 收集框架。它把各類資訊收集功能（DNS、WHOIS、搜尋引擎、API 查詢等）包成「模組」，用戶可以在工作區（workspace）中逐步執行、存檔與匯出調查結果



Recon-ng  的 tutorial 連結： https://hackertarget.com/recon-ng-tutorial/ 

整體的操作會類似於 Metasploit，一樣會先引入模組，設定參數然後執行

直接執行 `recon-ng` 後可以使用 `marketplace search` 查看有什麼可以用的 modules

```
$ [recon-ng][default] > marketplace search

  +--------------------------------------------------------------------------------------------------+
  |                        Path                       | Version |     Status    |  Updated   | D | K |
  +--------------------------------------------------------------------------------------------------+
  | discovery/info_disclosure/cache_snoop             | 1.1     | not installed | 2020-10-13 |   |   |
  | discovery/info_disclosure/interesting_files       | 1.2     | not installed | 2021-10-04 |   |   |
  | exploitation/injection/command_injector           | 1.0     | not installed | 2019-06-24 |   |   |
  | exploitation/injection/xpath_bruter               | 1.2     | not installed | 2019-10-08 |   |   |
  | import/csv_file                                   | 1.1     | not installed | 2019-08-09 |   |   |
  | import/list                                       | 1.1     | not installed | 2019-06-24 |   |   |
  | import/masscan                                    | 1.0     | not installed | 2020-04-07 |   |   |
  | import/nmap                                       | 1.1     | not installed | 2020-10-06 |   |   |
  | recon/companies-contacts/bing_linkedin_cache      | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/companies-contacts/censys_email_address     | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/companies-contacts/pen                      | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/companies-domains/censys_subdomains         | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/companies-domains/pen                       | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/companies-domains/viewdns_reverse_whois     | 1.1     | not installed | 2021-08-24 |   |   |
  | recon/companies-domains/whoxy_dns                 | 1.1     | not installed | 2020-06-17 |   | * |
  | recon/companies-multi/censys_org                  | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/companies-multi/censys_tls_subjects         | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/companies-multi/github_miner                | 1.1     | not installed | 2020-05-15 |   | * |
  | recon/companies-multi/shodan_org                  | 1.1     | not installed | 2020-07-01 | * | * |
  | recon/companies-multi/whois_miner                 | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/contacts-contacts/abc                       | 1.0     | not installed | 2019-10-11 | * |   |
  | recon/contacts-contacts/mailtester                | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/contacts-contacts/mangle                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/contacts-contacts/unmangle                  | 1.1     | not installed | 2019-10-27 |   |   |
  | recon/contacts-credentials/hibp_breach            | 1.2     | not installed | 2019-09-10 |   | * |
  | recon/contacts-credentials/hibp_paste             | 1.1     | not installed | 2019-09-10 |   | * |
  | recon/contacts-domains/censys_email_to_domains    | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/contacts-domains/migrate_contacts           | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/contacts-profiles/fullcontact               | 1.1     | not installed | 2019-07-24 |   | * |
  | recon/credentials-credentials/adobe               | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/credentials-credentials/bozocrack           | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/credentials-credentials/hashes_org          | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-companies/censys_companies          | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/domains-companies/pen                       | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/domains-companies/whoxy_whois               | 1.1     | not installed | 2020-06-24 |   | * |
  | recon/domains-contacts/hunter_io                  | 1.3     | not installed | 2020-04-14 |   | * |
  | recon/domains-contacts/metacrawler                | 1.1     | not installed | 2019-06-24 | * |   |
  | recon/domains-contacts/pen                        | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/domains-contacts/pgp_search                 | 1.4     | not installed | 2019-10-16 |   |   |
  | recon/domains-contacts/whois_pocs                 | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-contacts/wikileaker                 | 1.0     | not installed | 2020-04-08 |   |   |
  | recon/domains-domains/brute_suffix                | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/domains-hosts/binaryedge                    | 1.2     | not installed | 2020-06-18 |   | * |
  | recon/domains-hosts/bing_domain_api               | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-hosts/bing_domain_web               | 1.1     | not installed | 2019-07-04 |   |   |
  | recon/domains-hosts/brute_hosts                   | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/builtwith                     | 1.1     | not installed | 2021-08-24 |   | * |
  | recon/domains-hosts/censys_domain                 | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/domains-hosts/certificate_transparency      | 1.3     | not installed | 2019-09-16 |   |   |
  | recon/domains-hosts/google_site_web               | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/hackertarget                  | 1.1     | installed     | 2020-05-17 |   |   |
  | recon/domains-hosts/mx_spf_ip                     | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/netcraft                      | 1.1     | not installed | 2020-02-05 |   |   |
  | recon/domains-hosts/shodan_hostname               | 1.1     | not installed | 2020-07-01 | * | * |
  | recon/domains-hosts/spyse_subdomains              | 1.1     | not installed | 2021-08-24 |   | * |
  | recon/domains-hosts/ssl_san                       | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/threatcrowd                   | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/threatminer                   | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-vulnerabilities/ghdb                | 1.1     | not installed | 2019-06-26 |   |   |
  | recon/domains-vulnerabilities/xssed               | 1.1     | not installed | 2020-10-18 |   |   |
  | recon/hosts-domains/migrate_hosts                 | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/hosts-hosts/bing_ip                         | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/hosts-hosts/censys_hostname                 | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/hosts-hosts/censys_ip                       | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/hosts-hosts/censys_query                    | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/hosts-hosts/ipinfodb                        | 1.2     | not installed | 2021-08-24 |   | * |
  | recon/hosts-hosts/ipstack                         | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/hosts-hosts/resolve                         | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/hosts-hosts/reverse_resolve                 | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/hosts-hosts/ssltools                        | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/hosts-hosts/virustotal                      | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/hosts-locations/migrate_hosts               | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/hosts-ports/binaryedge                      | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/hosts-ports/shodan_ip                       | 1.2     | not installed | 2020-07-01 | * | * |
  | recon/locations-locations/geocode                 | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/locations-locations/reverse_geocode         | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/locations-pushpins/flickr                   | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/locations-pushpins/shodan                   | 1.1     | not installed | 2020-07-07 | * | * |
  | recon/locations-pushpins/twitter                  | 1.1     | not installed | 2019-10-17 |   | * |
  | recon/locations-pushpins/youtube                  | 1.2     | not installed | 2020-09-02 |   | * |
  | recon/netblocks-companies/censys_netblock_company | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/netblocks-companies/whois_orgs              | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/netblocks-hosts/censys_netblock             | 2.1     | not installed | 2022-01-31 | * | * |
  | recon/netblocks-hosts/reverse_resolve             | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/netblocks-hosts/shodan_net                  | 1.2     | not installed | 2020-07-21 | * | * |
  | recon/netblocks-hosts/virustotal                  | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/netblocks-ports/census_2012                 | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/netblocks-ports/censysio                    | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/ports-hosts/migrate_ports                   | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/ports-hosts/ssl_scan                        | 1.1     | not installed | 2021-08-24 |   |   |
  | recon/profiles-contacts/bing_linkedin_contacts    | 1.2     | not installed | 2021-08-24 |   | * |
  | recon/profiles-contacts/dev_diver                 | 1.1     | not installed | 2020-05-15 |   |   |
  | recon/profiles-contacts/github_users              | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/profiles-profiles/namechk                   | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/profiles-profiles/profiler                  | 1.2     | not installed | 2023-12-30 |   |   |
  | recon/profiles-profiles/twitter_mentioned         | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/profiles-profiles/twitter_mentions          | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/profiles-repositories/github_repos          | 1.1     | not installed | 2020-05-15 |   | * |
  | recon/repositories-profiles/github_commits        | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/repositories-vulnerabilities/gists_search   | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/repositories-vulnerabilities/github_dorks   | 1.0     | not installed | 2019-06-24 |   | * |
  | reporting/csv                                     | 1.0     | not installed | 2019-06-24 |   |   |
  | reporting/html                                    | 1.0     | not installed | 2019-06-24 |   |   |
  | reporting/json                                    | 1.0     | not installed | 2019-06-24 |   |   |
  | reporting/list                                    | 1.0     | not installed | 2019-06-24 |   |   |
  | reporting/proxifier                               | 1.0     | not installed | 2019-06-24 |   |   |
  | reporting/pushpin                                 | 1.0     | not installed | 2019-06-24 |   | * |
  | reporting/xlsx                                    | 1.0     | not installed | 2019-06-24 |   |   |
  | reporting/xml                                     | 1.1     | not installed | 2019-06-24 |   |   |
  +--------------------------------------------------------------------------------------------------+
```

接下來示範用 `hackertarget` 去尋找 hostname

首先先把 `hackertarget` 先下載下來

```
marketplace install hackertarget
```

再把它 load 進來

```
modules load hackertarget
```

接下來用 info 看一下會需要什麼參數

```
$ [recon-ng][default][hackertarget] > info

      Name: HackerTarget Lookup
    Author: Michael Henriksen (@michenriksen)
   Version: 1.1

Description:
  Uses the HackerTarget.com API to find host names. Updates the 'hosts' table with the results.

Options:
  Name    Current Value  Required  Description
  ------  -------------  --------  -----------
  SOURCE                 yes       source of input (see 'info' for details)

Source Options:
  default        SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
  <string>       string representing a single input
  <path>         path to a file containing a list of inputs
  query <sql>    database query returning one column of inputs
```

接下來可以看到 SOURCE 會需要填東西，那這欄就是要填要偵查的 domain，以 `google.com` 舉例。

用下面指令設定 SOURCE

```
options set SOURCE google.com
```

再看一次 info，可以看到它被設定成了 `google.com` 

```
$ [recon-ng][default][hackertarget] > info

      Name: HackerTarget Lookup
    Author: Michael Henriksen (@michenriksen)
   Version: 1.1

Description:
  Uses the HackerTarget.com API to find host names. Updates the 'hosts' table with the results.

Options:
  Name    Current Value  Required  Description
  ------  -------------  --------  -----------
  SOURCE  google.com     yes       source of input (see 'info' for details)

Source Options:
  default        SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
  <string>       string representing a single input
  <path>         path to a file containing a list of inputs
  query <sql>    database query returning one column of inputs
```

接下來打 run 就會開始執行

執行的過程中也會出現結果，最後在下 `show hosts` 指令就會出現表格樣式的結果

![](assets/svj4PUeEf1nUKpRCQjze7nr5oPS1zt2QQ496e2hZ8sw=.png)

### Whois.domaintools

網站連結：https://whois.domaintools.com/

這個網站可以找到關於 domain 的一些資訊，包括註冊商、何時註冊、何時到期與最後更新時間等等

![](assets/TBoAsZNRu4upfnloA9-lYEkUGjBbWF1mTuprg7Q2T_4=.png)

### Sherlock

下載連結：https://github.com/sherlock-project/sherlock

這是一個可以快速搜尋各大平台用戶名的工具

假設今天我們獲得到了一個用戶叫做`yunshiuan` 接下來丟進sherlock

![](assets/Rf9_ZONhV5xhlOF3CzJfPYdew6Xk7vKZLSNlSOWvBJc=.png)

發現了跑出許多用戶名稱是yunshiuan 的平台，接下來就可以一一去看是不是自己想要的

### HaveIBeenPwned

連結：https://haveibeenpwned.com/

這是一個可以輸入信箱，他會說輸入的信箱是否已經被洩漏出去了

假設輸入一個大家在測試時很常輸入的`aaaaa@gmail.com`

![](assets/YRv_jjfeqpWoNVRieLp2g4zT9Gl5_wRnteRh9wW8GYE=.png)

可以看到這個 email 在 20 多個平台被洩漏了，底下會跟你說是在何時因為什麼而被洩漏

![](assets/bfiSjA3fimrdDE8iTnRwjRZ3OuPwZ0oK4S-_tCSbWiU=.png)

### Epieos

網站連結：https://epieos.com/

他提供了email與手機號碼的反向查詢，幫你把和該email / phone 有關的社群帳號、Google 活動、評價、公開痕跡等串起來顯示，方便做初步調查或驗證線索

![](assets/9PHebz4gf0c55xyN-fS-TDK_HvYakSfp-GV0gIzMo_c=.png)

底下其實還有其他網站或者應用程式的掃描，但那些就會需要付費才能觀看

### Phoneinfoga

下載連結：https://github.com/sundowndev/phoneinfoga

這個工具可以查詢這個電話號碼的基本metadata

```
$ ./phoneinfoga scan -n +886911111111
```

![](assets/d6GCUzEdKWX2Yyr2GDw1FAU4ikSOyZx1De-DMHItZZc=.png)

另外也可以用開server 的方式用網頁查詢

```
$ ./phoneinfoga serve -p 8080

Listening on :8080
```

![](assets/PxCHUVESvr-Z_zTZpqgN7nlQQxibied7gFqCAL27Y40=.png)

### Google Hacking 

這是 Google 提供的進階搜尋法，它提供一些方式可以更準確地找到我們想要的資料或網站。

以下是常見的搜尋

•	`site:domain.com` — 限定在某個網域搜尋，ex:`site:github.com`。

•	`filetype:pdf / filetype:env / filetype:sql` — 找特定檔案類型。

•	`inurl:admin / inurl:login` — URL 中含特定字串（找管理頁面）。

•	`intitle:"index of"` — 找目錄列舉頁面（常暴露檔案列表）。

•	`"exact phrase"` — 精確比對字串（例如機密檔名或參數名）。

•	-（負號）排除字詞，ex: `site:example.com` `-site:blog.example.com`。

另外也可以用 `OR`、`+` 來串接多個進階搜尋結果

![](assets/DxLpxVnMZEKL_lROU9xsoRvZnZu_3iecohb79vO3gzU=.png)

### Google Map / Google Earth

Google 地圖是 Google 提供的網路地圖服務，這個服務提供了多種視圖模式，包括衛星圖、街道圖和地形圖，讓用戶可以根據需求選擇最適合的視角來查看地圖

![](assets/AM7XkPseqHtJ64J0lHNKzlYK_NjHdww-qvZ-EDJlbQY=.png)

Google Earth 是一個更進階的 3D 地球瀏覽器，讓用戶能夠以立體的方式探索世界。歷史影像功能讓用戶可以查看不同時期的衛星影像，觀察城市的發展變化，而街景整合功能則在 3D 環境中嵌入了街景視圖，並且可以匯入 KML 檔

![](assets/Nqm0R92EVsQ60NoKlkI9vqtx9kdYYYIJFoBYZhEUTA0=.png)

### Google 智慧鏡頭

Google 智慧鏡頭是一個基於 AI 的視覺搜尋工具，你可以把你想要辨識的圖片丟進去，它會把網路上類似的圖片丟給你

在搜尋列就可以找到智慧鏡頭的 icon

![](assets/jZWhq_f9A2B3eBaFBL80Oolkc6_952uiK4kCQq7InJ0=.png)

點擊後把圖片丟進去它就會幫你查有沒有類似的圖片

![](assets/kKnQobr1ng3IbFvcC_9I5sWMSVUr-T2nkvQ_24bhC3M=.png)

### Geohints

網站連結：https://geohints.com/

這個網站整理了很多每個國家的 Google 街景具有特色的部分，像是車牌、道路、電線竿、標誌等照片，如果遇到沒看過的都可以來這邊查

![](assets/hvedPNXTINc-yVUpWuTxXMSQBGihsp3dkifiHQYigmk=.png)

### Overpass turbo 

網址：https://overpass-turbo.eu/

Overpass Turbo 是一個基於網頁的查詢工具，專門用於查詢 OpenStreetMap 資料庫。它提供了一個直觀的介面，讓用戶能夠使用 Overpass QL 查詢語言來搜尋和提取 OSM 中的地理資料。

而 [OpenStreetMap](https://www.openstreetmap.org/#map=12/56.4984/16.6010) 是世界上最大的開放地理資料庫，包含了全球各地的道路、建築物、興趣點等詳細資訊。

![](assets/OCrdN1c5cGeTKK0BCCkvA-6cWK104_wpnCDz_fT2D5s=.png)

接下來介紹一下要怎麼使用Overpass QL 查詢我們想要的東西。



首先是 OSM 的資料結構，它使用節點 (nodes)、路徑 (ways) 和關係 (relations) 三種基本元素來描述地理物件：

* **節點 (Nodes)**：代表點狀物件，如商店或地標
* **路徑 (Ways)**：代表線狀或面狀物件，如道路或建築物
* **關係 (Relations)**：用於描述複雜的物件，如多個部分組成的建築物群

最基本的查詢以 `[out:json];` 開始，這指定了輸出格式。接著使用 `node`、`way` 或 `relation` 來指定要查詢的物件類型，而`nwr`則可以將三者都包含，然後在方括號中指定搜尋條件，關於搜尋條件的所有的key 跟value 都可以在這邊查到 https://wiki.openstreetmap.org/wiki/Map\_features 。

像圖示中是L3akCTF 2025的其中一題[Fidget Spinner](https://medium.com/@shibaosint/l3akctf-2025-fidget-spinner-writeup-cd94eafc2828)我們想要找在厄蘭島上所有的風車地點，可以這樣寫

```
[out:json][timeout:25];
//restrict our search to the island
area[name="Öland"];
(
  // search for windmills
  nwr["man_made"="windmill"](area); //(area)的功能是限制在Öland地點上查詢
);
// print results
out geom;
```

之後出來的結果就會是這樣

![](assets/hLt5ujf8M4p8aGhdbo4CVsi7_xOwj5CBfN3zKMmBMMo=.png)

接下來它也可以匯出成 KML 檔，然後放到 Google Map / Google Earth 上

![](assets/BoYcPTrtyYVX4YFzs6DzQ9bPESm3RDAuLS-dqbSBsUk=.png)

接下來就可以去一一驗證是否是題目想要的位置

另外也可以像這樣把想要的區域先匡起來然後查詢

![](assets/TEiO_tKmOGHWcEVH1ynu8k2Lze8ViVkW0SaFlpMOXQI=.png)

`source : https://medium.com/@PretendNotToBe/ea6e8f3fb763`

### [Exiftool](https://exiftool.org/)

它可以去看圖片的基本資料，例如圖片大小、修改時間等等，但它可以去看這張照片的拍攝地點在哪裡，並且會給你 GPS 定位。



舉個例子：[DownUnderCTF 2023 Excellent Vista!](https://drive.google.com/file/d/17rE9LAp7TNk8u09EwguZB3RQ4H3WNIMB/view)

下載之後用 exiftool 看一下

```
$ exiftool ExcellentVista.jpg

ExifTool Version Number         : 13.10
File Name                       : ExcellentVista.jpg
Directory                       : .
File Size                       : 2.7 MB
File Modification Date/Time     : 2025:09:23 15:41:41+08:00
File Access Date/Time           : 2025:09:23 15:41:45+08:00
File Inode Change Date/Time     : 2025:09:23 15:41:44+08:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Date/Time Original              : 2023:08:31 22:58:56
Create Date                     : 2023:08:31 22:58:56
Sub Sec Time Original           : 00
Sub Sec Time Digitized          : 00
GPS Version ID                  : 2.3.0.0
GPS Latitude Ref                : South
GPS Longitude Ref               : East
GPS Altitude Ref                : Above Sea Level
GPS Speed Ref                   : km/h
GPS Speed                       : 0
GPS Img Direction Ref           : True North
GPS Img Direction               : 122.5013812
GPS Dest Bearing Ref            : True North
GPS Dest Bearing                : 122.5013812
GPS Horizontal Positioning Error: 6.055886243 m
Padding                         : (Binary data 2060 bytes, use -b option to extract)
About                           : uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b
Image Width                     : 4032
Image Height                    : 3024
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 4032x3024
Megapixels                      : 12.2
Create Date                     : 2023:08:31 22:58:56.00
Date/Time Original              : 2023:08:31 22:58:56.00
GPS Altitude                    : 70.5 m Above Sea Level
GPS Latitude                    : 29 deg 30' 34.33" S
GPS Longitude                   : 153 deg 21' 34.46" E
GPS Position                    : 29 deg 30' 34.33" S, 153 deg 21' 34.46" E
```

最後它提供了拍照的地點。

### What3words

網站連結：https://what3words.com/

這個網站可以只利用三個相關的詞彙去定位到想要的地點，因為有些地方會沒有地址，所以會需要靠這個方式定位

像是成功大學資訊系館是 `imported.dull.buns`，之後去這個網站查就一樣會定位到這邊

![](assets/tVfxyDKTRPL6hxH59oD19ORtuhNS5r4Y-V8fsrTCtn8=.png)
