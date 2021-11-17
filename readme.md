
## 資訊安全技術概論
- 1.網路與通訊安全
  - 1-1.網路安全
    - 網路基本知識 ==> OSI vs TCP/IP vs IEEE 802
    - 網路攻擊模式分析
      - 網路協定的攻擊模式分析
        - DNS 的攻擊模式分析
          - [DNS 快取記憶體DNS Poisoning (DNS Spoofing)](https://www.cloudflare.com/zh-tw/learning/dns/dns-cache-poisoning/)
          - [DNS Amplification Attack](https://www.cc.ntu.edu.tw/chinese/epaper/0028/20140320_2808.html) 
        - NTP 的攻擊模式分析
          - [NTP 放大DDoS 攻擊](https://www.cloudflare.com/zh-tw/learning/ddos/ntp-amplification-ddos-attack/)
          - 有關XXXX攻擊的敘述,下列何者正確/錯誤? 
      - 著名的網路攻擊模式分析
        - DDOS
          - 2000年初的DDOS: ping of death, TCP syn flood, smurf attack (icmp flood attack) 
          - HTTP DDOS
        - 社交工程
          - 網路釣魚 (phishing）   
          - 魚叉式網路釣魚（Spear phishing）
          - 變臉詐騙/BEC(Business Email Compromise) 商務電子郵件詐騙
    - 安全的網路技術與協定
      - 應用層
        - https ==> SSL/TLS
        - sftp ftps
        - telnet ==> ssh
        - DNSsec
        - email 安全
      - 網路層
        - IPsec
      - 安全連線
        - ssh
        - VPN     


  - 1-2.通訊安全
    - 無線區域網路(WLAN)
      - [ap(access point)](https://zh.wikipedia.org/wiki/%E7%84%A1%E7%B7%9A%E6%8E%A5%E5%85%A5%E9%BB%9E) 
      - ad hoc mode(Ad-Hoc模式、無線隨意網路) vs infrastrcuture mode(基礎架構模式) 
      - 服務集識別碼(Service Set Identifier，SSID)
      - 獨立基本服務集（IBSS）、基本服務集（BSS）和擴充服務集（ESS）
    - 無線區域網路安全
      - Fake AP
      - 攻擊WEP
         - 有關WEP的敘述下列何者為非?
         - (A)有線等效加密(Wired Equivalent Privacy，WEP）是個保護無線網路資料安全的體制
         - (B)使用RC4串流加密技術達到機密性 ==>(B)使用RC4區塊加密技術達到機密性
         - (c)使用CRC-32 驗和達到資料正確性
         - (D)RC4是流加密的一種，同一個鑰匙絕不能使用二次，所以使用（雖然是用明文傳送的）IV的目的就是要避免重複；然而24位元的IV並沒有長到足以擔保在忙碌的網路上不會重複，而且IV的使用方式也使其可能遭受到關連式鑰匙攻擊
      - 攻擊WPA
      - WPA（英語：Wi-Fi Protected Access）
      - 意即「Wi-Fi存取保護」，一種保護無線網路（Wi-Fi）存取安全的技術標準
      - （WEP）系統中找到的幾個嚴重的弱點而產生的。
      - 攻擊WPA2
      - 攻擊WPA3 

- 2.作業系統與應用程式安全
  - 2-1.作業系統安全
    - windows 作業系統
      - [Windows Authentication](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview)
      - [Windows 驗證](https://docs.microsoft.com/zh-tw/windows-server/security/windows-authentication/windows-authentication-overview)
      - [NTLM 使用者驗證](https://docs.microsoft.com/zh-tw/troubleshoot/windows-server/windows-security/ntlm-user-authentication)
      - [Kerberos 認證](https://zh.wikipedia.org/wiki/Kerberos)
      - [Security and Protection(舊版)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831778(v=ws.11)) 
      - 使用者帳戶控制(User Account Control，UAC)
    - windows 作業系統常用指令 [Windows commands](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)
    - windows 作業系統管理與安全工具
      - task manager
      - 工作管理員
      - event viewer
      - 事件檢視器
      - systeminternals 
    - windows server技術:[官方網站](https://docs.microsoft.com/en-us/windows-server/)
      - Active Directory(AD) ==> LDAP
      - 通過IP協定提供存取控制和維護分散式資訊的目錄資訊。
      - Group Policy(GP) ==>  gpedit.msc [Local Group Policy Editor](https://www.isunshare.com/windows-10/5-ways-to-access-local-group-policy-editor-on-windows-10.html)
      - Windows Server Update Services (WSUS)
    - [Windows security眾多文件] (https://docs.microsoft.com/en-us/windows/security/)
      - [Security and Protection(舊版)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831778(v=ws.11)) 
    - windows 攻擊手法: 
      - Windows binary exploitation 
      - Windows Kernel exploitation
      - 傳遞雜湊(Pass-the-Hash)
      - 傳遞雜湊是一種利用竊取而來的憑證所施行的攻擊技術。此一技術牽涉到攻擊者從某台電腦中竊取到帳號憑證，
        並利用它對網路中其它的存取點進行認證。傳遞雜湊的攻擊無需純文字密碼，而可讓攻擊者使用密碼散列作認證。
        此密碼散列值是在針對安全儲存體建立密碼散列時，原始密碼經過單向的數學函數演算後所產生的。
因為傳遞雜湊攻擊利用的是受保護之散列形態中的密碼，故它讓攻擊者可以在完全不知道純文字密碼的情形中能模仿經認
證的使用者。攻擊者亦可在其它系統和服務中重複使用(傳遞)這些被竊取並經過散列演算的憑證，以獲取更多深入的存取
許可。例如，若攻擊者獲得了一個網域管理者已登入過之裝置的存取權，就可經由這網域竊取網域帳號憑證，並透過該網
域存取該帳號所有的相關資源、權限和特權。透過此一途徑，攻擊者便可一步步接近網域主控站。
      - wannacry 攻擊(2017)
      - 
    - LINUX 作業系統
    - LINUX 作業系統常用指令
    - LINUX 作業系統管理與安全工具
    - LINUX 攻擊手法: 
      - Linux binary exploitation 
      - Linux Kernel exploitation
      - 'root'kit
        - [nurupo/rootkit](https://github.com/nurupo/rootkit)
        - [惡意程式潛伏Linux主機　揪出系統遭植入Rootkit](https://www.netadmin.com.tw/netadmin/zh-tw/technology/F632D1F9D2B34E8B9FCC725B45509BB5) 
        - [f0rb1dd3n/Reptile](https://github.com/f0rb1dd3n/Reptile)
        - [后渗透之Rootkit及入门](https://zhuanlan.zhihu.com/p/132519704)
      - [髒牛漏洞(Dirty Cow)](https://ppfocus.com/0/scbf79101.html)
      - [LES: Linux privilege escalation auditing tool](https://github.com/mzet-/linux-exploit-suggester)
      - [入侵 Linux 系統的慣用姿勢：11 種提權方式揭祕 - 知乎](https://www.gushiciku.cn/pl/p96O/zh-tw)
      
      - [HackerCat](https://www.youtube.com/channel/UCkZAkJWOAExMfVp1XHt1VOA)
      
  - 2-2.作業系統與應用程式 (含資料庫與網頁)攻擊手法
    - 網站安全
    - OWASP TOP 10
      - sqli
        - SQL == Structured Query Language == 結構化查詢語言
```
SELECT first_name, last_name 
FROM users 
WHERE user_id = '$id'
```
      - XSS
        - [XSS DVWA 12 - XSS (Stored) (low/med/high) - Damn Vulnerable Web Application (DVWA)] (https://www.youtube.com/watch?v=P1I9UGpGdrU)
        - [11 - XSS (Reflected) (low/med/high) - Damn Vulnerable Web Application (DVWA)](https://www.youtube.com/watch?v=P1I9UGpGdrU)
    - OWASP API TOP 10
    - 網站安全測試 
    - 資料庫
      - SQL資料庫
      - NOSQL資料庫  
    - 資料庫的攻擊事件
    - 資料庫的攻擊手法
    - 資料庫的安全防護
  - 2-3.程式與開發安全
    - 應用程式(application) secure coding
      - desktop application
      - web application 網站應用程式 客戶端  vs 伺服器端(asp.net)
      - mobile application:  andriod(java  kotlin) ios 
      - [EC-Council CASE .NET應用程式安全工程師認證課程](https://www.uuu.com.tw/Course/Show/1501/EC-Council-CASE-NET%E6%87%89%E7%94%A8%E7%A8%8B%E5%BC%8F%E5%AE%89%E5%85%A8%E5%B7%A5%E7%A8%8B%E5%B8%AB%E8%AA%8D%E8%AD%89%E8%AA%B2%E7%A8%8B)
    - 應用程式的安全威脅
      - 逆向工程
      - 在無法輕易獲得必要的生產資訊下，直接從成品的分析，推導產品的設計原理。
    - 安全程式開發(secure code standard)
    - 程式的安全防護
      - 代碼渾淆
      - 是將電腦程式的原始碼或機器碼，轉換成功能上等價，但是難於閱讀和理解的形式的行為。
      - 加核與加密 
    - 開發安全與SSDLC

- [Mitre Att&CK](https://attack.mitre.org/)
- [Common Attack Pattern Enumeration and Classification (CAPEC™)](https://capec.mitre.org/about/index.html)

- 3.資安維運技術
  - 3-1.惡意程式防護與弱點管理
    -  各種惡意程式(malware)
       - 勒索軟體
       - 網站木馬
       - 蠕蟲(worm) 
    - 惡意程式分析(malware analysis)
       - 靜態分析
       - 靜態程式分析是對計算機軟體的分析，該軟體在沒有實際執行程序的情況下執行，
       - 與動態分析相反，動態分析是在程式執行時執行的
       - 動態分析
    -  惡意程式防護
    -  弱點與弱點資料庫
    -  弱點嚴重性 CVSS
    -  弱點管理
       - 弱點掃描(Vulnerability Assessment)
       - 「弱點掃描」則是使用自動化工具對系統進行檢測，找出所有已知的風險。
        漏洞評估是識別、量化和排序系統中的漏洞（或排名）的過程
       - 網站弱點掃描
        網站弱點掃描服務模擬各類型可能遭受攻擊的情境，目的在偵測弱點且不影響網站。
        全程為黑箱方式進行，並根據目標網站調整掃描政策，掃描結果再經由VSCAN檢視弱點，
        過濾誤判及人工判斷弱點風險，產生分析報告並提供顧問諮詢。
       - 系統弱點掃描
       - 企業主機環境則常由於組態設定不當或忘記更新軟體修正檔，使得本身資訊系統遭到非經授權的存取或導致其它安全性問題風險。
       - 藉由工具進行弱點掃瞄，提早發現系統維運及網站安全弱點，及時完成弱點修補作業，避免藉由弱點遭受入侵攻擊。
  - 3-2.資料安全及備份管理
    - 資料安全(data security)
      - 資料外洩
      - 數據泄露指的是個人或組織的私有、機密信息被有意或無意地發布到危險環境中
    - 備份管理
      - 資料備份方式:
        - 完全備份(Full Backup) 
         完全備份是指創建所有有效數據的備份，無論是新添加還是存在很長時間的數據。
         例如Windows 7的系統檔案佔用12GB，則該系統分割區的完整備份將包含12GB的數據。
         在進行磁碟的完全備份時，將備份磁碟上的所有數據。分割區的完全備份也是如此。
         完全備份的對象可以是系統分割區，數據分割區，整個磁碟等。
        - 差異備份(Differential Backup)  
         與增量備份類似，差異備份用於根據上次完全備份備份已更改的數據。
         也就是說，它是基於完全備份，而不是增量備份。
         對於其優點，它可以幫助提高備份效率並減少映像檔案所需的存儲磁碟空間
![OIP](https://user-images.githubusercontent.com/90738468/142200750-f2c8f4e6-12d9-48b5-8f03-3c2388e85850.jpg)
        - 增量備份(Incremental Backup)  
          增量備份是指根據第一次完整備份或最後一次備份，然後備份已更改和新添加的數據。  
         根據最後一次備份，增量備份將不會備份相同的數據。
         增量備份是基於最後一次備份的，所以它們之間會有相互依賴的關係。
![OIP1](https://user-images.githubusercontent.com/90738468/142200608-57eebd1c-57b8-42cb-b6d3-c8ccd2f90521.jpg)
      - 儲存媒體
      儲存媒體是指任何可以記錄、保存以及讀取電腦資料的物體。
      - RAID  
      容錯式磁碟陣列（RAID, Redundant Array of Independent Disks） 
      利用虛擬化儲存技術把多個硬碟組合起來，成為一個或多個硬碟陣列組，目的為提升效能或減少冗餘，或是兩者同時提升。 
      - 備份管理作業
  - 3-3.日誌管理
    - 日誌管理基本觀念
    - 日誌類型==> (A)系統日誌檔 (B) 應用程式日誌檔 (C) 安全性日誌檔
![2021-11-17 203445](https://user-images.githubusercontent.com/90738468/142203595-3ac39d07-bb4e-4880-bb91-a6b9d830124e.png)
    - Windows 作業系統日誌檔
    - 日誌分析
    日誌分析（log analysis）主要是針對電腦所產生的日誌檔（log files）進行歷程分析，以瞭解資訊系統的運作狀況。
    - 日誌管理
    藉由日誌管理，即可監控、稽核並報告檔案存取、使用者的未授權活動、政策變更，
    以及在內含專有或受監管之個人資料（例如員工、病患或財務紀錄）的檔案或資料夾上進行的其他關鍵活動。
    
  - 3.4.資安防護技術
    - [Mitre D3FEND™ - A knowledge graph of cybersecurity countermeasures](https://d3fend.mitre.org/) 
    - 防火牆(Firewall)
      - 防火牆類型
        - 封包過濾防火牆(Packet-Filtering Firewall)  
        利用封包過濾是最早被用來作為網路防火牆的技術，是在OSI七層架構中第三層以下的網路中運作。
        封包過濾器的功能主要是檢查過往的每一個IP資料封包，
        如果其表頭中所含的資料內容符合事先設定的可信賴安全標準就放行通過， 反之則阻檔在門外。
        管理者會先根據企業/組織的策略預先設定好封包通過的規則或採用內建規則，只允許符合規則的封包通過
        - 狀態檢視防火牆(Stateful Inspection Firewall)
         能夠持續追蹤穿過這個防火牆的各種網路連線（例如TCP與UDP連線）的狀態。
         這種防火牆被設計來區分不同連線種類下的合法封包。只有符合主動連線的封包才能夠被允許穿過防火牆，其他的封包都會被拒絕。
        - 代理伺服器(Proxy Server)
        代理式防火牆會將所有內外的連線予以接管，採用的策略是store-and-forward。
        從安全的角度來看，proxy 比起 filter 更加可靠：因為它將內部與外部網路完全區隔開來了，
        除非它幫您做連線代理，否則別想建立連線。而且，內部網路對外部網路而言，是完全"隱形"的！
    - 網站應用程式防火牆(Web Application Firewall, WAF)
        主要保護網站應用程式，透過監控及過濾網站傳輸的 HTTP 流量，避免您的網站遭受惡意攻擊、資料外洩，保障網站安全。
    - 蜜罐（Honeypot）
        用來偵測或抵禦未經授權操作或者是駭客攻擊的陷阱，因原理類似誘捕昆蟲的蜜罐因而得名。  
        蜜罐通常偽裝成看似有利用價值的網路、資料、電腦系統，並故意設定了bug，用來吸引駭客攻擊。
        由於蜜罐事實上並未對網路提供任何有價值的服務，所以任何對蜜罐的嘗試都是可疑的。
        蜜罐中還可能裝有監控軟體，用以監視駭客入侵後的舉動。
        蜜罐在拖延駭客攻擊真正目標上也有一定作用。不過駭客可能發現一個電腦系統是蜜罐，進而提前退出。
        而更常見的用法是用來吸引網路的電腦病毒入侵，從而獲得病毒樣本用於研究或破解的電腦，
        防毒軟體公司會利用這些電腦來監視或獲得電腦網路中的病毒樣本。
    - 滲透測試(Penetration Testing)  vs 紅隊演練 (Red Team Assessment) 
        滲透測試:是委任受信任的第三方進行一種評估網路安全的活動，
        它透過對企業網路進行各種手段的攻擊來找出系統存在的漏洞，進而驗證出網路系統存在安全風險的一種實踐活動。
        滲透測試透過模擬的真實攻擊行為，可證實惡意攻擊者有可能竊取或破壞企業的數位設備、資產、資訊與資料。
        
        紅隊演練:是在不影響企業營運的前提下，對企業進行模擬入侵攻擊，
        在有限的時間內以無所不用其極的方式，從各種進入點執行攻擊，嘗試達成企業指定的測試任務。
- 4.新興科技安全
  - 4-1.雲端安全概論
    - 雲端運算定義
    （英語：cloud computing），也被意譯為網路運算，是一種基於網際網路的運算方式，通過這種方式，
    共享的軟硬體資源和資訊可以按需求提供給電腦各種終端和其他裝置，使用服務商提供的電腦基建作運算和資源
    - 雲端安全
    (Cloud security），來自電腦安全、網路安全、甚至是更廣泛的資訊安全的子領域，而且還在持續發展中。
    雲端安全是指一套廣泛的政策、技術、與被佈署的控制方法, 以用來保護資料、應用程式、與雲端運算的基礎設施。
  - 4-2.行動裝置安全概論
    - OWASP MOBILE TOP 10 
M1： 平臺使用不當
M2：不安全的數據存儲
M3：不安全的通信
M4：不安全身份驗證
M5： 加密不足
M6： 不安全授權
M7：客戶代碼品質
M8： 代碼篡改
M9： 逆向工程
M10： 無關功能
  - 4-3.物聯網安全概論
    - 物聯網(IOT)
   Internet of Things是一種計算裝置、機械、數位機器相互關聯的系統，
   具備通用唯一辨識碼（UID），並具有通過網路傳輸數據的能力，無需人與人、或是人與裝置的互動
物聯網將現實世界數位化，應用範圍十分廣泛。物聯網可拉近分散的資料，統整物與物的數位資訊。
物聯網的應用領域主要包括以下方面：運輸和物流、工業製造、健康醫療、智慧型環境（家庭、辦公、工廠）、個人和社會領域等
物聯網為受各界矚目的新興領域，但安全性是物聯網應用受到各界質疑的主要因素，
主要的質疑在於物聯網技術正在快速發展中，但其中涉及的安全性挑戰，與可能需要的法規變更等，目前均相當欠缺
    - OWASP IOT TOP 10  
I1 弱可猜，或硬編碼密碼
I2 不安全網路服務
I3 不安全的生態系統介面
I4 缺乏安全更新機制
I5 使用不安全或過時的元件
I6 隱私保護不足
I7 不安全的數據傳輸和存儲
I8 缺乏設備管理
I9 不安全預設設置
I10 缺乏物理硬化

