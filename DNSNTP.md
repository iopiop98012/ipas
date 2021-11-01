# DNS 的攻擊模式分析

## DNS 快取記憶體DNS Poisoning (DNS Spoofing)  
DNS 快取記憶體中毒是向 DNS 快取記憶體中輸入錯誤資訊的行為，以便使 DNS 查詢返回錯誤回應並將使用者導向到錯誤網站
DNS 解析程式為用戶端提供與網域名稱關聯的 IP 位址  
DNS 解析程式使用 IP 位址進行回應，然後 Web 瀏覽器使用該地址開始載入此網站。  
只要與該 IP 位址關聯的指定存留時間 (TTL) 允許，DNS 解析程式就會將回應儲存在其快取記憶體中。  
攻擊者可透過模擬 DNS 名稱伺服器，向 DNS 解析程式發出請求，然後在 DNS 解析程式查詢名稱伺服器時偽造答覆，使 DNS 快取記憶體中毒  
https://www.cloudflare.com/zh-tw/learning/dns/dns-cache-poisoning/
## DNS Amplification Attack
當打開瀏覽器鍵入網址連上網時，其實就已經正在使用 DNS 的服務了。  
向目標主機發送大量 UDP 封包，藉此阻斷其正常服務，也由於受害 DNS 主機回傳到目標主機之封包大小會大於殭屍電腦群所發送的封包大小， 攻擊過程中流量具有放大的效果，故稱其為 DNS 放大攻擊。  
https://www.cc.ntu.edu.tw/chinese/epaper/0028/20140320_2808.html

# NTP 的攻擊模式分析

## NTP 放大DDoS 攻擊
https://www.cloudflare.com/zh-tw/learning/ddos/ntp-amplification-ddos-attack/
