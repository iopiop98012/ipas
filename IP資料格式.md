# IP資料的格式 
![IP格式](https://user-images.githubusercontent.com/90738468/138281109-6da4e304-8bee-4181-bb87-d8dc1cc575f2.PNG)
![ip ](https://user-images.githubusercontent.com/90738468/138283100-50c87e86-18a5-4d2b-9864-9325c71aa4c6.PNG)
(http://www.tsnien.idv.tw/Network_WebBook/Network.html)

## Version:  
表示IP的版本，現在的版本是4。  
## Header Length:  
IP資料頭的長度（除了IP資料欄位以外的所有欄位長度）。  
## Type of Service:  
表示資料段（segment）所提供的服務品質。此欄位又可進一步分為Procedence、D、T、R以及未使用等子欄位。  
Procedence用來讓主機的應用程式通知IP層傳送資料段的優先順序。並與D（延遲），T（傳輸量）及R（可靠性）等位元合併使用。  
## Total Length:  
以位元組為單位顯示資料段的的大小（資料頭長度加上資料的長度），所允許的最大長度為65535個位元組。  
## Identifier:  
這個欄位可以辨識分割後的資料段能彙集並排列成原來的資料段，所以每個資料段的資料頭都會加上識別號碼。  
## Flags:  
指示分割時的控制。提供的資訊有兩種：是否可以分割該資料段，以及某資料塊（fragment）為最後一個或者是後面還有其他資料塊。  
## Fragmented Offset:  
以8個位元組為單位的位移（offset），表示經過分割後的資料塊在原來的資料段的位址。  
## Time to Live:  
顯示資料段能夠在網路中保留的時間。資料段每經過一個路由器這個值遞減1，當這個欄位值減到0時，此資料段會被丟棄不再傳送，  
並通知該資料段的傳送者無法傳送該資料，如此就可以避免萬一傳送的路徑形成迴路時無法停止傳送。  
## Protocol:  
顯示IP上一層的協定號碼。告知目的端主機將此資料段交給哪一個協定（TCP或UDP….）模組繼續處理。   
## Header Checksum:   
顯示IP資料頭的總和檢查，主要是確保資料頭的一致性。   
## Source Address:  
來源端的網際網路位址。  
## Destination Address:  
目的端的網際網路位址。  
## Options:  
此欄位不是資料段一定需要的。大多數用在資料段的測試或除錯。  
## Padding:   
為了能使資料頭的長度能以32個位元結束，所需附加的位元，內容為0。因為資料頭的長度是以32個位元為計算單位。   

