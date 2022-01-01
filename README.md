# networkprogramming_hw3
封包檢視工具
請寫出一個封包檢視工具，具有底下功能：

可以讀入既有的pcap檔案，並對於檔案中的每個封包顯示(每個封包一行)：

1. 那個封包擷取的時間戳記

2. 來源MAC位址、目的MAC位址、Ethernet type欄位

3. 如果那個封包是IP封包，則再多顯示來源IP位址與目的地IP位址

4. 如果那個封包是TCP或UDP封包，則再多顯示來源port號碼與目的port號碼

## 執行方式
```c
sudo ./read_pcap sample.pcap
```

因獲取網路device需要權限

## 執行結果圖
![image](https://user-images.githubusercontent.com/60705979/147855590-c5787128-a18e-461f-ab5e-0103b32c91fe.png)
