# Real-time Intrusion Detection Web App
<b>Nhóm 8</b><br>
## About
* Real-time Intrusion Detection System implementing Machine Learning. 

* We combine Supervised learning (RF) for detecting known attacks from CICIDS 2018 & SCVIC-APT datasets, and Unsupervised Learning (AE) for anomaly detection.

## Requirements:
1. Windows OS.

2. Python 3.9:
    * link 64-bit: https://www.python.org/ftp/python/3.9.13/python-3.9.13-amd64.exe 
    * link 32-bit: https://www.python.org/ftp/python/3.9.13/python-3.9.13.exe

     <b> Note: select "Add Python 3.9 to PATH" in installation procedure.</b>

3. Npcap 1.71:
    https://npcap.com/dist/npcap-1.71.exe

## Download project folder & environment setups:
<code>git clone https://github.com/phamhaian2508/APT_Detection
    cd APT_Detection
    # Tạo môi trường ảo
    py -3.9 -m venv venv
    # Vào máy ảo
    venv\Scripts\Activate  
    # Nếu lệnh trên lỗi chạy
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    # Tải thư viện
    python -m pip install -r requirements.txt
    # hoặc: pip install -r requirements.txt</code>

Run program:

<codeếu </code>

Web app address: [http://localhost:5000](http://localhost:5000)

## Visible alert types
The dashboard filter currently shows these categories:

* `Lưu lượng hợp lệ`
* `Tấn công dò quét database`
* `Tấn công DDoS`
* `Tấn công DoS`
* `Tấn công dò quét FTP`
* `Dò quét thăm dò`
* `Tấn công dò quét SSH`

The trained model also still contains `Botnet` and `Web Attack`, but those categories remain hidden from the filter for now because they usually need a more specialized lab to reproduce and validate consistently.


