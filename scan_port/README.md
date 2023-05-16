# 高危端口扫描工具: san_port

## 1.背景

​ 在对华为云进行安全整改，会涉及到端口暴露风险，这就涉及到端口扫描，所以提出对华为云的所有的账户下的管理的的IP进行端口扫描。

## 2.需求

​ 根据配置信息获取有的华为云账户下的公网eip, 并使用nmap工具对指定的ip扫描，分别对改ip的tcp, udp进行nmap扫描，并对tcp扫描的端口使用http协议请求，检查是否能获取后端服务的版本号。

## 3.使用

1.安装软件

~~~bash
yum install nmap
pip3 install huaweicloudsdkeip
pip3 install huaweicloudsdknat
pip3 install huaweicloudsdkelb
pip3 install huaweicloudsdkbms
pip3 install huaweicloudsdkecs
pip3 install huaweicloudsdkrds
pip3 install huaweicloudsdkvpc
pip3 install huaweicloudsdkiam
pip3 install openpyxl
pip3 install PyYAML
~~~

2.修改配置文件： scap_ips.yaml

~~~BASH
high_risk_port: [ 21, 22, 23, 69, 135, 137, 138, 139, 161, 177, 389, 445, 513, 873, 1025, 1099, 1433, 1521, 2082, 2083, 2222, 2601, 2604, 3128, 3306, 3312, 3311, 3389, 4440, 4848, 4899, 5432, 6379, 7001, 7002, 7778, 8080, 8649, 8083, 8649, 9000, 9200, 9043, 10000, 27017, 50060, 50030, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010, 6011, 6012, 6013, 6014, 6015, 6016, 6017, 6018, 6019, 6020, 6021, 6022, 6023, 6024, 6025, 6026, 6027, 6028, 6029, 6030, 6031, 6032, 6033, 6034, 6035, 6036, 6037, 6038, 6039, 6040, 6041, 6042, 6043, 6044, 6045, 6046, 6047, 6048, 6049, 6050, 6051, 6052, 6053, 6054, 6055, 6056, 6057, 6058, 6059, 6060, 6061, 6062, 6063, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010, 50011, 50012, 50013, 50014, 50015, 50016, 50017, 50018, 50019, 50020, 50021, 50022, 50023, 50024, 50025, 50026, 50027, 50028, 50029, 50030, 50031, 50032, 50033, 50034, 50035, 50036, 50037, 50038, 50039, 50040, 50041, 50042, 50043, 50044, 50045, 50046, 50047, 50048, 50049, 50050] # 常用的高危端口
account_info:
    - ak: 华为云账户1的ak
      sk: 华为云账户1的sk
    
    - ak: 华为云账户2的ak
      sk: 华为云账户2的sk
~~~

3.执行脚本

~~~bash
python3 scan_ips.py 
即可输出：公网IP端口扫描统计表.xlsx
~~~
