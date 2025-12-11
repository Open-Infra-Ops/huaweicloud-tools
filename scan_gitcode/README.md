## scan gitcode工具
### 1.使用说明
该工具借助华为内容审核对gitcode仓库进行敏感信息扫描，并通过邮件将扫描结果发出来。

### 2.配置说明
scan_url:        内容审核的url  \
scan_token:      内容审核的token  \
gitcode_url:     gitcode的网址    \
gitcode_token:   gitcode的token（可选）  \
community:       社区              \
mta_sender:      邮件发送者         \
mta_receivers:   xxxxx@163.com,xxxx@huawei.com 邮件接受者 \
mta_ip:          邮件服务的ip \
mta_port:        邮件服务的端口 \ 
mta_username:    邮件服务的用户名 \
mta_password:    邮件服务的密码 \
mta_subject:     gitcode仓库敏感信息通知

### 使用说明
python3 scan_gitcode.py --path=/root/config.yaml
如果配置和脚本在同一目录中，则不需要携带path参数,也可以通过环境变量config_path获取

#####部署建议
1.先将config.yaml挂在在容器中。  \
2.设置环境变量config_path为config.yaml挂载的位置 \
3.启动容器运行 
~~~
docker run -it -v /root/scan_gitcode/config.yaml:/opt/config.yaml --env config_path=/opt/config.yaml scan_gitcode:latest
~~~