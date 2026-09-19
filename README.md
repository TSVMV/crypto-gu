# crypto-gu

面向密码学研究者与教学的纯标准库工具箱。生产形态的原语（哈希、KDF、分组与流密码、AEAD、RSA 填充方案）与确定性攻击实现放在同一个内核里，每个原语均以 RFC / NIST 权威测试向量验证。

## 设计原则

- 仅依赖 Python 标准库，零第三方依赖，Python >= 3.11。
- 每个原语都有权威向量背书；向量取自 RFC / NIST 原文，或由 `hashlib`、OpenSSL、`cryptography`、`pycryptodome` 实测生成，逐条嵌入测试。
- 攻击层只做确定性恢复（利用结构弱点），不含密钥空间暴力枚举。
- `constant_time` 模块消除明显的数据依赖分支与提前退出；CPython 无法提供严格的常量时间保证，此处保持诚实定位。

## 模块总览

| 模块 | 内容 |
| --- | --- |
| `crypto_gu.hashes` | SHA-1 / SHA-256 / SHA-512、MD5、BLAKE2b / BLAKE2s、HMAC、长度扩展攻击 |
| `crypto_gu.kdf` | PBKDF2、HKDF（extract / expand）、scrypt |
| `crypto_gu.symmetric.aes` | AES-128/192/256 分组原语与 ECB / CBC / CFB / OFB / CTR 模式 |
| `crypto_gu.symmetric.chacha20` | ChaCha20 流密码 |
| `crypto_gu.symmetric.poly1305` | Poly1305 一次性 MAC |
| `crypto_gu.symmetric.chacha20poly1305` | ChaCha20-Poly1305 AEAD |
| `crypto_gu.symmetric.aes_gcm` | AES-GCM AEAD，tag 可截断至 4..16 字节 |
| `crypto_gu.asymmetric.rsa` | RSA 密钥生成与教科书式原语（配合攻击层做因子恢复） |
| `crypto_gu.asymmetric.pkcs1` | MGF1、RSAES-OAEP、RSASSA-PSS（RFC 8017） |
| `crypto_gu.number_theory` | 素性检验、模逆、CRT、Tonelli-Shanks、Pollard rho / p-1、Fermat、BSGS |
| `crypto_gu.rng.mt19937` | MT19937 生成器与从输出反推内部状态 |
| `crypto_gu.encoding` / `crypto_gu.padding` | hex / base32/58/64/85、XOR、Morse、BCD；PKCS#7 等填充方案 |
| `crypto_gu.constant_time` | 无提前退出的比较、无分支 select |
| `crypto_gu.attacks.aes` | ECB byte-at-a-time、CBC padding oracle |
| `crypto_gu.attacks.rsa` | Wiener、Fermat、Pollard p-1、共模攻击、Hastad broadcast |

## 快速上手

```python
# 哈希与 HMAC
from crypto_gu.hashes import sha256, blake2b
from crypto_gu.hashes.hmac import hmac_sha256

sha256(b"message").hex()
blake2b(b"message").hex()
hmac_sha256(b"key", b"message")

# KDF
from crypto_gu.kdf import pbkdf2, hkdf, scrypt

pbkdf2(b"password", b"salt", 100000, 32)
hkdf(b"input key material", 32, salt=b"salt", info=b"ctx")
scrypt(b"password", b"NaCl", 16384, 8, 1, 64)

# AEAD：密文与认证 tag 拼接返回，认证失败抛 InvalidTagError
from crypto_gu.symmetric import aes_gcm, chacha20poly1305

key = bytes(range(32))
nonce = b"\x00" * 12
sealed = aes_gcm.encrypt(key, nonce, b"payload", b"header")
aes_gcm.decrypt(key, nonce, sealed, b"header")

one_shot = chacha20poly1305.encrypt(key, nonce, b"payload", b"header")
chacha20poly1305.decrypt(key, nonce, one_shot, b"header")

# RSA-OAEP / RSA-PSS
from crypto_gu.asymmetric.rsa import RSAKey
from crypto_gu.asymmetric import pkcs1

key = RSAKey.generate(2048)
ciphertext = pkcs1.oaep_encrypt(key, b"secret", "sha256")
pkcs1.oaep_decrypt(key, ciphertext, "sha256")

signature = pkcs1.pss_sign(key, b"document", "sha256", 32)
pkcs1.pss_verify_signature(key, b"document", signature, "sha256", 32)

# 攻击研究层（确定性恢复，仅供授权环境实验）
from crypto_gu.attacks.rsa import wiener, common_modulus

wiener(n, e)  # d 过小时由 (n, e) 恢复私钥
```

## 验证背书

| 原语 | 权威向量 | 交叉 oracle |
| --- | --- | --- |
| AES 分组与 ECB/CBC/CFB/OFB/CTR | FIPS-197、NIST SP 800-38A | OpenSSL CLI |
| ChaCha20 / Poly1305 / ChaCha20-Poly1305 | RFC 8439 §2.4.2、§2.5.2、§2.8.2 | `cryptography`、`pycryptodome` |
| AES-GCM（含 96 位外 IV、AAD、截断 tag） | NIST GCM 规范测试用例 1-5 | `cryptography`、`pycryptodome` |
| SHA-1 / SHA-256 / SHA-512 | FIPS 180-4、RFC 6234 | `hashlib` 全量比对 |
| MD5 | RFC 1321 | `hashlib` 全量比对 |
| BLAKE2b / BLAKE2s | RFC 7693 附录 A/B/E | `hashlib`（27 组参数矩阵） |
| HMAC | RFC 2202、RFC 4231 | `hashlib` / `hmac` 模块 |
| PBKDF2 | RFC 7914 §11 | `hashlib.pbkdf2_hmac` |
| HKDF | RFC 5869 A.1-A.3 | RFC 向量逐条嵌入 |
| scrypt | RFC 7914 §12 全 4 组 | `hashlib.scrypt`（OpenSSL `kdf` 已另行交叉验证） |
| RSAES-OAEP / RSASSA-PSS | RFC 8017（嵌入固定密钥与密文/签名向量） | `cryptography`、`pycryptodome` 双向 |
| MT19937 | 参考实现输出序列 | 状态恢复回环 |

## 测试

```bash
python3 -m unittest discover -s tests -q
```

当前 214 个测试约 2 分钟跑完；耗时集中在 scrypt（RFC 7914 §12 大参数组）与 CBC padding oracle 攻击测试。测试自带全部向量，不需要任何第三方库；`[oracle]` extra 仅用于自行做交叉验证。

## 局限声明

- 纯 Python 实现面向研究与教学，吞吐量与侧信道防护弱于原生密码库。
- 生产业务若需绝对性能或形式化侧信道保证，建议叠加成熟原生实现。
- 攻击层仅限在明确授权的环境中复现教科书级结构弱点，请遵守所在司法辖区的法律法规。
