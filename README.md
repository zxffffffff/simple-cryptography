# simple-cryptography

![workflow](https://github.com/zxffffffff/simple-cryptography/actions/workflows/build-windows.yml/badge.svg?event=push)
![workflow](https://github.com/zxffffffff/simple-cryptography/actions/workflows/build-macos.yml/badge.svg?event=push)
![workflow](https://github.com/zxffffffff/simple-cryptography/actions/workflows/build-ubuntu.yml/badge.svg?event=push)

一个最少依赖的密码学库，把 openssl crypto++ zlib 等常用加解密和压缩算法封装成独立的函数

## 非对称加密算法

也称 公开密钥密码学 (Public-key cryptography)、非对称式密码学 (Asymmetric cryptography)。

公钥加密，私钥解密。

### 1. `RSA`

1977 年由 Ron Rivest、Adi Shamir、Leonard Adleman 提出，三人姓氏开头字母拼在一起组成 RSA。

是一种基于大数分解问题的加密算法，RSA 的安全性直接与密钥的长度成正比，长度至少为 2048 位，但随着时间推移可能需要更长的密钥。

主要用于 数据加密 和 数字签名，广泛应用于 SSL/TLS 加密协议、电子邮件加密、数字证书等领域。

`PKCS #1` 是 `RSA 实验室` 发布的的第一个 公钥密码学标准 (Public-Key Cryptography Standards)，它定义了公钥和私钥的数学属性、加密和签名的原始操作、安全加密方案以及相关的ASN.1语法表示。

`RSAES-PKCS1-v1_5` 是较旧的加密方案，在 PKCS #1 的 1.5 版本中首次标准化，已知易受攻击。`RSAES-OAEP` 是改进的方案，基于 最优非对称加密填充 (OAEP)。

`RSASSA-PKCS1-v1_5` 是带有附录 (SSA) 的旧签名方案，在 PKCS #1 的 1.5 版中首次标准化。`RSASSA-PSS` 是改进的方案，基于 概率签名方案 (PSS)。

### 2. `ECC`

椭圆曲线密码学 (Elliptic Curve Cryptography).

也称椭圆曲线数字签名算法 ECDSA (Elliptic Curve Digital Signature Algorithm)。

基于 椭圆曲线 数学原理。它通过椭圆曲线上的点的加法运算和离散对数问题来生成公钥和私钥。

主要用于 数字签名 和 加密货币 中，因其较短的密钥和高效的计算性能。

比特币使用 `secp256k1` 和 `ECDSA` 算法，椭圆曲线参数选择 secp256k1 是因为计算效率更高，特别是在需要快速处理大量签名和验证操作的场景中 (比其他曲线快 30%)。

256 位的 secp256k1 安全性约等于 3072 位 RSA，加密和解密性能高于 2048 位 RSA。

此类坐标的曲线没有任何连续线的概念，它的图实际上看起来像随机散点

![image](https://github.com/zxffffffff/simple-cryptography/blob/main/docs/Secp256k1.png)

## 对称加密算法

也称为 对称密钥算法 (Symmetric-key algorithm)。

### 1. `AES`

高级加密标准 (Advanced Encryption Standard)，原始名称 `Rijndael` 加密法

美国联邦政府采用的一种区块加密标准，用来替代 1977 年发布的 `DES`，该算法为比利时密码学家 Joan Daemen、Vincent Rijmen 所设计，结合两位作者的名字，以 Rijndael 为名投稿高级加密标准的甄选流程。

`AES-256` 被认为具有量子抗性，`AES-192` 针对量子攻击的强度为 96 位，而 `AES-128` 针对量子攻击的强度为 64 位，这使得它们都不安全。

![image](https://github.com/zxffffffff/simple-cryptography/blob/main/docs/AES_(Rijndael)_Round_Function.png)

## 秘密共享算法

Secret sharing，也称为 秘密分裂 (secret splitting)、门限秘密共享。

### 1. SSS

Shamir 秘密共享 (Shamir's secret sharing)，1979 年发明由 Adi Shamir 发明，该方案利用拉格朗日插值定理。

具体来说 k 多项式上的点唯一确定次数小于或等于的多项式 k−1。例如，2 个点足以定义直线，3 个点足以定义抛物线，4 个点足以定义三次曲线等等。

![image](https://github.com/zxffffffff/simple-cryptography/blob/main/docs/3_polynomials_of_degree_2_through_2_points.svg.png)
