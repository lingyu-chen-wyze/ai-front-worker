# iOS App Attest 集成指南

## 📱 客户端实现（Swift）

### 1. 启用 App Attest

在 Xcode 中：
1. 添加 `DeviceCheck` framework
2. 在 `Info.plist` 添加 App Attest 权限

### 2. 生成 Attestation

```swift
import DeviceCheck
import CryptoKit

class AttestationManager {
    let service = DCAppAttestService.shared
    
    // 步骤 1: 生成 Key (首次使用)
    func generateKey() async throws -> String {
        guard service.isSupported else {
            throw AttestationError.notSupported
        }
        
        let keyId = try await service.generateKey()
        // 保存 keyId 到 Keychain
        KeychainHelper.save(keyId, forKey: "attestation_key_id")
        return keyId
    }
    
    // 步骤 2: 生成 Attestation
    func attest() async throws -> [String: Any] {
        // 1. 获取或生成 keyId
        var keyId = KeychainHelper.get(forKey: "attestation_key_id")
        if keyId == nil {
            keyId = try await generateKey()
        }
        
        // 2. 生成 challenge (包含时间戳)
        let challengeData = try JSONEncoder().encode([
            "timestamp": Date().timeIntervalSince1970 * 1000,
            "nonce": UUID().uuidString
        ])
        let challenge = challengeData.base64EncodedString()
        
        // 3. 计算 clientDataHash
        let clientDataHash = Data(SHA256.hash(data: challengeData))
        
        // 4. 请求 attestation
        let attestationObject = try await service.attestKey(
            keyId!,
            clientDataHash: clientDataHash
        )
        
        // 5. 返回给服务端的数据
        return [
            "keyId": keyId!,
            "attestationObject": attestationObject.base64EncodedString(),
            "challenge": challenge
        ]
    }
    
    // 步骤 3: 调用后端接口
    func getJWTToken() async throws -> String {
        let attestation = try await attest()
        
        let request = [
            "platform": "ios",
            "attestation": attestation
        ]
        
        let url = URL(string: "https://ai-front.suyeqaaq.workers.dev/v1/auth/attest")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = try JSONEncoder().encode(request)
        
        let (data, response) = try await URLSession.shared.data(for: urlRequest)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw AttestationError.serverError
        }
        
        let result = try JSONDecoder().decode(AttestResponse.self, from: data)
        return result.token
    }
}

// MARK: - Models

struct AttestResponse: Codable {
    let ok: Bool
    let token: String
    let installId: String
    let expiresInSec: Int
}

enum AttestationError: Error {
    case notSupported
    case serverError
}

// MARK: - Keychain Helper

class KeychainHelper {
    static func save(_ value: String, forKey key: String) {
        let data = value.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    static func get(forKey key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)
        
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
```

### 3. 使用示例

```swift
// 首次启动或 token 过期时
let manager = AttestationManager()

do {
    let token = try await manager.getJWTToken()
    // 保存 token
    UserDefaults.standard.set(token, forKey: "jwt_token")
    
    // 使用 token 调用其他接口
    await parseReminder(token: token)
} catch {
    print("Attestation failed: \(error)")
}

// 调用 parse-text 接口
func parseReminder(token: String) async {
    let url = URL(string: "https://ai-front.suyeqaaq.workers.dev/v1/reminder/parse-text")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    
    let body: [String: Any] = [
        "text": "明天下午三点开会",
        "timezone": "Asia/Shanghai",
        "locale": "zh-CN"
    ]
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    
    let (data, _) = try? await URLSession.shared.data(for: request)
    // 处理响应...
}
```

---

## ⚙️ 服务端配置

### 环境变量

需要在 Cloudflare Worker 设置以下环境变量：

```bash
# 必需
wrangler secret put JWT_SECRET
wrangler secret put GEMINI_API_KEY

# iOS App Attest（推荐）
wrangler secret put IOS_APP_ID
# 值格式: "TEAM_ID.BUNDLE_ID"
# 例如: "ABC123DEF.com.yourcompany.yourapp"
```

**获取 Team ID 和 Bundle ID:**
1. Team ID: 在 [Apple Developer Account](https://developer.apple.com/account) → Membership
2. Bundle ID: Xcode → Target → General → Bundle Identifier

---

## 🔒 安全特性

### 已实现
- ✅ CBOR 格式解析
- ✅ Challenge 时间戳验证（5分钟有效期）
- ✅ App ID 验证（Team ID + Bundle ID）
- ✅ 证书链基础验证
- ✅ Nonce 计算和验证
- ✅ Public key 存储（用于后续 assertion）
- ✅ 防重放攻击（challenge 过期）

### TODO（可选增强）
- ⚠️ 完整的 X.509 证书链验证到 Apple Root CA
- ⚠️ OCSP 证书吊销检查
- ⚠️ 证书扩展字段完整解析
- ⚠️ Assertion 验证（后续请求验证）

---

## 🧪 测试

### 开发环境测试

**注意：** App Attest 在模拟器上不可用，必须用真机测试。

1. 确保使用真实 iOS 设备（iOS 14+）
2. App 必须用正确的 Team ID 签名
3. 检查 `DCAppAttestService.shared.isSupported` 返回 true

### 测试步骤

```swift
// 1. 检查支持
print("App Attest supported: \(DCAppAttestService.shared.isSupported)")

// 2. 生成 attestation
let manager = AttestationManager()
let attestation = try await manager.attest()
print("Attestation generated: \(attestation)")

// 3. 发送到服务端
let token = try await manager.getJWTToken()
print("JWT token: \(token)")
```

### 预期响应

**成功:**
```json
{
  "ok": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "installId": "B1C2D3E4-...",
  "expiresInSec": 900
}
```

**失败（模拟器/格式错误）:**
```json
{
  "ok": false,
  "error": "INVALID_ATTESTATION_FORMAT"
}
```

---

## 🚨 常见错误

| 错误码 | 原因 | 解决方法 |
|--------|------|----------|
| `MISSING_ATTESTATION_FIELDS` | 缺少 keyId/attestationObject/challenge | 检查客户端数据格式 |
| `INVALID_ATTESTATION_FORMAT` | CBOR 格式错误 | 确保用真机，检查 attestationObject 编码 |
| `CHALLENGE_EXPIRED` | Challenge 超过 5 分钟 | 客户端时间戳不准确，重新生成 |
| `APP_ID_MISMATCH` | Team ID 或 Bundle ID 不匹配 | 检查 IOS_APP_ID 环境变量 |
| `CERT_VERIFICATION_FAILED` | 证书链验证失败 | 检查 Apple 证书有效性 |

---

## 📚 参考资料

- [Apple App Attest 官方文档](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server)
- [WWDC 2021: Mitigate fraud with App Attest](https://developer.apple.com/videos/play/wwdc2021/10244/)
- [WebAuthn CBOR Spec](https://www.w3.org/TR/webauthn-2/#sctn-attestation)

---

## ⏭️ 下一步

1. **在真机上测试** App Attest 流程
2. **配置 IOS_APP_ID** 环境变量
3. **可选：** 实现完整的证书链验证
4. **可选：** 实现 Assertion 验证（后续请求无需重新 attest）
