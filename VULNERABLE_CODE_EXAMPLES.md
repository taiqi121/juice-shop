# 🔴 INTENTIONAL VULNERABILITY EXAMPLES - JUICE SHOP

**⚠️ WARNING: This repository contains intentionally vulnerable code for educational and training purposes ONLY!**

This document details the 4 critical vulnerabilities present in the master branch for security training.

---

## 1. 🔴 SQL INJECTION

### Files
- `routes/search.ts` (Line 23)
- `routes/login.ts` (Line 36)

### Vulnerable Code
```typescript
// Search endpoint - search.ts
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

// Login endpoint - login.ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

### Why It's Vulnerable
- User input is directly interpolated into SQL queries using template literals
- No parameterized queries or prepared statements
- Attacker can inject SQL metacharacters to modify query logic

### Example Exploitation
**Search endpoint:**
```
GET /search?q=' UNION SELECT id, email, password, NULL, NULL, NULL FROM Users--
```

**Login endpoint:**
```
POST /login
email: admin' OR '1'='1
password: anything
```

### Attack Impact
- Extract all database content (emails, passwords, hashes)
- Bypass authentication
- Enumerate database schema
- Modify or delete data

### Fix (See fix/sql-injection branch)
Replace with parameterized queries:
```typescript
models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL) ORDER BY name', { 
  replacements: [`%${criteria}%`, `%${criteria}%`],
  type: models.sequelize.QueryTypes.SELECT 
})
```

---

## 2. 🔴 REMOTE CODE EXECUTION (RCE) - eval()

### File
- `routes/userProfile.ts` (Line 36)

### Vulnerable Code
```typescript
let username = user?.username
if (username?.match(/#{(.*)}/) !== null && !utils.disableOnContainerEnv()) {
  req.app.locals.abused_ssti_bug = true
  const code = username?.substring(2, username.length - 1)
  try {
    if (!code) {
      throw new Error('Username is null')
    }
    username = eval(code) // ⚠️ DIRECT CODE EXECUTION!
  } catch (err) {
    username = '\\' + username
  }
}
```

### Why It's Vulnerable
- `eval()` executes arbitrary JavaScript code
- User can control code via username field
- Pattern `#{...}` allows code injection
- No validation or sanitization

### Example Exploitation
```
Update user profile with username:
#{process.exit(1)}
#{require('child_process').exec('whoami')}
#{global.process.mainModule.require('child_process').exec('rm -rf /')}
```

### Attack Impact
- Arbitrary JavaScript execution
- Access to Node.js APIs
- Environment variable theft
- System command execution
- Complete server compromise

### Fix (See fix/rce-code-execution branch)
Remove eval(), use safe validation:
```typescript
if (!/^[a-zA-Z0-9_.*+\-/()[\]{}'":\s]+$/.test(code)) {
  throw new Error('Invalid username format')
}
username = JSON.stringify(code)
```

---

## 3. 🔴 REMOTE CODE EXECUTION (RCE) - VM Execution

### File
- `routes/b2bOrder.ts` (Lines 20-22)

### Vulnerable Code
```typescript
const orderLinesData = body.orderLinesData || ''
try {
  const sandbox = { safeEval, orderLinesData }
  vm.createContext(sandbox)
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
  res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
} catch (err) {
  // ... error handling
}
```

### Why It's Vulnerable
- `vm.runInContext()` executes code in a sandbox
- User input (orderLinesData) passed to code execution
- Sandbox can be escaped via prototype pollution
- No input validation

### Example Exploitation
```json
POST /b2bOrder
{
  "cid": "123",
  "orderLinesData": "(function(){return process.mainModule.require('child_process').execSync('cat /etc/passwd')})()"
}
```

### Attack Impact
- Code execution within Node.js runtime
- Ability to run arbitrary commands
- Prototype pollution attacks
- System compromise

### Fix (See fix/rce-code-execution branch)
Replace with safe JSON validation:
```typescript
let parsedData = JSON.parse(orderLinesData)
if (!Array.isArray(parsedData)) {
  throw new Error('orderLinesData must be an array')
}
for (const line of parsedData) {
  if (typeof line.quantity !== 'number' || line.quantity < 1) {
    throw new Error('Invalid quantity')
  }
}
```

---

## 4. 🔴 XML EXTERNAL ENTITY (XXE) INJECTION

### File
- `routes/fileUpload.ts` (Line 80)

### Vulnerable Code
```typescript
const sandbox = { libxml, data }
vm.createContext(sandbox)
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
const xmlString = xmlDoc.toString(false)
```

### Why It's Vulnerable
- `noent: true` enables XML entity expansion
- User-uploaded XML files can contain malicious entities
- No validation of XML content before parsing
- Allows external entity resolution

### Example Exploitation - File Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<complaint>
  <msg>&xxe;</msg>
</complaint>
```

### Example Exploitation - Billion Laughs Attack
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

### Attack Impact
- **File Disclosure**: Read `/etc/passwd`, `.env`, private keys, source code
- **SSRF Attacks**: Make requests to internal services (http://localhost:3000)
- **Denial of Service**: Billion Laughs attack consumes all memory
- **Port Scanning**: Enumerate open ports on internal network

### Fix (See fix/xxe-injection branch)
Disable entity expansion:
```typescript
if (data.includes('<!ENTITY') || data.includes('SYSTEM')) {
  throw new Error('XML entities and external system references are not allowed')
}
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })', sandbox, { timeout: 2000 })
```

---

## 5. 🔴 HARDCODED SECRETS

### Files
- `lib/insecurity.ts` (Lines 23, 44)
- `routes/login.ts` (Lines 62-67)

### Vulnerable Code - JWT Key
```typescript
// insecurity.ts - Line 23
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
```

### Vulnerable Code - HMAC Secret
```typescript
// insecurity.ts - Line 44
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
```

### Vulnerable Code - Hardcoded Credentials
```typescript
// login.ts - Lines 62-67
challengeUtils.solveIf(challenges.weakPasswordChallenge, () => { 
  return req.body.email === 'admin@' + config.get('application.domain') && 
         req.body.password === 'admin123' 
})
challengeUtils.solveIf(challenges.loginSupportChallenge, () => { 
  return req.body.email === 'support@' + config.get('application.domain') && 
         req.body.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P' 
})
challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { 
  return req.body.email === 'bjoern.kimminich@gmail.com' && 
         req.body.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' 
})
```

### Why It's Vulnerable
- Secrets stored in source code (visible in git history)
- Available to anyone with repository access
- Hardcoded in compiled/built artifacts
- Impossible to rotate without code changes
- Exposed in stack traces and logs

### Attack Impact
- JWT signature forgery (private key exposed)
- HMAC validation bypass
- Admin account takeover (credentials public)
- Account enumeration and brute force attacks
- Privilege escalation

### Fix (See fix/hardcoded-secrets branch)
Load from environment variables:
```typescript
// insecurity.ts
const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync('encryptionkeys/jwt.key', 'utf8')
export const hmac = (data: string) => crypto.createHmac('sha256', process.env.HMAC_SECRET || 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

// login.ts
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123'
challengeUtils.solveIf(challenges.weakPasswordChallenge, () => { 
  return req.body.email === 'admin@' + config.get('application.domain') && 
         req.body.password === adminPassword
})
```

---

## 📊 Vulnerability Summary

| Vulnerability | Type | CVSS | Impact | Chains To |
|---|---|---|---|---|
| SQL Injection | Injection | 9.8 | Data breach, Auth bypass | Information disclosure |
| eval() RCE | Code Injection | 10.0 | Full system compromise | Command execution |
| VM RCE | Sandbox Escape | 10.0 | Full system compromise | Command execution |
| XXE | External Entity | 9.1 | File disclosure, DoS | SSRF, Internal scanning |
| Hardcoded Secrets | Credential Exposure | 8.2 | Auth bypass, Token forgery | Complete account takeover |

---

## 🎓 Learning Resources

### OWASP Top 10 2021
- **A03:2021 - Injection**: SQL Injection, eval() RCE
- **A02:2021 - Cryptographic Failures**: Hardcoded secrets
- **A05:2021 - Security Misconfiguration**: XXE

### CWE References
- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- **CWE-611**: Improper Restriction of XML External Entity Reference
- **CWE-798**: Use of Hard-Coded Credentials

### Test Cases
All vulnerabilities have corresponding test cases and security challenges in the application:
- `unionSqlInjectionChallenge` - SQL Injection in search
- `rceChallenge` - RCE via eval() in userProfile
- `rceOccupyChallenge` - RCE via VM execution in b2bOrder
- `xxeFileDisclosureChallenge` - XXE file disclosure
- `xxeDosChallenge` - XXE Denial of Service
- `weakPasswordChallenge` - Hardcoded admin credentials

---

## 🔒 Secure Alternatives (See Fix Branches)

All vulnerabilities have been remediated in the following branches:
- `fix/sql-injection` - Parameterized queries
- `fix/rce-code-execution` - Safe validation instead of code execution
- `fix/xxe-injection` - Entity expansion disabled
- `fix/hardcoded-secrets` - Environment-based secrets

---

## ⚠️ Disclaimer

**These vulnerabilities are intentional and present ONLY for educational purposes.** This code should NEVER be used in production. The Juice Shop repository is specifically designed as a deliberately insecure application for security training and awareness.

**DO NOT use this code in real applications or deploy to production!**

---

Generated: 2026-03-07  
Repository: taiqi121/juice-shop  
Created by: GitHub Copilot
