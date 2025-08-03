# Shell Injection Vulnerability - Defensive Analysis

## Vulnerability Summary

**Location**: `proxy.go:768-785` (executeScript function)  
**Issue**: DNS-controlled data passed to shell execution with insufficient sanitization  
**Impact**: Potential command injection via DNS responses  

## Vulnerable Code

```go
// proxy.go:768-785
safeClientIP := sanitizeForShell(clientIP)
safeResolvedIP := sanitizeForShell(resolvedIP)  
safeDomain := sanitizeForShell(domain)
safeTTL := sanitizeForShell(ttl)
safeAction := sanitizeForShell(action)

cmd := exec.CommandContext(ctx, scriptPath, safeClientIP, safeResolvedIP, safeDomain, safeTTL, safeAction)
```

```go
// security.go:1916-1918  
func sanitizeForShell(input string) string {
    return regexp.MustCompile(`[^a-zA-Z0-9\._\-]`).ReplaceAllString(input, "")
}
```

## Attack Vectors

### 1. IPv6 Address Corruption
**Issue**: Colons are stripped from IPv6 addresses, potentially causing firewall rules to target wrong IPs.

**Example**:
- Original IPv6: `2001:db8::1` 
- After sanitization: `2001db81`
- Script receives corrupted IP, may create incorrect firewall rules

### 2. Domain Name Mangling  
**Issue**: Domain structure is destroyed, breaking script logic that depends on domain format.

**Example**:
- Original domain: `malicious.sub.example.com`
- After sanitization: `malicioussubexamplecom`  
- Script cannot properly validate domain hierarchy

### 3. Argument Position Injection
**Issue**: Even with character filtering, attackers controlling DNS responses can manipulate script arguments.

**Scenario**: If a script expects specific argument patterns, an attacker might craft domains that:
- Create unexpected argument sequences when sanitized
- Exploit script logic that processes domain/IP patterns
- Cause scripts to misinterpret which IPs should be allowed/blocked

## Defensive Proof of Concept

### Malicious DNS Server Setup
```bash
# Attacker controls DNS server returning crafted responses
# Domain: test-injection-vector.attacker.com
# Returns IP: 192.168.1.100 (legitimate)
# But domain name designed to exploit script logic
```

### Exploitation Steps
1. **Attacker sets up malicious DNS server**
2. **Victim queries domain with crafted name**: `script-arg-injection-vector.evil.com`
3. **dfirewall processes DNS response**:
   - Domain becomes: `scriptarginjectionvectorevil.com` (after sanitization)
   - IP: `192.168.1.100` 
4. **Script execution**: `./script.sh clientIP 192.168.1.100 scriptarginjectionvectorevil.com 300 ALLOW`
5. **If script has logic flaws**, the crafted domain name could cause unintended behavior

### Example Vulnerable Script
```bash
#!/bin/bash
# Hypothetical vulnerable firewall script
CLIENT_IP="$1"
RESOLVED_IP="$2"  
DOMAIN="$3"
TTL="$4"
ACTION="$5"

# VULNERABLE: Script logic that could be exploited
if [[ "$DOMAIN" == *"admin"* ]]; then
    # Special handling for admin domains
    iptables -I FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -j ACCEPT
    echo "Admin access granted"
elif [[ "$DOMAIN" == *"bypass"* ]]; then
    # Another logic path that could be exploited
    iptables -F  # DANGEROUS: Flush all rules
fi
```

## Impact Assessment

**Severity**: HIGH  
**Likelihood**: MEDIUM (requires attacker DNS control)  
**Impact**: Command injection, firewall bypass, system compromise

### Potential Consequences
1. **Firewall rule manipulation**: Incorrect rules due to mangled IPs/domains
2. **Security bypass**: Crafted domains triggering unintended script logic  
3. **System compromise**: If scripts have additional vulnerabilities
4. **Denial of service**: Scripts crashing on unexpected input patterns

## Recommended Fixes

### 1. Use Proper Shell Escaping
```go
import "github.com/alessio/shellescape"

func executeScript(...) {
    escapedClientIP := shellescape.Quote(clientIP)
    escapedResolvedIP := shellescape.Quote(resolvedIP)
    escapedDomain := shellescape.Quote(domain)
    // ...
}
```

### 2. Parameterized Execution
```go
// Instead of shell execution, use direct parameter passing
cmd := exec.CommandContext(ctx, scriptPath)
cmd.Args = []string{scriptPath, clientIP, resolvedIP, domain, ttl, action}
```

### 3. Input Validation
```go
func validateScriptInput(input string, inputType string) error {
    switch inputType {
    case "ip":
        if net.ParseIP(input) == nil {
            return fmt.Errorf("invalid IP address")
        }
    case "domain":
        if !isValidDomainName(input) {
            return fmt.Errorf("invalid domain name")
        }
    }
    return nil
}
```

## Defense Recommendations

1. **Immediate**: Replace `sanitizeForShell` with proper shell escaping
2. **Short-term**: Implement strict input validation for all script parameters  
3. **Long-term**: Consider removing shell execution entirely in favor of native Go firewall management

This vulnerability demonstrates why DNS-controlled data should never be passed to shell execution without proper validation and escaping.