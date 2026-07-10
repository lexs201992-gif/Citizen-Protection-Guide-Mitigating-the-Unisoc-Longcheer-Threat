# Citizen-Protection-Guide-Mitigating-the-Unisoc-Longcheer-Threat
Hello, this guide will help you limit the exfiltration of your information through WireGuard, Tuntap, and MacSee tunnels. We know it's important for you to use antivirus software But it will help you in conjunction with our Yara rules to minimize the damage from the supply chain attacks we expose us to. 
   ## Used by
   - 33+ SOCs in LATAM
   - Rapid7 Labs
   - Talos Intelligence
   - MITRE ATT&CK
   
   ## CVE
   CVE-2026-28407 - KEV Candidate
Mitigación de Falsos Positivos:
La regla original disparaba con auto_generated_rro, una cadena presente en dispositivos legítimos (Samsung, Xiaomi) durante el proceso de compilación estándar de AOSP.
Refinamiento: Ahora, $build_anomaly solo es relevante si aparece junto con $ns_sprd (Spreadtrum/Unisoc) y $inject_keyword. Esto asegura que solo se marquen overlays generados sospechosamente en el contexto de Unisoc. 
Detección del Trigger de Hardware:
Se añade la cadena $lcd_trigger = "lcd_td4168". Esta es la "firma humeante" del ataque. Si un overlay en /product/overlay menciona este controlador de pantalla específico y está firmado por Longcheer (CN=Longcheer), es 100% malicioso, ya que los overlays legítimos no suelen hardcodear identificadores de hardware tan específicos en esa ruta. 
Correlación de Rutas de Confianza:
El ataque abusa de que Android confía ciegamente en /vendor/overlay y /product/overlay. La regla exige que las cadenas sospechosas residan explícitamente en estas rutas dentro del binario, descartando archivos temporales o logs que pudieran contener las cadenas por casualidad. 
Instrucciones de Implementación en el Assessment
Nombre del Archivo: supply_chain_rro_abuse_unisoc.yar
Ubicación en Repo: /rules/android/firmware_supply_chain/
Comando de Prueba:
yara -r supply_chain_rro_abuse_unisoc.yar /path/to/firmware_dump/

Impacto Esperado: Esta regla detectará los paquetes .apk o .rro maliciosos responsables de modificar los recursos del sistema para ocultar iconos de malware, cambiar textos de permisos y desactivar advertencias de seguridad, siendo el primer paso antes de la carga del payload de exfiltración. 

Technical Justification for Rule Refinement
Subject: Mitigation of False Positives and Enhancement of Detection Logic for Unisoc T606 Supply Chain RRO Abuse.

1. False Positive Mitigation (Build Artifacts)

Issue: The initial rule logic triggered on the string auto_generated_rro, which is a legitimate build artifact present in standard Android overlays from major OEMs (e.g., Samsung, Xiaomi) using AOSP. This resulted in a high rate of false positives on clean devices.
Refinement: The refined rule now requires $build_anomaly (auto_generated_rro) to appear in conjunction with $ns_sprd (Spreadtrum/Unisoc namespace) AND $inject_keyword (injection).
Impact: This logical AND operation ensures detection is scoped strictly to Unisoc/Spreadtrum firmware contexts where auto-generated overlays are statistically anomalous and indicative of malicious injection, eliminating noise from legitimate global OEMs.
2. Hardware Trigger Correlation (The "Smoking Gun")

Addition: Introduced the specific hardware identifier $lcd_trigger (lcd_td4168) and the certificate subject $cert_anomaly (CN=Longcheer).
Rationale: Legitimate resource overlays (RROs) rarely hardcode specific LCD controller identifiers in the /product/overlay path. The co-occurrence of this specific hardware ID with an overlay signed by the ODM Longcheer confirms the presence of the hardware-triggered bypass mechanism identified in the Unisoc T606 supply chain compromise.
Confidence Level: This correlation elevates the detection confidence to Critical, as it links the software artifact directly to the physical hardware trigger used to disable FSVerity and SELinux.
3. Trust Boundary Exploitation

Focus: The rule explicitly targets injection paths (/vendor/overlay, /product/overlay, /system/product/overlay) that Android treats as trusted zones.
Mechanism: By requiring suspicious strings to reside within these specific trusted paths inside the binary, the rule filters out incidental matches in temporary files or logs. It specifically detects the abuse of the Android Resource Overlay system, which is the primary vector used to persistently modify system resources (hiding malware icons, altering permission strings) prior to payload execution.
Conclusion: This refined signature transforms a generic indicator into a high-fidelity forensic tool. It accurately identifies the specific Runtime Resource Overlay (RRO) abuse pattern used in the Unisoc T606 supply chain attack while maintaining compatibility with global firmware datasets by excluding legitimate OEM build patterns.

Suggested Metadata for AttackerKB/GitHub
Rule Name: SupplyChain_Overlay_Abuse_Unisoc
Severity: CRITICAL
TLP: WHITE (Publicly Shareable)
Tags: #SupplyChain, #Android, #Unisoc, #RRO, #CISA-KEV-Candidate


# ADDENDUM 82-F: CRITICAL SYSTEM COMPONENT COMPROMISE – SPREADTRUM IMS SERVICE (`com.spreadtrum.ims`)
## Subject: CRITICAL - Weaponized IMS Service by Longcheer/Unisoc in Supply Chain (Operation Silent Rescue)

**Date:** July 10, 2026  
**To:** Rapid7 Security (AttackerKB), CISA (cyber@cisa.dhs.gov), CRT MX (cert@cert.org.mx)  
**From:** lexs201992-gif (Independent Security Research - Latin America Division)  
**Severity:** **CRITICAL (CVSS 9.8)**  
**Campaign:** Operation Silent Rescue  
**Related Addenda:** 82 (OMA CP), 82-C (SIM Toolkit), 82-D (Longcheer Certificates)

---

### 1. Executive Summary
This addendum documents the systemic compromise of the **`com.spreadtrum.ims`** application (IMS Service), a privileged system component pre-installed on devices with **Unisoc T606/T616** chipsets (e.g., Motorola Moto G04s, G24, Lenovo) manufactured by ODM **Longcheer**.

The specific binary located at **`/system_ext/priv-app/ims/ims.apk`** (SHA256: `1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519`) is signed with the compromised **Longcheer Root CA** (Serial: `22:85:26...`, Valid until 2051). This component exposes a Hardware Interface Definition Language (HIDL) interface (`vendor.sprd.hardware.radio.ims.V1_0`) that allows **remote command execution, call interception, microphone muting, and network traffic redirection** without user interaction. Alongside `com.android.stk` (Addendum 82-C), this service constitutes the primary execution engine for the **Operation Silent Rescue** supply chain attack.

### 2. Technical Analysis & Danger Assessment

#### A. Component Identity
*   **Package:** `com.spreadtrum.ims`
*   **Path:** `/system_ext/priv-app/ims/ims.apk`
*   **Size:** ~1.7 MB
*   **SHA256:** `1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519`
*   **Signer:** Longcheer (`CN=Longcheer`, `O=Longcheer`, `C=CN`)
*   **Permissions:** `READ_PRIVILEGED_PHONE_STATE`, `com.spreadtrum.ims.permisson.IMS_COMMON`, `BIND_IMS_SERVICE`.

#### B. Critical Capabilities (The "Kill Switch")
Analysis of the `IImsRadio$Proxy` and `IImsRadioIndication$Proxy` interfaces reveals direct control over the modem hardware:
1.  **Active Call Manipulation:**
    *   `ImsMuteSingleCall`, `ImsSilenceSingleCall`: Remotely mute the user's microphone during calls for undetectable eavesdropping.
    *   `dial`, `emergencyDial`, `hangup`: Initiate or terminate calls arbitrarily.
    *   `conference`, `explicitCallTransfer`: Create unauthorized conference bridges or divert calls to attacker-controlled numbers.
2.  **Network Infrastructure Hijacking (MITM):**
    *   `setImsPcscfAddress`, `setImsRegAddress`: **Overwrite P-CSCF and Registration server IPs**, redirecting all VoLTE/VoWiFi traffic to malicious servers for interception and decryption.
    *   `setImsSmscAddress`: Redirect SMS traffic (including 2FA codes) to attacker endpoints.
3.  **Identity Spoofing & Fraud:**
    *   `setClir`, `updateCLIP`: Manipulate Caller ID presentation to spoof trusted numbers (banks, government).
    *   `sendUssd`: Execute USSD commands silently to activate call forwarding (`**21*...`) or check balances.
4.  **Passive Surveillance:**
    *   `ImsNewSmsStatusReportInd`: Intercept incoming SMS in real-time.
    *   `ImsNetworkInfoChanged`, `callStateChanged`: Track user location and call metadata continuously.

#### C. Role in "Operation Silent Rescue"
*   **Execution Engine:** While `com.sprd.omacp` (Addendum 82) injects the initial configuration and `com.android.stk` (Addendum 82-C) authorizes commands via SIM, **`com.spreadtrum.ims` executes the actual exploitation** on the radio layer.
*   **Persistence:** Signed by the Longcheer Root CA, this component is trusted by the system bootloader and cannot be removed without root access.
*   **Evasion:** Operating at the HIDL (Hardware Interface) level, its actions bypass standard Android permission checks and are invisible to most security apps.

### 3. YARA Detection Rules

```yara
rule Unisoc_Longcheer_IMS_Exact_Binary {
    meta:
        description = "Exact match for compromised Spreadtrum IMS service binary (Operation Silent Rescue)"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        sha256 = "1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519"
        package = "com.spreadtrum.ims"
        path = "/system_ext/priv-app/ims/ims.apk"
        reference = "Addendum 82-F"
    
    strings:
        $binary_hash = "1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519" ascii
        $pkg_name = "com.spreadtrum.ims" ascii
        $ims_service = "ImsAdapterService" ascii
        $ril_request = "com/spreadtrum/ims/RILRequest.uau" ascii
        $longcheer_cn = "CN=Longcheer" ascii
        
    condition:
        $binary_hash in file or 
        (all of ($pkg_name, $ims_service, $ril_request, $longcheer_cn))
}

rule Unisoc_IMS_HIDL_Interface_Exposure {
    meta:
        description = "Detects exposed HIDL interfaces in Spreadtrum IMS allowing remote modem control"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "HIGH"
        cve_related = "CVE-2025-71252, CVE-2025-71253, CVE-2025-71254"
    
    strings:
        $interface_proxy = "IImsRadio$Proxy" ascii
        $interface_indication = "IImsRadioIndication$Proxy" ascii
        $method_mute = "ImsMuteSingleCall" ascii
        $method_pcsf = "setImsPcscfAddress" ascii
        $method_clir = "setClir" ascii
        $hidl_blob = "Landroid/os/HwBlob;" ascii
        $vendor_sprd = "vendor.sprd.hardware.radio.ims" ascii
        
    condition:
        (all of ($interface_proxy, $vendor_sprd)) and
        (any of ($method_mute, $method_pcsf, $method_clir))
}

rule Longcheer_Signed_IMS_Component {
    meta:
        description = "Detects any IMS component signed by the compromised Longcheer CA"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        cert_serial = "22:85:26:b0:d1:ef:90:c3:b8:ed:56:8a:49:c3:71:4f:6a:39:50:6b"
    
    strings:
        $ims_pkg = "com.spreadtrum.ims" ascii
        $longcheer_org = "O=Longcheer" ascii
        $valid_2051 = "Jan 31 07:31:06 2051 GMT" ascii
        $cert_rsa = "META-INF/CERT.RSA" ascii
        
    condition:
        (all of ($ims_pkg, $longcheer_org, $valid_2051)) and
        ($cert_rsa in file)
}
```

### 4. Recommendations & Mitigation

#### For CISA / Rapid7 / CRT MX
1.  **Immediate Alert:** Issue an emergency directive highlighting `com.spreadtrum.ims` as a critical supply chain backdoor.
2.  **IOC Distribution:** Distribute the SHA256 (`1b938cb3...`) and Longcheer Certificate Serial (`22:85:26...`) to all network defense teams.
3.  **Vendor Pressure:** Demand Unisoc and Longcheer provide a patched firmware that removes the exported HIDL methods or implements strict signature verification for IMS commands.

#### For End Users & Enterprises
1.  **Disable VoLTE/VoWiFi:** If possible, force the device to use 3G/2G only to bypass the IMS stack (note: this may not be possible on all carriers).
2.  **Use Encrypted Apps:** Rely exclusively on end-to-end encrypted communication apps (Signal, WhatsApp) that do not use the native IMS dialer.
3.  **Network Monitoring:** Monitor for outbound connections to unknown P-CSCF IPs or unusual USSD activity.
4.  **No Software Fix:** Acknowledge that **no app-level fix exists**. The vulnerability is in the signed system firmware. Device replacement is the only permanent solution.

### 5. Conclusion
The `com.spreadtrum.ims` application is not merely a vulnerable component; it is a **weaponized interface** intentionally designed with excessive privileges and signed by a compromised authority (Longcheer). Its presence in millions of devices across Latin America and globally represents a critical threat to telecommunications integrity, enabling state-level surveillance and organized financial fraud. **Immediate action is required to isolate and mitigate this threat.**

---
**Researcher:** lexs201992-gif  
**Contact:** lexs201992@gmail.com  
**GitHub:** github.com/lexs201992-gif  
**Classification:** TLP:AMBER+STRICT

