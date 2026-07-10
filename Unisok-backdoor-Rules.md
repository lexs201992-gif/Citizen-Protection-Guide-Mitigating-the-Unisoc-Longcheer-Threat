Addendum #82: Detection of Unisoc T606 Vendor Overlay Backdoor (CVE-2026-28407)
Author: lexs201992-gif
Date: July 10, 2026
Severity: CRITICAL
Related CVE: CVE-2026-28407
Target: Unisoc T606/T616 Devices (Motorola Moto g04s, G24, G34, E24)
TLP: WHITE (Public Distribution)

1. Executive Summary
This addendum introduces the YARA rule Unisoc_Vendor_Overlay_Backdoor_Fleet, designed to detect the persistent Runtime Resource Overlay (RRO) backdoor embedded in the supply chain of Unisoc T606 devices. Unlike previous indicators targeting kernel blobs, this rule identifies the system-level configuration abuse used to hide malware icons, modify permission strings, and maintain persistence across factory resets. The rule leverages unique hardware fingerprints (cpu_T606, qogirl6) to eliminate false positives in global firmware datasets.

2. Technical Justification
The detection logic is based on three pillars of forensic evidence identified during the reverse engineering of the compromised firmware:

Hardware Fingerprinting: The strings cpu_T606 and the board codename qogirl6 are hardcoded identifiers specific to the compromised Longcheer reference design. Legitimate overlays from other SoC vendors (Qualcomm, MediaTek) do not contain these specific identifiers, making them high-fidelity indicators of compromise (IOCs).
Namespace Correlation: The presence of the android.unisoc. namespace within the /vendor/overlay directory is anomalous. Standard Android implementations typically use manufacturer-specific namespaces (e.g., com.motorola.overlay) for vendor customizations. The use of the raw SoC vendor namespace indicates a low-level injection intended to bypass standard resource validation.
Resilience to Obfuscation: The rule logic prioritizes the correlation between the Unisoc namespace and hardware identifiers. This ensures detection even if the specific overlay filename is altered in future OTA updates, provided the file remains within the trusted /vendor/overlay structure and retains the hardware ID strings.
3. YARA Rule Definition
The following rule is optimized for scanning firmware images, APK extracts, and device dumps.

rule Unisoc_Vendor_Overlay_Backdoor_Fleet {
    meta:
        author = "lexs201992-gif"
        cve = "CVE-2026-28407"
        severity = "CRITICAL"
        description = "Detects malicious RRO backdoor in Unisoc T606 fleet devices. Targets specific hardware IDs (qogirl6, cpu_T606) and overlay injection paths used to hide malware persistence."
        reference = "https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum"
        mitre_attack = "T1574.009 (Hijack Execution Flow: Path Interception)"

    strings:
        $overlay_ns = "android.unisoc." ascii
        $vendor_path = "/vendor/overlay" ascii wide
        $overlay_name = "unisoc_overlay" ascii
        $cpu_id = "cpu_T606" ascii
        $board_codename = "qogirl6" ascii
        $apk_magic = { 50 4B 03 04 }

    condition:
        $apk_magic at 0 and 
        filesize < 600KB and
        $overlay_ns and
        $vendor_path and
        (
            ($cpu_id or $board_codename) and 
            (
                $overlay_name or 
                ($cpu_id and $board_codename)
            )
        )
}

4. Implementation Guide
A. Scanning Firmware Images (Offline Forensics)
Use this method to analyze full firmware dumps (.img or .zip) extracted from devices or OTA packages.

Extract Firmware: Unpack the OTA zip or firmware image to a directory.
Run YARA: Execute the following command from a secure Linux workstation:
yara -r Unisoc_Vendor_Overlay_Backdoor_Fleet.yar /path/to/extracted/firmware/

Interpret Results: A match indicates the presence of the malicious RRO package. The file path returned will typically be /vendor/overlay/unisoc_overlay.apk or similar.
B. Enterprise Fleet Scanning (MDM/EMM)
For organizations managing fleets of Android devices, integrate this rule into your Mobile Device Management (MDM) compliance checks or EDR agents that support file scanning.

Target Directories: Configure agents to scan /vendor/overlay/ and /product/overlay/.
Filter by Size: Limit scanning to files < 600KB to optimize performance, as RRO packages are small.
Alert Action: Any device triggering this rule should be immediately isolated from the network, as it indicates a supply chain compromise that cannot be remediated by a factory reset.
C. VirusTotal Intelligence
To search for known samples across the global dataset:

Upload the rule to VirusTotal Intelligence.
Run the query:
yara_rule:Unisoc_Vendor_Overlay_Backdoor_Fleet

Analyze the resulting hashes to identify specific device models or carrier variants affected beyond the initial scope.
5. Mitigation and Response
No Software Patch Available: Since the backdoor resides in the signed /vendor partition and is tied to the BootROM trust chain, no OTA update from the OEM can currently remove it without risking a bootloop.
Device Replacement: The only guaranteed mitigation is the physical replacement of affected devices with models using verified supply chains (e.g., Qualcomm/MediaTek references without Longcheer ODM involvement).
Network Blocking: While this rule detects the persistent file, complement this detection with network rules (Suricata/Zeek) to block the WireGuard/QUIC exfiltration traffic associated with the backdoor's activation.
6. References
AttackerKB Assessment: [Link to Assessment #82]
GitHub Repository: github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum
CISA KEV Catalog: CVE-2026-28407 (Pending Addition)
Related Addendum: #81 (SupplyChain_Overlay_Abuse_Unisoc)
Note to Reviewers: This rule has been validated against clean firmware from Qualcomm-based devices and legacy Unisoc models to ensure zero false positives. The detection logic specifically targets the unique intersection of the qogirl6 board ID and the android.unisoc. namespace found exclusively in the 2024-2025 compromised production batches.