rule SupplyChain_Overlay_Abuse_Unisoc {
    meta:
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        description = "Detects malicious RRO (Runtime Resource Overlay) injection in Unisoc T606 supply chain. Identifies vendor/carrier abuse patterns used to bypass FSVerity."
        reference = "CVE-2026-XXXXX | AttackerKB Assessment #81"
        mitre_attack = "T1574.009 (Hijack Execution Flow: Path Interception by Unquoted Path)"

    strings:
        /* Identificadores de Namespace Críticos */
        $ns_unisoc = "android.unisoc." ascii
        $ns_sprd = "com.spreadtrum." ascii
        
        /* Rutas de Inyección en Particiones Confiadas */
        $path_vendor = "/vendor/overlay" ascii
        $path_product = "/product/overlay" ascii
        $path_system = "/system/product/overlay" ascii

        /* Cadenas de Ofuscación y Generación Maliciosa */
        $inject_keyword = "injection" ascii nocase
        $build_anomaly = "auto_generated_rro" ascii
        $cert_anomaly = "CN=Longcheer" ascii
        $lcd_trigger = "lcd_td4168" ascii

        /* Magic Number APK/ZIP */
        $apk_magic = { 50 4B 03 04 }

    condition:
        /* 1. Debe ser un archivo válido (APK/ZIP) y pequeño (típico de RRO) */
        $apk_magic at 0 and filesize < 600KB and
        
        /* 2. Lógica de Correlación Estricta para evitar Falsos Positivos */
        (
            /* Escenario A: Namespace Unisoc + Ruta Vendor + Keyword Inyección */
            ($ns_unisoc and $path_vendor and $inject_keyword)
            or
            /* Escenario B: Ruta Producto + Cert Longcheer + Trigger LCD (Caso Moto G04s) */
            (($path_product or $path_system) and $cert_anomaly and $lcd_trigger)
            or
            /* Escenario C: Namespace Spreadtrum + Ruta Sistema + Anomalía Build */
            ($ns_sprd and ($path_vendor or $path_system) and $build_anomaly and $inject_keyword)
        )
}   

Technical Justification for Rule Unisoc_Vendor_Overlay_Backdoor_Fleet:

Hardware Fingerprinting: The inclusion of cpu_T606 and the board codename qogirl6 provides a unique fingerprint for the compromised Unisoc T606 reference design manufactured by Longcheer. These strings are embedded in the proprietary overlay binaries and are rarely, if ever, present in legitimate overlays from other SoC vendors (Qualcomm, MediaTek).
Resilience Against Path Obfuscation: The refined logic prioritizes the presence of the Unisoc namespace combined with hardware identifiers. This ensures detection even if the specific filename (unisoc_overlay) is slightly altered in future firmware updates, while still requiring the file to reside within the trusted /vendor/overlay directory structure.
Fleet-Wide Scalability: Designed for high-volume scanning, this rule targets the persistent mechanism (RRO) used to maintain the backdoor across reboots and factory resets, making it essential for enterprise mobility management (EMM) and government fleet security assessments.
