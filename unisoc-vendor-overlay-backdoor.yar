rule Unisoc_Vendor_Overlay_Backdoor_Fleet {
    meta:
        author = "lexs201992-gif"
        cve = "CVE-2026-28407"
        severity = "CRITICAL"
        description = "Detects malicious RRO backdoor in Unisoc T606 fleet devices. Targets specific hardware IDs and overlay injection paths."
        reference = "AttackerKB Assessment #82 | CISA KEV Candidate"

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
        (
            ($cpu_id or $board_codename) and 
            ($vendor_path and (2 of ($overlay_name*, $cpu_id, $board_codename)))
        )
}   