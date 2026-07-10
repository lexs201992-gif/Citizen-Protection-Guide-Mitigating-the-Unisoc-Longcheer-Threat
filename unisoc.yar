rule Unisoc_Vendor_Overlay_Backdoor_Fleet {
  meta: author = "lexs201992-gif" cve = "CVE-2026-28407" severity = "CRITICAL"
  strings: $overlay = "android.unisoc." $vendor_path = "/vendor/overlay/unisoc_overlay"
           $cpu = "cpu_T606" $power = "qogirl6"
  condition: uint16(0) == 0x8B1F and filesize < 500KB and 2 of them
}