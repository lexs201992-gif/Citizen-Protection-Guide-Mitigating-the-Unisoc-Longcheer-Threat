rule SupplyChain_Overlay_Abuse_Generic {
  meta: author = "lexs201992-gif" severity = "HIGH" 
        description = "Detects vendor/carrier RRO abuse like Unisoc T606 case"
  strings: $rro1 = "android.unisoc." $rro2 = "com.google.android.overlay." 
           $path1 = "/vendor/overlay" $path2 = "/product/overlay"
           $suspicious = "injection" $suspicious2 = "auto_generated_rro"
  condition: uint16(0) == 0x8B1F and filesize < 500KB and 
             (2 of ($rro*) and 1 of ($path*)) or any of ($suspicious*)
}