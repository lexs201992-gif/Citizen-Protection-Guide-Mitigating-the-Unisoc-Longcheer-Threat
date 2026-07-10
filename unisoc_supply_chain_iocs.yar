import "hash"

/* 
   Issue #82: Unisoc Supply Chain Compromise
   Reporter: lexs201992-gif
   Target: Unisoc T606/T616 (Motorola G04s, etc.)
   Date: July 2026
*/

rule Unisoc_CarrierLocation_Injector {
    meta:
        description = "Detects compromised Carrier Location overlay (com.sprd.android.networkstack.overlay)"
        author = "lexs201992-gif"
        date = "2026-07-10"
        issue = "AttackerKB #82"
        severity = "Critical"
        sha256 = "442e8ed1344f34ced55cf3cbf430fbf4c2379eb904a840ff15342bb3e815d8ae"
    strings:
        $pkg_name = "com.sprd.android.networkstack.overlay" ascii wide
        $sprd_net = "UnisocNetworkStackOverlay" ascii
        $apk_magic = { 50 4B 03 04 }
    condition:
        hash.sha256(0, filesize) == "442e8ed1344f34ced55cf3cbf430fbf4c2379eb904a840ff15342bb3e815d8ae" or
        ($apk_magic at 0 and all of ($pkg_name, $sprd_net))
}

rule Unisoc_IMS_Privileged_Backdoor {
    meta:
        description = "Detects malicious IMS App (com.spreadtrum.ims) with RCE potential"
        author = "lexs201992-gif"
        date = "2026-07-10"
        issue = "AttackerKB #82"
        severity = "Critical"
        sha256 = "1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519"
    strings:
        $pkg_name = "com.spreadtrum.ims" ascii wide
        $ims_priv = "android.uid.phone" ascii
        $sprd_ims = "sprd.ims" ascii
        $apk_magic = { 50 4B 03 04 }
    condition:
        hash.sha256(0, filesize) == "1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519" or
        ($apk_magic at 0 and all of ($pkg_name, $ims_priv))
}

rule Unisoc_PhotoStorage_Exfil {
    meta:
        description = "Detects compromised Photos Provider (com.sprd.providers.photos)"
        author = "lexs201992-gif"
        date = "2026-07-10"
        issue = "AttackerKB #82"
        severity = "High"
        sha256 = "cc9f657b723ac21108f4c1af8e33f8b93baae17bae91da15b33ef16840fd9558"
    strings:
        $pkg_name = "com.sprd.providers.photos" ascii wide
        $usc_photo = "USCPhotosProvider" ascii
        $media_shared = "android.media" ascii
        $apk_magic = { 50 4B 03 04 }
    condition:
        hash.sha256(0, filesize) == "cc9f657b723ac21108f4c1af8e33f8b93baae17bae91da15b33ef16840fd9558" or
        ($apk_magic at 0 and all of ($pkg_name, $usc_photo))
}

rule Unisoc_OTA_OMACP_Handler {
    meta:
        description = "Detects malicious OMA CP Handler (com.sprd.omacp)"
        author = "lexs201992-gif"
        date = "2026-07-10"
        issue = "AttackerKB #82"
        severity = "Critical"
        sha256 = "6b568400c82f0fda18f4048777d1df9415911c109605307964bd0c3983f8c313"
    strings:
        $pkg_name = "com.sprd.omacp" ascii wide
        $oma_cp = "Omacp" ascii
        $phone_uid = "android.uid.phone" ascii
        $apk_magic = { 50 4B 03 04 }
    condition:
        hash.sha256(0, filesize) == "6b568400c82f0fda18f4048777d1df9415911c109605307964bd0c3983f8c313" or
        ($apk_magic at 0 and all of ($pkg_name, $oma_cp))
}

rule Unisoc_YLogManager_Spyware {
    meta:
        description = "Detects compromised Log Manager (com.sprd.logmanager)"
        author = "lexs201992-gif"
        date = "2026-07-10"
        issue = "AttackerKB #82"
        severity = "High"
        sha256 = "f1387c3523c4ccff7cc915a6580d62b32466dbdd0dfabfd242751a5a6714ce64"
    strings:
        $pkg_name = "com.sprd.logmanager" ascii wide
        $log_mgr = "LogManager" ascii
        $vendor_path = "/vendor/app/LogManager" ascii
        $apk_magic = { 50 4B 03 04 }
    condition:
        hash.sha256(0, filesize) == "f1387c3523c4ccff7cc915a6580d62b32466dbdd0dfabfd242751a5a6714ce64" or
        ($apk_magic at 0 and all of ($pkg_name, $vendor_path))
}   
