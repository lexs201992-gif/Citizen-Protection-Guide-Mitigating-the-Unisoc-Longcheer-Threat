rule Unisoc_T606_Rescue_Party_Indicator {
    meta:
        description = "Detecta componentes de la infraestructura 'Rescue Party' en chipsets Unisoc T606/T616 (ODM Longcheer). Vinculado a CVE-2022-38694 y brechas SAT/INE México 2026."
        author = "Alex de la Cruz (lexs201992)"
        date = "2026-07-09"
        version = "2.0 (Fase 2 - Longcheer C2)"
        severity = "CRITICAL"
        cve = "CVE-2022-38694, CVE-2021-39658, CVE-2026-40003"
        mitre_attack = "T1071 (App Layer Protocol), T1572 (Protocol Tunneling), T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)"
        reference = "https://attackerkb.com/topics/CVE-2022-38694/assessments"
        
    strings:
        /* --- Componentes Críticos Spreadtrum/Unisoc --- */
        $pkg_sgps      = "com.spreadtrum.sgps" ascii wide
        $pkg_ims       = "com.spreadtrum.ims" ascii wide
        $pkg_engine    = "com.spreadtrum.engineermode" ascii wide
        $str_sprd      = "spreadtrum" ascii nocase
        $str_ums9230   = "ums9230" ascii nocase  /* Chipset T606 */
        $str_ums9130   = "ums9130" ascii nocase  /* Chipset T616 */

        /* --- Actores de la Cadena de Suministro (ODM & Partners) --- */
        $pkg_inmobi    = "com.inmobi.installer" ascii wide
        $pkg_dti       = "com.dti.amx" ascii wide
        $pkg_dt        = "com.digitalturbine" ascii wide
        $str_longcheer = "longcheer" ascii nocase
        $str_lcheer    = "lcheer" ascii nocase
        $cert_issuer   = "CN=Longcheer" ascii
        $cert_swish    = "CN=Swish" ascii       /* Vinculado a InMobi */
        $cert_itrust   = "I Trust Asia" ascii   /* CA Shenzhen */

        /* --- Infraestructura C2 y Handshake (Fase 2) --- */
        $aws_prov      = "provisioning" ascii nocase
        $wireguard_cfg = "wireguard" ascii nocase
        $macsec_cfg    = "macsec" ascii nocase
        $rescue_party  = "RescueParty" ascii
        $rescue_cn     = "com.android.internal.app.RescueParty" ascii wide

        /* --- Hashes SHA256 de Binarios Comprometidos (IOCs Directos) --- */
        /* com.spreadtrum.sgps */
        $sha_sgps      = "4cfe803b578fd6958d236e494248585eccbc5c33a5113bda7ff1a47351e4118d" ascii
        /* com.spreadtrum.ims */
        $sha_ims       = "1b938cb3920d601a38e4d80e88c87aaacc56abfa6464f3054de2430172c6f519" ascii
        /* com.inmobi.installer */
        $sha_inmobi    = "1fe9c2c2e4b390f01d2bb7d90b5d219dbe85fdd42321f247a295d532c9b387d2" ascii
        
        /* --- Identificadores de Build Vulnerable (Fase 2) --- */
        $build_lion    = "lion_g" ascii
        $build_ula     = "ULAS34.89" ascii      /* Rango de compilación vulnerable */

    condition:
        /* 
           Lógica de Detección:
           1. Coincidencia directa por HASH (Alta certeza)
           OR
           2. Paquete Spreadtrum + Identificador ODM Longcheer/Certificado
           OR
           3. Paquete InMobi/DT + Certificado Sospechoso
           OR
           4. Componente RescueParty + Configuración WireGuard/MACsec en contexto Unisoc
        */
        any of ($sha_sgps, $sha_ims, $sha_inmobi)
        or 
        (all of ($pkg_sgps, $str_sprd) and any of ($str_longcheer, $cert_issuer, $build_ula))
        or
        (any of ($pkg_inmobi, $pkg_dti) and any of ($cert_swish, $cert_itrust, $str_longcheer))
        or
        (all of ($rescue_cn, $wireguard_cfg) and any of ($str_ums9230, $str_ums9130))
}