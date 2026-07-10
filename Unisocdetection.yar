# Addendum #82.1: Evidencia Forense de Paquetes del Sistema Comprometidos (qogirl6, UniTelephony, UniWifi)
# Addendum #82.1: Forensic Evidence of Compromised System Packages (qogirl6, UniTelephony, UniWifi)

**Fecha / Date:** 10 de julio de 2026 / July 10, 2026  
**Autor / Author:** lexs201992-gif  
**Severidad / Severity:** CRÍTICA / CRITICAL  
**Estado / Status:** EXPLOTACIÓN ACTIVA CONFIRMADA / CONFIRMED ACTIVE EXPLOITATION

---

## 1. Evidencia Forense Directa: Paquetes del Sistema Comprometidos
## 1. Direct Forensic Evidence: Compromised System Packages

El análisis de `dumpsys package` en dispositivos **Moto g04s** y variantes ha revelado la presencia de paquetes del sistema preinstalados que confirman la manipulación de la cadena de suministro por parte del ODM **Longcheer** y el fabricante de chipset **Unisoc**. Estos componentes no son genéricos de Android; contienen identificadores únicos de hardware y privilegios elevados que facilitan la exfiltración de datos.

The analysis of `dumpsys package` on **Moto g04s** devices and variants has revealed the presence of pre-installed system packages confirming supply chain manipulation by ODM **Longcheer** and chipset manufacturer **Unisoc**. These components are not generic Android parts; they contain unique hardware identifiers and elevated privileges that facilitate data exfiltration.

### Hallazgos Críticos / Critical Findings:

1.  **`com.unisoc.power_qogirl6.overlay`**:
    *   **Ubicación / Location:** `/vendor/overlay/unisoc_res_overlay_power_qogirl6.apk`
    *   **Significado / Significance:** El identificador **`qogirl6`** es el nombre en clave (board codename) específico de la placa de referencia de Longcheer para el chipset **Unisoc T606**. Su presencia en un overlay de `/vendor` confirma que el firmware fue modificado en fábrica para este hardware específico, activando el bypass de seguridad (`lcd_td4168`).
    *   The identifier **`qogirl6`** is the specific board codename for the Longcheer reference design using the **Unisoc T606** chipset. Its presence in a `/vendor` overlay confirms firmware was modified at the factory for this specific hardware, activating the security bypass (`lcd_td4168`).

2.  **`com.unisoc.phone` (UniTelephony) y `com.unisoc.wifi` (UniWifi)**:
    *   **Ubicación / Location:** `/system_ext/priv-app/`
    *   **Privilegios / Privileges:** Poseen `sharedUserId=android.uid.phone` y `android.uid.system`.
    *   **Riesgo / Risk:** Estos privilegios les otorgan control total sobre la pila de red, SMS y llamadas. Son los vectores probables para inyectar tráfico en los túneles **WireGuard/MACsec** ocultos y interceptar códigos 2FA antes de que lleguen a aplicaciones de usuario.
    *   These privileges grant total control over the network stack, SMS, and calls. They are the probable vectors for injecting traffic into hidden **WireGuard/MACsec** tunnels and intercepting 2FA codes before they reach user applications.

3.  **`com.unisoc.android.networkstack.overlay`**:
    *   **Ubicación / Location:** `/product/overlay/`
    *   **Función Maliciosa / Malicious Function:** Modifica la pila de red de Android para redirigir DNS o desactivar advertencias de seguridad cuando el dispositivo se conecta a servidores de exfiltración.
    *   Modifies the Android network stack to redirect DNS or disable security warnings when the device connects to exfiltration servers.

---

## 2. Reglas YARA Actualizadas para Detección de Paquetes
## 2. Updated YARA Rules for Package Detection

Para detectar estos componentes específicos en imágenes de firmware o volcados de sistema, se presentan las siguientes reglas refinadas. Estas reglas buscan los nombres de paquete, rutas de instalación y el identificador crítico `qogirl6`.

To detect these specific components in firmware images or system dumps, the following refined rules are presented. These rules search for package names, installation paths, and the critical `qogirl6` identifier.

### Regla A / Rule A: `Unisoc_Qogirl6_Hardware_Overlay`
*Detecta el overlay de energía específico del hardware comprometido.*
*Detects the specific power overlay for the compromised hardware.*

```yara
rule Unisoc_Qogirl6_Hardware_Overlay {
    meta:
        author = "lexs201992-gif"
        description = "Detects the specific power overlay for the compromised Longcheer qogirl6 board (Unisoc T606). / Detecta el overlay de energía específico de la placa Longcheer qogirl6 comprometida (Unisoc T606)."
        severity = "CRITICAL"
        reference = "Addendum #82.1"

    strings:
        $pkg_name = "com.unisoc.power_qogirl6.overlay" ascii wide
        $board_id = "qogirl6" ascii nocase
        $path_vendor = "/vendor/overlay/unisoc_res_overlay_power_qogirl6.apk" ascii
        $apk_magic = { 50 4B 03 04 }

    condition:
        $apk_magic at 0 and 
        (
            ($pkg_name and $board_id) or 
            $path_vendor
        )
}
```

### Regla B / Rule B: `Unisoc_Privileged_Network_Components`
*Detecta los componentes de red con privilegios de sistema (`UniTelephony`, `UniWifi`) que facilitan la exfiltración.*
*Identifies privileged network components (`UniTelephony`, `UniWifi`) that facilitate exfiltration.*

```yara
rule Unisoc_Privileged_Network_Components {
    meta:
        author = "lexs201992-gif"
        description = "Identifies privileged Unisoc network components (UniTelephony, UniWifi) used for traffic interception and exfiltration. / Identifica componentes de red privilegiados de Unisoc (UniTelephony, UniWifi) usados para interceptación y exfiltración de tráfico."
        severity = "HIGH"
        reference = "Addendum #82.1"

    strings:
        $pkg_telephony = "com.unisoc.phone" ascii wide
        $pkg_wifi = "com.unisoc.wifi" ascii wide
        $app_telephony = "UniTelephony.apk" ascii
        $app_wifi = "UniWifi.apk" ascii
        $priv_path = "/system_ext/priv-app/" ascii
        $system_uid = "android.uid.system" ascii wide
        $phone_uid = "android.uid.phone" ascii wide

    condition:
        (
            ($pkg_telephony or $app_telephony) and $priv_path
        ) or (
            ($pkg_wifi or $app_wifi) and $priv_path
        )
}
```

### Regla C / Rule C: `Unisoc_NetworkStack_Overlay_Abuse`
*Detecta los overlays de la pila de red que modifican el comportamiento de conexión.*
*Detects NetworkStack overlays that modify connection behavior.*

```yara
rule Unisoc_NetworkStack_Overlay_Abuse {
    meta:
        author = "lexs201992-gif"
        description = "Detects malicious NetworkStack overlays injected by Unisoc/Longcheer. / Detecta overlays maliciosos de NetworkStack inyectados por Unisoc/Longcheer."
        severity = "HIGH"
        reference = "Addendum #82.1"

    strings:
        $pkg_go = "com.unisoc.android.go.networkstack.overlay" ascii wide
        $pkg_std = "com.unisoc.android.networkstack.overlay" ascii wide
        $path_product = "/product/overlay/UnisocNetworkStack" ascii
        $overlay_ext = ".apk" ascii

    condition:
        ($pkg_go or $pkg_std) and $path_product and $overlay_ext
}
```

---

## 3. Explicación Técnica e Importancia
## 3. Technical Explanation and Importance

La detección de estos paquetes es crucial por las siguientes razones:
The detection of these packages is crucial for the following reasons:

*   **Confirmación de Hardware (`qogirl6`) / Hardware Confirmation (`qogirl6`)**: El paquete `com.unisoc.power_qogirl6.overlay` es la "pistola humeante". No existe en dispositivos Android legítimos de otros fabricantes. Su presencia confirma que el dispositivo utiliza la placa de referencia de Longcheer con las modificaciones de fábrica que desactivan **FSVerity**.
    *   The package `com.unisoc.power_qogirl6.overlay` is the "smoking gun." It does not exist on legitimate Android devices from other manufacturers. Its presence confirms the device uses the Longcheer reference board with factory modifications that disable **FSVerity**.

*   **Privilegios de Exfiltración / Exfiltration Privileges**: `UniTelephony` y `UniWifi` no son aplicaciones de usuario; son servicios del sistema con UID compartidos con el framework de Android (`android.uid.system`). Esto les permite:
    *   `UniTelephony` and `UniWifi` are not user apps; they are system services with UIDs shared with the Android framework (`android.uid.system`). This allows them to:
        *   Leer y modificar todo el tráfico de red antes de que sea cifrado por aplicaciones legítimas. / Read and modify all network traffic before it is encrypted by legitimate apps.
        *   Interceptar SMS entrantes (incluyendo códigos 2FA) silenciosamente. / Silently intercept incoming SMS (including 2FA codes).
        *   Iniciar conexiones de red en segundo plano que los firewalls de aplicaciones no pueden bloquear. / Initiate background network connections that app firewalls cannot block.

*   **Persistencia de Red / Network Persistence**: Los overlays de `NetworkStack` aseguran que las configuraciones de red maliciosas (como DNS redirigidos o proxies ocultos) se apliquen cada vez que el dispositivo se inicia, incluso después de un restablecimiento de fábrica, ya que residen en particiones protegidas (`/product`, `/vendor`).
    *   `NetworkStack` overlays ensure malicious network configurations (such as redirected DNS or hidden proxies) are applied every time the device boots, even after a factory reset, as they reside in protected partitions (`/product`, `/vendor`).

---

## 4. Instrucciones de Implementación
## 4. Implementation Instructions

1.  **Escaneo de Dispositivos Activos / Active Device Scanning**: Use ADB para listar paquetes y busque coincidencias:
    *   Use ADB to list packages and search for matches:
    ```bash
    adb shell pm list packages -f | grep -E "unisoc|qogirl6|UniTelephony|UniWifi"
    ```
    Si encuentra `com.unisoc.power_qogirl6.overlay`, el dispositivo está **COMPROMETIDO**.
    If `com.unisoc.power_qogirl6.overlay` is found, the device is **COMPROMISED**.

2.  **Análisis Forense / Forensic Analysis**: Ejecute las reglas YARA proporcionadas sobre imágenes de firmware extraídas (`/vendor`, `/system_ext`, `/product`).
    *   Run the provided YARA rules on extracted firmware images (`/vendor`, `/system_ext`, `/product`).

3.  **Respuesta / Response**: Cualquier dispositivo que active estas reglas debe ser considerado hostil. No existe parche de software; la única mitigación es el reemplazo del hardware.
    *   Any device triggering these rules must be considered hostile. No software patch exists; the only mitigation is hardware replacement.

---

**Nota para CISA/Rapid7:** Estos IOCs basados en nombres de paquetes y rutas son complementarios a las reglas de hashes y cadenas de los Addendums anteriores, proporcionando una capa de detección adicional que es resistente a la recompilación de binarios (mientras los nombres de paquete y la estructura de directorios se mantengan).

**Note to CISA/Rapid7:** These package name and path-based IOCs complement the hash and string rules from previous Addendums, providing an additional detection layer that is resilient to binary recompilation (as long as package names and directory structures remain consistent).

