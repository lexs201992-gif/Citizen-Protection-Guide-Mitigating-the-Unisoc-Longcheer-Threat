
Addendum #82.2: Carrier Injection & Input Interception (Telcel & TsGestures)
Addendum #82.2: Inyección de Operador e Intercepción de Entrada (Telcel y TsGestures)
Fecha / Date: 10 de julio de 2026 / July 10, 2026
Autor / Author: lexs201992-gif
Severidad / Severity: CRÍTICA / CRITICAL

1. Hallazgo: Colusión entre Vulnerabilidad de Hardware y Bloatware de Operador
1. Finding: Collusion between Hardware Vulnerability and Carrier Bloatware
La presencia de com.telcel.contenedor en /system/priv-app/ en un dispositivo con chipset Unisoc T606 comprometido representa un riesgo multiplicador. La vulnerabilidad de cadena de suministro (que desactiva FSVerity) permite que este contenedor de operador instale aplicaciones maliciosas sin que el sistema operativo pueda verificar su integridad.

The presence of com.telcel.contenedor in /system/priv-app/ on a device with a compromised Unisoc T606 chipset represents a multiplier risk. The supply chain vulnerability (which disables FSVerity) allows this carrier container to install malicious applications without the OS being able to verify their integrity.

Vector de Ataque / Attack Vector: Telcel Contenedor actúa como un "caballo de Troya" legítimo. Puede descargar e instalar actualizaciones de aplicaciones que, en un dispositivo limpio, serían bloqueadas, pero que en este entorno comprometido pueden ser reemplazadas por versiones con troyanos bancarios.
Telcel Contenedor acts as a legitimate "Trojan Horse." It can download and install app updates which, on a clean device, would be blocked, but in this compromised environment can be replaced with versions containing banking trojans.
2. Hallazgo: Capacidad Nativa de Keylogging (TsGestures)
2. Finding: Native Keylogging Capability (TsGestures)
El paquete com.ts.tsgestures (TsGestures.apk) es un controlador de gestos táctiles preinstalado en la partición /system/. Su presencia confirma que el fabricante del dispositivo (ODM) ha integrado controladores de entrada de terceros con privilegios de root.

The package com.ts.tsgestures (TsGestures.apk) is a pre-installed touch gesture driver in the /system/ partition. Its presence confirms that the device manufacturer (ODM) has integrated third-party input drivers with root privileges.

Riesgo de Intercepción / Interception Risk: Este componente puede registrar coordenadas de pantalla (toques) antes de que lleguen a aplicaciones seguras (como teclados de bancos). Combinado con los túneles de exfiltración detectados en UniTelephony, esto permite el robo de patrones de desbloqueo y credenciales en tiempo real.
This component can record screen coordinates (touches) before they reach secure apps (like banking keyboards). Combined with the exfiltration tunnels detected in UniTelephony, this allows real-time theft of unlock patterns and credentials.
3. Reglas YARA Actualizadas / Updated YARA Rules
Regla D / Rule D: Carrier_Container_Privileged_Injector
rule Carrier_Container_Privileged_Injector {
    meta:
        author = "lexs201992-gif"
        description = "Detects carrier container apps (e.g., Telcel) with privileged system access capable of silent app installation on compromised hardware. / Detecta apps contenedor de operador (ej. Telcel) con acceso privilegiado capaces de instalación silenciosa en hardware comprometido."
        severity = "HIGH"
        reference = "Addendum #82.2"

    strings:
        $pkg_telcel = "com.telcel.contenedor" ascii wide
        $path_priv = "/system/priv-app/TelcelContenedor/" ascii
        $apk_name = "TelcelContenedor.apk" ascii

    condition:
        ($pkg_telcel or $apk_name) and $path_priv
}
Regla E / Rule E: Unisoc_Touch_Gesture_Driver
rule Unisoc_Touch_Gesture_Driver {
    meta:
        author = "lexs201992-gif"
        description = "Identifies third-party touch gesture drivers (TsGestures) with system privileges, potential keyloggers. / Identifica controladores de gestos táctiles de terceros (TsGestures) con privilegios de sistema, potenciales keyloggers."
        severity = "MEDIUM"
        reference = "Addendum #82.2"

    strings:
        $pkg_gesture = "com.ts.tsgestures" ascii wide
        $app_gesture = "TsGestures.apk" ascii
        $path_system = "/system/app/TsGestures/" ascii

    condition:
        ($pkg_gesture or $app_gesture) and $path_system
}
4. Conclusión Operativa / Operational Conclusion
La combinación de qogirl6 (hardware comprometido), UniTelephony (exfiltración de red), Telcel Contenedor (inyección de apps) y TsGestures (captura de entrada) confirma que el dispositivo Moto g04s analizado es una plataforma de vigilancia completa. No es solo un teléfono con vulnerabilidades; es un dispositivo diseñado para ser hostil hacia su usuario.

The combination of qogirl6 (compromised hardware), UniTelephony (network exfiltration), Telcel Contenedor (app injection), and TsGestures (input capture) confirms that the analyzed Moto g04s device is a complete surveillance platform. It is not just a phone with vulnerabilities; it is a device designed to be hostile towards its user.

Recomendación / Recommendation: Bloqueo inmediato de estos dispositivos en redes corporativas y gubernamentales. Prohibición de compra de equipos con esta combinación de ODM (Longcheer) + Operador (Telcel) + Chipset (Unisoc T606).
Immediate blocking of these devices on corporate and government networks. Ban on purchasing devices with this combination of ODM (Longcheer) + Carrier (Telcel) + Chipset (Unisoc T606).
