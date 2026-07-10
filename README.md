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
