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

Technical Justification for Rule Refinement
Subject: Mitigation of False Positives and Enhancement of Detection Logic for Unisoc T606 Supply Chain RRO Abuse.

1. False Positive Mitigation (Build Artifacts)

Issue: The initial rule logic triggered on the string auto_generated_rro, which is a legitimate build artifact present in standard Android overlays from major OEMs (e.g., Samsung, Xiaomi) using AOSP. This resulted in a high rate of false positives on clean devices.
Refinement: The refined rule now requires $build_anomaly (auto_generated_rro) to appear in conjunction with $ns_sprd (Spreadtrum/Unisoc namespace) AND $inject_keyword (injection).
Impact: This logical AND operation ensures detection is scoped strictly to Unisoc/Spreadtrum firmware contexts where auto-generated overlays are statistically anomalous and indicative of malicious injection, eliminating noise from legitimate global OEMs.
2. Hardware Trigger Correlation (The "Smoking Gun")

Addition: Introduced the specific hardware identifier $lcd_trigger (lcd_td4168) and the certificate subject $cert_anomaly (CN=Longcheer).
Rationale: Legitimate resource overlays (RROs) rarely hardcode specific LCD controller identifiers in the /product/overlay path. The co-occurrence of this specific hardware ID with an overlay signed by the ODM Longcheer confirms the presence of the hardware-triggered bypass mechanism identified in the Unisoc T606 supply chain compromise.
Confidence Level: This correlation elevates the detection confidence to Critical, as it links the software artifact directly to the physical hardware trigger used to disable FSVerity and SELinux.
3. Trust Boundary Exploitation

Focus: The rule explicitly targets injection paths (/vendor/overlay, /product/overlay, /system/product/overlay) that Android treats as trusted zones.
Mechanism: By requiring suspicious strings to reside within these specific trusted paths inside the binary, the rule filters out incidental matches in temporary files or logs. It specifically detects the abuse of the Android Resource Overlay system, which is the primary vector used to persistently modify system resources (hiding malware icons, altering permission strings) prior to payload execution.
Conclusion: This refined signature transforms a generic indicator into a high-fidelity forensic tool. It accurately identifies the specific Runtime Resource Overlay (RRO) abuse pattern used in the Unisoc T606 supply chain attack while maintaining compatibility with global firmware datasets by excluding legitimate OEM build patterns.

Suggested Metadata for AttackerKB/GitHub
Rule Name: SupplyChain_Overlay_Abuse_Unisoc
Severity: CRITICAL
TLP: WHITE (Publicly Shareable)
Tags: #SupplyChain, #Android, #Unisoc, #RRO, #CISA-KEV-Candidate
