Field-Validated Manual Mitigation: The "Telcel Blue APN" Method
Mitigación Manual Validada en Campo: Método "APN Azul Telcel"
English: Researcher lexs201992-gif has validated a manual network configuration that successfully bypasses the compromised OMA CP provisioning chain on Unisoc T606/T616 devices in Mexico. This method forces the device to ignore malicious automatic configurations (Cyan) in favor of user-defined secure profiles (Blue).

he validado una configuración de red manual que bypassa exitosamente la cadena de provisionamiento OMA CP comprometida en dispositivos Unisoc T606/T616 en México. Este método fuerza al dispositivo a ignorar configuraciones automáticas maliciosas (Cyan) a favor de perfiles seguros definidos por el usuario (Azul). 

Step-by-Step Containment | Paso a Paso de Contención
Delete Automatic APNs: Remove all APNs labeled with "Telcel" that were automatically provisioned (often marked with a Cyan/Light Blue dot). These may contain injected proxy or mmsc parameters from the OMA CP exploit.
Eliminar APNs Automáticos: Borrar todas las APNs etiquetadas como "Telcel" provisionadas automáticamente (punto Cyan/Azul Claro). Pueden contener parámetros proxy o mmsc inyectados.
Create Manual "Blue" APN: Add a new APN with the following strict parameters to force PAP Authentication and bypass default IMS routing.
Crear APN "Azul" Manual: Añadir nueva APN con parámetros estrictos para forzar Autenticación PAP y bypassear ruteo IMS por defecto.
Name: Telcel Secure Manual
APN: internet.itelcel.com
Username: webgprs
Password: webgprs2002
Authentication Type: PAP (Critical: Do not leave as 'None' or 'Default')
APN Type: default,supl (Exclude 'ims' or 'mms' if not needed to reduce attack surface)
Protocol: IPv4 (Avoid IPv6 if not strictly required to simplify inspection)
Network Selection: Manually select "Telmex" or "Telcel" network operator instead of "Automatic". Connect to a local tower (e.g., Telmex local antenna) to avoid roaming partners that might re-trigger OMA CP.
Selección de Red: Seleccionar manualmente operador "Telmex" o "Telcel" en lugar de "Automático".
Verification: Ensure the APN indicator dot is Dark Blue/Black (User Defined), not Cyan (System Defined).
Verificación: Asegurar que el indicador de la APN sea Azul Oscuro/Negro (Definida por Usuario), no Cyan. 
Why It Works | Por Qué Funciona
Breaks the Chain: The Unisoc OMA CP exploit relies on the system trusting the automatically provisioned APN (com.sprd.omacp writing to telephony.db). Manual APNs with PAP credentials override this trust.
Blocks STK Exfiltration: SIM Toolkit commands often fail to exfiltrate data when the data bearer requires explicit PAP authentication that the STK command does not provide.
IMS Bypass: Forcing a manual data profile prevents the vulnerable Spreadtrum IMS service from automatically negotiating a compromised VoLTE/VoWiFi path. 
