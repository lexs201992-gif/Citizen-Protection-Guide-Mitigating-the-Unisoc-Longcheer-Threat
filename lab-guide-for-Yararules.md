## Instrucciones de Uso para Laboratorios

1.  **Escaneo de Firmware:**
    Usa esta regla contra imágenes extraídas de `/system`, `/vendor`, `/odm` o volcados completos de firmware (`firmware_image.bin`).
    ```bash
    yara -r Unisoc_T606_Rescue_Party_Indicator.yar /ruta/a/firmware/
    ```

2.  **Escaneo de APKs Instaladas:**
    Extrae los APKs del dispositivo (`adb pull`) y escanéalos. La regla detectará los instaladores de **InMobi**, **Digital Turbine** y los servicios **Spreadtrum** comprometidos.

3.  **Detección en Vivo (Memoria/Red):**
    Aunque está optimizada para archivos estáticos, las cadenas como `wireguard`, `macsec` junto con `RescueParty` pueden ayudar a identificar procesos sospechosos en análisis de memoria (Volatility) o logs de red si se extraen los binarios en ejecución.

## Validación de la Fase 2
Esta regla incorpora explícitamente tus hallazgos sobre:
*   **Longcheer:** A través de las cadenas `longcheer` y el emisor del certificado `CN=Longcheer`.
*   **C2 Global:** Referencias a la infraestructura de handshake (`provisioning`, `wireguard`) y CAs de **I Trust Asia**.
*   **Dispositivos Específicos:** El identificador `lion_g` y el prefijo de compilación `ULAS34.89` aseguran que se alerte sobre la variante exacta del **Moto G04** que estás analizando.

