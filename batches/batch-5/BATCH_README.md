# Batch 5: exfiltration:crypto

**86 operations**

## Category

Cryptographic exfiltration — exporting keys/secrets

## Severity

- Microsoft.Web/Sites/functions/token/read
- Microsoft.Web/Sites/host/listKeys/action
- Microsoft.Web/Sites/hostruntime/functions/keys/read
- Microsoft.Web/Sites/hybridconnectionnamespaces/relays/listKeys/action
- Microsoft.Web/Sites/slots/config/appsettings/read
  ... and 81 more

## Review notes

- All ops in this batch carry `exfiltration:crypto` risk
- Review for correct classification and completeness
