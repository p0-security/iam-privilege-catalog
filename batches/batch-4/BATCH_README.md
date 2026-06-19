# Batch 4: exfiltration:crypto

**87 operations**

## Category

Cryptographic exfiltration — exporting keys/secrets

## Severity

- Microsoft.ApiManagement/service/authorizationServers/listSecrets/action
- Microsoft.ApiManagement/service/backends/listSecrets/action
- Microsoft.ApiManagement/service/gateways/generateToken/action
- Microsoft.ApiManagement/service/gateways/getConfiguration/action
- Microsoft.ApiManagement/service/gateways/keys/action
  ... and 82 more

## Review notes

- All ops in this batch carry `exfiltration:crypto` risk
- Review for correct classification and completeness
