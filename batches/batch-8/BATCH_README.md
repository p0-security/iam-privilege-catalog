# Batch 8: persistence:account

**44 operations**

## Category

Account persistence — creating backdoor accounts

## Severity

- Microsoft.ApiManagement/service/tenants/keys/regeneratePrimaryKey/action
- Microsoft.ApiManagement/service/tenants/keys/regenerateSecondaryKey/action
- Microsoft.ApiManagement/service/tenants/keys/write
- Microsoft.ContainerService/aiManagers/secrets/write
- Microsoft.ContainerService/fleets/members/secrets/write
  ... and 39 more

## Review notes

- All ops in this batch carry `persistence:account` risk
- Review for correct classification and completeness
