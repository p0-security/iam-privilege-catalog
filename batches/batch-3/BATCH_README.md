# Batch 3: takeover:account

**70 operations**

## Category

Account takeover — exporting account credentials

## Severity

- Microsoft.ApiManagement/service/clientApplications/listSecrets/action
- Microsoft.ApiManagement/service/users/keys/read
- Microsoft.ContainerRegistry/registries/listCredentials/action
- Microsoft.ContainerService/aiManagers/listCredential/action
- Microsoft.ContainerService/aiManagers/secrets/read
  ... and 65 more

## Review notes

- All ops in this batch carry `takeover:account` risk
- Review for correct classification and completeness
