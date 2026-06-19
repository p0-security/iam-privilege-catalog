# Batch 2: escalation:privilege

**77 operations**

## Category

Privilege escalation — gaining higher-privilege identity access

## Severity

- Microsoft.ContainerService/managedClusters/serviceaccounts/impersonate/action
- Microsoft.ContainerService/managedClusters/serviceaccounts/write
- Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings/write
- Microsoft.ContainerService/managedClusters/users/impersonate/action
- Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write
  ... and 72 more

## Review notes

- All ops in this batch carry `escalation:privilege` risk
- Review for correct classification and completeness
