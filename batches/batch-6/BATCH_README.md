# Batch 6: exfiltration:data

**88 operations**

## Category

Data exfiltration — exporting sensitive data

## Severity

- Microsoft.ContainerService/aiManagers/pods/exec/action
- Microsoft.ContainerService/fleets/admissionregistration.k8s.io/validatingwebhookconfigurations/write
- Microsoft.ContainerService/fleets/members/pods/exec/action
- Microsoft.ContainerService/managedClusters/pods/exec/action
- Microsoft.ContainerService/managedClusters/runCommand/action
  ... and 83 more

## Review notes

- All ops in this batch carry `exfiltration:data` risk
- Review for correct classification and completeness
