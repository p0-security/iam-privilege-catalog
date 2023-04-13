# IAM services catalog

A catalog of services and associated privileges for each service.

## Scope score

Each service has an associated scope rating, indicating the potential
scope of an attack on the service:

- **CRITICAL**: The service potentially contains sensitive data from a
  signficant fraction of organizational functions, interruption of
  the service would interrupt the main function of the organization,
  or exploit of the system could lead to significant privilege escalation.
  Examples include data warehouses, application workloads, and IAM controls.
- **HIGH**: The service potentially contains sensitive data from a single
  organizational function, or interruption of the service would prevent an
  organizational department from functioning. Examples include
  machine-learning backends and HRMS systems.
- **MEDIUM**: The service contains confidential data, or interruption
  of the service would incur operational cost. Examples include internal
  resource inventories.
- **LOW**: The service contains data that are not meant to be public,
  but are otherwise not sensitive. Examples include billing histories
  and API quota usage.
- **PUBLIC**: The service contains data that are meant to
  be public. Examples include DNS read privileges.

In addition to the service scope rating, individual service privileges may
have higher or lower ratings. For instance, read privileges on public data
will likely have a PUBLIC rating, but write permissions on the same data
can have a CRITICAL rating (e.g., for DNS configuration).
