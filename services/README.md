# IAM services catalog

A catalog of services and associated privileges for each service.

## Scope score

Each service has an associated scope rating, indicating the potential
scope of an attack on the service:

- **CRITICAL**: The service potentially contains sensitive data from a
  significant fraction of organizational functions, interruption of
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

## Schema

Privileges are grouped within the catalog file system by service. Additional
directory nesting indicates subservices; within these directories each
privilege component is referenced with a single file in YAML format.

Each component has the following data:

- **name**: A human-readable name for the component
- **description**: A description of the component indicating its typical uses
- **scope**: One of the above scope ratings, indicating the generally applicable
  broadest scope of the component when used fully within a production
  environment
- **notes**: Any additional notes; these should indicate any reasoning behind
  assignment of the scope score
- **privileges**: Privileges available on the component; this is an object where
  each key is the privilege's identifier within the component, and each value
  obeys the following schema:
  - **vulnerabilities**: An array of vulnerabilities described within this catalog
  - **scope**: If present, overrides the component-wide scope; used, for example,
    when read privileges have differing scope from write privileges (such as DNS
    records, public web assets, SSL certificates, and the like)
  - **notes**: If present, any additional notes specific to this privilege; these
    should explain any scope override
  - **links**: If present, an array of additional links
- **links**: An array of external-reference URLs

Note that privilege identifiers are determined on a per-service basis from the
component's location on the file system and the privilege's key. For example,
GCP privileges are identified by combining component path elements (excluding
the file extension) with the privilege's key, then joining these with a `.`.
So privilege `create` within `services/gcp/storage/objects.yml` has key
`storage.objects.create`.
