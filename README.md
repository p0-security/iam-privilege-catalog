# The P0 IAM privilege risk catalog

A mapping of IAM privileges in various systems to their potential risk of abuse.

When combined with details of how a system (and its services and components) are
used, this catalog can help identify the risk of compromised or abused identities
in an organization.

## How this catalog is organized

This catalog is broken into two main components:

1. A catalog of general privilege risks, with assigned risk ratings
2. A catalog of privileges in IAM systems, with details on potential abuses and scopes
   of impact

## How to use this catalog

This catalog has multiple intended purposes:

- Understand the security posture associated with a specific IAM configuration
- Determine the effect of an IAM configuration modification on organizational
  security posture
- Discover references detailing the security effects of specific privileges

### Viewing online

To view this catalog online, visit [p0.app/catalog](https://p0.app/catalog).

#### Example: account-compromise reach

As an example, consider using this catalog to understand the security posture
associated with an IAM configuration. A motivating question might be: what is
the potential reach of an attack wherein a single principal is compromised?

To answer this question:

1. Assemble all privileges that are granted to the account in question.
1. Map each privilege to the associated risks and scopes using this catalog.
1. For each resource reachable from the account, determine a scope. E.g.
   resources containing critical data should be assigned "CRITICAL", low-sensitivity
   resources should be assigned lower scores in accordance with the values in
   [services/README.md](https://github.com/p0-security/services/README.md).
1. Assemble the unique tuples of account, service, resource, and risks
   reachable from this account, assigning each tuple a scope score equal to the
   minimum of the resource's and the privilege's scope score.
1. For each tuple, assign a reach score by converting risks and scopes to numerical
   scores. One methodology may be to apply a Fibonnaci mapping, so, e.g.:
   1. For risk:
      ```
      CRITICAL = 5
      HIGH = 3
      MEDIUM = 2
      EVASION = 2
      BOOST = 2
      LOW = 1
      ```
   1. For scope:
      ```
      CRITICAL = 5
      HIGH = 3
      MEDIUM = 2
      LOW = 1
      ```
1. Construct a total reach score for each tuple by multiplying risk and scope scores:
   ```
   tuple.score_reach = tuple.score_risk * tuple.score_scope
   ```
1. Now assign a total reach score by summing each unique tuple's reach scores:
   ```
   score_reach = sum(tuples, t: t.score_reach)
   ```

### Extracting the catalog as JSON

A script is provided to convert the catalog to JSON format. To use this script:

1. Install [yarn](https://yarnpkg.com/) in your environment.
1. Run `yarn install`.
1. Run `yarn ts-node scripts/generate.ts`.
1. Generated JSON will be stored in `/dist`.

## Contributing

Contributions are welcome. By contributing you are agreeing to release your
contribution under this repository's [license](https://github.com/p0-security/iam-privilege-catalog/blob/main/LICENSE).
