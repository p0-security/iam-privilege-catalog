# IAM vulnerabilities catalog

A catalog of potential IAM privilege abuses.

This is primarily inspired by the [MITRE ATT&CK Matrix for infrastructure-as-a-service](https://attack.mitre.org/matrices/enterprise/cloud/iaas/).

## Risk scores

Each vulnerability is tagged with a risk score. This score indicates the risk associated
with exploit independent of the size and scope of the system exploited, or the sensitivity
of the exploited system.

- **CRITICAL**: Used alone, has the potential to disrupt central organizational operations,
  destroy trust, or create significant liability. Additionally, includes vulnerabilities
  that give attackers access to broadly provisioned identities that enable the above impacts
  (such as root privilege escalation vulnerabilites).
- **HIGH**: Used alone, has the potential to disrupt ancillary organization operations,
  cause reputational damage, or run afoul of compliance requirements.
- **MEDIUM**: Used alone, has the potential to create operational burden or monetary costs,
  or access organizational secrets.
- **BOOST**: Allows an attacker to significantly increase the scope of an attack, or the
  sensitivity of accessed systems. Includes automated collection and lateral movement
  vulnerabilities.
- **EVASION**: Allows an attacker to evade detection, allowing the attacker to exploit
  additional vulnerabilites without detection, and prevent exploit remediation.
- **LOW**: Assists in additional attacks, or gains access to confidential data that do not
  create organizational risk on their own.

## Schema

Each vulnerability entry has the following data:

- **id**: Inferred in this catalog by the path to the entry. E.g., `/destruction/data.yml`
  has the identifier `destruction:data`.
- **name**: A human-readable name for the vulnerability.
- **description**: An in-depth description of the vulnerability, describing:
  - Details of the vulnerability
  - The impact of exploiting the vulnerability
  - How the risk depends on the scope and sensitivity of the exploited system / component
- **risk**: The vulnerabilities risk score. For vulnerabilities where more than one
  score may apply, the highest-risk score is applied (e.g. if EVASION and LOW both apply,
  the score will be EVASION).
- **mitigations**: Potential steps that an organization can take to lower the impact of
  exploit.
- **links**: External links to further reading and references.
