# IAM risks catalog

A catalog of potential IAM privilege abuses.

This is primarily inspired by the [MITRE ATT&CK Matrix for infrastructure-as-a-service](https://attack.mitre.org/matrices/enterprise/cloud/iaas/).

## Risk scores

Each risk is tagged with a risk score. This score indicates the risk associated
with exploit independent of the size and scope of the system exploited, or the sensitivity
of the exploited system.

- **CRITICAL**: Assigned to risks that result in loss of data or policy control,
  such as exfiltration, escalation, and takeover risks.
- **HIGH**: Used alone, has the potential to disrupt organizational operations,
  cause reputational damage, or run afoul of compliance requirements.
- **MEDIUM**: Used alone, has the potential to create operational burden or monetary costs,
  or access organizational secrets.
- **BOOST**: Allows an attacker to significantly increase the scope of an attack, or the
  sensitivity of accessed systems. Includes automated collection and lateral movement risks.
- **EVASION**: Allows an attacker to evade detection, allowing the attacker to exploit
  additional risks without detection, and prevent exploit remediation.
- **LOW**: Assists in additional attacks, or gains access to confidential data that do not
  create organizational risk on their own.

## Schema

Each risk entry has the following data:

- **id**: Inferred in this catalog by the path to the entry. E.g., `/destruction/data.yml`
  has the identifier `destruction:data`.
- **name**: A human-readable name for the risk.
- **description**: An in-depth description of the risk, describing:
  - Details of the risk
  - The impact of exploiting the risk
  - How the risk depends on the scope and sensitivity of the exploited system / component
- **score**: The risk's score. For risks where more than one
  score may apply, the highest-risk score is applied (e.g. if EVASION and LOW both apply,
  the score will be EVASION).
- **mitigations**: Potential steps that an organization can take to lower the impact of
  exploit.
- **links**: External links to further reading and references.
