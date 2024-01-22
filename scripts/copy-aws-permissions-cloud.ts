import { Dictionary, entries, mapValues, uniq } from "lodash";
import * as yaml from "yaml";
import * as fs from "node:fs/promises";

const RiskTagToRisk = {
  CredentialExposure: "exfiltration:crypto",
  DataAccess: "exfiltration:data",
  ResourceExposure: "destruction:policy",
  PrivEsc: "escalation:privilege",
} as const;

const AWS_SERVICE_PATH = "services/aws/-";

async function fetchDataset() {
  const fetch = (await import("node-fetch")).default;
  const response = await fetch(
    "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/tags.json"
  );
  const tags = (await response.json()) as any;
  return tags.iam;
}

function reorder(tags: Dictionary<string[]>) {
  const out: Dictionary<Set<string>> = {};
  for (const [tag, values] of entries(tags)) {
    for (const action of values) {
      out[action] ||= new Set();
      if (tag in RiskTagToRisk) {
        out[action].add(RiskTagToRisk[tag as keyof typeof RiskTagToRisk]);
      }
    }
  }
  return mapValues(out, (risks) => [...risks].sort());
}

async function writeAws() {
  const data = await fetchDataset();
  const tagData = reorder(data);

  const services: Dictionary<Dictionary<any>> = {};
  for (const [action, value] of entries(tagData)) {
    const [service, suffix] = action.split(":");
    services[service] ||= {};
    services[service][suffix] = { risks: value };
  }

  for (const [service, privileges] of entries(services)) {
    await fs.mkdir(AWS_SERVICE_PATH, { recursive: true });
    const sdata = {
      name: service,
      description: "Automatically imported from aws.permissions.cloud.",
      scope: "HIGH",
      notes:
        "The contents of this file were automatically generated using the data hosted on aws.permissions.cloud (see links).",
      links: [`https://aws.permissions.cloud/iam/${service}`],
      privileges: privileges,
    };
    const out = yaml.stringify(sdata, { sortMapEntries: true });
    await fs.writeFile(`${AWS_SERVICE_PATH}/${service}.yml`, out, {
      encoding: "utf-8",
    });
  }
}

void writeAws();
