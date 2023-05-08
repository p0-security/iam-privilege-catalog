#!/usr/bin/env ts-node

import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as yaml from "yaml";
import { size, omit, sum, sortBy, pick } from "lodash";
import { sys } from "typescript";

const ROOT = path.resolve(__dirname, "..");
const OUTPUT_PATH = "dist";
const VULNERABILITIES_FOLDER = "vulnerabilities";
const SERVICES_FOLDER = "services";

const SERVICE_IDS = {
  gcp: (path: string, key: string) => `${path.replace(/\//g, ".")}.${key}`,
};

let exitFlag = 0;

const recursiveRead = async (
  base: string,
  location: string,
  cb: (data: any, file: string) => Promise<void>
) => {
  for (const c of await fs.readdir(location)) {
    const file = path.join(location, c);
    const stat = await fs.stat(file);
    if (stat.isFile() && file.endsWith(".yml")) {
      const buffer = await fs.readFile(file, { encoding: "utf-8" });
      try {
        const data = yaml.parse(buffer);
        await cb(data, file);
      } catch (error: any) {
        if (error instanceof yaml.YAMLParseError) {
          console.warn(`${error.message}\n${file}`);
        }
      }
      continue;
    }
    if (stat.isDirectory()) {
      await recursiveRead(base, file, cb);
    }
  }
};

const generateVulns = async (base: string) => {
  const model: Record<string, any>[] = [];
  await recursiveRead(base, base, async (data, file) => {
    const id = path.relative(base, file).replace("/", ":").slice(0, -4);
    model.push({ id, ...data });
  });
  await fs.mkdir(OUTPUT_PATH, { recursive: true });
  await fs.writeFile(
    path.join(OUTPUT_PATH, "vulnerabilities.json"),
    JSON.stringify(model, undefined, 2),
    { encoding: "utf-8" }
  );
  console.log(`Wrote ${size(model)} vulnerabilities`);
  return model;
};

const generateVulnMd = async (model: Record<string, any>[]) => {
  const sorted = sortBy(model, (m) => m.id);
  const header = `# Vulnerability reference

`;
  const texts = sorted.map(
    (m) => `
#### \`${m.id}\` - ${m.name}

*Risk*: \`${m.risk}\`

${m.description}

*Mitigations*:
${
  m.mitigations?.map((m: any) => `- ${m}`).join("\n") ??
  "(no mitigations for this vulnerability)"
}

*Links*:
${
  m.links?.map((m: any) => `- ${m}`).join("\n") ??
  "(no links for this vulnerability)"
}
`
  );
  const all = header + texts.join("\n\n");

  await fs.mkdir(OUTPUT_PATH, { recursive: true });
  await fs.writeFile(path.join(OUTPUT_PATH, "vulnerabilities.md"), all, {
    encoding: "utf-8",
  });
};

const privilegeToMd = (privilege: Record<string, any>) =>
  `
### ${privilege.name}

${privilege.parent.description}

*Notes*:
${privilege.parent.notes ?? "(no notes for this component)"}

### \`${privilege.id}\`

*Scope*: \`${privilege.scope}\`

${privilege.description ? `${privilege.description}\n\n` : ""}*Vulnerabilities*:
${
  (privilege.vulnerabilities?.length ?? 0) > 0
    ? privilege.vulnerabilities?.map((v: any) => `- \`${v}\``).join("\n")
    : "(no known vulnerabilities for this privilege)"
}

*Notes*:
${privilege.notes ?? "(no notes for this privilege)"}

*Links*:
${
  (privilege.links?.length ?? 0) > 0
    ? privilege.links.map((v: any) => `- ${v}`).join("\n")
    : "(no links for this privilege)"
}
`.trim();

const generatePrivileges = async (base: string, vulnerabilities: string[]) => {
  const model: Record<string, Record<string, any>[]> = {};
  await fs.mkdir(OUTPUT_PATH, { recursive: true });
  for (const sid of Object.keys(SERVICE_IDS)) {
    model[sid] = [];
    const serviceBase = path.join(base, sid);
    await recursiveRead(serviceBase, serviceBase, async (data, file) => {
      const privileges = data.privileges as Record<string, any>;
      for (const [key, value] of Object.entries(privileges)) {
        if (!value) {
          console.warn(`Null privilege at ${path.relative(ROOT, file)}:${key}`);
          exitFlag |= 2;
          continue;
        }
        for (const vuln of value.vulnerabilities) {
          if (!vulnerabilities.includes(vuln)) {
            console.warn(
              `Missing vulnerability ${vuln} at ${path.relative(
                ROOT,
                file
              )} ${key}`
            );
            exitFlag |= 4;
          }
        }
        const pData = {
          ...omit(data, "description", "notes", "privileges"),
          ...value,
          parent: pick(data, "description", "notes", "privileges"),
          links: [...(data.links ?? []), ...(value.links ?? [])],
        };
        const id = SERVICE_IDS[sid as keyof typeof SERVICE_IDS](
          path.relative(serviceBase, file).slice(0, -4),
          key
        );
        model[sid].push({ id, ...pData });
      }
      await fs.mkdir(`${OUTPUT_PATH}/${sid}`, { recursive: true });
      for (const priv of model[sid]) {
        await fs.writeFile(
          path.join(OUTPUT_PATH, sid, `${priv.id}.md`),
          privilegeToMd(priv),
          { encoding: "utf-8" }
        );
      }
    });
  }
  await fs.writeFile(
    path.join(OUTPUT_PATH, "privileges.json"),
    JSON.stringify(model, undefined, 2),
    { encoding: "utf-8" }
  );
  console.log(
    `Wrote ${sum(Object.values(model).map((m) => size(m)))} privileges`
  );
};

void (async () => {
  const vulns = await generateVulns(path.join(ROOT, VULNERABILITIES_FOLDER));
  await generatePrivileges(
    path.join(ROOT, SERVICES_FOLDER),
    vulns.map((v) => v.id)
  );
  await generateVulnMd(vulns);
  sys.exit(exitFlag);
})().catch(console.error);
