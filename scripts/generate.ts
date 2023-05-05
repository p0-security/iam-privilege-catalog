#!/usr/bin/env ts-node

import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as yaml from "yaml";
import { size, omit, sum } from "lodash";
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
  cb: (data: any, file: string) => void
) => {
  for (const c of await fs.readdir(location)) {
    const file = path.join(location, c);
    const stat = await fs.stat(file);
    if (stat.isFile() && file.endsWith(".yml")) {
      const buffer = await fs.readFile(file, { encoding: "utf-8" });
      try {
        const data = yaml.parse(buffer);
        cb(data, file);
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
  await recursiveRead(base, base, (data, file) => {
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
  return model.map((v) => v.id);
};

const generatePrivileges = async (base: string, vulnerabilities: string[]) => {
  const model: Record<string, object[]> = {};
  for (const sid of Object.keys(SERVICE_IDS)) {
    model[sid] = [];
    const serviceBase = path.join(base, sid);
    await recursiveRead(serviceBase, serviceBase, (data, file) => {
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
          ...omit(data, "privileges"),
          ...value,
          notes: `${data.notes ?? ""}${
            value.notes ? "\n" + value.notes : ""
          }`.trim(),
          links: [...(data.links ?? []), ...(value.links ?? [])],
        };
        const id = SERVICE_IDS[sid as keyof typeof SERVICE_IDS](
          path.relative(serviceBase, file).slice(0, -4),
          key
        );
        model[sid].push({ id, ...pData });
      }
    });
  }
  await fs.mkdir(OUTPUT_PATH, { recursive: true });
  await fs.writeFile(
    path.join(OUTPUT_PATH, "privileges.json"),
    JSON.stringify(model, undefined, 2),
    { encoding: "utf-8" }
  );
  console.log(
    `Wrote ${sum(Object.values(model).map((m) => size(m)))} privileges`
  );
};

void generateVulns(path.join(ROOT, VULNERABILITIES_FOLDER))
  .then((vulns) => generatePrivileges(path.join(ROOT, SERVICES_FOLDER), vulns))
  .then(() => sys.exit(exitFlag))
  .catch(console.error);
