import type { Config } from "jest";

const config: Config = {
  preset: "ts-jest/presets/default-esm", // 👈 ESM + TS
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { useESM: true }],
  },
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1", // Fix TS import paths with .js in ESM
  },
};

export default config;
