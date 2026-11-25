import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/bin.ts", "src/index.ts"],
  format: ["esm"],
  target: "node18",
  clean: true,
  splitting: false,
  banner: { js: "#!/usr/bin/env node" },
});
