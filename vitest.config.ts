import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The corpus, decoder-property and multibyte-window suites run the real
    // generated hook as a subprocess for every case, dozens of times per test.
    // On GitHub's 3-core macOS runner the slowest of them took 3.2 s under
    // vitest 2 and 6.7 s under vitest 5, so the 5 s default timeout turned
    // runner speed into a verdict. A hang still fails, at 30 s.
    testTimeout: 30_000,
  },
});
