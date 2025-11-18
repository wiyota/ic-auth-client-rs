import { defineConfig } from "vite";
import environment from "vite-plugin-environment";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    environment("all", { prefix: "CANISTER_", defineOn: `import.meta.env` }),]
});
