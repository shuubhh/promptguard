import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The JS scanner imports the shared pattern spec from ../scanner/spec.json
    // (outside the dashboard root), so allow serving files from the workspace root.
    fs: {
      allow: ['..']
    }
  }
});
