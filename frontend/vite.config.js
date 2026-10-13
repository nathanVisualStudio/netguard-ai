import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const policy = "default-src 'self'; connect-src http://127.0.0.1:*; style-src 'self' 'unsafe-inline'; img-src 'self' data:"

const csp = {
  name: 'csp',
  apply: 'build',
  transformIndexHtml: (html) =>
    html.replace('</title>', `</title>\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`),
}

export default defineConfig({
  plugins: [react(), csp],
  base: './',
  build: { outDir: 'dist', emptyOutDir: true },
})
