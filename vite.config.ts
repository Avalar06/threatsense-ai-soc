import dotenv from 'dotenv';
dotenv.config();

import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, type Plugin } from 'vite';
import { createDevApiApp } from './server/apiMiddleware.js';

function apiServerPlugin(): Plugin {
  return {
    name: 'api-server-plugin',
    configureServer(server) {
      const apiApp = createDevApiApp();
      server.middlewares.use((req, res, next) => {
        if (req.url?.startsWith('/api')) {
          apiApp(req as any, res as any, (err?: any) => {
            if (err) {
              res.statusCode = 500;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({
                success: false,
                error: {
                  code: 'INTERNAL_ERROR',
                  message: err?.message || 'Internal server error',
                },
              }));
            } else {
              res.statusCode = 404;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({
                success: false,
                error: {
                  code: 'NOT_FOUND',
                  message: 'API endpoint not found',
                },
              }));
            }
          });
        } else {
          next();
        }
      });
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), apiServerPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
