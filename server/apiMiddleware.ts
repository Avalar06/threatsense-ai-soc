import express, { Express } from "express";
import { apiRouter } from "./apiRouter.js";

export function createDevApiApp(): Express {
  const app = express();
  app.use(express.json({ limit: "10mb" }));
  app.use("/api", apiRouter);

  // Catch-all 404 handler for unhandled /api requests to prevent falling through to Vite SPA
  app.use("/api", (_req, res) => {
    res.status(404).json({
      success: false,
      error: {
        code: "NOT_FOUND",
        message: "API endpoint not found",
      },
    });
  });

  return app;
}
