import express, { Express } from "express";
import { apiRouter } from "./apiRouter.js";

export function createDevApiApp(): Express {
  const app = express();
  app.use(express.json({ limit: "10mb" }));
  app.use("/api", apiRouter);
  return app;
}
