import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

// Ensure environment variables from .env are loaded into process.env
dotenv.config();

let cachedClient: GoogleGenAI | null = null;
let cachedApiKey: string | null = null;

export function getAiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY || process.env.API_KEY;
  if (!apiKey) {
    throw new Error(
      "GEMINI_API_KEY is not set. Please ensure GEMINI_API_KEY is defined in your .env file or environment variables."
    );
  }

  // Refresh client if API key changed or not yet instantiated
  if (!cachedClient || cachedApiKey !== apiKey) {
    cachedApiKey = apiKey;
    cachedClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }

  return cachedClient;
}

// Shared server-side Gemini client proxy with dynamic API key resolution
export const ai = new Proxy({} as GoogleGenAI, {
  get(_target, prop: string | symbol) {
    const client = getAiClient();
    const value = (client as any)[prop];
    if (typeof value === "function") {
      return value.bind(client);
    }
    return value;
  },
});

