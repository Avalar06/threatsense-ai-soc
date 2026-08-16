import { GoogleGenAI } from "@google/genai";

// Shared server-side Gemini client utility with required telemetry header
export const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});
