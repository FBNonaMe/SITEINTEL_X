
import { GoogleGenAI } from "@google/genai";
import { SiteAnalysisData, ScanMode } from "../types";

export const analyzeSite = async (url: string, mode: ScanMode): Promise<SiteAnalysisData> => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API Key not found. Please check your environment configuration.");
  }

  const ai = new GoogleGenAI({ apiKey });

  const systemInstruction = `
    You are 'SiteIntel-X', an advanced offensive cybersecurity reconnaissance AI. 
    Your goal is to perform deep analysis on target websites using Google Search for real-time threat intelligence.
    
    MODES:
    1. PASSIVE: Non-intrusive. Focus on SEO, public reputation, tech stack, and SSL info.
    2. AGGRESSIVE: Offensive simulation. Focus on subdomain enumeration, potential vulnerability inference (CVEs), hidden directories, and API exposures.

    API SECURITY SUITE (AGGRESSIVE MODE):
    When in AGGRESSIVE mode, you must specifically analyze:
    - BOLA/IDOR: Infer potential Broken Object Level Authorization by looking for sequential IDs in public URLs (e.g., /api/users/101).
    - Auth Bypass: Check for exposed admin routes or documentation indicating weak auth.
    - Rate Limiting: Infer lack of rate limiting based on technology stack (e.g., default Express/Flask configs) or public bug bounty reports.

    OUTPUT INSTRUCTION:
    You MUST strictly return the result as a valid JSON object. 
    Do not add Markdown formatting (like \`\`\`json). Just return the raw JSON if possible.
    If you must include text, ensure the JSON is distinct and parseable.

    JSON STRUCTURE:
    {
      "summary": "Executive summary of the security posture.",
      "targetIp": "Likely IP or 'Hidden behind CDN'",
      "techStack": ["string", "string"],
      "reputationScore": number (0-100),
      "securityGrade": "string (A, B, C, D, F)",
      "subdomains": ["string", "string"],
      "hiddenDirectories": ["/path1", "/path2"],
      "openPorts": [
        {"port": number, "service": "string", "status": "OPEN", "version": "string"}
      ],
      "vulnerabilities": [
        {
          "id": "string (e.g., CVE-2023-XXXX)",
          "name": "string",
          "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
          "description": "string",
          "location": "string"
        }
      ],
      "securityHeaders": [
        {"name": "X-Frame-Options", "value": "string", "status": "SECURE|MISSING|WEAK"}
      ],
      "sslInfo": {
        "issuer": "string",
        "validTo": "string",
        "grade": "string"
      },
      "apiSecurity": ["BOLA: Potential IDOR at /users/:id", "Rate Limit: Missing on login endpoint"],
      "apiEndpoints": ["/api/v1/users", "/auth/login", "/graphql"],
      "cloudConfig": ["string notes"],
      "graphql": boolean
    }
  `;

  const userPrompt = `
    TARGET: "${url}"
    SCAN_MODE: ${mode}

    INSTRUCTIONS:
    1. Use the 'googleSearch' tool to find real-time information about this domain.
    2. Look for subdomains (e.g., site:*.${url}).
    3. Look for exposed files or directories (e.g., site:${url} inurl:admin, inurl:dashboard).
    4. Infer open ports based on the technology stack found (e.g., if PHP/Apache is found, assume port 80/443; if Node.js, maybe 3000/8080).
    5. Search for known vulnerabilities (CVEs) associated with the detected software versions.
    
    ${mode === ScanMode.AGGRESSIVE ? `
    6. EXECUTE API SECURITY SUITE:
       - Detect BOLA/IDOR: Look for API patterns like /users/{id} or /orders/{id} in search results.
       - Auth Bypass: Search for exposed admin panels, 'test' users, or unprotected API routes.
       - Rate Limiting: Check if the tech stack (e.g., bare Express/Flask/Nginx default) suggests missing rate limits.
       - Discovery: List all found API endpoints in the 'apiEndpoints' array.
    ` : ''}

    7. Return ONLY the JSON object.
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: userPrompt,
      config: {
        systemInstruction: systemInstruction,
        tools: [{ googleSearch: {} }],
      },
    });

    let text = response.text;
    if (!text) {
        if (response.candidates && response.candidates[0] && response.candidates[0].content && response.candidates[0].content.parts) {
             const parts = response.candidates[0].content.parts;
             const textPart = parts.find(p => p.text);
             if (textPart && textPart.text) {
                 text = textPart.text;
             }
        }
        
        if (!text) throw new Error("AI returned empty response.");
    }

    // Clean up potential markdown formatting
    text = text.trim();
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      text = jsonMatch[0];
    } else {
        console.warn("No JSON block found in response, attempting to parse raw text:", text);
    }

    const data = JSON.parse(text) as SiteAnalysisData;
    return data;

  } catch (error) {
    console.error("Analysis failed:", error);
    throw new Error("Scan failed. The target might be blocking requests or the AI encountered an error.");
  }
};
