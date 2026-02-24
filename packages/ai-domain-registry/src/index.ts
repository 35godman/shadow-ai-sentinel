import type { AiToolEntry, AiToolRiskLevel } from "@sentinel/shared-types";

// ============================================================
// Shadow AI Domain Registry
// Curated database of AI services for Shadow AI detection
// Updated: 2026-02 | Version: 1.0.0
//
// Risk Levels:
//   SAFE     - SOC2/HIPAA compliant, enterprise agreements available, no training on user data
//   CAUTION  - Generally safe but may train on data or lack compliance certs
//   RISKY    - Known to train on user data, limited privacy controls, or based in jurisdictions with weak data protection
//   BLOCKED  - Default block for known-dangerous or unvetted services
// ============================================================

export const REGISTRY_VERSION = "1.0.0";
export const REGISTRY_UPDATED = "2026-02-24";

export const AI_DOMAINS: AiToolEntry[] = [
  // === MAJOR CHATBOTS ===
  { domain: "chat.openai.com", name: "ChatGPT", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: true, hipaaCompliant: false, knownIncidents: 3, lastUpdated: "2026-02" },
  { domain: "chatgpt.com", name: "ChatGPT", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: true, hipaaCompliant: false, knownIncidents: 3, lastUpdated: "2026-02" },
  { domain: "api.openai.com", name: "OpenAI API", category: "api", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 1, lastUpdated: "2026-02" },
  { domain: "claude.ai", name: "Claude", category: "chatbot", riskLevel: "SAFE", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: true, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "api.anthropic.com", name: "Anthropic API", category: "api", riskLevel: "SAFE", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: true, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "gemini.google.com", name: "Gemini", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US", "EU"], trainsOnUserData: true, soc2Certified: true, hipaaCompliant: false, knownIncidents: 1, lastUpdated: "2026-02" },
  { domain: "aistudio.google.com", name: "Google AI Studio", category: "api", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "copilot.microsoft.com", name: "Microsoft Copilot", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US", "EU"], trainsOnUserData: null, soc2Certified: true, hipaaCompliant: false, knownIncidents: 1, lastUpdated: "2026-02" },
  { domain: "perplexity.ai", name: "Perplexity", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "chat.deepseek.com", name: "DeepSeek", category: "chatbot", riskLevel: "RISKY", dataResidency: ["CN"], trainsOnUserData: true, soc2Certified: false, hipaaCompliant: false, knownIncidents: 2, lastUpdated: "2026-02" },
  { domain: "api.deepseek.com", name: "DeepSeek API", category: "api", riskLevel: "RISKY", dataResidency: ["CN"], trainsOnUserData: true, soc2Certified: false, hipaaCompliant: false, knownIncidents: 2, lastUpdated: "2026-02" },
  { domain: "poe.com", name: "Poe", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "you.com", name: "You.com", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "character.ai", name: "Character.AI", category: "chatbot", riskLevel: "RISKY", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: false, hipaaCompliant: false, knownIncidents: 1, lastUpdated: "2026-02" },
  { domain: "pi.ai", name: "Pi (Inflection)", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "grok.x.ai", name: "Grok", category: "chatbot", riskLevel: "RISKY", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "huggingface.co", name: "HuggingFace", category: "api", riskLevel: "CAUTION", dataResidency: ["US", "EU"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "chat.mistral.ai", name: "Mistral Le Chat", category: "chatbot", riskLevel: "CAUTION", dataResidency: ["EU"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "groq.com", name: "Groq", category: "api", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },

  // === CODE ASSISTANTS ===
  { domain: "github.com/features/copilot", name: "GitHub Copilot", category: "code_assistant", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 1, lastUpdated: "2026-02" },
  { domain: "codeium.com", name: "Codeium", category: "code_assistant", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "cursor.sh", name: "Cursor", category: "code_assistant", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "replit.com", name: "Replit AI", category: "code_assistant", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "tabnine.com", name: "Tabnine", category: "code_assistant", riskLevel: "SAFE", dataResidency: ["US", "EU"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "v0.dev", name: "Vercel v0", category: "code_assistant", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "bolt.new", name: "Bolt", category: "code_assistant", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },

  // === IMAGE GENERATION ===
  { domain: "midjourney.com", name: "Midjourney", category: "image_gen", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "labs.openai.com", name: "DALL-E", category: "image_gen", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: true, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "stability.ai", name: "Stable Diffusion", category: "image_gen", riskLevel: "CAUTION", dataResidency: ["US", "EU"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "ideogram.ai", name: "Ideogram", category: "image_gen", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "leonardo.ai", name: "Leonardo AI", category: "image_gen", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },

  // === EMBEDDED AI (inside approved SaaS) ===
  { domain: "notion.so", name: "Notion AI", category: "embedded", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "grammarly.com", name: "Grammarly AI", category: "embedded", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "canva.com", name: "Canva AI", category: "embedded", riskLevel: "CAUTION", dataResidency: ["US", "AU"], trainsOnUserData: null, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "jasper.ai", name: "Jasper", category: "embedded", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "writesonic.com", name: "Writesonic", category: "embedded", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "copy.ai", name: "Copy.ai", category: "embedded", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "otter.ai", name: "Otter.ai", category: "voice", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "descript.com", name: "Descript", category: "voice", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "fireflies.ai", name: "Fireflies.ai", category: "voice", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: null, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },

  // === API ENDPOINTS (for API traffic fingerprinting) ===
  { domain: "api.together.xyz", name: "Together AI", category: "api", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "api.cohere.ai", name: "Cohere API", category: "api", riskLevel: "CAUTION", dataResidency: ["US", "CA"], trainsOnUserData: false, soc2Certified: true, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "api.replicate.com", name: "Replicate", category: "api", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
  { domain: "api.fireworks.ai", name: "Fireworks AI", category: "api", riskLevel: "CAUTION", dataResidency: ["US"], trainsOnUserData: false, soc2Certified: false, hipaaCompliant: false, knownIncidents: 0, lastUpdated: "2026-02" },
];

// ============================================================
// LOOKUP FUNCTIONS
// ============================================================

/** Domain -> AiToolEntry mapping for O(1) lookup */
const domainIndex = new Map<string, AiToolEntry>();
for (const entry of AI_DOMAINS) {
  domainIndex.set(entry.domain, entry);
  // Also index without subdomains
  const parts = entry.domain.split(".");
  if (parts.length > 2) {
    domainIndex.set(parts.slice(-2).join("."), entry);
  }
}

/** Check if a URL belongs to a known AI tool */
export function matchDomain(url: string): AiToolEntry | null {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    // Exact match first
    if (domainIndex.has(hostname)) return domainIndex.get(hostname)!;
    // Try parent domain
    const parts = hostname.split(".");
    if (parts.length > 2) {
      const parent = parts.slice(-2).join(".");
      if (domainIndex.has(parent)) return domainIndex.get(parent)!;
    }
    return null;
  } catch {
    return null;
  }
}

/** Check if a URL matches known AI API endpoints */
export function isAiApiEndpoint(url: string): boolean {
  const apiPatterns = [
    "/v1/chat/completions",
    "/v1/messages",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/images/generations",
    "/api/generate",         // Ollama
    "/api/chat",             // Ollama
    "/v1beta/models",        // Google
  ];
  return apiPatterns.some((p) => url.includes(p));
}

/** Get all domains as a simple array (for extension manifest) */
export function getAllDomains(): string[] {
  return AI_DOMAINS.map((d) => d.domain);
}

/** Get domains filtered by risk level */
export function getDomainsByRisk(level: AiToolRiskLevel): AiToolEntry[] {
  return AI_DOMAINS.filter((d) => d.riskLevel === level);
}
