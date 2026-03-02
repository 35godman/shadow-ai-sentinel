import type { EntityType, Detection, SensitivityLevel, ScanResult, PolicyAction } from "@sentinel/shared-types";

// ============================================================
// Regex Pattern Definitions
// Each pattern includes: regex, validator function, risk level
// These run in <5ms for the entire suite
// ============================================================

export interface RegexPattern {
  id: string;
  entityType: EntityType;
  name: string;
  pattern: RegExp;
  validator?: (match: string) => boolean;   // Post-match validation (e.g. Luhn check)
  sensitivityLevel: SensitivityLevel;
  complianceFrameworks: string[];
  description: string;
}

// --- Luhn Algorithm for credit card validation ---
function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// --- SSN area number validation (basic) ---
function validateSSN(ssn: string): boolean {
  const clean = ssn.replace(/\D/g, "");
  if (clean.length !== 9) return false;
  const area = parseInt(clean.substring(0, 3), 10);
  const group = parseInt(clean.substring(3, 5), 10);
  const serial = parseInt(clean.substring(5, 9), 10);
  // Invalid ranges
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0 || serial === 0) return false;
  // Known test/example SSNs
  if (clean === "123456789" || clean === "000000000") return false;
  return true;
}

// --- Shannon entropy for secret detection ---
function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function highEntropySecret(match: string): boolean {
  // Secrets typically have entropy > 4.0
  const clean = match.replace(/^(sk-|AKIA|ghp_|xoxb-|xoxp-)/, "");
  return shannonEntropy(clean) > 3.5 && clean.length >= 16;
}

// ============================================================
// PATTERN REGISTRY — All detection patterns
// ============================================================

export const PATTERNS: RegexPattern[] = [
  // --- US Social Security Number ---
  {
    id: "ssn-dashed",
    entityType: "SSN",
    name: "US SSN (Dashed)",
    pattern: /\b(\d{3}-\d{2}-\d{4})\b/g,
    validator: (m) => validateSSN(m),
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["HIPAA", "SOC2", "CCPA", "PCI-DSS"],
    description: "US Social Security Number in XXX-XX-XXXX format",
  },
  {
    id: "ssn-nodash",
    entityType: "SSN",
    name: "US SSN (No Dash)",
    pattern: /\b(\d{9})\b/g,
    validator: (m) => validateSSN(m) && !/^0{9}$/.test(m),
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["HIPAA", "SOC2", "CCPA"],
    description: "US SSN as continuous 9-digit number (higher false positive rate)",
  },

  // --- Credit Card Numbers ---
  {
    id: "cc-visa",
    entityType: "CREDIT_CARD",
    name: "Visa Card",
    pattern: /\b(4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/g,
    validator: (m) => luhnCheck(m),
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["PCI-DSS"],
    description: "Visa credit card number (starts with 4)",
  },
  {
    id: "cc-mastercard",
    entityType: "CREDIT_CARD",
    name: "Mastercard",
    pattern: /\b(5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/g,
    validator: (m) => luhnCheck(m),
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["PCI-DSS"],
    description: "Mastercard number (starts with 51-55)",
  },
  {
    id: "cc-amex",
    entityType: "CREDIT_CARD",
    name: "American Express",
    pattern: /\b(3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})\b/g,
    validator: (m) => luhnCheck(m),
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["PCI-DSS"],
    description: "Amex card number (starts with 34/37)",
  },

  // --- API Keys & Secrets ---
  {
    id: "openai-key",
    entityType: "API_KEY",
    name: "OpenAI API Key",
    pattern: /\b(sk-[a-zA-Z0-9_-]{20,})\b/g,
    validator: highEntropySecret,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2"],
    description: "OpenAI API key (sk- prefix)",
  },
  {
    id: "anthropic-key",
    entityType: "API_KEY",
    name: "Anthropic API Key",
    pattern: /\b(sk-ant-[a-zA-Z0-9_-]{20,})\b/g,
    validator: highEntropySecret,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2"],
    description: "Anthropic API key",
  },
  {
    id: "github-token",
    entityType: "API_KEY",
    name: "GitHub Token",
    pattern: /\b(ghp_[a-zA-Z0-9]{36,})\b/g,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["SOC2"],
    description: "GitHub personal access token",
  },
  {
    id: "github-oauth",
    entityType: "API_KEY",
    name: "GitHub OAuth Token",
    pattern: /\b(gho_[a-zA-Z0-9]{36,})\b/g,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["SOC2"],
    description: "GitHub OAuth access token",
  },
  {
    id: "slack-token",
    entityType: "API_KEY",
    name: "Slack Token",
    pattern: /\b(xox[bprs]-[a-zA-Z0-9-]{10,})\b/g,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["SOC2"],
    description: "Slack bot/user/app token",
  },
  {
    id: "stripe-key",
    entityType: "API_KEY",
    name: "Stripe API Key",
    pattern: /\b([rs]k_(live|test)_[a-zA-Z0-9]{20,})\b/g,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["PCI-DSS", "SOC2"],
    description: "Stripe secret or restricted key",
  },
  {
    id: "generic-bearer",
    entityType: "CREDENTIALS",
    name: "Bearer Token",
    pattern: /Bearer\s+([a-zA-Z0-9_\-.]{20,})/g,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["SOC2"],
    description: "Bearer authentication token in header",
  },

  // --- Cloud Provider Keys ---
  {
    id: "aws-access-key",
    entityType: "AWS_KEY",
    name: "AWS Access Key ID",
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2", "CIS"],
    description: "AWS IAM access key ID",
  },
  {
    id: "aws-secret-key",
    entityType: "AWS_KEY",
    name: "AWS Secret Access Key",
    pattern: /\b([a-zA-Z0-9/+=]{40})\b/g,
    validator: (m) => shannonEntropy(m) > 4.5 && /[A-Z]/.test(m) && /[a-z]/.test(m) && /[0-9]/.test(m),
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2", "CIS"],
    description: "AWS secret access key (high entropy 40-char string)",
  },
  {
    id: "gcp-service-account",
    entityType: "GCP_KEY",
    name: "GCP Service Account Key",
    pattern: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2", "CIS"],
    description: "GCP service account JSON key file content",
  },

  // --- Email Addresses ---
  {
    id: "email",
    entityType: "EMAIL",
    name: "Email Address",
    pattern: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["GDPR", "CCPA"],
    description: "Email address (RFC 5322 simplified)",
  },

  // --- Phone Numbers ---
  {
    id: "phone-us",
    entityType: "PHONE",
    name: "US Phone Number",
    pattern: /\b(\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b/g,
    validator: (m) => {
      const digits = m.replace(/\D/g, "");
      return digits.length >= 10 && digits.length <= 11;
    },
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["GDPR", "CCPA"],
    description: "US phone number in various formats",
  },
  {
    id: "phone-intl",
    entityType: "PHONE",
    name: "International Phone",
    pattern: /(\+[1-9]\d{1,2}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4})/g,
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["GDPR", "CCPA"],
    description: "International phone with country code",
  },

  // --- IP Addresses ---
  {
    id: "ipv4-private",
    entityType: "IP_ADDRESS",
    name: "Private IPv4 Address",
    pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["SOC2"],
    description: "Private/internal IPv4 address (may reveal network topology)",
  },

  // --- Medical Identifiers ---
  {
    id: "npi",
    entityType: "MEDICAL_ID",
    name: "NPI Number",
    pattern: /\b(NPI[:\s#]*\d{10})\b/gi,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["HIPAA"],
    description: "National Provider Identifier (10-digit)",
  },
  {
    // Requires a medical context prefix to avoid matching version numbers, model IDs, etc.
    id: "icd10",
    entityType: "DIAGNOSIS",
    name: "ICD-10 Code",
    pattern: /\b(?:ICD|DX|diagnosis|code)[-:\s]*([A-TV-Z]\d{2}(?:\.\d{1,4})?)\b/gi,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["HIPAA"],
    description: "ICD-10 diagnosis code with required medical context prefix",
  },
  {
    id: "dea-number",
    entityType: "MEDICAL_ID",
    name: "DEA Number",
    pattern: /\b(DEA[:\s#]*[A-Z]{2}\d{7})\b/gi,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["HIPAA"],
    description: "DEA registration number",
  },

  // --- Financial Data ---
  {
    id: "iban",
    entityType: "IBAN",
    name: "IBAN",
    pattern: /\b([A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4})\b/g,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["PCI-DSS", "GDPR"],
    description: "International Bank Account Number",
  },
  {
    id: "routing-number",
    entityType: "FINANCIAL_ACCOUNT",
    name: "US Routing Number",
    pattern: /\b((?:routing|aba|rtn)[:\s#]*\d{9})\b/gi,
    sensitivityLevel: "HIGH",
    complianceFrameworks: ["PCI-DSS"],
    description: "US bank routing/ABA number with context keyword",
  },

  // --- Source Code Detection ---
  {
    id: "code-function-py",
    entityType: "SOURCE_CODE",
    name: "Python Function",
    pattern: /\b(def\s+[a-zA-Z_]\w*\s*\([^)]*\)\s*(?:->[\s\w\[\],]*)?:)/g,
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["IP"],
    description: "Python function definition",
  },
  {
    id: "code-function-js",
    entityType: "SOURCE_CODE",
    name: "JS/TS Function",
    pattern: /\b((?:export\s+)?(?:async\s+)?function\s+[a-zA-Z_]\w*\s*\([^)]*\))/g,
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["IP"],
    description: "JavaScript/TypeScript function definition",
  },
  {
    id: "code-class",
    entityType: "SOURCE_CODE",
    name: "Class Definition",
    pattern: /\b((?:export\s+)?class\s+[A-Z]\w*(?:\s+extends\s+\w+)?(?:\s+implements\s+\w+)?\s*\{)/g,
    sensitivityLevel: "MEDIUM",
    complianceFrameworks: ["IP"],
    description: "Class definition (Python/JS/TS/Java)",
  },
  {
    id: "code-import",
    entityType: "SOURCE_CODE",
    name: "Import Statement",
    pattern: /\b(import\s+(?:\{[^}]+\}\s+from\s+|[\w*]+\s+from\s+)?['"][^'"]+['"])/g,
    sensitivityLevel: "LOW",
    complianceFrameworks: ["IP"],
    description: "Import/require statement",
  },
  {
    // Requires user:pass@ to avoid flagging bare connection strings without credentials.
    id: "connection-string",
    entityType: "CREDENTIALS",
    name: "Database Connection String",
    pattern: /((?:mongodb|postgres|mysql|redis|amqp):\/\/[^:\s'"]+:[^@\s'"]+@[^\s'"]+)/g,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2"],
    description: "Database connection URI containing credentials (user:pass@host)",
  },
  {
    id: "private-key",
    entityType: "CREDENTIALS",
    name: "Private Key",
    pattern: /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/g,
    sensitivityLevel: "CRITICAL",
    complianceFrameworks: ["SOC2", "CIS"],
    description: "PEM-encoded private key header",
  },
];

// ============================================================
// SCAN ENGINE — Runs all patterns against input text
// ============================================================

export interface ScanOptions {
  enabledTypes?: EntityType[];    // Filter to specific entity types
  minConfidence?: number;         // Default: 0 (return all matches)
  maxResults?: number;            // Limit results
}

export function scanText(text: string, options: ScanOptions = {}): ScanResult {
  const startTime = performance.now();
  const detections: Detection[] = [];
  const seen = new Set<string>();   // Dedup overlapping matches

  for (const pattern of PATTERNS) {
    // Filter by enabled types
    if (options.enabledTypes && !options.enabledTypes.includes(pattern.entityType)) {
      continue;
    }

    // Reset regex state for global patterns
    pattern.pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.pattern.exec(text)) !== null) {
      const matchedText = match[1] || match[0];
      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;

      // Run post-match validator
      if (pattern.validator && !pattern.validator(matchedText)) {
        continue;
      }

      // Dedup: skip if this exact range was already matched
      const key = `${startOffset}-${endOffset}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Generate redacted placeholder
      const redactedText = `[${pattern.entityType}_REDACTED]`;

      detections.push({
        id: `${pattern.id}-${startOffset}`,
        entityType: pattern.entityType,
        confidence: 0.95,         // Regex matches have high confidence
        source: "REGEX",
        matchedText,
        redactedText,
        contextRiskScore: pattern.sensitivityLevel,
        startOffset,
        endOffset,
        regexPatternId: pattern.id,
      });
    }
  }

  // Sort by severity (CRITICAL first), then by position
  const severityOrder: Record<SensitivityLevel, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3,
  };
  detections.sort((a, b) =>
    severityOrder[a.contextRiskScore] - severityOrder[b.contextRiskScore] || a.startOffset - b.startOffset
  );

  // Apply max results limit
  const limited = options.maxResults ? detections.slice(0, options.maxResults) : detections;

  // Determine combined risk score
  const combinedRiskScore = determineCombinedRisk(limited);
  const recommendedAction = determineAction(combinedRiskScore);

  const scanDurationMs = performance.now() - startTime;

  return {
    detections: limited,
    combinedRiskScore,
    recommendedAction,
    scanDurationMs,
    regexDurationMs: scanDurationMs,
  };
}

function determineCombinedRisk(detections: Detection[]): SensitivityLevel {
  if (detections.length === 0) return "LOW";
  if (detections.some((d) => d.contextRiskScore === "CRITICAL")) return "CRITICAL";
  if (detections.some((d) => d.contextRiskScore === "HIGH")) return "HIGH";
  if (detections.some((d) => d.contextRiskScore === "MEDIUM")) return "MEDIUM";
  return "LOW";
}

function determineAction(risk: SensitivityLevel): PolicyAction {
  switch (risk) {
    case "CRITICAL": return "BLOCK";
    case "HIGH": return "REDACT";
    case "MEDIUM": return "WARN";
    case "LOW": return "LOG";
  }
}

// ============================================================
// REDACTION — Replace detected PII with placeholders
// ============================================================

export function redactText(text: string, detections: Detection[]): string {
  // Sort detections by offset descending so we can replace from end to start
  const sorted = [...detections].sort((a, b) => b.startOffset - a.startOffset);
  let result = text;
  for (const d of sorted) {
    result = result.substring(0, d.startOffset) + d.redactedText + result.substring(d.endOffset);
  }
  return result;
}

// ============================================================
// EXPORTS
// ============================================================

export { luhnCheck, validateSSN, shannonEntropy };
