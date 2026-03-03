import { describe, it, expect } from "vitest";
import { scanText, luhnCheck, validateSSN, shannonEntropy, PATTERNS, redactText } from "./index";

// ============================================================
// VALIDATOR UNIT TESTS
// ============================================================

describe("luhnCheck", () => {
  it("validates known valid card numbers", () => {
    expect(luhnCheck("4111111111111111")).toBe(true);   // Visa test
    expect(luhnCheck("5500000000000004")).toBe(true);   // MC test
    expect(luhnCheck("340000000000009")).toBe(true);    // Amex test
    expect(luhnCheck("4111-1111-1111-1111")).toBe(true);
  });

  it("rejects invalid card numbers", () => {
    expect(luhnCheck("4111111111111112")).toBe(false);
    expect(luhnCheck("1234567890123456")).toBe(false);
    expect(luhnCheck("0000000000000000")).toBe(true);  // Luhn passes but BIN check would fail
    expect(luhnCheck("123")).toBe(false);               // Too short
  });
});

describe("validateSSN", () => {
  it("validates plausible SSNs", () => {
    expect(validateSSN("078-05-1120")).toBe(true);
    expect(validateSSN("219099999")).toBe(true);
  });

  it("rejects invalid SSNs", () => {
    expect(validateSSN("000-00-0000")).toBe(false);     // Area 000
    expect(validateSSN("666-12-1234")).toBe(false);     // Area 666
    expect(validateSSN("900-12-1234")).toBe(false);     // Area 900+
    expect(validateSSN("123-00-1234")).toBe(false);     // Group 00
    expect(validateSSN("123-45-0000")).toBe(false);     // Serial 0000
    expect(validateSSN("123456789")).toBe(false);       // Known test SSN
  });
});

describe("shannonEntropy", () => {
  it("calculates entropy correctly", () => {
    expect(shannonEntropy("aaaa")).toBeCloseTo(0);
    expect(shannonEntropy("abcd")).toBeCloseTo(2.0);
    // High entropy string (typical of API keys)
    const highEntropy = shannonEntropy("aB3kL9mN2xRf7yQp5sWv");
    expect(highEntropy).toBeGreaterThan(3.5);
  });

  it("rates random-looking strings as high entropy", () => {
    expect(shannonEntropy("sk-proj-aB3kL9mN2xRf7yQp5sWv")).toBeGreaterThan(3.0);
  });
});

// ============================================================
// PATTERN DETECTION TESTS
// ============================================================

describe("SSN Detection", () => {
  it("detects dashed SSNs", () => {
    const result = scanText("My SSN is 078-05-1120");
    expect(result.detections.length).toBeGreaterThanOrEqual(1);
    expect(result.detections.some(d => d.entityType === "SSN")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });

  it("does not detect invalid SSNs", () => {
    const result = scanText("Code: 000-00-0000 and 666-12-1234");
    const ssnDetections = result.detections.filter(d => d.entityType === "SSN");
    expect(ssnDetections).toHaveLength(0);
  });

  it("does not flag date-like patterns as SSN", () => {
    // This is a common false positive scenario
    const result = scanText("The date is 2024-01-15 and reference 123-45");
    const ssnDetections = result.detections.filter(d => d.entityType === "SSN");
    // None should match because 2024-01-15 doesn't match SSN pattern
    // and 123-45 is incomplete
    expect(ssnDetections).toHaveLength(0);
  });
});

describe("Credit Card Detection", () => {
  it("detects Visa cards", () => {
    const result = scanText("Card: 4111 1111 1111 1111");
    expect(result.detections.some(d => d.entityType === "CREDIT_CARD")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });

  it("detects Mastercard", () => {
    const result = scanText("Pay with 5500-0000-0000-0004");
    expect(result.detections.some(d => d.entityType === "CREDIT_CARD")).toBe(true);
  });

  it("detects Amex", () => {
    const result = scanText("Amex: 3400-000000-00009");
    expect(result.detections.some(d => d.entityType === "CREDIT_CARD")).toBe(true);
  });

  it("rejects numbers failing Luhn check", () => {
    const result = scanText("Not a card: 4111111111111112");
    const ccDetections = result.detections.filter(d => d.entityType === "CREDIT_CARD");
    expect(ccDetections).toHaveLength(0);
  });
});

describe("API Key Detection", () => {
  it("detects OpenAI keys", () => {
    const result = scanText("Key: sk-proj-aB3kL9mN2xRf7yQp5sWvZ1");
    expect(result.detections.some(d => d.entityType === "API_KEY")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });

  it("detects GitHub tokens", () => {
    const result = scanText("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12");
    expect(result.detections.some(d => d.entityType === "API_KEY")).toBe(true);
  });

  it("detects Slack tokens", () => {
    const result = scanText("Bot: xoxb-123456789012-abcdefghijkl");
    expect(result.detections.some(d => d.entityType === "API_KEY")).toBe(true);
  });

  it("detects Stripe keys", () => {
    const result = scanText("sk_live_FAKEKEYFORTESTINGONLY1234567");
    expect(result.detections.some(d => d.entityType === "API_KEY")).toBe(true);
  });
});

describe("AWS Key Detection", () => {
  it("detects AWS access key IDs", () => {
    const result = scanText("AWS key: AKIAIOSFODNN7EXAMPLE");
    expect(result.detections.some(d => d.entityType === "AWS_KEY")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });
});

describe("Email Detection", () => {
  it("detects standard emails", () => {
    const result = scanText("Contact john.doe@company.com for details");
    expect(result.detections.some(d => d.entityType === "EMAIL")).toBe(true);
    expect(result.detections.find(d => d.entityType === "EMAIL")?.contextRiskScore).toBe("MEDIUM");
  });

  it("detects various email formats", () => {
    const result = scanText("user+tag@subdomain.example.co.uk");
    expect(result.detections.some(d => d.entityType === "EMAIL")).toBe(true);
  });
});

describe("Phone Detection", () => {
  it("detects US phone numbers", () => {
    const result = scanText("Call (555) 123-4567");
    expect(result.detections.some(d => d.entityType === "PHONE")).toBe(true);
  });

  it("detects international numbers", () => {
    const result = scanText("Phone: +44 20 7946 0958");
    expect(result.detections.some(d => d.entityType === "PHONE")).toBe(true);
  });
});

describe("IP Address Detection", () => {
  it("detects IPv4 addresses", () => {
    const result = scanText("Server at 172.16.254.1");
    expect(result.detections.some(d => d.entityType === "IP_ADDRESS")).toBe(true);
  });

  it("detects private ranges with elevated risk", () => {
    const result = scanText("Internal: 10.0.0.1 and 192.168.1.100");
    const privateIPs = result.detections.filter(d => d.contextRiskScore === "MEDIUM" && d.entityType === "IP_ADDRESS");
    expect(privateIPs.length).toBeGreaterThanOrEqual(1);
  });

  it("rejects invalid IPs", () => {
    const result = scanText("Version 999.999.999.999");
    const ipDetections = result.detections.filter(d => d.entityType === "IP_ADDRESS");
    expect(ipDetections).toHaveLength(0);
  });
});

describe("Medical ID Detection", () => {
  it("detects NPI numbers", () => {
    const result = scanText("Provider NPI: 1234567890");
    expect(result.detections.some(d => d.entityType === "MEDICAL_ID")).toBe(true);
  });

  it("detects DEA numbers", () => {
    const result = scanText("DEA# AB1234567");
    expect(result.detections.some(d => d.entityType === "MEDICAL_ID")).toBe(true);
  });

  it("detects ICD-10 codes", () => {
    const result = scanText("Diagnosis: E11.65 and I10");
    expect(result.detections.some(d => d.entityType === "DIAGNOSIS")).toBe(true);
  });
});

describe("Financial Data Detection", () => {
  it("detects IBAN numbers", () => {
    const result = scanText("IBAN: GB29 NWBK 6016 1331 9268 19");
    expect(result.detections.some(d => d.entityType === "IBAN")).toBe(true);
  });

  it("detects routing numbers with context", () => {
    const result = scanText("Routing: 021000021");
    expect(result.detections.some(d => d.entityType === "FINANCIAL_ACCOUNT")).toBe(true);
  });
});

describe("Source Code Detection", () => {
  it("detects Python functions", () => {
    const result = scanText("def process_payment(amount: float, card: str) -> bool:");
    expect(result.detections.some(d => d.entityType === "SOURCE_CODE")).toBe(true);
  });

  it("detects JS/TS functions", () => {
    const result = scanText("export async function fetchUserData(userId: string)");
    expect(result.detections.some(d => d.entityType === "SOURCE_CODE")).toBe(true);
  });

  it("detects class definitions", () => {
    const result = scanText("export class PaymentProcessor extends BaseProcessor {");
    expect(result.detections.some(d => d.entityType === "SOURCE_CODE")).toBe(true);
  });
});

describe("Credential Detection", () => {
  it("detects database connection strings", () => {
    const result = scanText("DB: postgres://admin:secretpass@db.internal:5432/production");
    expect(result.detections.some(d => d.entityType === "CREDENTIALS")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });

  it("detects private key headers", () => {
    const result = scanText("-----BEGIN RSA PRIVATE KEY-----");
    expect(result.detections.some(d => d.entityType === "CREDENTIALS")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });

  it("detects bearer tokens", () => {
    const result = scanText("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123");
    expect(result.detections.some(d => d.entityType === "CREDENTIALS")).toBe(true);
  });
});

// ============================================================
// COMBINED / INTEGRATION TESTS
// ============================================================

describe("Multi-pattern detection", () => {
  it("detects multiple PII types in one text", () => {
    const text = `
      Patient: John Doe
      SSN: 078-05-1120
      Email: john.doe@hospital.com
      Phone: (555) 123-4567
      Diagnosis: E11.65
    `;
    const result = scanText(text);
    const types = new Set(result.detections.map(d => d.entityType));
    expect(types.has("SSN")).toBe(true);
    expect(types.has("EMAIL")).toBe(true);
    expect(types.has("PHONE")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
    expect(result.recommendedAction).toBe("BLOCK");
  });

  it("correctly prioritizes CRITICAL over HIGH", () => {
    const result = scanText("SSN 078-05-1120 and email john@test.com");
    expect(result.combinedRiskScore).toBe("CRITICAL");
    expect(result.recommendedAction).toBe("BLOCK");
  });
});

describe("Clean text (no false positives)", () => {
  it("does not flag normal business text", () => {
    const result = scanText("Please review the quarterly report and provide feedback by Friday.");
    expect(result.detections).toHaveLength(0);
  });

  it("does not flag normal conversation", () => {
    const result = scanText("Can you help me write a cover letter for a software engineering position?");
    expect(result.detections).toHaveLength(0);
  });

  it("does not flag generic numbers", () => {
    const result = scanText("We need 1500 units by Q3, budget is $50000");
    const ssnOrCC = result.detections.filter(d => d.entityType === "SSN" || d.entityType === "CREDIT_CARD");
    expect(ssnOrCC).toHaveLength(0);
  });
});

describe("Google/Gemini API Key Detection", () => {
  // Real Google API keys are exactly 39 chars: "AIza" prefix + 35 alphanumeric chars.
  const validKey1 = "AIzaOhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCL"; // 39 chars
  const validKey2 = "AIzarZ3aWZkSBvrjn9Wvgfygw2wMqZcUDIh7yfJ"; // 39 chars

  it("detects a valid Google API key (AIza prefix, 39 chars total)", () => {
    const result = scanText(`GOOGLE_KEY=${validKey1}`);
    expect(result.detections.some(d => d.entityType === "GCP_KEY")).toBe(true);
    expect(result.combinedRiskScore).toBe("CRITICAL");
  });

  it("detects Google API key inline in text", () => {
    const result = scanText(`Please use this key: ${validKey2} for the Gemini API`);
    expect(result.detections.some(d => d.entityType === "GCP_KEY")).toBe(true);
  });

  it("does not flag short AIza prefixed strings (fewer than 35 chars after prefix)", () => {
    const result = scanText("This is AIzaShort and should not match");
    const gcpDetections = result.detections.filter(d => d.entityType === "GCP_KEY");
    expect(gcpDetections).toHaveLength(0);
  });

  it("does not flag AIza string that is too short (34 chars after prefix, needs 35)", () => {
    const tooShort = "AIzaSyD8aBcDeFgHiJkLmNoPqRsTuVwXyZ1234"; // 38 total, 34 after AIza
    const result = scanText(`key=${tooShort}`);
    const gcpDetections = result.detections.filter(d => d.entityType === "GCP_KEY");
    expect(gcpDetections).toHaveLength(0);
  });
});

describe("Performance", () => {
  it("scans short text in under 5ms", () => {
    const result = scanText("SSN 078-05-1120 and card 4111111111111111");
    expect(result.scanDurationMs).toBeLessThan(5);
  });

  it("scans long text in under 50ms", () => {
    const longText = "Hello world. ".repeat(10000) + "SSN: 078-05-1120";
    const result = scanText(longText);
    expect(result.scanDurationMs).toBeLessThan(50);
    expect(result.detections.some(d => d.entityType === "SSN")).toBe(true);
  });
});

// ============================================================
// REDACTION TESTS
// ============================================================

describe("redactText", () => {
  it("replaces detections with placeholders", () => {
    const text = "SSN is 078-05-1120 and email john@test.com";
    const result = scanText(text);
    const redacted = redactText(text, result.detections);
    expect(redacted).not.toContain("078-05-1120");
    expect(redacted).not.toContain("john@test.com");
    expect(redacted).toContain("[SSN_REDACTED]");
    expect(redacted).toContain("[EMAIL_REDACTED]");
  });

  it("preserves non-sensitive text", () => {
    const text = "Patient SSN is 078-05-1120 please review";
    const result = scanText(text);
    const redacted = redactText(text, result.detections);
    expect(redacted).toContain("Patient");
    expect(redacted).toContain("please review");
  });
});

// ============================================================
// FILTER OPTIONS TESTS
// ============================================================

describe("Scan options", () => {
  it("filters by enabled entity types", () => {
    const text = "SSN 078-05-1120 and email john@test.com";
    const result = scanText(text, { enabledTypes: ["EMAIL"] });
    expect(result.detections.every(d => d.entityType === "EMAIL")).toBe(true);
  });

  it("limits max results", () => {
    const text = "john@a.com bob@b.com carol@c.com dave@d.com eve@e.com";
    const result = scanText(text, { maxResults: 2 });
    expect(result.detections.length).toBeLessThanOrEqual(2);
  });
});

// ============================================================
// FALSE POSITIVE PREVENTION TESTS (post-fix validation)
// ============================================================

describe("False positive prevention", () => {
  it("does not flag connection strings without credentials", () => {
    // mongodb://host/db with no user:pass@ should NOT be flagged as CREDENTIALS
    const result = scanText("uri = mongodb://localhost:27017/mydb");
    const credDets = result.detections.filter(d => d.entityType === "CREDENTIALS"
      && d.matchedText.startsWith("mongodb://"));
    expect(credDets).toHaveLength(0);
  });

  it("flags connection strings that contain credentials", () => {
    const result = scanText("DB: postgres://user:secret@db.internal:5432/prod");
    expect(result.detections.some(d => d.entityType === "CREDENTIALS")).toBe(true);
  });

  it("does not flag low-entropy anthropic key lookalikes", () => {
    // sk-ant- prefix but all same character — entropy too low for a real key
    const result = scanText("key = sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const apiKeys = result.detections.filter(d =>
      d.entityType === "API_KEY" && d.matchedText.includes("sk-ant-aaa")
    );
    expect(apiKeys).toHaveLength(0);
  });

  it("detects high-entropy anthropic keys", () => {
    const result = scanText("ANTHROPIC_KEY=sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd");
    expect(result.detections.some(d => d.entityType === "API_KEY")).toBe(true);
  });

  it("does not flag ICD-like codes outside medical context", () => {
    // "E11.65" as a standalone value (version number, model ID) should NOT match
    const result = scanText("Component version E11.65 released");
    const diagDets = result.detections.filter(d => d.entityType === "DIAGNOSIS");
    expect(diagDets).toHaveLength(0);
  });

  it("detects ICD-10 codes with medical context prefix", () => {
    const result = scanText("Diagnosis: E11.65 and ICD E10");
    expect(result.detections.some(d => d.entityType === "DIAGNOSIS")).toBe(true);
  });

  it("detects github oauth tokens (gho_ prefix)", () => {
    const result = scanText("token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12");
    expect(result.detections.some(d => d.entityType === "API_KEY")).toBe(true);
  });
});
