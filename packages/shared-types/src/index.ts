// ============================================================
// Shadow AI Sentinel — Shared Type Definitions
// These types are the contract between ALL services:
//   browser-extension, proxy-service, ml-service, dashboard
// ============================================================

// --- Detection & Classification ---

export type SensitivityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type PolicyAction = "LOG" | "WARN" | "REDACT" | "BLOCK";

export type DetectionSource = "REGEX" | "ML" | "COMBINED";

export type EntityType =
  | "SSN"
  | "CREDIT_CARD"
  | "API_KEY"
  | "AWS_KEY"
  | "GCP_KEY"
  | "EMAIL"
  | "PHONE"
  | "IP_ADDRESS"
  | "PERSON"
  | "ORGANIZATION"
  | "LOCATION"
  | "MEDICAL_CONDITION"
  | "DIAGNOSIS"
  | "MEDICATION"
  | "MEDICAL_ID"
  | "FINANCIAL_ACCOUNT"
  | "IBAN"
  | "SOURCE_CODE"
  | "CREDENTIALS"
  | "TRADE_SECRET"
  | "CUSTOM";

export interface Detection {
  id: string;
  entityType: EntityType;
  confidence: number;           // 0.0 - 1.0
  source: DetectionSource;
  matchedText: string;          // The actual matched text (for local use only, NEVER stored in logs)
  redactedText: string;         // The replacement placeholder e.g. [PERSON_1]
  contextRiskScore: SensitivityLevel;
  startOffset: number;
  endOffset: number;
  regexPatternId?: string;      // Which regex pattern matched
  mlModelVersion?: string;      // Which ML model version
}

export interface ScanResult {
  detections: Detection[];
  combinedRiskScore: SensitivityLevel;
  recommendedAction: PolicyAction;
  scanDurationMs: number;
  regexDurationMs: number;
  mlDurationMs?: number;
}

// --- Policy Engine ---

export interface PolicyRule {
  id: string;
  name: string;
  orgId: string;
  enabled: boolean;
  priority: number;             // Lower = higher priority
  conditions: PolicyCondition[];
  action: PolicyAction;
  notifyAdmin: boolean;
  notifyUser: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface PolicyCondition {
  field: "entity_type" | "ai_tool" | "user_department" | "sensitivity" | "confidence";
  operator: "equals" | "in" | "greater_than" | "less_than";
  value: string | string[] | number;
}

// --- Proxy Request/Response ---

export interface ProxyRequest {
  requestId: string;
  orgId: string;
  userId: string;
  userEmail: string;
  userDepartment?: string;
  targetAiTool: string;         // e.g. "chatgpt", "claude", "gemini"
  targetUrl: string;
  promptText: string;
  attachments?: AttachmentMeta[];
  timestamp: string;
  browserMeta: BrowserMeta;
}

export interface ProxyResponse {
  requestId: string;
  scanResult: ScanResult;
  actionTaken: PolicyAction;
  policyMatched?: string;       // ID of the policy rule that fired
  redactedPrompt?: string;      // Sanitized version sent to LLM
  llmResponse?: string;         // Response from LLM (re-identified)
  routedTo: "external" | "onprem" | "blocked";
  latencyMs: number;
}

export interface AttachmentMeta {
  filename: string;
  mimeType: string;
  sizeBytes: number;
  scanResult?: ScanResult;
}

export interface BrowserMeta {
  browser: string;
  version: string;
  os: string;
  managed: boolean;             // Corporate-managed device?
  extensionVersion: string;
}

// --- Shadow AI Discovery ---

export type AiToolRiskLevel = "SAFE" | "CAUTION" | "RISKY" | "BLOCKED";

export interface AiToolEntry {
  domain: string;
  name: string;
  category: "chatbot" | "code_assistant" | "image_gen" | "voice" | "embedded" | "api" | "other";
  riskLevel: AiToolRiskLevel;
  dataResidency: string[];      // e.g. ["US", "EU"]
  trainsOnUserData: boolean | null; // null = unknown
  soc2Certified: boolean | null;
  hipaaCompliant: boolean | null;
  knownIncidents: number;
  lastUpdated: string;
}

export interface ShadowAiEvent {
  id: string;
  orgId: string;
  userId: string;
  userEmail: string;
  domain: string;
  aiToolName: string;
  category: AiToolEntry["category"];
  riskLevel: AiToolRiskLevel;
  action: "visited" | "prompted" | "uploaded" | "api_call";
  timestamp: string;
  durationSeconds?: number;
  estimatedTokens?: number;
  browserMeta: BrowserMeta;
}

// --- Audit Log ---

export interface AuditEvent {
  id: string;
  orgId: string;
  userId: string;
  userEmail: string;
  eventType: "scan" | "block" | "redact" | "warn" | "shadow_ai" | "policy_change" | "login";
  aiTool?: string;
  entityTypesDetected: EntityType[];
  sensitivityLevel: SensitivityLevel;
  actionTaken: PolicyAction;
  policyId?: string;
  timestamp: string;
  metadata: Record<string, string>;
  // NOTE: Original sensitive text is NEVER stored here. Only entity types + metadata.
}

// --- Dashboard Analytics ---

export interface UserRiskScore {
  userId: string;
  email: string;
  department: string;
  totalEvents: number;
  criticalEvents: number;
  highEvents: number;
  compositeRiskScore: number;   // 0-100
  topEntityTypes: EntityType[];
  topAiTools: string[];
  trend: "increasing" | "stable" | "decreasing";
  lastEventAt: string;
}

export interface DepartmentRiskSummary {
  department: string;
  userCount: number;
  totalEvents: number;
  riskBreakdown: Record<SensitivityLevel, number>;
  topAiTools: { tool: string; count: number }[];
  topEntityTypes: { type: EntityType; count: number }[];
}

export interface RiskHeatmapCell {
  department: string;
  sensitivityLevel: SensitivityLevel;
  eventCount: number;
  uniqueUsers: number;
  intensity: number;            // 0.0 - 1.0 for color mapping
}

// --- Organization & User ---

export interface Organization {
  id: string;
  name: string;
  plan: "free" | "starter" | "professional" | "enterprise";
  apiKey: string;
  settings: OrgSettings;
  createdAt: string;
}

export interface OrgSettings {
  defaultAction: PolicyAction;
  learningMode: boolean;        // When true: log everything, block nothing
  enabledDetectors: EntityType[];
  allowedAiTools: string[];     // Empty = all allowed
  blockedAiTools: string[];
  onPremLlmEndpoint?: string;   // Ollama/vLLM URL if configured
  webhookUrl?: string;          // SIEM integration
  slackWebhookUrl?: string;
  teamsWebhookUrl?: string;
  emailAlerts: string[];        // Admin emails for CRITICAL alerts
}

export interface User {
  id: string;
  orgId: string;
  email: string;
  name?: string;
  department?: string;
  role: "admin" | "user" | "viewer";
  createdAt: string;
}

// --- API Response Wrappers ---

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  meta?: {
    page?: number;
    pageSize?: number;
    total?: number;
  };
}

// --- Extension <-> Backend Communication ---

export interface ExtensionConfig {
  orgId: string;
  apiKey: string;
  proxyEndpoint: string;        // Where to send intercepted requests
  pollingIntervalMs: number;    // How often to check for policy updates
  enabledDetectors: EntityType[];
  learningMode: boolean;
  aiDomainRegistryVersion: string;
  regexPatternsVersion: string;
}

export interface ExtensionScanRequest {
  content: string;
  contentType: "paste" | "type" | "upload" | "prompt";
  targetDomain: string;
  targetUrl: string;
  userId: string;
  timestamp: string;
}

export interface ExtensionScanResponse {
  action: PolicyAction;
  detections: Pick<Detection, "entityType" | "confidence" | "contextRiskScore" | "redactedText" | "startOffset" | "endOffset">[];
  userMessage?: string;         // Message to show the user (e.g. "This content contains SSN data")
  redactedContent?: string;     // Full content with PII replaced
}
