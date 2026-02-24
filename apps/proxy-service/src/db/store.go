package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ============================================================
// CONNECTION MANAGEMENT
// ============================================================

type Store struct {
	PG    *pgxpool.Pool
	Redis *redis.Client
}

func NewStore(databaseURL, redisURL string) (*Store, error) {
	pgCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	pgCfg.MaxConns = 20
	pgCfg.MinConns = 2
	pgCfg.MaxConnLifetime = 30 * time.Minute

	pg, err := pgxpool.NewWithConfig(context.Background(), pgCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	if err := pg.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse Redis URL: %w", err)
	}
	rdb := redis.NewClient(opt)

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("ping Redis: %w", err)
	}

	return &Store{PG: pg, Redis: rdb}, nil
}

func (s *Store) Close() {
	s.PG.Close()
	s.Redis.Close()
}

// ============================================================
// ORGANIZATION QUERIES
// ============================================================

type Organization struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Plan     string          `json:"plan"`
	APIKey   string          `json:"apiKey"`
	Settings OrgSettings     `json:"settings"`
}

type OrgSettings struct {
	DefaultAction    string   `json:"defaultAction"`
	LearningMode     bool     `json:"learningMode"`
	EnabledDetectors []string `json:"enabledDetectors"`
	AllowedAiTools   []string `json:"allowedAiTools"`
	BlockedAiTools   []string `json:"blockedAiTools"`
	OnPremLLMEndpoint string  `json:"onPremLlmEndpoint,omitempty"`
	WebhookURL       string   `json:"webhookUrl,omitempty"`
	SlackWebhookURL  string   `json:"slackWebhookUrl,omitempty"`
	EmailAlerts      []string `json:"emailAlerts"`
}

func (s *Store) GetOrgByAPIKey(ctx context.Context, apiKey string) (*Organization, error) {
	var org Organization
	var settingsJSON []byte

	err := s.PG.QueryRow(ctx,
		"SELECT id, name, plan, api_key, settings FROM organizations WHERE api_key = $1",
		apiKey,
	).Scan(&org.ID, &org.Name, &org.Plan, &org.APIKey, &settingsJSON)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(settingsJSON, &org.Settings); err != nil {
		return nil, fmt.Errorf("unmarshal org settings: %w", err)
	}

	return &org, nil
}

func (s *Store) GetOrgByID(ctx context.Context, orgID string) (*Organization, error) {
	var org Organization
	var settingsJSON []byte

	err := s.PG.QueryRow(ctx,
		"SELECT id, name, plan, api_key, settings FROM organizations WHERE id = $1",
		orgID,
	).Scan(&org.ID, &org.Name, &org.Plan, &org.APIKey, &settingsJSON)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(settingsJSON, &org.Settings); err != nil {
		return nil, fmt.Errorf("unmarshal org settings: %w", err)
	}

	return &org, nil
}

// ============================================================
// POLICY QUERIES
// ============================================================

type PolicyRule struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"orgId"`
	Name        string          `json:"name"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	Conditions  json.RawMessage `json:"conditions"`
	Action      string          `json:"action"`
	NotifyAdmin bool            `json:"notifyAdmin"`
	NotifyUser  bool            `json:"notifyUser"`
}

func (s *Store) GetPolicies(ctx context.Context, orgID string) ([]PolicyRule, error) {
	rows, err := s.PG.Query(ctx,
		"SELECT id, org_id, name, enabled, priority, conditions, action, notify_admin, notify_user FROM policy_rules WHERE org_id = $1 AND enabled = true ORDER BY priority ASC",
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []PolicyRule
	for rows.Next() {
		var p PolicyRule
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Enabled, &p.Priority, &p.Conditions, &p.Action, &p.NotifyAdmin, &p.NotifyUser); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (s *Store) CreatePolicy(ctx context.Context, p *PolicyRule) error {
	return s.PG.QueryRow(ctx,
		`INSERT INTO policy_rules (org_id, name, enabled, priority, conditions, action, notify_admin, notify_user)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		p.OrgID, p.Name, p.Enabled, p.Priority, p.Conditions, p.Action, p.NotifyAdmin, p.NotifyUser,
	).Scan(&p.ID)
}

func (s *Store) UpdatePolicy(ctx context.Context, p *PolicyRule) error {
	_, err := s.PG.Exec(ctx,
		`UPDATE policy_rules SET name=$2, enabled=$3, priority=$4, conditions=$5, action=$6, notify_admin=$7, notify_user=$8, updated_at=NOW()
		 WHERE id=$1 AND org_id=$9`,
		p.ID, p.Name, p.Enabled, p.Priority, p.Conditions, p.Action, p.NotifyAdmin, p.NotifyUser, p.OrgID,
	)
	return err
}

func (s *Store) DeletePolicy(ctx context.Context, orgID, policyID string) error {
	_, err := s.PG.Exec(ctx, "DELETE FROM policy_rules WHERE id=$1 AND org_id=$2", policyID, orgID)
	return err
}

// ============================================================
// AUDIT EVENT LOGGING
// ============================================================

type AuditEvent struct {
	OrgID              string   `json:"orgId"`
	UserID             string   `json:"userId,omitempty"`
	UserEmail          string   `json:"userEmail"`
	EventType          string   `json:"eventType"`
	AiTool             string   `json:"aiTool,omitempty"`
	EntityTypesDetected []string `json:"entityTypesDetected"`
	SensitivityLevel   string   `json:"sensitivityLevel"`
	ActionTaken        string   `json:"actionTaken"`
	PolicyID           string   `json:"policyId,omitempty"`
	Metadata           map[string]string `json:"metadata"`
}

func (s *Store) InsertAuditEvent(ctx context.Context, e *AuditEvent) error {
	metaJSON, _ := json.Marshal(e.Metadata)
	var policyID *string
	if e.PolicyID != "" {
		policyID = &e.PolicyID
	}
	var userID *string
	if e.UserID != "" {
		userID = &e.UserID
	}

	_, err := s.PG.Exec(ctx,
		`INSERT INTO audit_events (org_id, user_id, user_email, event_type, ai_tool, entity_types_detected, sensitivity_level, action_taken, policy_id, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		e.OrgID, userID, e.UserEmail, e.EventType, e.AiTool, e.EntityTypesDetected, e.SensitivityLevel, e.ActionTaken, policyID, metaJSON,
	)
	return err
}

func (s *Store) InsertAuditEventBatch(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, e := range events {
		metaJSON, _ := json.Marshal(e.Metadata)
		var policyID *string
		if e.PolicyID != "" {
			policyID = &e.PolicyID
		}
		var userID *string
		if e.UserID != "" {
			userID = &e.UserID
		}
		batch.Queue(
			`INSERT INTO audit_events (org_id, user_id, user_email, event_type, ai_tool, entity_types_detected, sensitivity_level, action_taken, policy_id, metadata)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			e.OrgID, userID, e.UserEmail, e.EventType, e.AiTool, e.EntityTypesDetected, e.SensitivityLevel, e.ActionTaken, policyID, metaJSON,
		)
	}

	br := s.PG.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(events); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch insert event %d: %w", i, err)
		}
	}
	return nil
}

// ============================================================
// SHADOW AI EVENT LOGGING
// ============================================================

type ShadowAiEvent struct {
	OrgID           string          `json:"orgId"`
	UserID          string          `json:"userId,omitempty"`
	UserEmail       string          `json:"userEmail"`
	Domain          string          `json:"domain"`
	AiToolName      string          `json:"aiToolName"`
	Category        string          `json:"category,omitempty"`
	RiskLevel       string          `json:"riskLevel,omitempty"`
	Action          string          `json:"action"`
	DurationSeconds *int            `json:"durationSeconds,omitempty"`
	EstimatedTokens *int            `json:"estimatedTokens,omitempty"`
	BrowserMeta     json.RawMessage `json:"browserMeta,omitempty"`
}

func (s *Store) InsertShadowAiEventBatch(ctx context.Context, events []ShadowAiEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, e := range events {
		var userID *string
		if e.UserID != "" {
			userID = &e.UserID
		}
		batch.Queue(
			`INSERT INTO shadow_ai_events (org_id, user_id, user_email, domain, ai_tool_name, category, risk_level, action, duration_seconds, estimated_tokens, browser_meta)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			e.OrgID, userID, e.UserEmail, e.Domain, e.AiToolName, e.Category, e.RiskLevel, e.Action, e.DurationSeconds, e.EstimatedTokens, e.BrowserMeta,
		)
	}

	br := s.PG.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(events); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch insert shadow event %d: %w", i, err)
		}
	}
	return nil
}

// ============================================================
// REDIS: REDACTION SESSION CACHE
// PII <-> Placeholder mappings stored temporarily for re-identification
// ============================================================

type RedactionMapping struct {
	Placeholder string `json:"placeholder"`
	Original    string `json:"original"`
	EntityType  string `json:"entityType"`
}

func (s *Store) StoreRedactionSession(ctx context.Context, requestID string, mappings []RedactionMapping, ttl time.Duration) error {
	data, err := json.Marshal(mappings)
	if err != nil {
		return err
	}
	return s.Redis.Set(ctx, "redact:"+requestID, data, ttl).Err()
}

func (s *Store) GetRedactionSession(ctx context.Context, requestID string) ([]RedactionMapping, error) {
	data, err := s.Redis.Get(ctx, "redact:"+requestID).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var mappings []RedactionMapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		return nil, err
	}
	return mappings, nil
}

func (s *Store) DeleteRedactionSession(ctx context.Context, requestID string) error {
	return s.Redis.Del(ctx, "redact:"+requestID).Err()
}

// ============================================================
// REDIS: ORG CONFIG CACHE (avoid DB round-trip on every request)
// ============================================================

func (s *Store) CacheOrgConfig(ctx context.Context, apiKey string, org *Organization, ttl time.Duration) error {
	data, err := json.Marshal(org)
	if err != nil {
		return err
	}
	return s.Redis.Set(ctx, "org:"+apiKey, data, ttl).Err()
}

func (s *Store) GetCachedOrgConfig(ctx context.Context, apiKey string) (*Organization, error) {
	data, err := s.Redis.Get(ctx, "org:"+apiKey).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var org Organization
	if err := json.Unmarshal(data, &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// ============================================================
// ANALYTICS QUERIES
// ============================================================

type UserRiskScore struct {
	UserID             string  `json:"userId"`
	Email              string  `json:"email"`
	Department         string  `json:"department"`
	TotalEvents        int     `json:"totalEvents"`
	CriticalEvents     int     `json:"criticalEvents"`
	HighEvents         int     `json:"highEvents"`
	CompositeRiskScore float64 `json:"compositeRiskScore"`
	LastEventAt        *string `json:"lastEventAt,omitempty"`
}

func (s *Store) GetUserRiskScores(ctx context.Context, orgID string, limit int) ([]UserRiskScore, error) {
	// Use materialized view for performance
	rows, err := s.PG.Query(ctx,
		`SELECT user_id, email, department, total_events, critical_events, high_events, composite_risk_score, last_event_at
		 FROM mv_user_risk_scores WHERE org_id = $1 ORDER BY composite_risk_score DESC LIMIT $2`,
		orgID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scores []UserRiskScore
	for rows.Next() {
		var s UserRiskScore
		var lastEvent *time.Time
		if err := rows.Scan(&s.UserID, &s.Email, &s.Department, &s.TotalEvents, &s.CriticalEvents, &s.HighEvents, &s.CompositeRiskScore, &lastEvent); err != nil {
			return nil, err
		}
		if lastEvent != nil {
			t := lastEvent.Format(time.RFC3339)
			s.LastEventAt = &t
		}
		scores = append(scores, s)
	}
	return scores, rows.Err()
}

func (s *Store) RefreshMaterializedViews(ctx context.Context) error {
	_, err := s.PG.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_user_risk_scores")
	if err != nil {
		return err
	}
	_, err = s.PG.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_department_risk")
	return err
}
