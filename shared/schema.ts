import { z } from "zod";
import { pgTable, varchar, text, json, timestamp, pgEnum } from "drizzle-orm/pg-core";
import { relations, sql } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";

// Alert Schema
export const alertSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(["Critical", "High", "Medium", "Low"]),
  status: z.enum(["New", "In Progress", "Resolved", "Dismissed"]),
  timestamp: z.string(),
  affected_endpoints: z.array(z.string()),
  mitre_tactics: z.array(z.string()),
  description: z.string().optional(),
});

// Endpoint Schema
export const endpointSchema = z.object({
  id: z.string(),
  hostname: z.string(),
  ip_address: z.string(),
  user: z.string(),
  status: z.enum(["Normal", "Affected", "Isolated", "Quarantined"]),
  os: z.string().optional(),
  department: z.string().optional(),
});

// Log Entry Schema
export const logEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  source: z.string(),
  severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]),
  message: z.string(),
  event_id: z.string().optional(),
  endpoint_id: z.string().optional(),
  raw_data: z.record(z.any()).optional(),
});

// Playbook Node Schema
export const playbookNodeSchema = z.object({
  id: z.string(),
  title: z.string(),
  ai_prompt: z.string(),
  phase: z.enum(["Detection", "Scoping", "Investigation", "Remediation", "Post-Incident"]),
  options: z.array(z.object({
    label: z.string(),
    action: z.string().optional(),
    next_node: z.string().optional(),
  })),
  mitre_techniques: z.array(z.string()).optional(),
  playbook_reference: z.string().optional(),
});

export type PlaybookNode = z.infer<typeof playbookNodeSchema>;

// Playbook Schema
export const playbookSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  start_node: z.string(),
  nodes: z.record(playbookNodeSchema),
});

// MITRE ATT&CK Technique Schema
export const mitreAttackTechniqueSchema = z.object({
  id: z.string(),
  name: z.string(),
  tactic: z.string(),
  description: z.string(),
  status: z.enum(["Active", "Detected", "Mitigated", "Monitored"]),
});

export type MitreAttackTechnique = z.infer<typeof mitreAttackTechniqueSchema>;

// Workflow Session Schema
export const workflowSessionSchema = z.object({
  id: z.string(),
  alert_id: z.string(),
  current_node: z.string(),
  started_at: z.string(),
  completed_nodes: z.array(z.string()),
  actions_taken: z.array(z.object({
    timestamp: z.string(),
    action: z.string(),
    details: z.record(z.any()),
  })),
  status: z.enum(["Active", "Completed", "Paused"]),
  user_role: z.enum(["Analyst", "Manager", "Client"]),
});

// Report Schema
export const reportSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  generated_at: z.string(),
  incident_summary: z.object({
    title: z.string(),
    severity: z.string(),
    affected_assets: z.number(),
    response_time: z.string(),
    status: z.string(),
  }),
  timeline: z.array(z.object({
    timestamp: z.string(),
    phase: z.string(),
    action: z.string(),
    details: z.string(),
  })),
  mitre_techniques: z.array(z.string()),
  recommendations: z.array(z.string()),
});

// Drizzle ORM Table Definitions
// Using varchar for IDs to maintain UUID compatibility with existing data

// Enums
export const severityEnum = pgEnum('severity', ['Critical', 'High', 'Medium', 'Low']);
export const logSeverityEnum = pgEnum('log_severity', ['Critical', 'High', 'Medium', 'Low', 'Info']);
export const alertStatusEnum = pgEnum('alert_status', ['New', 'In Progress', 'Resolved', 'Dismissed']);
export const endpointStatusEnum = pgEnum('endpoint_status', ['Normal', 'Affected', 'Isolated', 'Quarantined']);
export const workflowPhaseEnum = pgEnum('workflow_phase', ['Detection', 'Scoping', 'Investigation', 'Remediation', 'Post-Incident']);
export const workflowStatusEnum = pgEnum('workflow_status', ['Active', 'Completed', 'Paused']);
export const userRoleEnum = pgEnum('user_role', ['Analyst', 'Manager', 'Client']);
export const mitreStatusEnum = pgEnum('mitre_status', ['Active', 'Detected', 'Mitigated', 'Monitored']);

// Tables
export const alerts = pgTable('alerts', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  title: varchar('title').notNull(),
  severity: severityEnum('severity').notNull(),
  status: alertStatusEnum('status').notNull().default('New'),
  timestamp: timestamp('timestamp').notNull().defaultNow(),
  affected_endpoints: json('affected_endpoints').$type<string[]>().notNull().default([]),
  mitre_tactics: json('mitre_tactics').$type<string[]>().notNull().default([]),
  description: text('description'),
});

export const endpoints = pgTable('endpoints', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  hostname: varchar('hostname').notNull(),
  ip_address: varchar('ip_address').notNull(),
  user: varchar('user').notNull(),
  status: endpointStatusEnum('status').notNull().default('Normal'),
  os: varchar('os'),
  department: varchar('department'),
});

export const logs = pgTable('logs', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  timestamp: timestamp('timestamp').notNull().defaultNow(),
  source: varchar('source').notNull(),
  severity: logSeverityEnum('severity').notNull(),
  message: text('message').notNull(),
  event_id: varchar('event_id'),
  endpoint_id: varchar('endpoint_id'),
  raw_data: json('raw_data'),
});

export const playbooks = pgTable('playbooks', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  name: varchar('name').notNull(),
  description: text('description').notNull(),
  start_node: varchar('start_node').notNull(),
  nodes: json('nodes').notNull(),
});

export const workflow_sessions = pgTable('workflow_sessions', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  alert_id: varchar('alert_id').notNull(),
  current_node: varchar('current_node').notNull(),
  started_at: timestamp('started_at').notNull().defaultNow(),
  completed_nodes: json('completed_nodes').$type<string[]>().notNull().default([]),
  actions_taken: json('actions_taken').notNull().default([]),
  status: workflowStatusEnum('status').notNull().default('Active'),
  user_role: userRoleEnum('user_role').notNull(),
});

export const reports = pgTable('reports', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  session_id: varchar('session_id').notNull(),
  generated_at: timestamp('generated_at').notNull().defaultNow(),
  incident_summary: json('incident_summary').notNull(),
  timeline: json('timeline').notNull(),
  mitre_techniques: json('mitre_techniques').$type<string[]>().notNull().default([]),
  recommendations: json('recommendations').$type<string[]>().notNull().default([]),
});

// Relations
export const alertsRelations = relations(alerts, ({ many }) => ({
  workflow_sessions: many(workflow_sessions),
}));

export const workflowSessionsRelations = relations(workflow_sessions, ({ one, many }) => ({
  alert: one(alerts, {
    fields: [workflow_sessions.alert_id],
    references: [alerts.id],
  }),
  reports: many(reports),
}));

export const reportsRelations = relations(reports, ({ one }) => ({
  workflow_session: one(workflow_sessions, {
    fields: [reports.session_id],
    references: [workflow_sessions.id],
  }),
}));

export const logsRelations = relations(logs, ({ one }) => ({
  endpoint: one(endpoints, {
    fields: [logs.endpoint_id],
    references: [endpoints.id],
  }),
}));

// Insert schemas for forms
export const insertAlertSchema = createInsertSchema(alerts);
export const insertEndpointSchema = createInsertSchema(endpoints);
export const insertLogSchema = createInsertSchema(logs);
export const insertPlaybookSchema = createInsertSchema(playbooks);
export const insertWorkflowSessionSchema = createInsertSchema(workflow_sessions);
export const insertReportSchema = createInsertSchema(reports);

// Types
export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;
export type Endpoint = typeof endpoints.$inferSelect;
export type InsertEndpoint = typeof endpoints.$inferInsert;
export type LogEntry = typeof logs.$inferSelect;
export type InsertLogEntry = typeof logs.$inferInsert;
export type Playbook = typeof playbooks.$inferSelect;
export type InsertPlaybook = typeof playbooks.$inferInsert;
export type WorkflowSession = typeof workflow_sessions.$inferSelect;
export type InsertWorkflowSession = typeof workflow_sessions.$inferInsert;
export type Report = typeof reports.$inferSelect;
export type InsertReport = typeof reports.$inferInsert;
