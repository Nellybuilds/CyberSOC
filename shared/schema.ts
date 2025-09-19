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

// Training Schemas

// Training Module Schema
export const trainingModuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  scenario_id: z.string(),
  order: z.number(),
  objectives: z.array(z.string()),
  prerequisites: z.array(z.string()).optional(),
  estimated_duration: z.number(), // in minutes
});

// Training Lesson Schema
export const trainingLessonSchema = z.object({
  id: z.string(),
  module_id: z.string(),
  title: z.string(),
  content: z.string(),
  order: z.number(),
  lesson_type: z.enum(["content", "decision", "quiz"]),
  max_score: z.number(),
});

// Learning Objective Schema
export const learningObjectiveSchema = z.object({
  id: z.string(),
  module_id: z.string(),
  description: z.string(),
  weight: z.number(), // importance weight for scoring
  status: z.enum(["not_started", "in_progress", "completed", "failed"]),
});

// Decision Point Schema
export const decisionPointSchema = z.object({
  id: z.string(),
  lesson_id: z.string(),
  question: z.string(),
  options: z.array(z.object({
    id: z.string(),
    text: z.string(),
    is_correct: z.boolean(),
    feedback: z.string(),
    points: z.number(),
  })),
  explanation: z.string(),
  mitre_technique: z.string().optional(),
});

// Quiz Question Schema
export const quizQuestionSchema = z.object({
  id: z.string(),
  lesson_id: z.string(),
  question: z.string(),
  options: z.array(z.object({
    id: z.string(),
    text: z.string(),
  })),
  correct_option_ids: z.array(z.string()),
  explanation: z.string(),
  points: z.number(),
  difficulty: z.enum(["easy", "medium", "hard"]),
});

// Training Session Schema
export const trainingSessionSchema = z.object({
  id: z.string(),
  module_id: z.string(),
  user_role: z.enum(["analyst", "manager", "client"]),
  current_lesson_id: z.string().optional(),
  status: z.enum(["not_started", "in_progress", "completed", "failed"]),
  started_at: z.string(),
  completed_at: z.string().optional(),
  total_score: z.number(),
  max_possible_score: z.number(),
  completion_percentage: z.number(),
});

// Session Progress Schema
export const sessionProgressSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  objective_id: z.string(),
  status: z.enum(["not_started", "in_progress", "completed", "failed"]),
  score: z.number(),
  completed_at: z.string().optional(),
});

// Decision Attempt Schema
export const decisionAttemptSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  decision_point_id: z.string(),
  selected_option_id: z.string(),
  is_correct: z.boolean(),
  points_earned: z.number(),
  feedback_shown: z.boolean(),
  attempted_at: z.string(),
});

// Quiz Attempt Schema
export const quizAttemptSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  question_id: z.string(),
  selected_option_ids: z.array(z.string()),
  is_correct: z.boolean(),
  points_earned: z.number(),
  attempted_at: z.string(),
});

// Score Breakdown Schema
export const scoreBreakdownSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  category: z.string(), // "decisions", "quiz", "time_bonus", "evidence_usage"
  points_earned: z.number(),
  points_possible: z.number(),
  details: z.record(z.any()),
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

// Training enums
export const trainingUserRoleEnum = pgEnum('training_user_role', ['analyst', 'manager', 'client']);
export const lessonTypeEnum = pgEnum('lesson_type', ['content', 'decision', 'quiz']);
export const objectiveStatusEnum = pgEnum('objective_status', ['not_started', 'in_progress', 'completed', 'failed']);
export const trainingSessionStatusEnum = pgEnum('training_session_status', ['not_started', 'in_progress', 'completed', 'failed']);
export const difficultyEnum = pgEnum('difficulty', ['easy', 'medium', 'hard']);

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

// Training Tables
export const training_modules = pgTable('training_modules', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  name: varchar('name').notNull(),
  description: text('description').notNull(),
  scenario_id: varchar('scenario_id').notNull(),
  order: varchar('order').notNull(),
  objectives: json('objectives').$type<string[]>().notNull().default([]),
  prerequisites: json('prerequisites').$type<string[]>().default([]),
  estimated_duration: varchar('estimated_duration').notNull(),
});

export const training_lessons = pgTable('training_lessons', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  module_id: varchar('module_id').notNull(),
  title: varchar('title').notNull(),
  content: text('content').notNull(),
  order: varchar('order').notNull(),
  lesson_type: lessonTypeEnum('lesson_type').notNull(),
  max_score: varchar('max_score').notNull(),
});

export const learning_objectives = pgTable('learning_objectives', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  module_id: varchar('module_id').notNull(),
  description: text('description').notNull(),
  weight: varchar('weight').notNull(),
  status: objectiveStatusEnum('status').notNull().default('not_started'),
});

export const decision_points = pgTable('decision_points', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  lesson_id: varchar('lesson_id').notNull(),
  question: text('question').notNull(),
  options: json('options').notNull(),
  explanation: text('explanation').notNull(),
  mitre_technique: varchar('mitre_technique'),
});

export const quiz_questions = pgTable('quiz_questions', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  lesson_id: varchar('lesson_id').notNull(),
  question: text('question').notNull(),
  options: json('options').notNull(),
  correct_option_ids: json('correct_option_ids').$type<string[]>().notNull(),
  explanation: text('explanation').notNull(),
  points: varchar('points').notNull(),
  difficulty: difficultyEnum('difficulty').notNull(),
});

export const training_sessions = pgTable('training_sessions', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  module_id: varchar('module_id').notNull(),
  user_role: trainingUserRoleEnum('user_role').notNull(),
  current_lesson_id: varchar('current_lesson_id'),
  status: trainingSessionStatusEnum('status').notNull().default('not_started'),
  started_at: varchar('started_at').notNull(),
  completed_at: varchar('completed_at'),
  total_score: varchar('total_score').notNull().default('0'),
  max_possible_score: varchar('max_possible_score').notNull().default('0'),
  completion_percentage: varchar('completion_percentage').notNull().default('0'),
});

export const session_progress = pgTable('session_progress', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  session_id: varchar('session_id').notNull(),
  objective_id: varchar('objective_id').notNull(),
  status: objectiveStatusEnum('status').notNull().default('not_started'),
  score: varchar('score').notNull().default('0'),
  completed_at: varchar('completed_at'),
});

export const decision_attempts = pgTable('decision_attempts', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  session_id: varchar('session_id').notNull(),
  decision_point_id: varchar('decision_point_id').notNull(),
  selected_option_id: varchar('selected_option_id').notNull(),
  is_correct: varchar('is_correct').notNull(),
  points_earned: varchar('points_earned').notNull().default('0'),
  feedback_shown: varchar('feedback_shown').notNull().default('false'),
  attempted_at: varchar('attempted_at').notNull(),
});

export const quiz_attempts = pgTable('quiz_attempts', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  session_id: varchar('session_id').notNull(),
  question_id: varchar('question_id').notNull(),
  selected_option_ids: json('selected_option_ids').$type<string[]>().notNull(),
  is_correct: varchar('is_correct').notNull(),
  points_earned: varchar('points_earned').notNull().default('0'),
  attempted_at: varchar('attempted_at').notNull(),
});

export const score_breakdowns = pgTable('score_breakdowns', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  session_id: varchar('session_id').notNull(),
  category: varchar('category').notNull(),
  points_earned: varchar('points_earned').notNull().default('0'),
  points_possible: varchar('points_possible').notNull().default('0'),
  details: json('details'),
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

// Training insert schemas
export const insertTrainingModuleSchema = createInsertSchema(training_modules);
export const insertTrainingLessonSchema = createInsertSchema(training_lessons);
export const insertLearningObjectiveSchema = createInsertSchema(learning_objectives);
export const insertDecisionPointSchema = createInsertSchema(decision_points);
export const insertQuizQuestionSchema = createInsertSchema(quiz_questions);
export const insertTrainingSessionSchema = createInsertSchema(training_sessions);
export const insertSessionProgressSchema = createInsertSchema(session_progress);
export const insertDecisionAttemptSchema = createInsertSchema(decision_attempts);
export const insertQuizAttemptSchema = createInsertSchema(quiz_attempts);
export const insertScoreBreakdownSchema = createInsertSchema(score_breakdowns);

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

// Training types
export type TrainingModule = typeof training_modules.$inferSelect;
export type InsertTrainingModule = typeof training_modules.$inferInsert;
export type TrainingLesson = typeof training_lessons.$inferSelect;
export type InsertTrainingLesson = typeof training_lessons.$inferInsert;
export type LearningObjective = typeof learning_objectives.$inferSelect;
export type InsertLearningObjective = typeof learning_objectives.$inferInsert;
export type DecisionPoint = typeof decision_points.$inferSelect;
export type InsertDecisionPoint = typeof decision_points.$inferInsert;
export type QuizQuestion = typeof quiz_questions.$inferSelect;
export type InsertQuizQuestion = typeof quiz_questions.$inferInsert;
export type TrainingSession = typeof training_sessions.$inferSelect;
export type InsertTrainingSession = typeof training_sessions.$inferInsert;
export type SessionProgress = typeof session_progress.$inferSelect;
export type InsertSessionProgress = typeof session_progress.$inferInsert;
export type DecisionAttempt = typeof decision_attempts.$inferSelect;
export type InsertDecisionAttempt = typeof decision_attempts.$inferInsert;
export type QuizAttempt = typeof quiz_attempts.$inferSelect;
export type InsertQuizAttempt = typeof quiz_attempts.$inferInsert;
export type ScoreBreakdown = typeof score_breakdowns.$inferSelect;
export type InsertScoreBreakdown = typeof score_breakdowns.$inferInsert;
