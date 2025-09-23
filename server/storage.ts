import type { Alert, Endpoint, LogEntry, Playbook, WorkflowSession, Report, InsertAlert, InsertEndpoint, InsertLogEntry, InsertPlaybook, InsertWorkflowSession, InsertReport } from "@shared/schema";
import { alerts, endpoints, logs, playbooks, workflow_sessions, reports } from "@shared/schema";
import { db } from "./db";
import { eq, and, desc, asc } from "drizzle-orm";
import { randomUUID } from "crypto";
import fs from "fs/promises";
import path from "path";

export interface IStorage {
  // Alerts
  getAlerts(): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  updateAlert(id: string, updates: Partial<Alert>): Promise<Alert | undefined>;

  // Endpoints
  getEndpoints(): Promise<Endpoint[]>;
  getEndpoint(id: string): Promise<Endpoint | undefined>;
  updateEndpoint(id: string, updates: Partial<Endpoint>): Promise<Endpoint | undefined>;

  // Logs
  getLogs(filters?: { source?: string; severity?: string; limit?: number }): Promise<LogEntry[]>;
  
  // Playbooks
  getPlaybook(id: string): Promise<Playbook | undefined>;
  
  // Workflow Sessions
  createWorkflowSession(session: Omit<WorkflowSession, "id">): Promise<WorkflowSession>;
  getWorkflowSession(id: string): Promise<WorkflowSession | undefined>;
  getWorkflowSessionByAlertId(alertId: string): Promise<WorkflowSession | undefined>;
  updateWorkflowSession(id: string, updates: Partial<WorkflowSession>): Promise<WorkflowSession | undefined>;
  clearAllWorkflowSessions(): Promise<void>;
  resetEndpointsToInitialState(): Promise<void>;
  applyScenario(scenario: string): Promise<{ activeAlertId: string; scenarioName: string }>;

  // Reports
  generateReport(sessionId?: string): Promise<Report>;
}

export class FileStorage implements IStorage {
  private dataDir: string;

  constructor() {
    this.dataDir = path.join(import.meta.dirname, "data");
  }

  private async readJsonFile<T>(filename: string): Promise<T[]> {
    try {
      const filePath = path.join(this.dataDir, filename);
      const data = await fs.readFile(filePath, "utf-8");
      return JSON.parse(data);
    } catch (error) {
      console.error(`Error reading ${filename}:`, error);
      return [];
    }
  }

  private async writeJsonFile<T>(filename: string, data: T[]): Promise<void> {
    try {
      const filePath = path.join(this.dataDir, filename);
      await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error(`Error writing ${filename}:`, error);
    }
  }

  async getAlerts(): Promise<Alert[]> {
    return this.readJsonFile<Alert>("alerts.json");
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const alerts = await this.getAlerts();
    return alerts.find(alert => alert.id === id);
  }

  async updateAlert(id: string, updates: Partial<Alert>): Promise<Alert | undefined> {
    const alerts = await this.getAlerts();
    const index = alerts.findIndex(alert => alert.id === id);
    if (index === -1) return undefined;

    alerts[index] = { ...alerts[index], ...updates };
    await this.writeJsonFile("alerts.json", alerts);
    return alerts[index];
  }

  async getEndpoints(): Promise<Endpoint[]> {
    return this.readJsonFile<Endpoint>("endpoints.json");
  }

  async getEndpoint(id: string): Promise<Endpoint | undefined> {
    const endpoints = await this.getEndpoints();
    return endpoints.find(endpoint => endpoint.id === id);
  }

  async updateEndpoint(id: string, updates: Partial<Endpoint>): Promise<Endpoint | undefined> {
    const endpoints = await this.getEndpoints();
    const index = endpoints.findIndex(endpoint => endpoint.id === id);
    if (index === -1) return undefined;

    endpoints[index] = { ...endpoints[index], ...updates };
    await this.writeJsonFile("endpoints.json", endpoints);
    return endpoints[index];
  }

  async getLogs(filters?: { source?: string; severity?: string; limit?: number }): Promise<LogEntry[]> {
    let logs = await this.readJsonFile<LogEntry>("logs.json");
    
    if (filters?.source && filters.source !== "All Sources") {
      logs = logs.filter(log => log.source === filters.source);
    }
    
    if (filters?.severity && filters.severity !== "All Severities") {
      logs = logs.filter(log => log.severity === filters.severity);
    }
    
    // Sort by timestamp (newest first)
    logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    
    if (filters?.limit) {
      logs = logs.slice(0, filters.limit);
    }
    
    return logs;
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const playbooks = await this.readJsonFile<Playbook>("playbook.json");
    return playbooks.find(playbook => playbook.id === id);
  }

  async createWorkflowSession(session: Omit<WorkflowSession, "id">): Promise<WorkflowSession> {
    const sessions = await this.readJsonFile<WorkflowSession>("workflow_sessions.json");
    const newSession: WorkflowSession = {
      ...session,
      id: randomUUID(),
    };
    
    sessions.push(newSession);
    await this.writeJsonFile("workflow_sessions.json", sessions);
    return newSession;
  }

  async getWorkflowSession(id: string): Promise<WorkflowSession | undefined> {
    const sessions = await this.readJsonFile<WorkflowSession>("workflow_sessions.json");
    return sessions.find(session => session.id === id);
  }

  async getWorkflowSessionByAlertId(alertId: string): Promise<WorkflowSession | undefined> {
    const sessions = await this.readJsonFile<WorkflowSession>("workflow_sessions.json");
    return sessions.find(session => session.alert_id === alertId);
  }

  async updateWorkflowSession(id: string, updates: Partial<WorkflowSession>): Promise<WorkflowSession | undefined> {
    const sessions = await this.readJsonFile<WorkflowSession>("workflow_sessions.json");
    const index = sessions.findIndex(session => session.id === id);
    if (index === -1) return undefined;

    sessions[index] = { ...sessions[index], ...updates };
    await this.writeJsonFile("workflow_sessions.json", sessions);
    return sessions[index];
  }

  async generateReport(sessionId?: string): Promise<Report> {
    const reports = await this.readJsonFile<Report>("reports.json");
    const report: Report = {
      id: randomUUID(),
      session_id: sessionId || null,
      generated_at: new Date(),
      incident_summary: {
        title: "Ransomware Attack - Financial Department",
        severity: "Critical",
        affected_assets: 5,
        response_time: "15 minutes",
        status: "In Progress"
      },
      timeline: [
        {
          timestamp: "2025-01-17T13:01:00Z",
          phase: "Detection",
          action: "Alert Generated",
          details: "Ransomware detected on 5 endpoints"
        },
        {
          timestamp: "2025-01-17T13:05:00Z",
          phase: "Scoping",
          action: "Impact Assessment",
          details: "Identified affected systems and users"
        }
      ],
      mitre_techniques: ["T1486", "T1059.001"],
      recommendations: [
        "Implement regular backup verification procedures",
        "Enhance endpoint detection capabilities",
        "Conduct ransomware response training"
      ]
    };

    // Persist report to file to match DatabaseStorage behavior
    reports.push(report);
    await this.writeJsonFile("reports.json", reports);
    
    return report;
  }

  async clearAllWorkflowSessions(): Promise<void> {
    // Clear all workflow sessions by writing empty array
    await this.writeJsonFile("workflow_sessions.json", []);
  }

  async resetEndpointsToInitialState(): Promise<void> {
    // Reset all endpoints to Normal status to match DatabaseStorage behavior
    const endpoints = await this.readJsonFile<Endpoint>("endpoints.json");
    const updatedEndpoints = endpoints.map(endpoint => ({
      ...endpoint,
      status: "Normal" as const
    }));
    await this.writeJsonFile("endpoints.json", updatedEndpoints);
  }

  async applyScenario(scenario: string): Promise<{ activeAlertId: string; scenarioName: string }> {
    // Map scenarios to alert IDs and configure endpoints
    const scenarioMap = {
      "ransomware": { alertId: "alert-001", name: "Ransomware Attack", affectedEndpoints: ["endpoint-01", "endpoint-02", "endpoint-03", "endpoint-04", "endpoint-05"] },
      "credential-compromise": { alertId: "alert-004", name: "Credential Compromise", affectedEndpoints: ["endpoint-03", "endpoint-06", "endpoint-07"] },
      "phishing": { alertId: "alert-005", name: "Phishing Campaign", affectedEndpoints: ["endpoint-01", "endpoint-02"] }
    };
    
    const config = scenarioMap[scenario as keyof typeof scenarioMap];
    if (!config) throw new Error(`Unknown scenario: ${scenario}`);
    
    // Update endpoints and alerts to match DatabaseStorage behavior
    const endpoints = await this.readJsonFile<Endpoint>("endpoints.json");
    const alerts = await this.readJsonFile<Alert>("alerts.json");
    
    // Reset all endpoints to Normal first
    const resetEndpoints = endpoints.map(ep => ({ ...ep, status: "Normal" as const }));
    
    // Set affected endpoints for this scenario
    const updatedEndpoints = resetEndpoints.map(ep => 
      config.affectedEndpoints.includes(ep.id) 
        ? { ...ep, status: "Affected" as const }
        : ep
    );
    
    // Update the target alert to make it "fresh" and active
    const updatedAlerts = alerts.map(alert => 
      alert.id === config.alertId
        ? { ...alert, status: "New" as const, timestamp: new Date().toISOString() }
        : alert
    );
    
    // Write updated data back to files
    await this.writeJsonFile("endpoints.json", updatedEndpoints);
    await this.writeJsonFile("alerts.json", updatedAlerts);
    
    return { activeAlertId: config.alertId, scenarioName: config.name };
  }
}

// Reference: Drizzle blueprint integration for database setup
export class DatabaseStorage implements IStorage {
  async getAlerts(): Promise<Alert[]> {
    return db.select().from(alerts).orderBy(desc(alerts.timestamp));
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
    return alert || undefined;
  }

  async updateAlert(id: string, updates: Partial<Alert>): Promise<Alert | undefined> {
    const [alert] = await db
      .update(alerts)
      .set(updates)
      .where(eq(alerts.id, id))
      .returning();
    return alert || undefined;
  }

  async getEndpoints(): Promise<Endpoint[]> {
    return db.select().from(endpoints).orderBy(asc(endpoints.hostname));
  }

  async getEndpoint(id: string): Promise<Endpoint | undefined> {
    const [endpoint] = await db.select().from(endpoints).where(eq(endpoints.id, id));
    return endpoint || undefined;
  }

  async updateEndpoint(id: string, updates: Partial<Endpoint>): Promise<Endpoint | undefined> {
    const [endpoint] = await db
      .update(endpoints)
      .set(updates)
      .where(eq(endpoints.id, id))
      .returning();
    return endpoint || undefined;
  }

  async getLogs(filters?: { source?: string; severity?: string; limit?: number }): Promise<LogEntry[]> {
    const conditions = [];
    
    if (filters?.source && filters.source !== "All Sources") {
      conditions.push(eq(logs.source, filters.source));
    }
    
    if (filters?.severity && filters.severity !== "All Severities") {
      conditions.push(eq(logs.severity, filters.severity as any));
    }
    
    let query = db.select().from(logs);

    if (conditions.length > 0) {
      query = query.where(and(...conditions)) as any;
    }
    
    const result = await query.orderBy(desc(logs.timestamp));
    
    if (filters?.limit) {
      return result.slice(0, filters.limit);
    }
    
    return result;
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const [playbook] = await db.select().from(playbooks).where(eq(playbooks.id, id));
    return playbook || undefined;
  }

  async createWorkflowSession(session: Omit<WorkflowSession, "id">): Promise<WorkflowSession> {
    const [newSession] = await db
      .insert(workflow_sessions)
      .values(session)
      .returning();
    return newSession;
  }

  async getWorkflowSession(id: string): Promise<WorkflowSession | undefined> {
    const [session] = await db.select().from(workflow_sessions).where(eq(workflow_sessions.id, id));
    return session || undefined;
  }

  async getWorkflowSessionByAlertId(alertId: string): Promise<WorkflowSession | undefined> {
    const [session] = await db.select().from(workflow_sessions).where(eq(workflow_sessions.alert_id, alertId));
    return session || undefined;
  }

  async updateWorkflowSession(id: string, updates: Partial<WorkflowSession>): Promise<WorkflowSession | undefined> {
    const [session] = await db
      .update(workflow_sessions)
      .set(updates)
      .where(eq(workflow_sessions.id, id))
      .returning();
    return session || undefined;
  }

  async generateReport(sessionId?: string): Promise<Report> {
    let session = null;
    let alert = null;
    
    if (sessionId === "current") {
      // Get the most recent active session or find an active alert to create context
      const activeSessions = await db.select().from(workflow_sessions).orderBy(desc(workflow_sessions.id)).limit(1);
      session = activeSessions[0] || null;
      
      // If no session exists, try to get the most recent alert to create context
      if (!session) {
        const recentAlerts = await db.select().from(alerts).orderBy(desc(alerts.id)).limit(1);
        alert = recentAlerts[0] || null;
      } else {
        alert = await this.getAlert(session.alert_id);
      }
    } else if (sessionId) {
      session = await this.getWorkflowSession(sessionId);
      alert = session ? await this.getAlert(session.alert_id) : null;
    }

    const reportData = {
      session_id: sessionId || null,
      incident_summary: {
        title: alert?.title || "Security Incident",
        severity: alert?.severity || "Medium",
        affected_assets: alert?.affected_endpoints?.length || 0,
        response_time: "15 minutes",
        status: alert?.status || "In Progress"
      },
      timeline: [
        {
          timestamp: new Date().toISOString(),
          phase: "Detection",
          action: "Alert Generated",
          details: alert?.description || "Security incident detected"
        },
        {
          timestamp: new Date().toISOString(),
          phase: "Investigation",
          action: "Analysis Started",
          details: "Incident response team engaged"
        }
      ],
      mitre_techniques: alert?.mitre_tactics || [],
      recommendations: [
        "Implement regular security assessments",
        "Enhance monitoring capabilities",
        "Conduct incident response training"
      ]
    };

    const [report] = await db
      .insert(reports)
      .values(reportData)
      .returning();
    
    return report;
  }

  async clearAllWorkflowSessions(): Promise<void> {
    await db.delete(workflow_sessions);
  }

  async resetEndpointsToInitialState(): Promise<void> {
    // Reset all endpoints to Normal status (their initial state)
    await db.update(endpoints).set({ status: "Normal" });
  }

  async applyScenario(scenario: string): Promise<{ activeAlertId: string; scenarioName: string }> {
    // Map scenarios to alert IDs and their configurations
    const scenarioMap = {
      "ransomware": {
        alertId: "alert-001",
        name: "Ransomware Attack",
        affectedEndpoints: ["endpoint-01", "endpoint-02", "endpoint-03", "endpoint-04", "endpoint-05"],
        status: "New" as const
      },
      "credential-compromise": {
        alertId: "alert-004", 
        name: "Credential Compromise",
        affectedEndpoints: ["endpoint-03", "endpoint-06", "endpoint-07"],
        status: "New" as const
      },
      "phishing": {
        alertId: "alert-005",
        name: "Phishing Campaign", 
        affectedEndpoints: ["endpoint-01", "endpoint-02"],
        status: "New" as const
      }
    };
    
    const config = scenarioMap[scenario as keyof typeof scenarioMap];
    if (!config) throw new Error(`Unknown scenario: ${scenario}`);
    
    // Reset all endpoints to Normal first
    await db.update(endpoints).set({ status: "Normal" });
    
    // Set affected endpoints for this scenario
    if (config.affectedEndpoints.length > 0) {
      await db.update(endpoints)
        .set({ status: "Affected" })
        .where(eq(endpoints.id, config.affectedEndpoints[0]));
      
      // Update remaining endpoints one by one to avoid complex where clause
      for (const endpointId of config.affectedEndpoints.slice(1)) {
        await db.update(endpoints)
          .set({ status: "Affected" })
          .where(eq(endpoints.id, endpointId));
      }
    }
    
    // Update the target alert to make it "fresh" and active
    await db.update(alerts)
      .set({ 
        status: config.status,
        timestamp: new Date() // Set current timestamp to make it appear as newest
      })
      .where(eq(alerts.id, config.alertId));
    
    return { activeAlertId: config.alertId, scenarioName: config.name };
  }
}

// Use DatabaseStorage for database-backed persistence
export const storage = new DatabaseStorage();
