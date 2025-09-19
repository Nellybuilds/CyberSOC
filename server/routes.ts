import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";

export async function registerRoutes(app: Express): Promise<Server> {
  // Alerts endpoints
  app.get("/api/alerts", async (req, res) => {
    try {
      const alerts = await storage.getAlerts();
      res.json(alerts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch alerts" });
    }
  });

  app.get("/api/alerts/:id", async (req, res) => {
    try {
      const alert = await storage.getAlert(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch alert" });
    }
  });

  app.patch("/api/alerts/:id", async (req, res) => {
    try {
      const alert = await storage.updateAlert(req.params.id, req.body);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      res.status(500).json({ error: "Failed to update alert" });
    }
  });

  // Endpoints
  app.get("/api/endpoints", async (req, res) => {
    try {
      const endpoints = await storage.getEndpoints();
      res.json(endpoints);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch endpoints" });
    }
  });

  app.patch("/api/endpoints/:id", async (req, res) => {
    try {
      const endpoint = await storage.updateEndpoint(req.params.id, req.body);
      if (!endpoint) {
        return res.status(404).json({ error: "Endpoint not found" });
      }
      res.json(endpoint);
    } catch (error) {
      res.status(500).json({ error: "Failed to update endpoint" });
    }
  });

  // Logs
  app.get("/api/logs", async (req, res) => {
    try {
      const { source, severity, limit } = req.query;
      const logs = await storage.getLogs({
        source: source as string,
        severity: severity as string,
        limit: limit ? parseInt(limit as string) : undefined
      });
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch logs" });
    }
  });

  // Playbooks
  app.get("/api/playbooks/:id", async (req, res) => {
    try {
      const playbook = await storage.getPlaybook(req.params.id);
      if (!playbook) {
        return res.status(404).json({ error: "Playbook not found" });
      }
      res.json(playbook);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbook" });
    }
  });

  // Get playbook for specific alert type
  app.get("/api/alerts/:alertId/playbook", async (req, res) => {
    try {
      const alert = await storage.getAlert(req.params.alertId);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }

      // Map alert title to playbook ID
      let playbookId = "ransomware-response"; // default
      if (alert.title.toLowerCase().includes("phishing")) {
        playbookId = "phishing-response";
      } else if (alert.title.toLowerCase().includes("credential")) {
        playbookId = "credential-compromise-response";
      }

      const playbook = await storage.getPlaybook(playbookId);
      if (!playbook) {
        return res.status(404).json({ error: "Playbook not found" });
      }
      res.json(playbook);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbook for alert" });
    }
  });

  // Workflow sessions
  app.get("/api/workflow-sessions/:alertId", async (req, res) => {
    try {
      const { alertId } = req.params;
      const session = await storage.getWorkflowSessionByAlertId(alertId);
      if (!session) {
        return res.status(404).json({ error: "No workflow session found for this alert" });
      }
      res.json(session);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch workflow session" });
    }
  });

  app.post("/api/workflow-sessions", async (req, res) => {
    try {
      const session = await storage.createWorkflowSession(req.body);
      res.json(session);
    } catch (error) {
      res.status(500).json({ error: "Failed to create workflow session" });
    }
  });

  app.put("/api/workflow-sessions/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const session = await storage.updateWorkflowSession(id, req.body);
      if (!session) {
        return res.status(404).json({ error: "Workflow session not found" });
      }
      res.json(session);
    } catch (error) {
      res.status(500).json({ error: "Failed to update workflow session" });
    }
  });

  // Reset simulation - clear all workflow sessions and apply selected scenario
  app.post("/api/workflow-sessions/reset", async (req, res) => {
    try {
      const { scenario } = req.body;
      
      // Validate scenario
      const validScenarios = ["ransomware", "credential-compromise", "phishing"];
      if (!scenario || !validScenarios.includes(scenario)) {
        return res.status(400).json({ error: "Invalid scenario. Must be one of: " + validScenarios.join(", ") });
      }
      
      // Clear all existing workflow sessions for fresh start
      await storage.clearAllWorkflowSessions();
      
      // Apply the selected scenario
      const scenarioResult = await storage.applyScenario(scenario);
      
      res.json({ 
        success: true, 
        scenario,
        activeAlertId: scenarioResult.activeAlertId,
        message: `${scenarioResult.scenarioName} simulation started successfully.` 
      });
    } catch (error) {
      console.error("Failed to reset simulation:", error);
      res.status(500).json({ error: "Failed to reset simulation" });
    }
  });

  // Reports
  app.post("/api/reports/generate", async (req, res) => {
    try {
      const { sessionId } = req.body;
      const report = await storage.generateReport(sessionId);
      res.json(report);
    } catch (error) {
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  // Actions
  app.post("/api/actions/isolate-endpoint", async (req, res) => {
    try {
      const { endpointId } = req.body;
      const endpoint = await storage.updateEndpoint(endpointId, { status: "Isolated" });
      res.json({ success: true, endpoint });
    } catch (error) {
      res.status(500).json({ error: "Failed to isolate endpoint" });
    }
  });

  app.post("/api/actions/isolate-all", async (req, res) => {
    try {
      const { endpointIds } = req.body;
      const promises = endpointIds.map((id: string) => 
        storage.updateEndpoint(id, { status: "Isolated" })
      );
      await Promise.all(promises);
      res.json({ success: true, message: "All endpoints isolated" });
    } catch (error) {
      res.status(500).json({ error: "Failed to isolate endpoints" });
    }
  });

  app.post("/api/actions/lock-accounts", async (req, res) => {
    try {
      // Simulate locking all user accounts to prevent lateral movement
      res.json({ 
        success: true, 
        message: "All user accounts have been locked",
        lockedAccounts: 15
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to lock accounts" });
    }
  });

  app.post("/api/actions/reconnect-endpoint", async (req, res) => {
    try {
      const { endpointId } = req.body;
      const endpoint = await storage.updateEndpoint(endpointId, { status: "Normal" });
      res.json({ success: true, endpoint });
    } catch (error) {
      res.status(500).json({ error: "Failed to reconnect endpoint" });
    }
  });

  app.post("/api/actions/analyze-traffic", async (req, res) => {
    try {
      const { alertId } = req.body;
      // Simulate network traffic analysis
      const analysisResults = {
        suspiciousConnections: 3,
        blockedIPs: ["192.168.1.100", "10.0.0.50"],
        malwareSignatures: ["Emotet.Variant.A", "Ransomware.Ryuk"],
        networkSegmentationStatus: "Partial"
      };
      
      res.json({ 
        success: true, 
        alertId,
        analysis: analysisResults,
        message: "Network traffic analysis complete" 
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to analyze network traffic" });
    }
  });

  app.post("/api/workflow/advance", async (req, res) => {
    try {
      const { alertId, phase } = req.body;
      
      // Create or update workflow session
      const session = await storage.createWorkflowSession({
        alert_id: alertId,
        current_node: phase.toLowerCase() + "_phase",
        started_at: new Date(),
        completed_nodes: ["detection_phase"],
        actions_taken: [{
          timestamp: new Date().toISOString(),
          action: `Advanced to ${phase}`,
          details: { phase, automated: true }
        }],
        status: "Active",
        user_role: "Analyst"
      });
      
      res.json({ 
        success: true, 
        session,
        currentPhase: phase,
        message: `Workflow advanced to ${phase} phase` 
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to advance workflow" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
