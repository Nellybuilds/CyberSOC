import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { generateIncidentResponse, type IncidentContext } from "./ai-service";

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

  // Playbook endpoints
  app.get("/api/alerts/:id/playbook", async (req, res) => {
    try {
      const { id } = req.params;
      const alert = await storage.getAlert(id);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }

      // Load actual playbook data from JSON file
      const playbooks = await storage.readJsonFile('playbook.json');
      
      // Map alert IDs to playbook IDs with intelligent classification
      const alertToPlaybookMap = {
        "alert-001": "ransomware-response",
        "alert-002": "ransomware-response", 
        "alert-003": "apt-response",
        "alert-004": "credential-compromise-response",
        "alert-005": "phishing-response",
        "alert-006": "data-breach-response",
        "alert-007": "ddos-response",
        "alert-008": "insider-threat-response"
      };

      const playbookId = alertToPlaybookMap[id as keyof typeof alertToPlaybookMap] || "ransomware-response";
      const playbook = playbooks.find((p: any) => p.id === playbookId);

      if (!playbook) {
        return res.status(404).json({ error: "Playbook not found" });
      }

      res.json(playbook);
    } catch (error) {
      console.error("Failed to fetch playbook:", error);
      res.status(500).json({ error: "Failed to fetch playbook" });
    }
  });

  // Workflow sessions
  app.get("/api/workflow-sessions/:alertId", async (req, res) => {
    try {
      const session = await storage.getWorkflowSessionByAlertId(req.params.alertId);
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

  // Create Incident - operational incident response
  app.post("/api/incidents/create", async (req, res) => {
    try {
      const { incidentType } = req.body;
      
      // Validate incident type with expanded options
      const validIncidentTypes = [
        "ransomware", 
        "credential-compromise", 
        "phishing", 
        "apt", 
        "data-breach", 
        "ddos", 
        "insider-threat"
      ];
      if (!incidentType || !validIncidentTypes.includes(incidentType)) {
        return res.status(400).json({ error: "Invalid incident type. Must be one of: " + validIncidentTypes.join(", ") });
      }
      
      // Clear all existing workflow sessions for fresh start
      await storage.clearAllWorkflowSessions();
      
      // Create incident from the selected type
      const incidentResult = await storage.createIncidentFromType(incidentType);
      
      res.json({ 
        success: true, 
        incidentType,
        incidentId: incidentResult.incident.id,
        activeAlertId: incidentResult.activeAlertId,
        message: `${incidentResult.incidentName} incident created successfully.` 
      });
    } catch (error: any) {
      console.error("Error creating incident:", error);
      res.status(500).json({ 
        error: "Failed to create incident", 
        details: error.message 
      });
    }
  });

  // Legacy endpoint - for backwards compatibility
  app.post("/api/workflow-sessions/reset", async (req, res) => {
    try {
      const { scenario } = req.body;
      
      // Validate scenario with expanded options
      const validScenarios = [
        "ransomware", 
        "credential-compromise", 
        "phishing", 
        "apt", 
        "data-breach", 
        "ddos", 
        "insider-threat"
      ];
      if (!scenario || !validScenarios.includes(scenario)) {
        return res.status(400).json({ error: "Invalid scenario. Must be one of: " + validScenarios.join(", ") });
      }
      
      // Clear all existing workflow sessions for fresh start
      await storage.clearAllWorkflowSessions();
      
      // Create incident from the selected type
      const incidentResult = await storage.createIncidentFromType(scenario);
      
      res.json({ 
        success: true, 
        scenario,
        activeAlertId: incidentResult.activeAlertId,
        message: `${incidentResult.incidentName} incident created successfully.` 
      });
    } catch (error) {
      console.error("Failed to reset simulation:", error);
      res.status(500).json({ error: "Failed to reset simulation" });
    }
  });

  // Reports
  app.post("/api/reports/generate", async (req, res) => {
    try {
      const { sessionId, format, userRole = 'Analyst' } = req.body;
      const report = await storage.generateReport(sessionId);
      
      if (format === 'pdf') {
        try {
          const { PDFGenerator } = await import('./pdf-generator');
          const pdfBuffer = await PDFGenerator.generatePDF({ userRole, report });
          
          res.setHeader('Content-Type', 'application/pdf');
          res.setHeader('Content-Disposition', `attachment; filename="incident-report-${new Date().toISOString().split('T')[0]}.pdf"`);
          res.send(pdfBuffer);
        } catch (pdfError) {
          // If PDF generation fails, return JSON instead
          console.warn('PDF generation failed, returning JSON report:', pdfError);
          res.json(report);
        }
      } else {
        // Return JSON for other formats (json, txt)
        res.json(report);
      }
    } catch (error) {
      console.error('Report generation error:', error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  // Simulation Control Endpoints
  app.post("/api/simulation/trigger-alert", async (req, res) => {
    try {
      const { alertType, timestamp } = req.body;
      
      const alertMap = {
        "critical-breach": {
          title: "Critical Data Breach Detected",
          severity: "Critical",
          description: "Unauthorized access to sensitive customer database detected",
          affectedEndpoints: ["endpoint-01", "endpoint-02", "endpoint-03"]
        },
        "ransomware-outbreak": {
          title: "Ransomware Outbreak in Progress",
          severity: "Critical",
          description: "Multiple endpoints showing ransomware encryption activity",
          affectedEndpoints: ["endpoint-01", "endpoint-04", "endpoint-05"]
        },
        "credential-theft": {
          title: "Credential Theft Attempt",
          severity: "High", 
          description: "Suspicious authentication attempts from unknown locations",
          affectedEndpoints: ["endpoint-02", "endpoint-06"]
        },
        "phishing-campaign": {
          title: "Active Phishing Campaign",
          severity: "High",
          description: "Mass phishing emails targeting employee credentials", 
          affectedEndpoints: ["endpoint-01", "endpoint-03"]
        }
      };
      
      const alertConfig = alertMap[alertType as keyof typeof alertMap];
      if (!alertConfig) {
        return res.status(400).json({ error: "Invalid alert type" });
      }
      
      // Create a new simulated alert by updating existing alerts
      const alerts = await storage.getAlerts();
      const targetAlert = alerts.find(alert => alert.status !== "New");
      
      if (targetAlert) {
        // Update an existing alert to simulate a new threat
        await storage.updateAlert(targetAlert.id, {
          title: alertConfig.title,
          severity: alertConfig.severity as any,
          status: "New" as any,
          timestamp: new Date(),
          description: alertConfig.description
        });
        
        // Update affected endpoints
        for (const endpointId of alertConfig.affectedEndpoints) {
          await storage.updateEndpoint(endpointId, { status: "Affected" });
        }
      }
      
      res.json({
        success: true,
        alertType,
        alertTitle: alertConfig.title,
        severity: alertConfig.severity,
        description: alertConfig.description,
        timestamp,
        affectedEndpoints: alertConfig.affectedEndpoints.length
      });
    } catch (error) {
      console.error("Simulation trigger error:", error);
      res.status(500).json({ error: "Failed to trigger simulation alert" });
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

  // AI Recommendation Actions
  app.post("/api/actions/isolate-all", async (req, res) => {
    try {
      const { endpointIds } = req.body;
      const results = [];
      
      for (const endpointId of endpointIds) {
        const endpoint = await storage.updateEndpoint(endpointId, { status: "Isolated" });
        if (endpoint) results.push(endpoint);
      }
      
      res.json({ success: true, isolatedEndpoints: results.length, endpoints: results });
    } catch (error) {
      res.status(500).json({ error: "Failed to isolate endpoints" });
    }
  });

  app.post("/api/actions/lock-accounts", async (req, res) => {
    try {
      res.json({ 
        success: true, 
        action: "accounts_locked",
        affected_accounts: 3,
        message: "User accounts locked as security precaution"
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to lock user accounts" });
    }
  });

  app.post("/api/actions/analyze-traffic", async (req, res) => {
    try {
      const { alertId } = req.body;
      
      const analysisResults = {
        suspicious_connections: 12,
        blocked_ips: ["192.168.1.100", "10.0.0.50"],
        threat_indicators: ["T1071.001", "T1090.003"],
        recommendation: "Immediate network segmentation required"
      };
      
      res.json({ 
        success: true, 
        action: "traffic_analyzed",
        alertId,
        results: analysisResults
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to analyze network traffic" });
    }
  });

  app.post("/api/workflow/advance", async (req, res) => {
    try {
      const { alertId, phase } = req.body;
      
      // Update or create workflow session to advance phase
      let session = await storage.getWorkflowSessionByAlertId(alertId);
      
      if (!session) {
        session = await storage.createWorkflowSession({
          alert_id: alertId,
          current_node: `${phase.toLowerCase()}-start`,
          started_at: new Date(),
          status: "Active",
          completed_nodes: [],
          actions_taken: { phase, advanced_at: new Date().toISOString() },
          user_role: "Analyst"
        });
      } else {
        session = await storage.updateWorkflowSession(session.id, {
          current_node: `${phase.toLowerCase()}-start`,
          actions_taken: { phase, advanced_at: new Date().toISOString() }
        });
      }
      
      res.json({ 
        success: true, 
        action: "phase_advanced",
        alertId,
        newPhase: phase,
        session 
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to advance workflow phase" });
    }
  });

  // AI Assistant endpoint
  app.post("/api/ai-assistant", async (req, res) => {
    try {
      const { scenario, evidence, severity, affected_systems, role } = req.body;
      
      // Validate required fields
      if (!scenario || !evidence || !severity || !affected_systems || !role) {
        return res.status(400).json({ 
          error: "Missing required fields: scenario, evidence, severity, affected_systems, role" 
        });
      }

      // Validate scenario type
      const validScenarios = ['perimeter-breach', 'internal-reconnaissance', 'lateral-movement'];
      if (!validScenarios.includes(scenario)) {
        return res.status(400).json({ 
          error: "Invalid scenario. Must be one of: " + validScenarios.join(', ') 
        });
      }

      // Validate role
      const validRoles = ['analyst', 'manager', 'client'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ 
          error: "Invalid role. Must be one of: " + validRoles.join(', ') 
        });
      }

      const incidentContext: IncidentContext = {
        scenario,
        evidence: Array.isArray(evidence) ? evidence : [evidence],
        severity,
        affected_systems: Array.isArray(affected_systems) ? affected_systems : [affected_systems],
        role
      };

      try {
        const aiResponse = await generateIncidentResponse(incidentContext);
        res.json({
          success: true,
          scenario,
          role,
          ...aiResponse
        });
      } catch (aiError) {
        console.error('AI service error:', aiError);
        
        // Fallback recommendations when AI service is unavailable
        const fallbackRecommendations = [
          {
            action: "Isolate All Endpoints",
            description: "Immediately isolate affected systems to prevent further spread",
            priority: 1,
            source: "NIST CSF RS.MI-3: Contain incidents"
          },
          {
            action: "Lock User Accounts", 
            description: "Disable compromised accounts to prevent unauthorized access",
            priority: 1,
            source: "SANS Incident Handling Guide"
          },
          {
            action: "Analyze Network Traffic",
            description: "Review network logs to identify attack vectors and scope",
            priority: 2,
            source: "NIST CSF DE.AE-2: Analyze events"
          }
        ];

        res.json({
          success: true,
          scenario,
          role,
          recommendations: fallbackRecommendations,
          fallback: true,
          message: "Using fallback recommendations - AI service temporarily unavailable"
        });
      }
    } catch (error) {
      console.error('AI assistant error:', error);
      res.status(500).json({ 
        error: "Failed to generate AI recommendations",
        fallback_message: "AI service unavailable. Please use standard incident response procedures."
      });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}