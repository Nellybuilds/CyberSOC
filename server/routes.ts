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

  // Intelligent Incident Classification Engine
  app.post("/api/classify-incident", async (req, res) => {
    try {
      const { evidence, organizationalContext } = req.body;
      
      // Initialize classification scores for all incident types
      const incidentScores = {
        ransomware: 0,
        "credential-compromise": 0,
        phishing: 0,
        apt: 0,
        "data-breach": 0,
        ddos: 0,
        "insider-threat": 0
      };

      // Evidence-based scoring system
      if (evidence) {
        // File system indicators
        if (evidence.fileEncryption || evidence.ransomnote) incidentScores.ransomware += 40;
        if (evidence.suspiciousFileExtensions) incidentScores.ransomware += 20;
        if (evidence.systemFilesModified) incidentScores.ransomware += 15;

        // Network indicators  
        if (evidence.commandAndControlTraffic) {
          incidentScores.apt += 35;
          incidentScores.ransomware += 20;
        }
        if (evidence.dataExfiltration) {
          incidentScores["data-breach"] += 45;
          incidentScores.apt += 25;
          incidentScores["insider-threat"] += 20;
        }
        if (evidence.ddosTraffic || evidence.networkSaturation) incidentScores.ddos += 50;
        if (evidence.unusualNetworkPatterns) {
          incidentScores.apt += 20;
          incidentScores["insider-threat"] += 15;
        }

        // Authentication indicators
        if (evidence.failedLogins || evidence.bruteForceAttempts) {
          incidentScores["credential-compromise"] += 35;
          incidentScores["insider-threat"] += 15;
        }
        if (evidence.privilegeEscalation) {
          incidentScores.apt += 30;
          incidentScores["credential-compromise"] += 25;
          incidentScores["insider-threat"] += 20;
        }
        if (evidence.abnormalAccessPatterns) {
          incidentScores["insider-threat"] += 35;
          incidentScores["credential-compromise"] += 20;
        }

        // Email and social engineering indicators
        if (evidence.phishingEmails || evidence.socialEngineering) {
          incidentScores.phishing += 40;
          incidentScores["credential-compromise"] += 15;
        }
        if (evidence.maliciousAttachments) {
          incidentScores.phishing += 25;
          incidentScores.ransomware += 15;
        }

        // Persistence and stealth indicators
        if (evidence.persistentAccess || evidence.lateralMovement) {
          incidentScores.apt += 40;
          incidentScores["insider-threat"] += 25;
        }
        if (evidence.antiForensics || evidence.evidenceDestruction) {
          incidentScores.apt += 30;
          incidentScores["insider-threat"] += 25;
        }

        // Data access patterns
        if (evidence.sensitiveDataAccess) {
          incidentScores["data-breach"] += 30;
          incidentScores["insider-threat"] += 25;
          incidentScores.apt += 20;
        }
        if (evidence.offHoursAccess) {
          incidentScores["insider-threat"] += 30;
          incidentScores.apt += 15;
        }

        // Business impact indicators
        if (evidence.serviceUnavailability) {
          incidentScores.ddos += 35;
          incidentScores.ransomware += 25;
        }
        if (evidence.financialLoss) {
          incidentScores["data-breach"] += 20;
          incidentScores.ransomware += 15;
        }
      }

      // Organizational context modifiers
      if (organizationalContext) {
        // Industry-specific risk adjustments
        if (organizationalContext.industry === "finance") {
          incidentScores["data-breach"] += 10;
          incidentScores.apt += 10;
          incidentScores["insider-threat"] += 5;
        } else if (organizationalContext.industry === "healthcare") {
          incidentScores["data-breach"] += 15;
          incidentScores.ransomware += 10;
        } else if (organizationalContext.industry === "government") {
          incidentScores.apt += 20;
          incidentScores["insider-threat"] += 10;
        }

        // Organization size impact
        if (organizationalContext.size === "enterprise") {
          incidentScores.apt += 10;
          incidentScores["insider-threat"] += 5;
        } else if (organizationalContext.size === "small") {
          incidentScores.ransomware += 5;
          incidentScores.phishing += 5;
        }

        // Security maturity adjustments
        if (organizationalContext.securityMaturity === "basic") {
          incidentScores.phishing += 10;
          incidentScores.ransomware += 5;
        } else if (organizationalContext.securityMaturity === "advanced") {
          incidentScores.apt += 15;
          incidentScores["insider-threat"] += 10;
        }
      }

      // Find the highest scoring incident type
      const sortedIncidents = Object.entries(incidentScores)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 3); // Top 3 recommendations

      // Generate confidence levels and recommendations
      const classification = {
        primaryIncidentType: sortedIncidents[0][0],
        confidence: Math.min(100, sortedIncidents[0][1]),
        alternativeTypes: sortedIncidents.slice(1).map(([type, score]) => ({
          type,
          confidence: Math.min(100, score)
        })),
        recommendedPlaybook: `${sortedIncidents[0][0]}-response`,
        reasoning: generateClassificationReasoning(sortedIncidents[0][0], evidence, organizationalContext),
        riskLevel: calculateRiskLevel(sortedIncidents[0][1], evidence),
        recommendedActions: generateRecommendedActions(sortedIncidents[0][0], evidence)
      };

      res.json(classification);
    } catch (error) {
      console.error("Error in incident classification:", error);
      res.status(500).json({ error: "Failed to classify incident" });
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

// Helper functions for intelligent classification
function generateClassificationReasoning(incidentType: string, evidence: any, organizationalContext: any): string {
  const reasoningMap = {
    ransomware: "File encryption and ransom note indicators suggest ransomware attack. Immediate containment required.",
    "credential-compromise": "Failed login attempts and privilege escalation patterns indicate credential compromise.",
    phishing: "Social engineering and malicious email patterns suggest phishing campaign targeting users.", 
    apt: "Persistent access, lateral movement, and stealth techniques indicate advanced persistent threat.",
    "data-breach": "Data exfiltration and sensitive data access patterns suggest data breach incident.",
    ddos: "Network saturation and service unavailability indicate distributed denial of service attack.",
    "insider-threat": "Abnormal access patterns and off-hours activity suggest potential insider threat."
  };

  let reasoning = reasoningMap[incidentType as keyof typeof reasoningMap] || "Classification based on evidence analysis.";
  
  if (organizationalContext) {
    if (organizationalContext.industry === "finance") {
      reasoning += " Financial sector faces elevated risks for APT and data theft.";
    } else if (organizationalContext.industry === "healthcare") {
      reasoning += " Healthcare data makes this organization a high-value target.";
    }
  }
  
  return reasoning;
}

function calculateRiskLevel(score: number, evidence: any): string {
  if (score >= 40) return "Critical";
  if (score >= 25) return "High"; 
  if (score >= 15) return "Medium";
  return "Low";
}

function generateRecommendedActions(incidentType: string, evidence: any): string[] {
  const actionMap = {
    ransomware: [
      "Isolate affected systems immediately",
      "Preserve evidence before cleanup", 
      "Contact law enforcement if required",
      "Assess backup integrity"
    ],
    "credential-compromise": [
      "Force password reset for affected accounts",
      "Enable multi-factor authentication",
      "Review access logs for unauthorized activity",
      "Monitor for lateral movement"
    ],
    phishing: [
      "Block sender and malicious URLs",
      "Remove emails from all mailboxes",
      "Educate users about the attack",
      "Update email security filters"
    ],
    apt: [
      "Maintain stealth monitoring",
      "Preserve evidence carefully",
      "Consider government notification",
      "Deploy advanced threat hunting"
    ],
    "data-breach": [
      "Assess data exposure scope",
      "Prepare regulatory notifications",
      "Secure backup evidence",
      "Coordinate legal response"
    ],
    ddos: [
      "Activate DDoS protection services",
      "Contact ISP for upstream filtering",
      "Monitor attack patterns",
      "Prepare business continuity"
    ],
    "insider-threat": [
      "Conduct covert investigation",
      "Preserve digital evidence",
      "Coordinate with HR and legal",
      "Monitor user activities carefully"
    ]
  };
  
  return actionMap[incidentType as keyof typeof actionMap] || ["Follow standard incident response procedures"];
}