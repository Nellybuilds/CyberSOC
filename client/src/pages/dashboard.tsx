import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Navbar from "@/components/Navbar";
import WorkflowTracker from "@/components/WorkflowTracker";
import AlertCard from "@/components/AlertCard";
import AssetTable from "@/components/AssetTable";
import LogViewer from "@/components/LogViewer";
import AIAssistantPanel from "@/components/AIAssistantPanel";
import ReportGenerator from "@/components/ReportGenerator";
import BusinessImpactMetrics from "@/components/BusinessImpactMetrics";
import SimulationControlPanel from "@/components/SimulationControlPanel";
import type { Alert, Endpoint, LogEntry } from "@shared/schema";
import { useWorkflow } from "@/hooks/use-workflow";
import { useScenario } from "@/contexts/ScenarioContext";
import { Badge } from "@/components/ui/badge";
import { BookOpen, AlertTriangle, Users, MapPin } from "lucide-react";

export default function Dashboard() {
  const [userRole, setUserRole] = useState<"Analyst" | "Manager" | "Client">("Analyst");
  const [selectedAlert, setSelectedAlert] = useState<string | null>(null);
  const { selectedScenario } = useScenario();
  
  const { data: alerts = [], isLoading: alertsLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: endpoints = [], isLoading: endpointsLoading } = useQuery<Endpoint[]>({
    queryKey: ["/api/endpoints"],
  });

  const { data: logs = [], isLoading: logsLoading } = useQuery<LogEntry[]>({
    queryKey: ["/api/logs"],
  });

  // Calculate active alert for workflow - must be done before any early returns
  const criticalAlerts = alerts.filter(alert => alert.severity === "Critical");
  const activeAlert = selectedAlert ? alerts.find(a => a.id === selectedAlert) : criticalAlerts[0];
  
  // Initialize workflow hook with the active alert - this must always be called
  const { currentNode, workflow, advanceWorkflow, playbook } = useWorkflow(activeAlert?.id || null);

  if (alertsLoading || endpointsLoading || logsLoading) {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
          <p className="mt-4 text-lg">Loading dashboard...</p>
        </div>
      </div>
    );
  }
  
  console.log('Dashboard state:', { selectedAlert, criticalAlerts: criticalAlerts.map(a => a.id), activeAlert: activeAlert?.id, workflowAlertId: activeAlert?.id });

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar userRole={userRole} onRoleChange={setUserRole} />
      
      {/* Active Scenario Indicator */}
      {selectedScenario && (
        <div className="bg-primary/5 border-b border-primary/20 px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-primary" />
                <span className="font-semibold text-primary">Active Playbook:</span>
                <span className="font-medium">{selectedScenario.name}</span>
              </div>
              <Badge variant={selectedScenario.threatLevel === 'Critical' ? 'destructive' : 'secondary'}>
                {selectedScenario.threatLevel}
              </Badge>
            </div>
            
            <div className="flex items-center gap-6 text-sm text-muted-foreground">
              <div className="flex items-center gap-1">
                <AlertTriangle className="w-4 h-4" />
                <span>Evidence: {selectedScenario.evidenceTypes.join(', ')}</span>
              </div>
              <div className="flex items-center gap-1">
                <Users className="w-4 h-4" />
                <span>{selectedScenario.affectedSystemsCount} systems</span>
              </div>
              <div className="flex items-center gap-1">
                <MapPin className="w-4 h-4" />
                <span>MITRE ATT&CK Coverage</span>
              </div>
            </div>
          </div>
          
          <div className="mt-2 text-sm text-muted-foreground">
            {selectedScenario.description}
          </div>
        </div>
      )}
      
      <div className="flex h-screen overflow-hidden">
        <WorkflowTracker 
          currentPhase={
            // Map current node ID to phase name for UI display
            (() => {
              const nodeToPhaseMap: Record<string, string> = {
                "detection_phase": "Detection",
                "scoping_phase": "Scoping",
                "investigation_phase": "Investigation", 
                "remediation_phase": "Remediation",
                "post_incident_phase": "Post-Incident"
              };
              return nodeToPhaseMap[workflow?.current_node || ""] || "Detection";
            })()
          }
          completedPhases={
            // Convert node IDs to phase names for UI display
            (workflow?.completed_nodes || []).map(nodeId => {
              const nodeToPhaseMap: Record<string, string> = {
                "detection_phase": "Detection",
                "scoping_phase": "Scoping",
                "investigation_phase": "Investigation", 
                "remediation_phase": "Remediation",
                "post_incident_phase": "Post-Incident"
              };
              return nodeToPhaseMap[nodeId] || nodeId;
            })
          }
          mitreAttackTechniques={activeAlert?.mitre_tactics || []}
          onPhaseClick={(phaseId) => {
            console.log('Phase clicked:', phaseId, 'for alert:', selectedAlert);
            
            // Map UI phase names to playbook node IDs
            const phaseToNodeMap: Record<string, string> = {
              "Detection": "detection_phase",
              "Scoping": "scoping_phase", 
              "Investigation": "investigation_phase",
              "Remediation": "remediation_phase",
              "Post-Incident": "post_incident_phase"
            };
            
            const nodeId = phaseToNodeMap[phaseId];
            console.log('Mapped to nodeId:', nodeId, 'playbook exists:', !!playbook, 'node exists:', !!(playbook?.nodes as any)?.[nodeId]);
            
            if (nodeId && (playbook?.nodes as any)?.[nodeId]) {
              console.log('Calling advanceWorkflow with:', nodeId);
              advanceWorkflow(nodeId, `Advanced to ${phaseId} phase`);
            } else {
              console.log('Cannot advance workflow - missing node or playbook');
            }
          }}
        />
        
        <div className="flex-1 flex">
          <div className="flex-1 p-6 overflow-y-auto">
            {/* Simulation Control Panel - Only visible to Analysts and Managers */}
            {(userRole === "Analyst" || userRole === "Manager") && (
              <div className="mb-6">
                <SimulationControlPanel />
              </div>
            )}
            
            <div className="mb-6">
              <h2 className="text-2xl font-semibold mb-4">
                {userRole === "Analyst" && "Active Incidents"}
                {userRole === "Manager" && "Incident Overview"}
                {userRole === "Client" && "Security Status"}
              </h2>
              
              {criticalAlerts.map((alert) => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  onStartInvestigation={() => setSelectedAlert(alert.id)}
                  isSelected={selectedAlert === alert.id}
                  userRole={userRole}
                />
              ))}
            </div>

            {userRole === "Analyst" && (
              <>
                <AssetTable 
                  endpoints={endpoints}
                  selectedAlert={activeAlert}
                />
                
                <LogViewer logs={logs} />
              </>
            )}
            
            {(userRole === "Manager" || userRole === "Client") && (
              <BusinessImpactMetrics 
                selectedAlert={activeAlert}
                endpoints={endpoints}
                userRole={userRole}
              />
            )}

            <ReportGenerator 
              selectedAlert={activeAlert}
              endpoints={endpoints}
              userRole={userRole}
            />
          </div>

          {userRole === "Analyst" && selectedAlert && (
            <AIAssistantPanel
              currentNode={currentNode}
              alertId={selectedAlert}
              onAction={(action) => console.log("Action:", action)}
              data-testid="ai-assistant-panel"
            />
          )}
        </div>
      </div>
    </div>
  );
}
