import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { X, Shield, BookOpen, Clock, Activity, RefreshCw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useScenario } from "@/contexts/ScenarioContext";
import type { PlaybookNode } from "@shared/schema";

interface AIAssistantPanelProps {
  currentNode?: PlaybookNode;
  alertId: string;
  onAction: (action: string) => void;
}

export default function AIAssistantPanel({ 
  currentNode, 
  alertId, 
  onAction 
}: AIAssistantPanelProps) {
  const [isMinimized, setIsMinimized] = useState(false);
  const [sessionTime, setSessionTime] = useState("00:15:32");
  const [actionsTaken, setActionsTaken] = useState(3);
  const [completion, setCompletion] = useState(25);
  const [selectedRole, setSelectedRole] = useState<'analyst' | 'manager' | 'client'>('analyst');
  
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { selectedScenario } = useScenario();

  const executeActionMutation = useMutation({
    mutationFn: async (action: string) => {
      let response;
      
      switch (action) {
        case "Isolate All Endpoints":
          // Get all affected endpoints from the current alert and isolate them
          const endpointsResponse = await fetch("/api/endpoints");
          const endpoints = await endpointsResponse.json();
          const affectedEndpointIds = endpoints
            .filter((ep: any) => ep.status === "Affected")
            .map((ep: any) => ep.id);
          
          response = await apiRequest("POST", "/api/actions/isolate-all", { 
            endpointIds: affectedEndpointIds 
          });
          break;
          
        case "Lock User Accounts":
          response = await apiRequest("POST", "/api/actions/lock-accounts", {});
          break;
          
        case "Analyze Network Traffic":
          response = await apiRequest("POST", "/api/actions/analyze-traffic", { 
            alertId 
          });
          break;
          
        case "Skip to Investigation":
          response = await apiRequest("POST", "/api/workflow/advance", { 
            alertId,
            phase: "Investigation" 
          });
          break;
          
        default:
          throw new Error(`Unknown action: ${action}`);
      }
      
      return { success: true, action, data: response };
    },
    onSuccess: (data) => {
      toast({
        title: "Action Completed",
        description: `${data.action} executed successfully.`,
      });
      setActionsTaken(prev => prev + 1);
      setCompletion(prev => Math.min(prev + 10, 100));
      onAction(data.action);
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to execute action.",
        variant: "destructive",
      });
    },
  });

  // Fetch playbook data for this alert
  const { data: playbookData } = useQuery({
    queryKey: ["/api/alerts", alertId, "playbook"],
    enabled: !!alertId,
  });

  // AI-powered recommendations query  
  const { data: aiRecommendations, isLoading: loadingAI, refetch: refreshAI } = useQuery({
    queryKey: ['/api/ai-assistant', alertId, selectedRole, playbookData?.id],
    queryFn: async () => {
      if (!alertId || !playbookData) return null;
      
      // Map playbook IDs to scenario types for AI
      const playbookToScenarioMap = {
        "ransomware-response": "lateral-movement",
        "credential-compromise-response": "internal-reconnaissance", 
        "phishing-response": "perimeter-breach"
      };
      
      const scenario = playbookToScenarioMap[playbookData.id as keyof typeof playbookToScenarioMap] || "lateral-movement";
      
      const response = await apiRequest(
        'POST',
        '/api/ai-assistant',
        {
          scenario,
          evidence: ["network_logs", "endpoint_data", "security_alerts"],
          severity: 'critical',
          affected_systems: ["endpoint-01", "endpoint-02"],
          role: selectedRole
        }
      );
      const data = await response.json();
      return data.recommendations as AIRecommendation[];
    },
    enabled: !!alertId && !!playbookData
  });

  interface AIRecommendation {
    action: string;
    description: string;
    priority: number;
    source: string;
    mitre_mapping?: {
      technique_id: string;
      technique_name: string;
    };
  }

  if (isMinimized) {
    return (
      <div className="fixed bottom-4 right-4 bg-card border border-border rounded-lg p-4 shadow-lg">
        <Button
          variant="outline"
          onClick={() => setIsMinimized(false)}
          className="w-full"
        >
          <Shield className="w-4 h-4 mr-2" />
          AI Assistant
        </Button>
      </div>
    );
  }

  return (
    <div className="w-96 bg-card border-l border-border p-6 overflow-y-auto" data-testid="ai-assistant-panel">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold flex items-center">
          <Shield className="w-5 h-5 mr-2 text-primary" />
          AI Assistant
          {loadingAI && <RefreshCw className="w-4 h-4 ml-2 animate-spin" />}
        </h2>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refreshAI()}
            disabled={loadingAI}
            data-testid="refresh-ai"
          >
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsMinimized(true)}
            data-testid="minimize-ai-panel"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      </div>
      
      <div className="space-y-4">
        {/* Playbook Indicator */}
        {playbookData && (
          <div className="bg-info/10 border border-info/20 rounded-lg p-4">
            <h4 className="font-medium mb-2 text-info flex items-center">
              <BookOpen className="w-4 h-4 mr-2" />
              Active Playbook: {playbookData.name}
            </h4>
            <p className="text-sm text-muted-foreground mb-2">
              {playbookData.description}
            </p>
            <div className="flex items-center gap-2 text-xs">
              <Badge variant="secondary">
                {Object.keys(playbookData.nodes || {}).length} phases
              </Badge>
              <span className="text-muted-foreground">
                Alert ID: {alertId}
              </span>
            </div>
          </div>
        )}

        {/* Role Selector */}
        <div className="bg-card border border-border rounded-lg p-4">
          <h4 className="font-medium mb-2">Your Role</h4>
          <div className="flex gap-2">
            {(['analyst', 'manager', 'client'] as const).map((role) => (
              <Button
                key={role}
                variant={selectedRole === role ? "default" : "outline"}
                size="sm"
                onClick={() => setSelectedRole(role)}
                className="capitalize"
                data-testid={`role-${role}`}
              >
                {role}
              </Button>
            ))}
          </div>
        </div>

        {/* Current Step */}
        <div className="bg-primary/10 border border-primary/20 rounded-lg p-4">
          <div className="flex items-start space-x-3">
            <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center flex-shrink-0">
              <Shield className="w-4 h-4 text-primary-foreground" />
            </div>
            <div>
              <h4 className="font-medium mb-2">
                AI-Powered Incident Response
              </h4>
              <p className="text-sm text-muted-foreground mb-3">
                {playbookData 
                  ? `Active incident analysis using ${playbookData.name.toLowerCase()} with role-based recommendations following NIST and SANS frameworks.`
                  : "Select a playbook to begin AI-powered incident response guidance."
                }
              </p>
            </div>
          </div>
        </div>
        
        {/* AI Recommendations */}
        <div className="bg-card border border-border rounded-lg p-4">
          <h4 className="font-medium mb-3">AI Recommendations</h4>
          
          {loadingAI ? (
            <div className="space-y-2">
              <div className="animate-pulse bg-muted h-16 rounded"></div>
              <div className="animate-pulse bg-muted h-16 rounded"></div>
              <div className="animate-pulse bg-muted h-16 rounded"></div>
            </div>
          ) : playbookData ? (
            <div className="space-y-2">
              {aiRecommendations?.map((rec, index) => (
                <Button
                  key={index}
                  onClick={() => executeActionMutation.mutate(rec.action)}
                  disabled={executeActionMutation.isPending}
                  variant={rec.priority === 1 ? "default" : rec.priority === 2 ? "secondary" : "outline"}
                  className="w-full p-3 text-sm font-medium text-left flex-col items-start h-auto"
                  data-testid={`ai-action-${index}`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span>🔒 {rec.action}</span>
                    <Badge variant={rec.priority === 1 ? "destructive" : "secondary"} className="text-xs">
                      P{rec.priority}
                    </Badge>
                  </div>
                  <div className="text-xs mt-1 opacity-80">{rec.description}</div>
                  <div className="text-xs mt-1 text-blue-400">
                    📚 Source: {rec.source}
                  </div>
                  {rec.mitre_mapping && (
                    <div className="text-xs mt-1 text-orange-400">
                      🎯 MITRE: {rec.mitre_mapping.technique_id} - {rec.mitre_mapping.technique_name}
                    </div>
                  )}
                </Button>
              ))}
              
              {(!aiRecommendations || aiRecommendations.length === 0) && (
                <div className="text-center text-muted-foreground py-4">
                  No AI recommendations available. Try refreshing or check your connection.
                </div>
              )}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-4">
              Please select a playbook to view AI-powered recommendations.
            </div>
          )}
        </div>
        
        {/* Playbook Reference */}
        <div className="bg-info/10 border border-info/20 rounded-lg p-4">
          <h4 className="font-medium mb-2 text-info flex items-center">
            <BookOpen className="w-4 h-4 mr-2" />
            Playbook Reference
          </h4>
          <p className="text-sm text-muted-foreground mb-2">
            Current step follows NIST Cybersecurity Framework: RESPOND (RS)
          </p>
          <ul className="text-xs text-muted-foreground space-y-1">
            <li>• RS.RP-1: Response plan is executed</li>
            <li>• RS.CO-2: Events are reported</li>
            <li>• RS.AN-1: Notifications from detection systems are investigated</li>
          </ul>
        </div>
        
        {/* Progress Tracker */}
        <div className="bg-card border border-border rounded-lg p-4">
          <h4 className="font-medium mb-3 flex items-center">
            <Activity className="w-4 h-4 mr-2" />
            Investigation Progress
          </h4>
          <div className="space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center">
                <Clock className="w-3 h-3 mr-1" />
                Time Elapsed
              </span>
              <span className="font-mono">{sessionTime}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Actions Taken</span>
              <span className="font-mono">{actionsTaken} / 12</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span>Completion</span>
              <span className="font-mono">{completion}%</span>
            </div>
            <Progress value={completion} className="w-full h-2" />
          </div>
        </div>
      </div>
    </div>
  );
}
