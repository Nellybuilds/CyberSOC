import { useState } from "react";
import { 
  Dialog, 
  DialogContent, 
  DialogDescription, 
  DialogHeader, 
  DialogTitle 
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Key, Mail, AlertTriangle } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface CreateIncidentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface IncidentType {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  alertId: string;
  severity: "Critical" | "High";
  estimatedTime: string;
}

const INCIDENT_TYPES: IncidentType[] = [
  {
    id: "ransomware",
    title: "Ransomware Attack",
    description: "Multiple endpoints infected with ransomware requiring immediate containment and recovery procedures.",
    icon: Shield,
    alertId: "alert-001",
    severity: "Critical",
    estimatedTime: "2-4 hours"
  },
  {
    id: "credential-compromise", 
    title: "Credential Compromise",
    description: "Suspicious login activity with evidence of lateral movement requiring account security response.",
    icon: Key,
    alertId: "alert-004",
    severity: "Critical", 
    estimatedTime: "1-3 hours"
  },
  {
    id: "phishing",
    title: "Phishing Campaign",
    description: "Malicious email campaign targeting users requiring email security response and user awareness.",
    icon: Mail,
    alertId: "alert-005",
    severity: "High",
    estimatedTime: "30min-2 hours"
  }
];

export default function CreateIncidentDialog({ open, onOpenChange }: CreateIncidentDialogProps) {
  const [selectedIncidentType, setSelectedIncidentType] = useState<string | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const createIncidentMutation = useMutation({
    mutationFn: async (incidentTypeId: string) => {
      // Create new incident and assign appropriate playbook
      const response = await apiRequest("POST", "/api/incidents/create", { incidentType: incidentTypeId });
      const result = await response.json();
      return { 
        incidentType: incidentTypeId, 
        activeAlertId: result.activeAlertId,
        incidentName: result.message
      };
    },
    onSuccess: (data) => {
      const incidentType = INCIDENT_TYPES.find(i => i.id === data.incidentType);
      toast({
        title: "Incident Created",
        description: `${incidentType?.title} incident created successfully. Begin investigation immediately.`,
      });
      
      // Invalidate specific queries to refresh all data with precise query keys
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["/api/logs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/workflow-sessions", data.activeAlertId] });
      queryClient.invalidateQueries({ queryKey: ["/api/alerts", data.activeAlertId, "playbook"] });
      
      onOpenChange(false);
      setSelectedIncidentType(null);
      
      // No page reload - let React Query handle the data refresh
    },
    onError: (error) => {
      toast({
        title: "Failed to Create Incident",
        description: "Unable to create new incident. Please try again.",
        variant: "destructive"
      });
      console.error("Failed to create new incident:", error);
    }
  });

  const handleCreateIncident = () => {
    if (selectedIncidentType) {
      createIncidentMutation.mutate(selectedIncidentType);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto" data-testid="create-incident-dialog">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-primary" />
            Create New Incident
          </DialogTitle>
          <DialogDescription>
            Select the type of security incident to create and assign the appropriate response playbook.
            This will initialize a new incident response workflow.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 mt-6">
          {INCIDENT_TYPES.map((incidentType) => {
            const IconComponent = incidentType.icon;
            const isSelected = selectedIncidentType === incidentType.id;
            
            return (
              <Card 
                key={incidentType.id}
                className={`cursor-pointer transition-all hover:shadow-md ${
                  isSelected ? "ring-2 ring-primary bg-primary/5" : ""
                }`}
                onClick={() => setSelectedIncidentType(incidentType.id)}
                data-testid={`incident-type-${incidentType.id}`}
              >
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <IconComponent className={`w-6 h-6 ${
                        isSelected ? "text-primary" : "text-muted-foreground"
                      }`} />
                      <div>
                        <CardTitle className="text-lg">{incidentType.title}</CardTitle>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            incidentType.severity === "Critical" 
                              ? "bg-destructive/10 text-destructive" 
                              : "bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400"
                          }`}>
                            {incidentType.severity}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            Est. {incidentType.estimatedTime}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <CardDescription className="text-sm">
                    {incidentType.description}
                  </CardDescription>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="flex justify-end gap-3 mt-6 pt-4 border-t">
          <Button 
            variant="outline" 
            onClick={() => onOpenChange(false)}
            data-testid="cancel-incident"
          >
            Cancel
          </Button>
          <Button 
            onClick={handleCreateIncident}
            disabled={!selectedIncidentType || createIncidentMutation.isPending}
            data-testid="create-incident"
          >
            {createIncidentMutation.isPending ? "Creating..." : "Create Incident"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}