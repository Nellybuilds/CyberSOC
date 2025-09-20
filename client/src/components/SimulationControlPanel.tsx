import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { AlertTriangle, Shield, Key, Mail, Volume2, VolumeX } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface AlertPopupProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alert: {
    type: string;
    title: string;
    severity: string;
    description: string;
  } | null;
}

function AlertPopup({ open, onOpenChange, alert }: AlertPopupProps) {
  if (!alert) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-red-500 border-2">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-red-600">
            <AlertTriangle className="w-5 h-5" />
            🚨 SECURITY ALERT DETECTED
          </DialogTitle>
          <DialogDescription>
            <div className="space-y-2 mt-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold">{alert.title}</span>
                <Badge variant="destructive">{alert.severity}</Badge>
              </div>
              <p className="text-sm">{alert.description}</p>
              <p className="text-xs text-muted-foreground">
                🕐 Detected: {new Date().toLocaleTimeString()}
              </p>
            </div>
          </DialogDescription>
        </DialogHeader>
        <div className="flex gap-2 mt-4">
          <Button 
            onClick={() => onOpenChange(false)} 
            variant="destructive" 
            className="flex-1"
            data-testid="acknowledge-alert"
          >
            Acknowledge & Respond
          </Button>
          <Button 
            onClick={() => onOpenChange(false)} 
            variant="outline"
            data-testid="dismiss-alert"
          >
            Dismiss
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function SimulationControlPanel() {
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [alertPopup, setAlertPopup] = useState<{
    open: boolean;
    alert: { type: string; title: string; severity: string; description: string } | null;
  }>({ open: false, alert: null });

  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Play alert sound
  const playAlertSound = () => {
    if (!soundEnabled) return;
    
    try {
      // Create a simple alert sound using Web Audio API
      const audioContext = new AudioContext();
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);

      oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(400, audioContext.currentTime + 0.1);
      oscillator.frequency.exponentialRampToValueAtTime(800, audioContext.currentTime + 0.2);

      gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);

      oscillator.start(audioContext.currentTime);
      oscillator.stop(audioContext.currentTime + 0.3);
    } catch (error) {
      console.warn('Could not play alert sound:', error);
    }
  };

  const triggerAlertMutation = useMutation({
    mutationFn: async (alertType: string) => {
      const response = await apiRequest("POST", "/api/simulation/trigger-alert", { 
        alertType,
        timestamp: new Date().toISOString()
      });
      return response.json();
    },
    onSuccess: (data) => {
      // Play alert sound
      playAlertSound();
      
      // Show alert popup
      setAlertPopup({
        open: true,
        alert: {
          type: data.alertType,
          title: data.alertTitle,
          severity: data.severity,
          description: data.description
        }
      });

      toast({
        title: "🚨 SECURITY ALERT",
        description: `${data.alertTitle} - Immediate response required!`,
        variant: "destructive"
      });

      // Refresh all data to show the new alert
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["/api/logs"] });
    },
    onError: () => {
      toast({
        title: "Simulation Error",
        description: "Failed to trigger alert simulation.",
        variant: "destructive"
      });
    }
  });

  const alertTypes = [
    {
      id: "critical-breach",
      title: "Critical Data Breach",
      icon: Shield,
      severity: "Critical",
      description: "Unauthorized access to sensitive customer database detected",
      color: "bg-red-500"
    },
    {
      id: "ransomware-outbreak", 
      title: "Ransomware Outbreak",
      icon: AlertTriangle,
      severity: "Critical", 
      description: "Multiple endpoints showing ransomware encryption activity",
      color: "bg-red-600"
    },
    {
      id: "credential-theft",
      title: "Credential Theft", 
      icon: Key,
      severity: "High",
      description: "Suspicious authentication attempts from unknown locations",
      color: "bg-orange-500"
    },
    {
      id: "phishing-campaign",
      title: "Active Phishing Campaign",
      icon: Mail,
      severity: "High", 
      description: "Mass phishing emails targeting employee credentials",
      color: "bg-orange-400"
    }
  ];

  return (
    <>
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              🎯 Threat Simulation Control
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSoundEnabled(!soundEnabled)}
              data-testid="toggle-sound"
            >
              {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
            </Button>
          </CardTitle>
          <CardDescription>
            Trigger realistic security alerts to test incident response procedures
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {alertTypes.map((alertType) => {
            const IconComponent = alertType.icon;
            return (
              <Button
                key={alertType.id}
                onClick={() => triggerAlertMutation.mutate(alertType.id)}
                disabled={triggerAlertMutation.isPending}
                variant="outline"
                className="w-full h-auto p-3 text-left flex items-start gap-3"
                data-testid={`trigger-${alertType.id}`}
              >
                <div className={`p-2 rounded ${alertType.color} text-white flex-shrink-0`}>
                  <IconComponent className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{alertType.title}</span>
                    <Badge variant={alertType.severity === "Critical" ? "destructive" : "secondary"}>
                      {alertType.severity}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">{alertType.description}</p>
                </div>
              </Button>
            );
          })}
          
          <div className="pt-2 border-t text-xs text-muted-foreground">
            💡 Each simulation triggers realistic security data, endpoint changes, and AI-powered response recommendations
          </div>
        </CardContent>
      </Card>

      <AlertPopup 
        open={alertPopup.open}
        onOpenChange={(open) => setAlertPopup({ ...alertPopup, open })}
        alert={alertPopup.alert}
      />
    </>
  );
}