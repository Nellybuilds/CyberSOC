import { Button } from "@/components/ui/button";
import { Shield, User } from "lucide-react";
import { useState } from "react";
import CreateIncidentDialog from "@/components/CreateIncidentDialog";

interface NavbarProps {
  userRole: "Analyst" | "Manager" | "Client";
  onRoleChange: (role: "Analyst" | "Manager" | "Client") => void;
}

export default function Navbar({ userRole, onRoleChange }: NavbarProps) {
  const [showCreateIncidentDialog, setShowCreateIncidentDialog] = useState(false);

  return (
    <nav className="bg-card border-b border-border px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-xl font-semibold">CyberSOC Playbook</h1>
          </div>
          
          <div className="flex bg-muted rounded-lg p-1" data-testid="role-switcher">
            {(["Analyst", "Manager", "Client"] as const).map((role) => (
              <button
                key={role}
                onClick={() => onRoleChange(role)}
                className={`px-3 py-1 text-sm font-medium transition-colors rounded-md ${
                  userRole === role
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
                data-testid={`role-${role.toLowerCase()}`}
              >
                {role}
              </button>
            ))}
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <Button 
            onClick={() => setShowCreateIncidentDialog(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground"
            data-testid="create-incident-btn"
          >
            Create Incident
          </Button>
          
          <CreateIncidentDialog 
            open={showCreateIncidentDialog}
            onOpenChange={setShowCreateIncidentDialog}
          />
          <div className="w-8 h-8 bg-muted rounded-full flex items-center justify-center">
            <User className="w-4 h-4" />
          </div>
        </div>
      </div>
    </nav>
  );
}
