import { useLocation } from "wouter";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, AlertTriangle, Zap, Network, Search, ArrowRight } from "lucide-react";
import { useScenario, scenarios, type Scenario } from "@/contexts/ScenarioContext";

const scenarioIcons = {
  'perimeter-breach': Network,
  'internal-reconnaissance': Search,
  'lateral-movement': Zap
};

const threatLevelColors = {
  'High': 'bg-orange-500',
  'Critical': 'bg-red-500'
};

export default function ScenarioSelector() {
  const { setSelectedScenario } = useScenario();
  const [, setLocation] = useLocation();

  const handleScenarioSelect = (scenario: Scenario) => {
    setSelectedScenario(scenario);
    setLocation('/dashboard');
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-6">
      <div className="max-w-6xl w-full">
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-6">
            <Shield className="w-16 h-16 text-primary mr-4" />
            <div>
              <h1 className="text-4xl font-bold">Incident Response Playbook</h1>
              <p className="text-xl text-muted-foreground mt-2">Cybersecurity Training Simulator</p>
            </div>
          </div>
          <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
            Select a network intrusion scenario to begin your guided incident response training. 
            Each scenario features unique evidence types, attack vectors, and response priorities.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {Object.values(scenarios).map((scenario) => {
            const IconComponent = scenarioIcons[scenario.id];
            return (
              <Card 
                key={scenario.id} 
                className="relative hover:shadow-lg transition-all duration-200 border-2 hover:border-primary/50 cursor-pointer group"
                data-testid={`scenario-card-${scenario.id}`}
              >
                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center">
                      <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mr-3">
                        <IconComponent className="w-6 h-6 text-primary" />
                      </div>
                      <div>
                        <CardTitle className="text-xl font-semibold group-hover:text-primary transition-colors">
                          {scenario.name}
                        </CardTitle>
                      </div>
                    </div>
                    <Badge 
                      variant={scenario.threatLevel === 'Critical' ? 'destructive' : 'secondary'}
                      className="font-medium"
                      data-testid={`threat-level-${scenario.id}`}
                    >
                      {scenario.threatLevel}
                    </Badge>
                  </div>
                  
                  <CardDescription className="text-sm leading-relaxed">
                    {scenario.description}
                  </CardDescription>
                </CardHeader>

                <CardContent className="pt-0">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center text-muted-foreground">
                        <AlertTriangle className="w-4 h-4 mr-2" />
                        <span>Affected Systems</span>
                      </div>
                      <span className="font-semibold" data-testid={`systems-count-${scenario.id}`}>
                        {scenario.affectedSystemsCount}
                      </span>
                    </div>

                    <div className="text-sm">
                      <div className="text-muted-foreground mb-2 font-medium">Primary Focus:</div>
                      <div className="text-foreground">{scenario.primaryFocus}</div>
                    </div>

                    <div className="text-sm">
                      <div className="text-muted-foreground mb-2 font-medium">Evidence Types:</div>
                      <div className="flex flex-wrap gap-1">
                        {scenario.evidenceTypes.slice(0, 3).map((evidence, index) => (
                          <Badge 
                            key={index} 
                            variant="outline" 
                            className="text-xs px-2 py-1"
                            data-testid={`evidence-${scenario.id}-${index}`}
                          >
                            {evidence.replace(/_/g, ' ')}
                          </Badge>
                        ))}
                        {scenario.evidenceTypes.length > 3 && (
                          <Badge variant="outline" className="text-xs px-2 py-1">
                            +{scenario.evidenceTypes.length - 3} more
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="text-sm">
                      <div className="text-muted-foreground mb-2 font-medium">MITRE ATT&CK:</div>
                      <div className="flex flex-wrap gap-1">
                        {scenario.mitreTechniques.map((technique, index) => (
                          <Badge 
                            key={index} 
                            variant="secondary" 
                            className="text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200"
                            data-testid={`mitre-${scenario.id}-${index}`}
                          >
                            {technique}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <Button
                      onClick={() => handleScenarioSelect(scenario)}
                      className="w-full mt-6 group-hover:bg-primary group-hover:text-primary-foreground transition-colors"
                      data-testid={`select-scenario-${scenario.id}`}
                    >
                      Start Investigation
                      <ArrowRight className="w-4 h-4 ml-2" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="text-center mt-12">
          <p className="text-sm text-muted-foreground">
            Each scenario is based on real-world attack patterns and follows NIST Cybersecurity Framework guidelines
          </p>
        </div>
      </div>
    </div>
  );
}