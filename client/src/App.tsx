import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ScenarioProvider } from "@/contexts/ScenarioContext";
import Dashboard from "@/pages/dashboard";
import ScenarioSelectionPage from "@/pages/scenario-selection";
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <Switch>
      <Route path="/" component={ScenarioSelectionPage} />
      <Route path="/dashboard" component={Dashboard} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ScenarioProvider>
          <div className="dark">
            <Toaster />
            <Router />
          </div>
        </ScenarioProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
