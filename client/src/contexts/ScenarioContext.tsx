import { createContext, useContext, useState, ReactNode } from 'react';

export interface Scenario {
  id: 'perimeter-breach' | 'internal-reconnaissance' | 'lateral-movement';
  name: string;
  description: string;
  threatLevel: 'High' | 'Critical';
  affectedSystemsCount: number;
  primaryFocus: string;
  evidenceTypes: string[];
  mitreTechniques: string[];
}

export const scenarios: Record<string, Scenario> = {
  'perimeter-breach': {
    id: 'perimeter-breach',
    name: 'Perimeter Breach',
    description: 'External attacker has compromised VPN endpoint and gained initial foothold through firewall vulnerability.',
    threatLevel: 'High',
    affectedSystemsCount: 2,
    primaryFocus: 'VPN/firewall analysis, access controls',
    evidenceTypes: ['firewall_logs', 'vpn_connection_logs', 'network_traffic_capture', 'failed_auth_attempts'],
    mitreTechniques: ['T1190', 'T1133', 'T1078']
  },
  'internal-reconnaissance': {
    id: 'internal-reconnaissance',
    name: 'Internal Reconnaissance',
    description: 'Threat actor is performing network discovery and enumeration from compromised internal workstation.',
    threatLevel: 'High',
    affectedSystemsCount: 8,
    primaryFocus: 'Network scanning, threat hunting',
    evidenceTypes: ['network_scan_logs', 'dns_queries', 'smb_enumeration', 'process_artifacts'],
    mitreTechniques: ['T1018', 'T1046', 'T1083', 'T1135']
  },
  'lateral-movement': {
    id: 'lateral-movement',
    name: 'Lateral Movement',
    description: 'Active ransomware deployment with file encryption spreading across Finance department systems.',
    threatLevel: 'Critical',
    affectedSystemsCount: 5,
    primaryFocus: 'Containment, ransomware response',
    evidenceTypes: ['ransom_note.txt', 'encrypted_files_436', 'network_traffic_logs', 'process_artifacts', 'smb_logs'],
    mitreTechniques: ['T1486', 'T1059.001', 'T1570']
  }
};

interface ScenarioContextType {
  selectedScenario: Scenario | null;
  setSelectedScenario: (scenario: Scenario) => void;
  resetScenario: () => void;
}

const ScenarioContext = createContext<ScenarioContextType | undefined>(undefined);

export function ScenarioProvider({ children }: { children: ReactNode }) {
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null);

  const resetScenario = () => {
    setSelectedScenario(null);
  };

  return (
    <ScenarioContext.Provider value={{
      selectedScenario,
      setSelectedScenario,
      resetScenario
    }}>
      {children}
    </ScenarioContext.Provider>
  );
}

export function useScenario() {
  const context = useContext(ScenarioContext);
  if (context === undefined) {
    throw new Error('useScenario must be used within a ScenarioProvider');
  }
  return context;
}