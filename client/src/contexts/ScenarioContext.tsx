import { createContext, useContext, useState, ReactNode } from 'react';

export interface Playbook {
  id: 'perimeter-breach' | 'internal-reconnaissance' | 'lateral-movement';
  name: string;
  description: string;
  threatLevel: 'High' | 'Critical';
  affectedSystemsCount: number;
  primaryFocus: string;
  evidenceTypes: string[];
  mitreTechniques: string[];
}

export const playbooks: Record<string, Playbook> = {
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

interface PlaybookContextType {
  selectedPlaybook: Playbook | null;
  setSelectedPlaybook: (playbook: Playbook) => void;
  resetPlaybook: () => void;
}

const PlaybookContext = createContext<PlaybookContextType | undefined>(undefined);

export function PlaybookProvider({ children }: { children: ReactNode }) {
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);

  const resetPlaybook = () => {
    setSelectedPlaybook(null);
  };

  return (
    <PlaybookContext.Provider value={{
      selectedPlaybook,
      setSelectedPlaybook,
      resetPlaybook
    }}>
      {children}
    </PlaybookContext.Provider>
  );
}

export function usePlaybook() {
  const context = useContext(PlaybookContext);
  if (context === undefined) {
    throw new Error('usePlaybook must be used within a PlaybookProvider');
  }
  return context;
}

// Backward compatibility exports during transition
export type Scenario = Playbook;
export const scenarios = playbooks;

export function useScenario() {
  const context = usePlaybook();
  return {
    selectedScenario: context.selectedPlaybook,
    setSelectedScenario: context.setSelectedPlaybook,
    resetScenario: context.resetPlaybook
  };
}

export const ScenarioProvider = PlaybookProvider;