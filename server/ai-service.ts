import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: process.env.OPENROUTER_API_KEY!,
  baseURL: 'https://openrouter.ai/api/v1'
});

export interface IncidentContext {
  scenario: 'perimeter-breach' | 'internal-reconnaissance' | 'lateral-movement';
  evidence: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  affected_systems: string[];
  role: 'analyst' | 'manager' | 'client';
}

export interface AIRecommendation {
  action: string;
  description: string;
  priority: number; // 1 = highest, 3 = lowest
  source: string;
  mitre_mapping?: {
    technique_id: string;
    technique_name: string;
  };
}

export interface AIResponse {
  recommendations: AIRecommendation[];
}

const scenarioPrompts = {
  'perimeter-breach': {
    context: "External attacker has compromised VPN endpoint and gained initial foothold through firewall vulnerability",
    focus: "VPN/firewall analysis, access controls, perimeter security",
    primaryActions: ["firewall_rule_review", "vpn_audit", "access_control_validation", "network_segmentation"],
    evidenceTypes: "firewall logs, VPN connection logs, network traffic captures, failed authentication attempts"
  },
  'internal-reconnaissance': {
    context: "Threat actor is performing network discovery and enumeration from compromised internal workstation",
    focus: "Network scanning detection, threat hunting, lateral movement prevention",
    primaryActions: ["network_scan_analysis", "threat_hunting", "endpoint_isolation", "privilege_escalation_prevention"],
    evidenceTypes: "network scan logs, DNS queries, SMB enumeration, process artifacts"
  },
  'lateral-movement': {
    context: "Active ransomware deployment with file encryption spreading across Finance department systems",
    focus: "Immediate containment, ransomware response, business continuity",
    primaryActions: ["system_isolation", "backup_verification", "ransom_analysis", "business_impact_assessment"],
    evidenceTypes: "ransom notes, encrypted files, network traffic logs, process artifacts, SMB logs"
  }
};

const rolePrompts = {
  analyst: "Provide detailed technical actions with specific commands and tools. Focus on immediate investigative steps and technical containment measures.",
  manager: "Provide strategic oversight actions with business impact considerations. Focus on resource allocation, communication planning, and escalation decisions.", 
  client: "Provide high-level status updates and business continuity actions. Focus on stakeholder communication, service impact, and recovery timelines."
};

function buildSystemPrompt(context: IncidentContext): string {
  const scenarioInfo = scenarioPrompts[context.scenario];
  const roleInfo = rolePrompts[context.role];
  
  return `You are an expert cybersecurity incident response advisor following NIST Cybersecurity Framework and SANS incident handling guidelines.

SCENARIO CONTEXT:
- Incident Type: ${scenarioInfo.context}
- Primary Focus: ${scenarioInfo.focus}
- Evidence Available: ${scenarioInfo.evidenceTypes}
- Severity Level: ${context.severity}
- Affected Systems: ${context.affected_systems.join(', ')}
- User Role: ${context.role}

ROLE GUIDANCE:
${roleInfo}

RESPONSE FORMAT:
You MUST respond with a valid JSON array of recommendations. Each recommendation must include:
- action: Clear, actionable step
- description: Brief explanation (1-2 sentences)
- priority: Number 1-3 (1=critical, 2=important, 3=recommended)
- source: Citation from NIST, SANS, or MITRE (be specific)
- mitre_mapping: Object with technique_id and technique_name (if applicable)

REQUIREMENTS:
- Provide 3-5 recommendations ranked by priority
- All actions must be specific to the ${context.scenario} scenario
- Include proper source citations (NIST CSF, SANS IH Guide, MITRE ATT&CK)
- Adapt detail level for ${context.role} perspective
- Focus on ${scenarioInfo.focus}

Example response format:
[
  {
    "action": "Isolate Affected VPN Gateway",
    "description": "Immediately disconnect compromised VPN endpoint to prevent further lateral movement",
    "priority": 1,
    "source": "NIST CSF RS.MI-3: Contain incidents",
    "mitre_mapping": {
      "technique_id": "T1133",
      "technique_name": "External Remote Services"
    }
  }
]

Respond ONLY with the JSON array, no other text.`;
}

export async function generateIncidentResponse(context: IncidentContext): Promise<AIResponse> {
  try {
    const systemPrompt = buildSystemPrompt(context);
    
    const completion = await openai.chat.completions.create({
      model: 'meta-llama/llama-3.1-8b-instruct:free',
      messages: [
        { role: 'system', content: systemPrompt },
        { 
          role: 'user', 
          content: `Generate incident response recommendations for this ${context.scenario} scenario with evidence: ${context.evidence.join(', ')}` 
        }
      ],
      max_tokens: 1000,
      temperature: 0.7
    });

    const responseText = completion.choices[0]?.message?.content?.trim();
    
    if (!responseText) {
      throw new Error('Empty response from AI service');
    }

    // Try to parse JSON response
    let recommendations: AIRecommendation[];
    try {
      // Clean up the response in case it has markdown formatting
      const cleanedResponse = responseText.replace(/```json\n?|\n?```/g, '').trim();
      recommendations = JSON.parse(cleanedResponse);
    } catch (parseError) {
      console.warn('Failed to parse AI response as JSON, using fallback:', responseText);
      recommendations = getFallbackRecommendations(context);
    }

    // Validate and filter recommendations
    const validRecommendations = recommendations
      .filter(rec => rec.action && rec.description && rec.priority)
      .slice(0, 5); // Limit to 5 recommendations

    if (validRecommendations.length === 0) {
      console.warn('No valid recommendations from AI, using fallback');
      return { recommendations: getFallbackRecommendations(context) };
    }

    return { recommendations: validRecommendations };
    
  } catch (error) {
    console.error('AI service error:', error);
    return { recommendations: getFallbackRecommendations(context) };
  }
}

function getFallbackRecommendations(context: IncidentContext): AIRecommendation[] {
  const scenarioInfo = scenarioPrompts[context.scenario];
  
  const fallbackMap = {
    'perimeter-breach': [
      {
        action: "Review Firewall Rules",
        description: "Analyze firewall logs and rules to identify how the breach occurred",
        priority: 1,
        source: "NIST CSF PR.AC-4: Access control for networks",
        mitre_mapping: { technique_id: "T1190", technique_name: "Exploit Public-Facing Application" }
      },
      {
        action: "Audit VPN Access",
        description: "Review all active VPN connections and terminate suspicious sessions",
        priority: 1,
        source: "SANS Incident Handling Guide - Containment phase",
        mitre_mapping: { technique_id: "T1133", technique_name: "External Remote Services" }
      },
      {
        action: "Strengthen Access Controls",
        description: "Implement additional authentication factors for perimeter access",
        priority: 2,
        source: "NIST CSF PR.AC-1: Identity management and access control"
      }
    ],
    'internal-reconnaissance': [
      {
        action: "Hunt for Network Scanning",
        description: "Search network logs for systematic port scanning and service enumeration",
        priority: 1,
        source: "MITRE ATT&CK Threat Hunting Guide",
        mitre_mapping: { technique_id: "T1046", technique_name: "Network Service Scanning" }
      },
      {
        action: "Isolate Suspected Systems",
        description: "Quarantine workstations showing signs of reconnaissance activity",
        priority: 1,
        source: "SANS Incident Handling Guide - Containment",
        mitre_mapping: { technique_id: "T1018", technique_name: "Remote System Discovery" }
      },
      {
        action: "Monitor Privilege Escalation",
        description: "Watch for attempts to gain administrative access on discovered systems",
        priority: 2,
        source: "NIST CSF DE.CM-1: Monitor network events"
      }
    ],
    'lateral-movement': [
      {
        action: "Isolate Affected Systems",
        description: "Immediately disconnect all systems showing ransomware encryption activity",
        priority: 1,
        source: "SANS Incident Handling Guide - Containment phase",
        mitre_mapping: { technique_id: "T1486", technique_name: "Data Encrypted for Impact" }
      },
      {
        action: "Verify Backup Integrity",
        description: "Check backup systems to ensure they aren't compromised and are available for recovery",
        priority: 1,
        source: "NIST CSF PR.IP-4: Backup and recovery procedures"
      },
      {
        action: "Analyze Ransom Note",
        description: "Document ransom demands and payment instructions for law enforcement",
        priority: 2,
        source: "SANS Ransomware Response Guide"
      }
    ]
  };
  
  return fallbackMap[context.scenario] || fallbackMap['lateral-movement'];
}