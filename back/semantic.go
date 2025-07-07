package main

import (
	"regexp"
)

type SemanticAnalysis struct {
	MaliciousIntent   MaliciousIntent   `json:"malicious_intent"`
	EvasionTechniques EvasionTechniques `json:"evasion_techniques"`
	SystemImpact      SystemImpact      `json:"system_impact"`
	ThreatCategory    string           `json:"threat_category"`
	RiskScore         int              `json:"risk_score"`
	AttackChain       []AttackStep     `json:"attack_chain"`
}

type MaliciousIntent struct {
	PayloadDownload     bool   `json:"payload_download"`
	Persistence         bool   `json:"persistence"`
	PrivilegeEscalation bool   `json:"privilege_escalation"`
	DataExfiltration    bool   `json:"data_exfiltration"`
	SystemModification  bool   `json:"system_modification"`
	Reconnaissance      bool   `json:"reconnaissance"`
	LateralMovement     bool   `json:"lateral_movement"`
	DefenseEvasion      bool   `json:"defense_evasion"`
	Details            []string `json:"details"`
}

type EvasionTechniques struct {
	AntiForensic       bool     `json:"anti_forensic"`
	LogDeletion        bool     `json:"log_deletion"`
	ProcessHollowing   bool     `json:"process_hollowing"`
	AMSIBypass         bool     `json:"amsi_bypass"`
	PowerShellLogging  bool     `json:"powershell_logging"`
	Timestomp          bool     `json:"timestomp"`
	Techniques         []string `json:"techniques"`
}

type SystemImpact struct {
	FileSystemChanges  bool     `json:"file_system_changes"`
	RegistryChanges    bool     `json:"registry_changes"`
	NetworkActivity    bool     `json:"network_activity"`
	ProcessCreation    bool     `json:"process_creation"`
	ServiceModification bool    `json:"service_modification"`
	ScheduledTasks     bool     `json:"scheduled_tasks"`
	ImpactAreas        []string `json:"impact_areas"`
}

type AttackStep struct {
	Phase       string `json:"phase"`
	Technique   string `json:"technique"`
	Description string `json:"description"`
	MITREATT    string `json:"mitre_att"`
}

type SemanticAnalyzer struct {
	maliciousPatterns map[string][]string
	evasionPatterns   map[string][]string
	impactPatterns    map[string][]string
	mitreMapping      map[string]string
}

func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{
		maliciousPatterns: map[string][]string{
			"payload_download": {
				`(?i)(downloadstring|downloadfile|invoke-webrequest)`,
				`(?i)(webclient|net\.webclient)`,
				`(?i)(curl|wget)`,
				`(?i)(bitstransfer|start-bitstransfer)`,
			},
			"persistence": {
				`(?i)(new-scheduledtask|schtasks)`,
				`(?i)(new-service|sc\.exe)`,
				`(?i)(currentversion\\run|userinit)`,
				`(?i)(startup|winlogon)`,
				`(?i)(wmi.*permanent)`,
			},
			"privilege_escalation": {
				`(?i)(runas|start-process.*credential)`,
				`(?i)(uac.*bypass)`,
				`(?i)(token.*impersonation)`,
				`(?i)(elevate|admin)`,
			},
			"data_exfiltration": {
				`(?i)(send-mailmessage|smtp)`,
				`(?i)(ftp.*upload)`,
				`(?i)(invoke-restmethod.*post)`,
				`(?i)(compress-archive.*password)`,
				`(?i)(copy-item.*network)`,
			},
			"system_modification": {
				`(?i)(set-itemproperty.*registry)`,
				`(?i)(new-item.*registry)`,
				`(?i)(disable.*defender|mppreference)`,
				`(?i)(set-executionpolicy)`,
			},
			"reconnaissance": {
				`(?i)(get-process|get-service)`,
				`(?i)(get-wmiobject|gwmi)`,
				`(?i)(get-computerinfo|systeminfo)`,
				`(?i)(get-aduser|get-adcomputer)`,
				`(?i)(test-netconnection|ping)`,
			},
			"lateral_movement": {
				`(?i)(invoke-command.*computername)`,
				`(?i)(enter-pssession|new-pssession)`,
				`(?i)(copy-item.*session)`,
				`(?i)(wmi.*remote)`,
			},
			"defense_evasion": {
				`(?i)(bypass|unrestricted)`,
				`(?i)(hidden|windowstyle)`,
				`(?i)(noprofile|noninteractive)`,
				`(?i)(encodedcommand|enc)`,
			},
		},
		
		evasionPatterns: map[string][]string{
			"anti_forensic": {
				`(?i)(clear-eventlog|wevtutil.*cl)`,
				`(?i)(remove-item.*\$profile)`,
				`(?i)(disable.*logging)`,
			},
			"log_deletion": {
				`(?i)(clear-eventlog)`,
				`(?i)(wevtutil.*clear-log)`,
				`(?i)(remove-item.*\.evtx)`,
				`(?i)(fsutil.*deletejournal)`,
			},
			"process_hollowing": {
				`(?i)(suspend.*thread)`,
				`(?i)(ntunmapviewofsection)`,
				`(?i)(zwunmapviewofsection)`,
			},
			"amsi_bypass": {
				`(?i)(amsi.*bypass)`,
				`(?i)(amsiutils|amsiinitfailed)`,
				`(?i)(reflection.*assembly)`,
			},
			"powershell_logging": {
				`(?i)(scriptblocklogging.*disable)`,
				`(?i)(transcription.*stop)`,
				`(?i)(modulelogging.*disable)`,
			},
			"timestomp": {
				`(?i)(creationtime|lastwritetime)`,
				`(?i)(set-itemproperty.*time)`,
				`(?i)(timestomp)`,
			},
		},
		
		impactPatterns: map[string][]string{
			"file_system": {
				`(?i)(new-item|remove-item)`,
				`(?i)(copy-item|move-item)`,
				`(?i)(set-content|add-content)`,
				`(?i)(compress-archive|expand-archive)`,
			},
			"registry": {
				`(?i)(new-item.*registry)`,
				`(?i)(set-itemproperty.*hk)`,
				`(?i)(remove-itemproperty)`,
				`(?i)(get-itemproperty.*hk)`,
			},
			"network": {
				`(?i)(invoke-webrequest|webclient)`,
				`(?i)(test-netconnection)`,
				`(?i)(new-object.*tcpclient)`,
				`(?i)(udpclient|socket)`,
			},
			"process": {
				`(?i)(start-process|stop-process)`,
				`(?i)(get-process|invoke-command)`,
				`(?i)(new-object.*process)`,
			},
			"service": {
				`(?i)(new-service|set-service)`,
				`(?i)(stop-service|start-service)`,
				`(?i)(sc\.exe)`,
			},
			"scheduled_task": {
				`(?i)(new-scheduledtask)`,
				`(?i)(register-scheduledtask)`,
				`(?i)(schtasks)`,
			},
		},
		
		mitreMapping: map[string]string{
			"payload_download":      "T1105",
			"persistence":          "T1053",
			"privilege_escalation": "T1548",
			"data_exfiltration":    "T1041",
			"system_modification":  "T1112",
			"reconnaissance":       "T1082",
			"lateral_movement":     "T1021",
			"defense_evasion":      "T1562",
			"anti_forensic":        "T1070",
			"log_deletion":         "T1070.001",
			"process_hollowing":    "T1055",
			"amsi_bypass":          "T1562.001",
		},
	}
}

func (sa *SemanticAnalyzer) AnalyzeSemantics(script string, tokens []Token, syntaxAnalysis SyntaxAnalysis) SemanticAnalysis {
	maliciousIntent := sa.analyzeMaliciousIntent(script)
	evasionTechniques := sa.analyzeEvasionTechniques(script)
	systemImpact := sa.analyzeSystemImpact(script)
	
	analysis := SemanticAnalysis{
		MaliciousIntent:   maliciousIntent,
		EvasionTechniques: evasionTechniques,
		SystemImpact:      systemImpact,
		ThreatCategory:    sa.categorizeThreat(maliciousIntent, evasionTechniques),
		RiskScore:         sa.calculateRiskScore(maliciousIntent, evasionTechniques, systemImpact, tokens),
		AttackChain:       sa.reconstructAttackChain(script, maliciousIntent),
	}
	
	return analysis
}

func (sa *SemanticAnalyzer) analyzeMaliciousIntent(script string) MaliciousIntent {
	intent := MaliciousIntent{}
	var details []string
	
	// Analizar cada categoría de intención maliciosa
	for category, patterns := range sa.maliciousPatterns {
		found := false
		for _, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, script); matched {
				found = true
				details = append(details, "Detected "+category+" pattern: "+pattern)
				break
			}
		}
		
		switch category {
		case "payload_download":
			intent.PayloadDownload = found
		case "persistence":
			intent.Persistence = found
		case "privilege_escalation":
			intent.PrivilegeEscalation = found
		case "data_exfiltration":
			intent.DataExfiltration = found
		case "system_modification":
			intent.SystemModification = found
		case "reconnaissance":
			intent.Reconnaissance = found
		case "lateral_movement":
			intent.LateralMovement = found
		case "defense_evasion":
			intent.DefenseEvasion = found
		}
	}
	
	// Asegurar que details no sea nil
	if details == nil {
		details = []string{}
	}
	
	intent.Details = details
	return intent
}

func (sa *SemanticAnalyzer) analyzeEvasionTechniques(script string) EvasionTechniques {
	techniques := EvasionTechniques{}
	var techniqueList []string
	
	for category, patterns := range sa.evasionPatterns {
		found := false
		for _, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, script); matched {
				found = true
				techniqueList = append(techniqueList, category)
				break
			}
		}
		
		switch category {
		case "anti_forensic":
			techniques.AntiForensic = found
		case "log_deletion":
			techniques.LogDeletion = found
		case "process_hollowing":
			techniques.ProcessHollowing = found
		case "amsi_bypass":
			techniques.AMSIBypass = found
		case "powershell_logging":
			techniques.PowerShellLogging = found
		case "timestomp":
			techniques.Timestomp = found
		}
	}
	
	// Asegurar que techniqueList no sea nil
	if techniqueList == nil {
		techniqueList = []string{}
	}
	
	techniques.Techniques = techniqueList
	return techniques
}

func (sa *SemanticAnalyzer) analyzeSystemImpact(script string) SystemImpact {
	impact := SystemImpact{}
	var impactAreas []string
	
	for category, patterns := range sa.impactPatterns {
		found := false
		for _, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, script); matched {
				found = true
				impactAreas = append(impactAreas, category)
				break
			}
		}
		
		switch category {
		case "file_system":
			impact.FileSystemChanges = found
		case "registry":
			impact.RegistryChanges = found
		case "network":
			impact.NetworkActivity = found
		case "process":
			impact.ProcessCreation = found
		case "service":
			impact.ServiceModification = found
		case "scheduled_task":
			impact.ScheduledTasks = found
		}
	}
	
	// Asegurar que impactAreas no sea nil
	if impactAreas == nil {
		impactAreas = []string{}
	}
	
	impact.ImpactAreas = impactAreas
	return impact
}

func (sa *SemanticAnalyzer) categorizeThreat(intent MaliciousIntent, evasion EvasionTechniques) string {
	// Categorizar basado en las intenciones detectadas
	if intent.DataExfiltration {
		return "Robo de Datos"
	}
	
	if intent.Persistence && intent.DefenseEvasion {
		return "Amenaza Persistente Avanzada (APT)"
	}
	
	if intent.PayloadDownload && intent.SystemModification {
		return "Descargador de Malware"
	}
	
	if intent.PrivilegeEscalation && intent.LateralMovement {
		return "Framework de Post-Explotación"
	}
	
	if evasion.AntiForensic && evasion.LogDeletion {
		return "Malware Sigiloso"
	}
	
	if intent.Reconnaissance {
		return "Recopilación de Información"
	}
	
	if intent.SystemModification {
		return "Manipulación del Sistema"
	}
	
	return "Actividad Sospechosa"
}

func (sa *SemanticAnalyzer) calculateRiskScore(intent MaliciousIntent, evasion EvasionTechniques, impact SystemImpact, tokens []Token) int {
	score := 0
	
	// Puntaje por intenciones maliciosas
	if intent.PayloadDownload { score += 20 }
	if intent.Persistence { score += 25 }
	if intent.PrivilegeEscalation { score += 30 }
	if intent.DataExfiltration { score += 35 }
	if intent.SystemModification { score += 20 }
	if intent.Reconnaissance { score += 10 }
	if intent.LateralMovement { score += 25 }
	if intent.DefenseEvasion { score += 15 }
	
	// Puntaje por técnicas de evasión
	if evasion.AntiForensic { score += 20 }
	if evasion.LogDeletion { score += 15 }
	if evasion.ProcessHollowing { score += 25 }
	if evasion.AMSIBypass { score += 20 }
	if evasion.PowerShellLogging { score += 15 }
	if evasion.Timestomp { score += 10 }
	
	// Puntaje por impacto en sistema
	if impact.FileSystemChanges { score += 10 }
	if impact.RegistryChanges { score += 15 }
	if impact.NetworkActivity { score += 10 }
	if impact.ProcessCreation { score += 10 }
	if impact.ServiceModification { score += 15 }
	if impact.ScheduledTasks { score += 15 }
	
	// Puntaje por tokens sospechosos
	for _, token := range tokens {
		if token.IsSuspicious {
			switch token.Severity {
			case "high":
				score += 5
			case "medium":
				score += 3
			case "low":
				score += 1
			}
		}
	}
	
	// Normalizar a escala 0-100
	if score > 100 {
		score = 100
	}
	
	return score
}

func (sa *SemanticAnalyzer) reconstructAttackChain(script string, intent MaliciousIntent) []AttackStep {
	var chain []AttackStep
	
	// Reconstruir cadena de ataque basada en las técnicas detectadas
	if intent.Reconnaissance {
		chain = append(chain, AttackStep{
			Phase:       "Reconocimiento",
			Technique:   "Descubrimiento del Sistema",
			Description: "Recopilación de información del sistema y detalles del entorno",
			MITREATT:    "T1082",
		})
	}
	
	if intent.DefenseEvasion {
		chain = append(chain, AttackStep{
			Phase:       "Evasión de Defensas",
			Technique:   "Bypass de Política de Ejecución",
			Description: "Eludiendo controles de seguridad y políticas de ejecución",
			MITREATT:    "T1562",
		})
	}
	
	if intent.PayloadDownload {
		chain = append(chain, AttackStep{
			Phase:       "Entrega",
			Technique:   "Descarga de Archivo Remoto",
			Description: "Descargando payload malicioso desde servidor remoto",
			MITREATT:    "T1105",
		})
	}
	
	if intent.PrivilegeEscalation {
		chain = append(chain, AttackStep{
			Phase:       "Escalación de Privilegios",
			Technique:   "Bypass de UAC",
			Description: "Intentando obtener privilegios elevados",
			MITREATT:    "T1548",
		})
	}
	
	if intent.Persistence {
		chain = append(chain, AttackStep{
			Phase:       "Persistencia",
			Technique:   "Creación de Tarea Programada",
			Description: "Estableciendo persistencia mediante tareas programadas",
			MITREATT:    "T1053",
		})
	}
	
	if intent.LateralMovement {
		chain = append(chain, AttackStep{
			Phase:       "Movimiento Lateral",
			Technique:   "Servicios Remotos",
			Description: "Moviéndose lateralmente a través de la red",
			MITREATT:    "T1021",
		})
	}
	
	if intent.DataExfiltration {
		chain = append(chain, AttackStep{
			Phase:       "Exfiltración",
			Technique:   "Transferencia de Datos",
			Description: "Exfiltrando datos sensibles del sistema",
			MITREATT:    "T1041",
		})
	}
	
	// Asegurar que chain no sea nil
	if chain == nil {
		chain = []AttackStep{}
	}
	
	return chain
}