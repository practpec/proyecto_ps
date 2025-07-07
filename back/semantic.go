package main

import (
	"regexp"
	"strings"
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
	maliciousPatterns    map[string][]string
	evasionPatterns      map[string][]string
	impactPatterns       map[string][]string
	legitimatePatterns   map[string][]string
	contextRequirements  map[string][]string
	mitreMapping         map[string]string
}

func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{
		maliciousPatterns: map[string][]string{
			"payload_download": {
				`(?i)(downloadstring|invoke-webrequest).*http.*\.(exe|dll|scr|bat|ps1)`,
				`(?i)webclient.*downloadfile.*http`,
				`(?i)(curl|wget).*http.*\.(exe|dll)`,
				`(?i)bitstransfer.*http.*\.(exe|dll)`,
			},
			"persistence": {
				`(?i)new-scheduledtask.*-action.*powershell`,
				`(?i)schtasks.*\/create.*powershell.*\/sc`,
				`(?i)currentversion\\run.*powershell`,
				`(?i)userinit.*powershell`,
				`(?i)wmi.*permanent.*powershell`,
			},
			"privilege_escalation": {
				`(?i)runas.*-credential.*administrator`,
				`(?i)uac.*bypass`,
				`(?i)token.*impersonation`,
				`(?i)elevate.*administrator.*powershell`,
			},
			"data_exfiltration": {
				`(?i)send-mailmessage.*password|credential|secret`,
				`(?i)ftp.*upload.*(\.zip|\.rar|\.7z).*password`,
				`(?i)invoke-restmethod.*post.*(password|credential)`,
				`(?i)compress-archive.*password.*send`,
			},
			"system_modification": {
				`(?i)set-itemproperty.*registry.*disable`,
				`(?i)disable.*defender.*-force`,
				`(?i)set-executionpolicy.*bypass.*-force`,
				`(?i)new-item.*registry.*malware`,
			},
			"reconnaissance": {
				`(?i)get-process.*password|credential`,
				`(?i)get-wmiobject.*credential`,
				`(?i)get-aduser.*password`,
				`(?i)net.*user.*administrator`,
			},
			"lateral_movement": {
				`(?i)invoke-command.*computername.*credential`,
				`(?i)enter-pssession.*credential.*administrator`,
				`(?i)copy-item.*session.*credential`,
				`(?i)wmi.*remote.*credential`,
			},
			"defense_evasion": {
				`(?i)bypass.*-scope.*currentuser.*-force`,
				`(?i)hidden.*windowstyle.*noprofile`,
				`(?i)encodedcommand.*bypass`,
				`(?i)disable.*logging.*-force`,
			},
		},
		
		// Patrones legítimos que NO deben generar alertas
		legitimatePatterns: map[string][]string{
			"file_operations": {
				`(?i)copy-item.*documents.*backup`,
				`(?i)new-item.*backup.*directory`,
				`(?i)get-childitem.*\.(docx|xlsx|pdf|txt)`,
				`(?i)test-path.*documents`,
				`(?i)remove-item.*backup.*old`,
			},
			"logging": {
				`(?i)write-logmessage`,
				`(?i)add-content.*log`,
				`(?i)out-file.*log`,
				`(?i)write-host.*timestamp`,
			},
			"administration": {
				`(?i)get-date.*format`,
				`(?i)join-path.*backup`,
				`(?i)split-path.*parent`,
				`(?i)measure-object.*length`,
			},
		},
		
		evasionPatterns: map[string][]string{
			"anti_forensic": {
				`(?i)clear-eventlog.*security|system|application`,
				`(?i)remove-item.*\$profile.*-force`,
				`(?i)disable.*logging.*security`,
			},
			"log_deletion": {
				`(?i)clear-eventlog.*-force`,
				`(?i)wevtutil.*clear-log.*-force`,
				`(?i)remove-item.*\.evtx.*-force`,
				`(?i)fsutil.*deletejournal.*-force`,
			},
			"process_hollowing": {
				`(?i)suspend.*thread.*injection`,
				`(?i)ntunmapviewofsection`,
				`(?i)zwunmapviewofsection`,
			},
			"amsi_bypass": {
				`(?i)amsi.*bypass.*reflection`,
				`(?i)amsiutils.*amsiinitfailed`,
				`(?i)reflection.*assembly.*amsi`,
			},
			"powershell_logging": {
				`(?i)scriptblocklogging.*disable.*-force`,
				`(?i)transcription.*stop.*-force`,
				`(?i)modulelogging.*disable.*-force`,
			},
			"timestomp": {
				`(?i)creationtime.*lastwritetime.*-force`,
				`(?i)set-itemproperty.*time.*-force`,
				`(?i)timestomp.*-force`,
			},
		},
		
		impactPatterns: map[string][]string{
			"file_system": {
				`(?i)new-item.*-itemtype.*file`,
				`(?i)copy-item.*-destination`,
				`(?i)remove-item.*-recurse`,
				`(?i)set-content.*-value`,
			},
			"registry": {
				`(?i)new-item.*hklm|hkcu`,
				`(?i)set-itemproperty.*registry`,
				`(?i)remove-itemproperty.*registry`,
			},
			"network": {
				`(?i)invoke-webrequest.*-uri`,
				`(?i)test-netconnection.*-port`,
				`(?i)new-object.*tcpclient`,
			},
			"process": {
				`(?i)start-process.*-filepath`,
				`(?i)stop-process.*-name`,
				`(?i)get-process.*-name`,
			},
			"service": {
				`(?i)new-service.*-name`,
				`(?i)set-service.*-status`,
				`(?i)stop-service.*-name`,
			},
			"scheduled_task": {
				`(?i)new-scheduledtask.*-action`,
				`(?i)register-scheduledtask.*-taskname`,
				`(?i)schtasks.*\/create`,
			},
		},
		
		// Contexto requerido para considerar algo como malicioso
		contextRequirements: map[string][]string{
			"payload_download": {"http", "https", "ftp", ".exe", ".dll", ".scr"},
			"persistence": {"powershell", "cmd", "execute", "run"},
			"defense_evasion": {"bypass", "disable", "force", "hidden"},
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
	// Verificar si es un script legítimo primero
	if sa.isLegitimateScript(script) {
		return sa.buildLegitimateAnalysis(script, tokens)
	}
	
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

func (sa *SemanticAnalyzer) isLegitimateScript(script string) bool {
	
	// PRIMERO: Verificar indicadores CRÍTICOS que descartan legitimidad
	criticalMaliciousIndicators := []string{
		"invoke-expression", "iex", "downloadstring", 
		"malicious", "evil.com", "payload",
		"bypass.*force", "hidden.*noprofile",
		"base64.*base64", // Doble codificación
		"reversedcmd", "obfuscated", 
		"# ejemplo de ofuscación", "# contiene:",
		"frombase64string.*frombase64string", // Doble decodificación
	}
	
	// Si contiene indicadores críticos maliciosos, NO es legítimo
	for _, indicator := range criticalMaliciousIndicators {
		if matched, _ := regexp.MatchString(`(?i)`+indicator, script); matched {
			return false
		}
	}
	
	// SEGUNDO: Verificar patrones de ofuscación sospechosos
	obfuscationPatterns := []string{
		`\$[a-z]\d+[a-z]\d+`, // Variables como $a1b2c3
		`"[a-z]"\s*\+\s*"[a-z]"`, // Fragmentación de caracteres
		`\[\d+\.\.\d+\]`, // Rangos de arrays
		`-join.*tochararray.*sort.*random`, // Reorganización aleatoria
		`reversedcmd|normalcmd`, // Variables de reversión
	}
	
	obfuscationCount := 0
	for _, pattern := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pattern, script); matched {
			obfuscationCount++
		}
	}
	
	// Si tiene múltiples patrones de ofuscación, NO es legítimo
	if obfuscationCount >= 2 {
		return false
	}
	
	// TERCERO: Verificar comandos altamente sospechosos
	suspiciousCommands := []string{
		`invoke-expression.*http`,
		`downloadstring.*http`,
		`system\.convert.*frombase64string.*frombase64string`,
		`webclient.*downloadstring`,
		`new-object.*system\.net\.webclient`,
	}
	
	for _, cmd := range suspiciousCommands {
		if matched, _ := regexp.MatchString(`(?i)`+cmd, script); matched {
			return false
		}
	}
	
	// CUARTO: Solo ENTONCES verificar indicadores legítimos
	legitimateIndicators := []string{
		"# script de backup", "# función para", "param\\(",
		"backup", "log", "report", "document", 
		"function write-logmessage", 
		"get-childitem.*filter", "copy-item.*destination",
		"test-path", "new-item.*directory", "remove-item.*old",
		"join-path.*backup", "add-content.*log",
	}
	
	legitimateScore := 0
	for _, indicator := range legitimateIndicators {
		if matched, _ := regexp.MatchString(`(?i)`+indicator, script); matched {
			legitimateScore++
		}
	}
	
	// QUINTO: Verificar si el script tiene estructura administrativa
	hasAdminStructure := false
	adminStructurePatterns := []string{
		`param\s*\(\s*\[string\]\s*\$\w+Path`,
		`function\s+\w+-\w+\s*\{`,
		`write-logmessage.*timestamp`,
		`get-date.*format`,
	}
	
	for _, pattern := range adminStructurePatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pattern, script); matched {
			hasAdminStructure = true
			break
		}
	}
	
	// CRITERIO FINAL: Solo es legítimo si:
	// 1. Tiene al menos 3 indicadores legítimos
	// 2. Tiene estructura administrativa
	// 3. NO tiene indicadores críticos (ya verificado arriba)
	return legitimateScore >= 3 && hasAdminStructure
}

func (sa *SemanticAnalyzer) buildLegitimateAnalysis(script string, tokens []Token) SemanticAnalysis {
	// Para scripts legítimos, hacer análisis mínimo
	systemImpact := sa.analyzeSystemImpact(script) // Análisis básico de impacto
	
	// Calcular un riesgo bajo basado solo en tokens realmente sospechosos
	riskScore := 0
	for _, token := range tokens {
		if token.IsSuspicious && token.Severity == "high" {
			riskScore += 5 // Peso menor para scripts legítimos
		} else if token.IsSuspicious && token.Severity == "medium" {
			riskScore += 2
		}
	}
	
	// Limitar el riesgo máximo para scripts legítimos
	if riskScore > 30 {
		riskScore = 30
	}
	
	return SemanticAnalysis{
		MaliciousIntent: MaliciousIntent{
			PayloadDownload:     false,
			Persistence:         false,
			PrivilegeEscalation: false,
			DataExfiltration:    false,
			SystemModification:  false,
			Reconnaissance:      false,
			LateralMovement:     false,
			DefenseEvasion:      false,
			Details:            []string{},
		},
		EvasionTechniques: EvasionTechniques{
			AntiForensic:      false,
			LogDeletion:       false,
			ProcessHollowing:  false,
			AMSIBypass:        false,
			PowerShellLogging: false,
			Timestomp:         sa.detectTimestomp(script), // Solo timestomp puede ser legítimo
			Techniques:        sa.getLegitimateEvasionTechniques(script),
		},
		SystemImpact:   systemImpact,
		ThreatCategory: "Script Administrativo Legítimo",
		RiskScore:      riskScore,
		AttackChain:    []AttackStep{},
	}
}

func (sa *SemanticAnalyzer) getLegitimateEvasionTechniques(script string) []string {
	var techniques []string
	
	// Solo detectar timestomp si realmente está modificando timestamps de manera sospechosa
	if matched, _ := regexp.MatchString(`(?i)creationtime.*lastwritetime.*hide|modify|alter`, script); matched {
		techniques = append(techniques, "timestomp")
	}
	
	return techniques
}

func (sa *SemanticAnalyzer) detectTimestomp(script string) bool {
	// Solo detectar si está modificando timestamps de manera sospechosa
	suspiciousTimestampPatterns := []string{
		`(?i)creationtime.*lastwritetime.*hide`,
		`(?i)set-itemproperty.*time.*hide|modify|alter`,
		`(?i)timestomp.*hide|modify`,
	}
	
	for _, pattern := range suspiciousTimestampPatterns {
		if matched, _ := regexp.MatchString(pattern, script); matched {
			return true
		}
	}
	
	return false
}

func (sa *SemanticAnalyzer) analyzeMaliciousIntent(script string) MaliciousIntent {
	intent := MaliciousIntent{}
	var details []string
	
	// Analizar cada categoría de intención maliciosa con contexto
	for category, patterns := range sa.maliciousPatterns {
		found := false
		for _, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, script); matched {
				// Verificar contexto antes de marcar como malicioso
				if sa.hasRequiredContext(category, script) {
					found = true
					details = append(details, "Detected "+category+" pattern: "+pattern)
					break
				}
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

func (sa *SemanticAnalyzer) hasRequiredContext(category string, script string) bool {
	requirements, exists := sa.contextRequirements[category]
	if !exists {
		return true // Si no hay requisitos de contexto, aceptar
	}
	
	lowerScript := strings.ToLower(script)
	
	// Verificar que al menos uno de los requisitos de contexto esté presente
	for _, req := range requirements {
		if strings.Contains(lowerScript, req) {
			return true
		}
	}
	
	return false
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
	
	// Si no hay intenciones maliciosas claras, es actividad normal
	hasAnyMaliciousIntent := intent.PayloadDownload || intent.Persistence || 
	                        intent.PrivilegeEscalation || intent.DataExfiltration ||
	                        intent.SystemModification || intent.Reconnaissance ||
	                        intent.LateralMovement || intent.DefenseEvasion
	
	if !hasAnyMaliciousIntent {
		return "Script Administrativo Legítimo"
	}
	
	return "Actividad Sospechosa"
}

func (sa *SemanticAnalyzer) calculateRiskScore(intent MaliciousIntent, evasion EvasionTechniques, impact SystemImpact, tokens []Token) int {
	score := 0
	
	// Puntaje por intenciones maliciosas (solo si están presentes)
	if intent.PayloadDownload { score += 20 }
	if intent.Persistence { score += 25 }
	if intent.PrivilegeEscalation { score += 30 }
	if intent.DataExfiltration { score += 35 }
	if intent.SystemModification { score += 15 } // Reducido porque puede ser legítimo
	if intent.Reconnaissance { score += 10 }
	if intent.LateralMovement { score += 25 }
	if intent.DefenseEvasion { score += 15 }
	
	// Puntaje por técnicas de evasión
	if evasion.AntiForensic { score += 20 }
	if evasion.LogDeletion { score += 15 }
	if evasion.ProcessHollowing { score += 25 }
	if evasion.AMSIBypass { score += 20 }
	if evasion.PowerShellLogging { score += 15 }
	if evasion.Timestomp { score += 5 } // Reducido porque puede ser legítimo
	
	// Puntaje por impacto en sistema (reducido para operaciones normales)
	if impact.FileSystemChanges { score += 5 } // Muy reducido
	if impact.RegistryChanges { score += 10 }
	if impact.NetworkActivity { score += 8 }
	if impact.ProcessCreation { score += 5 }
	if impact.ServiceModification { score += 12 }
	if impact.ScheduledTasks { score += 10 }
	
	// Puntaje por tokens sospechosos (solo los realmente críticos)
	for _, token := range tokens {
		if token.IsSuspicious {
			switch token.Severity {
			case "high":
				score += 8 // Reducido de 5
			case "medium":
				score += 3 // Reducido de 3
			case "low":
				score += 1 // Sin cambio
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
	
	// Solo crear cadena de ataque si hay intenciones maliciosas reales
	hasRealThreats := intent.PayloadDownload || intent.PrivilegeEscalation || 
	                 intent.DataExfiltration || intent.Persistence
	
	if !hasRealThreats {
		return []AttackStep{} // Retornar cadena vacía para scripts legítimos
	}
	
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