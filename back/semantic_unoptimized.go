package main

import (
	"regexp"
)

// NOTA: Este archivo es la versión NO OPTIMIZADA del analizador semántico.
// No utiliza la librería "strings" para demostrar un rendimiento inferior.

type SemanticAnalyzer_Unoptimized struct {
	maliciousPatterns    map[string][]string
	evasionPatterns      map[string][]string
	impactPatterns       map[string][]string
	legitimatePatterns   map[string][]string
	contextRequirements  map[string][]string
	mitreMapping         map[string]string
}

func NewSemanticAnalyzer_Unoptimized() *SemanticAnalyzer_Unoptimized {
	// La definición de patrones es idéntica
	return &SemanticAnalyzer_Unoptimized{
		maliciousPatterns: map[string][]string{
			"payload_download": {`(?i)(downloadstring|invoke-webrequest).*http.*\.(exe|dll|scr|bat|ps1)`, `(?i)webclient.*downloadfile.*http`, `(?i)webclient.*downloadstring.*http`, `(?i)(curl|wget).*http.*\.(exe|dll)`, `(?i)bitstransfer.*http.*\.(exe|dll)`, `(?i)new-object.*webclient.*downloadstring`, `(?i)system\.net\.webclient.*downloadstring`},
			"persistence": {`(?i)new-scheduledtask.*-action.*powershell`, `(?i)schtasks.*\/create.*powershell.*\/sc`, `(?i)currentversion\\run.*powershell`, `(?i)set-itemproperty.*run.*powershell`, `(?i)userinit.*powershell`, `(?i)wmi.*permanent.*powershell`, `(?i)hkcu.*run.*powershell`, `(?i)hklm.*run.*powershell`},
			"privilege_escalation": {`(?i)runas.*-credential.*administrator`, `(?i)uac.*bypass`, `(?i)token.*impersonation`, `(?i)elevate.*administrator.*powershell`},
			"data_exfiltration": {`(?i)send-mailmessage.*password|credential|secret`, `(?i)ftp.*upload.*(\.zip|\.rar|\.7z).*password`, `(?i)invoke-restmethod.*post.*(password|credential)`, `(?i)compress-archive.*password.*send`},
			"system_modification": {`(?i)set-itemproperty.*registry.*disable`, `(?i)disable.*defender.*-force`, `(?i)set-executionpolicy.*bypass.*-force`, `(?i)new-item.*registry.*malware`, `(?i)set-executionpolicy.*bypass`, `(?i)executionpolicy.*bypass`},
			"reconnaissance": {`(?i)get-process.*password|credential`, `(?i)get-wmiobject.*credential`, `(?i)get-aduser.*password`, `(?i)net.*user.*administrator`},
			"lateral_movement": {`(?i)invoke-command.*computername.*credential`, `(?i)enter-pssession.*credential.*administrator`, `(?i)copy-item.*session.*credential`, `(?i)wmi.*remote.*credential`},
			"defense_evasion": {`(?i)bypass.*-scope.*currentuser.*-force`, `(?i)hidden.*windowstyle.*noprofile`, `(?i)encodedcommand.*bypass`, `(?i)disable.*logging.*-force`, `(?i)-windowstyle.*hidden`, `(?i)-noprofile`, `(?i)createnowindow.*true`},
		},
		legitimatePatterns: map[string][]string{
			"file_operations": {`(?i)copy-item.*documents.*backup`, `(?i)new-item.*backup.*directory`, `(?i)get-childitem.*\.(docx|xlsx|pdf|txt)`, `(?i)test-path.*documents`, `(?i)remove-item.*backup.*old`},
			"logging": {`(?i)write-logmessage`, `(?i)add-content.*log`, `(?i)out-file.*log`, `(?i)write-host.*timestamp`},
			"administration": {`(?i)get-date.*format`, `(?i)join-path.*backup`, `(?i)split-path.*parent`, `(?i)measure-object.*length`},
		},
		evasionPatterns: map[string][]string{
			"anti_forensic": {`(?i)clear-eventlog.*security|system|application`, `(?i)remove-item.*\$profile.*-force`, `(?i)disable.*logging.*security`, `(?i)remove-variable.*-erroraction.*silentlycontinue`},
			"log_deletion": {`(?i)clear-eventlog.*-force`, `(?i)wevtutil.*clear-log.*-force`, `(?i)remove-item.*\.evtx.*-force`, `(?i)fsutil.*deletejournal.*-force`},
			"process_hollowing": {`(?i)suspend.*thread.*injection`, `(?i)ntunmapviewofsection`, `(?i)zwunmapviewofsection`},
			"amsi_bypass": {`(?i)amsi.*bypass.*reflection`, `(?i)amsiutils.*amsiinitfailed`, `(?i)reflection.*assembly.*amsi`},
			"powershell_logging": {`(?i)scriptblocklogging.*disable.*-force`, `(?i)transcription.*stop.*-force`, `(?i)modulelogging.*disable.*-force`},
			"timestomp": {`(?i)creationtime.*lastwritetime.*-force`, `(?i)set-itemproperty.*time.*-force`, `(?i)timestomp.*-force`},
		},
		impactPatterns: map[string][]string{
			"file_system": {`(?i)new-item.*-itemtype.*file`, `(?i)copy-item.*-destination`, `(?i)remove-item.*-recurse`, `(?i)set-content.*-value`},
			"registry": {`(?i)new-item.*hklm|hkcu`, `(?i)set-itemproperty.*registry`, `(?i)remove-itemproperty.*registry`, `(?i)set-itemproperty.*run`, `(?i)hkcu.*software.*microsoft.*windows.*currentversion.*run`},
			"network": {`(?i)invoke-webrequest.*-uri`, `(?i)test-netconnection.*-port`, `(?i)new-object.*tcpclient`, `(?i)system\.net\.webclient`},
			"process": {`(?i)start-process.*-filepath`, `(?i)stop-process.*-name`, `(?i)get-process.*-name`, `(?i)system\.diagnostics\.process`},
			"service": {`(?i)new-service.*-name`, `(?i)set-service.*-status`, `(?i)stop-service.*-name`},
			"scheduled_task": {`(?i)new-scheduledtask.*-action`, `(?i)register-scheduledtask.*-taskname`, `(?i)schtasks.*\/create`},
		},
		contextRequirements: map[string][]string{
			"payload_download": {"http", "https", "ftp", ".exe", ".dll", ".scr"},
			"persistence": {"powershell", "cmd", "execute", "run"},
			"defense_evasion": {"bypass", "disable", "force", "hidden"},
		},
		mitreMapping: map[string]string{
			"payload_download": "T1105", "persistence": "T1053", "privilege_escalation": "T1548",
			"data_exfiltration": "T1041", "system_modification": "T1112", "reconnaissance": "T1082",
			"lateral_movement": "T1021", "defense_evasion": "T1562", "anti_forensic": "T1070",
			"log_deletion": "T1070.001", "process_hollowing": "T1055", "amsi_bypass": "T1562.001",
		},
	}
}

func (sa *SemanticAnalyzer_Unoptimized) AnalyzeSemantics(script string, tokens []Token, syntaxAnalysis SyntaxAnalysis) SemanticAnalysis {
	maliciousIntent := sa.analyzeMaliciousIntent(script)
	evasionTechniques := sa.analyzeEvasionTechniques(script)
	systemImpact := sa.analyzeSystemImpact(script)
	if sa.isLegitimateScript(script, maliciousIntent, evasionTechniques, tokens) {
		return sa.buildLegitimateAnalysis(script, tokens, systemImpact)
	}
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

func (sa *SemanticAnalyzer_Unoptimized) isLegitimateScript(script string, maliciousIntent MaliciousIntent, evasionTechniques EvasionTechniques, tokens []Token) bool {
	hasMaliciousIntent := maliciousIntent.PayloadDownload || maliciousIntent.Persistence || maliciousIntent.PrivilegeEscalation || maliciousIntent.DataExfiltration || maliciousIntent.DefenseEvasion
	if hasMaliciousIntent { return false }
	hasEvasionTechniques := evasionTechniques.AntiForensic || evasionTechniques.LogDeletion || evasionTechniques.AMSIBypass || len(evasionTechniques.Techniques) > 0
	if hasEvasionTechniques { return false }
	highSeverityCount := 0
	for _, token := range tokens {
		if token.IsSuspicious && token.Severity == "high" { highSeverityCount++ }
	}
	if highSeverityCount > 0 { return false }
	criticalMaliciousIndicators := []string{`(?i)evil\.com|malicious|payload\.txt`, `(?i)hxxp.*evil.*payload`, `(?i)downloadstring.*http`, `(?i)webclient.*downloadstring`, `(?i)frombase64string.*frombase64string`, `(?i)invoke-expression.*http`, `(?i)system\.net\.webclient.*downloadstring`, `(?i)currentversion.*run.*powershell.*hidden`, `(?i)executionpolicy.*bypass.*encodedcommand`, `(?i)windowsstyle.*hidden.*executionpolicy.*bypass`, `(?i)createnowindow.*true`, `(?i)remove-variable.*erroraction.*silentlycontinue`}
	for _, indicator := range criticalMaliciousIndicators {
		if matched, _ := regexp.MatchString(indicator, script); matched { return false }
	}
	obfuscationPatterns := []string{`(?i)\$[a-z]\d+\s*=\s*"[^"]{1,3}".*\$[a-z]\d+\s*=\s*"[^"]{1,3}"`, `(?i)replace\s*\(\s*"\[.*?\]"\s*,\s*".*?"\s*\)`, `(?i)\$[a-z]\d+\s*\+\s*\$[a-z]\d+\s*\+\s*\$[a-z]\d+`}
	obfuscationCount := 0
	for _, pattern := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(pattern, script); matched { obfuscationCount++ }
	}
	if obfuscationCount >= 2 { return false }
	legitimateIndicators := []string{`(?i)# script de backup`, `(?i)# función para`, `(?i)param\s*\(`, `(?i)function\s+\w+-\w+`, `(?i)write-logmessage`, `(?i)get-childitem.*filter`, `(?i)copy-item.*destination.*backup`, `(?i)test-path.*documents`, `(?i)join-path.*backup`, `(?i)add-content.*log`}
	legitimateScore := 0
	for _, indicator := range legitimateIndicators {
		if matched, _ := regexp.MatchString(indicator, script); matched { legitimateScore++ }
	}
	return legitimateScore >= 3
}

func (sa *SemanticAnalyzer_Unoptimized) buildLegitimateAnalysis(script string, tokens []Token, systemImpact SystemImpact) SemanticAnalysis {
	riskScore := 0
	for _, token := range tokens {
		if token.IsSuspicious {
			if token.Severity == "high" { riskScore += 10 } else if token.Severity == "medium" { riskScore += 3 }
		}
	}
	if riskScore > 25 { riskScore = 25 }
	return SemanticAnalysis{
		MaliciousIntent:   MaliciousIntent{Details: []string{}},
		EvasionTechniques: EvasionTechniques{Techniques: []string{}},
		SystemImpact:      systemImpact,
		ThreatCategory:    "Script Administrativo Legítimo",
		RiskScore:         riskScore,
		AttackChain:       []AttackStep{},
	}
}

func (sa *SemanticAnalyzer_Unoptimized) analyzeMaliciousIntent(script string) MaliciousIntent {
	intent := MaliciousIntent{}
	var details []string
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
		case "payload_download": intent.PayloadDownload = found
		case "persistence": intent.Persistence = found
		case "privilege_escalation": intent.PrivilegeEscalation = found
		case "data_exfiltration": intent.DataExfiltration = found
		case "system_modification": intent.SystemModification = found
		case "reconnaissance": intent.Reconnaissance = found
		case "lateral_movement": intent.LateralMovement = found
		case "defense_evasion": intent.DefenseEvasion = found
		}
	}
	if details == nil { details = []string{} }
	intent.Details = details
	return intent
}

func (sa *SemanticAnalyzer_Unoptimized) analyzeEvasionTechniques(script string) EvasionTechniques {
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
		case "anti_forensic": techniques.AntiForensic = found
		case "log_deletion": techniques.LogDeletion = found
		case "process_hollowing": techniques.ProcessHollowing = found
		case "amsi_bypass": techniques.AMSIBypass = found
		case "powershell_logging": techniques.PowerShellLogging = found
		case "timestomp": techniques.Timestomp = found
		}
	}
	if techniqueList == nil { techniqueList = []string{} }
	techniques.Techniques = techniqueList
	return techniques
}

func (sa *SemanticAnalyzer_Unoptimized) analyzeSystemImpact(script string) SystemImpact {
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
		case "file_system": impact.FileSystemChanges = found
		case "registry": impact.RegistryChanges = found
		case "network": impact.NetworkActivity = found
		case "process": impact.ProcessCreation = found
		case "service": impact.ServiceModification = found
		case "scheduled_task": impact.ScheduledTasks = found
		}
	}
	if impactAreas == nil { impactAreas = []string{} }
	impact.ImpactAreas = impactAreas
	return impact
}

func (sa *SemanticAnalyzer_Unoptimized) categorizeThreat(intent MaliciousIntent, evasion EvasionTechniques) string {
	if intent.DataExfiltration { return "Robo de Datos" }
	if intent.Persistence && intent.DefenseEvasion { return "Amenaza Persistente Avanzada (APT)" }
	if intent.PayloadDownload && intent.SystemModification { return "Descargador de Malware" }
	if intent.PayloadDownload && intent.Persistence { return "Malware Dropper con Persistencia" }
	if intent.PrivilegeEscalation && intent.LateralMovement { return "Framework de Post-Explotación" }
	if evasion.AntiForensic && evasion.LogDeletion { return "Malware Sigiloso" }
	if intent.Reconnaissance { return "Recopilación de Información" }
	if intent.SystemModification { return "Manipulación del Sistema" }
	if intent.DefenseEvasion { return "Script de Evasión" }
	if intent.PayloadDownload { return "Descargador de Payload" }
	return "Actividad Sospechosa"
}

func (sa *SemanticAnalyzer_Unoptimized) calculateRiskScore(intent MaliciousIntent, evasion EvasionTechniques, impact SystemImpact, tokens []Token) int {
	score := 0
	if intent.PayloadDownload { score += 25 }
	if intent.Persistence { score += 30 }
	if intent.PrivilegeEscalation { score += 35 }
	if intent.DataExfiltration { score += 40 }
	if intent.SystemModification { score += 20 }
	if intent.Reconnaissance { score += 15 }
	if intent.LateralMovement { score += 30 }
	if intent.DefenseEvasion { score += 25 }
	if evasion.AntiForensic { score += 25 }
	if evasion.LogDeletion { score += 20 }
	if evasion.ProcessHollowing { score += 30 }
	if evasion.AMSIBypass { score += 25 }
	if evasion.PowerShellLogging { score += 20 }
	if evasion.Timestomp { score += 10 }
	if impact.FileSystemChanges { score += 8 }
	if impact.RegistryChanges { score += 15 }
	if impact.NetworkActivity { score += 12 }
	if impact.ProcessCreation { score += 10 }
	if impact.ServiceModification { score += 15 }
	if impact.ScheduledTasks { score += 15 }
	for _, token := range tokens {
		if token.IsSuspicious {
			switch token.Severity {
			case "high": score += 10
			case "medium": score += 5
			case "low": score += 2
			}
		}
	}
	if score > 100 { score = 100 }
	return score
}

func (sa *SemanticAnalyzer_Unoptimized) reconstructAttackChain(script string, intent MaliciousIntent) []AttackStep {
	var chain []AttackStep
	hasRealThreats := intent.PayloadDownload || intent.PrivilegeEscalation || intent.DataExfiltration || intent.Persistence || intent.DefenseEvasion
	if !hasRealThreats { return []AttackStep{} }
	if intent.Reconnaissance { chain = append(chain, AttackStep{Phase: "Reconocimiento", Technique: "Descubrimiento del Sistema", Description: "Recopilación de información del sistema y detalles del entorno", MITREATT: "T1082"}) }
	if intent.DefenseEvasion { chain = append(chain, AttackStep{Phase: "Evasión de Defensas", Technique: "Bypass de Política de Ejecución", Description: "Eludiendo controles de seguridad y políticas de ejecución", MITREATT: "T1562"}) }
	if intent.PayloadDownload { chain = append(chain, AttackStep{Phase: "Entrega", Technique: "Descarga de Archivo Remoto", Description: "Descargando payload malicioso desde servidor remoto", MITREATT: "T1105"}) }
	if intent.PrivilegeEscalation { chain = append(chain, AttackStep{Phase: "Escalación de Privilegios", Technique: "Bypass de UAC", Description: "Intentando obtener privilegios elevados", MITREATT: "T1548"}) }
	if intent.Persistence { chain = append(chain, AttackStep{Phase: "Persistencia", Technique: "Creación de Tarea Programada", Description: "Estableciendo persistencia mediante tareas programadas", MITREATT: "T1053"}) }
	if intent.LateralMovement { chain = append(chain, AttackStep{Phase: "Movimiento Lateral", Technique: "Servicios Remotos", Description: "Moviéndose lateralmente a través de la red", MITREATT: "T1021"}) }
	if intent.DataExfiltration { chain = append(chain, AttackStep{Phase: "Exfiltración", Technique: "Transferencia de Datos", Description: "Exfiltrando datos sensibles del sistema", MITREATT: "T1041"}) }
	if chain == nil { chain = []AttackStep{} }
	return chain
}
