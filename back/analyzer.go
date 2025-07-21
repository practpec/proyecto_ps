package main

import (
	"crypto/sha256"
	"fmt"
	"time"
)

type PowerShellAnalyzer struct {
	lexer            *Lexer
	parser           *Parser
	semanticAnalyzer *SemanticAnalyzer
}

type AnalysisResult struct {
	Timestamp        time.Time        `json:"timestamp"`
	ScriptHash       string           `json:"script_hash"`
	ThreatLevel      string           `json:"threat_level"`
	OverallRisk      int              `json:"overall_risk"`
	LexicalAnalysis  LexicalResult    `json:"lexical_analysis"`
	SyntaxAnalysis   SyntaxAnalysis   `json:"syntax_analysis"`
	SemanticAnalysis SemanticAnalysis `json:"semantic_analysis"`
	Recommendations  []string         `json:"recommendations"`
	Summary          AnalysisSummary  `json:"summary"`
}

type LexicalResult struct {
	Tokens            []Token          `json:"tokens"`
	SuspiciousCount   int              `json:"suspicious_count"`
	CriticalTokens    []Token          `json:"critical_tokens"`
	ObfuscationLevel  string           `json:"obfuscation_level"`
	TokenStatistics   TokenStatistics  `json:"token_statistics"`
}

type TokenStatistics struct {
	TotalTokens       int            `json:"total_tokens"`
	SuspiciousTokens  int            `json:"suspicious_tokens"`
	HighSeverity      int            `json:"high_severity"`
	MediumSeverity    int            `json:"medium_severity"`
	LowSeverity       int            `json:"low_severity"`
	TokenDistribution map[string]int `json:"token_distribution"`
}

type AnalysisSummary struct {
	MainThreats       []string `json:"main_threats"`
	KeyFindings       []string `json:"key_findings"`
	AttackVector      string   `json:"attack_vector"`
	Confidence        string   `json:"confidence"`
	ActionRequired    string   `json:"action_required"`
}

func NewPowerShellAnalyzer() *PowerShellAnalyzer {
	return &PowerShellAnalyzer{
		lexer:            NewLexer(),
		parser:           NewParser(),
		semanticAnalyzer: NewSemanticAnalyzer(),
	}
}

func (psa *PowerShellAnalyzer) AnalyzeScript(script string) AnalysisResult {
	// Fase 1: Análisis léxico
	tokens := psa.lexer.Tokenize(script)
	lexicalResult := psa.buildLexicalResult(tokens)
	
	// Fase 2: Análisis sintáctico
	syntaxAnalysis := psa.parser.ParseSyntax(script, tokens)
	
	// Fase 3: Análisis semántico
	semanticAnalysis := psa.semanticAnalyzer.AnalyzeSemantics(script, tokens, syntaxAnalysis)
	
	// Calcular riesgo general y nivel de amenaza con lógica corregida
	overallRisk := psa.calculateOverallRisk(lexicalResult, syntaxAnalysis, semanticAnalysis)
	threatLevel := psa.determineThreatLevel(overallRisk, semanticAnalysis, lexicalResult)
	
	// Generar recomendaciones
	recommendations := psa.generateRecommendations(lexicalResult, syntaxAnalysis, semanticAnalysis, threatLevel)
	
	// Crear resumen
	summary := psa.generateSummary(lexicalResult, syntaxAnalysis, semanticAnalysis, threatLevel)
	
	return AnalysisResult{
		Timestamp:        time.Now(),
		ScriptHash:       psa.calculateScriptHash(script),
		ThreatLevel:      threatLevel,
		OverallRisk:      overallRisk,
		LexicalAnalysis:  lexicalResult,
		SyntaxAnalysis:   syntaxAnalysis,
		SemanticAnalysis: semanticAnalysis,
		Recommendations:  recommendations,
		Summary:          summary,
	}
}

func (psa *PowerShellAnalyzer) buildLexicalResult(tokens []Token) LexicalResult {
	var criticalTokens []Token
	var suspiciousCount int
	tokenDistribution := make(map[string]int)
	
	highSeverity := 0
	mediumSeverity := 0
	lowSeverity := 0
	
	// Asegurar que tokens no sea nil
	if tokens == nil {
		tokens = []Token{}
	}
	
	for _, token := range tokens {
		// Contar distribución de tokens
		tokenDistribution[string(token.Type)]++
		
		if token.IsSuspicious {
			suspiciousCount++
			
			// Contar por severidad
			switch token.Severity {
			case "high":
				highSeverity++
				criticalTokens = append(criticalTokens, token)
			case "medium":
				mediumSeverity++
			case "low":
				lowSeverity++
			}
		}
	}
	
	// Determinar nivel de ofuscación basado en tokens
	obfuscationLevel := psa.determineObfuscationLevel(tokens)
	
	// Asegurar que criticalTokens no sea nil
	if criticalTokens == nil {
		criticalTokens = []Token{}
	}
	
	return LexicalResult{
		Tokens:           tokens,
		SuspiciousCount:  suspiciousCount,
		CriticalTokens:   criticalTokens,
		ObfuscationLevel: obfuscationLevel,
		TokenStatistics: TokenStatistics{
			TotalTokens:       len(tokens),
			SuspiciousTokens:  suspiciousCount,
			HighSeverity:      highSeverity,
			MediumSeverity:    mediumSeverity,
			LowSeverity:       lowSeverity,
			TokenDistribution: tokenDistribution,
		},
	}
}

func (psa *PowerShellAnalyzer) determineObfuscationLevel(tokens []Token) string {
	obfuscationScore := 0
	
	for _, token := range tokens {
		switch token.Type {
		case BASE64_ENCODED:
			obfuscationScore += 3
		case OBFUSCATED_VAR:
			obfuscationScore += 2
		case SPECIAL_CHAR:
			obfuscationScore += 1
		}
	}
	
	if obfuscationScore == 0 {
		return "none"
	} else if obfuscationScore < 3 {
		return "low"
	} else if obfuscationScore < 8 {
		return "medium"
	} else {
		return "high"
	}
}

func (psa *PowerShellAnalyzer) calculateOverallRisk(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis) int {
	// NO usar la lógica de scripts legítimos aquí - eso se maneja en semántico
	risk := 0
	
	// Riesgo del análisis léxico (30%)
	lexicalRisk := (lexical.TokenStatistics.HighSeverity * 15) + 
	              (lexical.TokenStatistics.MediumSeverity * 8) + 
	              (lexical.TokenStatistics.LowSeverity * 3)
	risk += int(float64(lexicalRisk) * 0.3)
	
	// Riesgo del análisis sintáctico (20%)
	syntaxRisk := syntax.ComplexityScore/10 + (len(syntax.Anomalies) * 8)
	if !syntax.IsValid {
		syntaxRisk += 15
	}
	risk += int(float64(syntaxRisk) * 0.2)
	
	// Riesgo del análisis semántico (50%) - peso mayor
	risk += int(float64(semantic.RiskScore) * 0.5)
	
	// Normalizar a escala 0-100
	if risk > 100 {
		risk = 100
	}
	
	return risk
}

func (psa *PowerShellAnalyzer) determineThreatLevel(riskScore int, semantic SemanticAnalysis, lexical LexicalResult) string {
	// Primero verificar si es realmente un script legítimo
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		// Para scripts legítimos, ser más conservador pero no demasiado
		if lexical.TokenStatistics.HighSeverity > 0 {
			return "MEDIUM" // Si hay tokens críticos, mínimo MEDIUM
		}
		if lexical.TokenStatistics.MediumSeverity > 10 || semantic.RiskScore > 30 {
			return "LOW"
		}
		return "MINIMAL"
	}
	
	// Para scripts NO legítimos, usar lógica escalonada basada en ejemplos
	
	// CRÍTICO: APT, múltiples técnicas avanzadas, exfiltración activa
	hasCriticalIndicators := semantic.MaliciousIntent.DataExfiltration ||
	                       (semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence && semantic.EvasionTechniques.AntiForensic) ||
	                       (semantic.EvasionTechniques.AMSIBypass && semantic.EvasionTechniques.LogDeletion) ||
	                       lexical.TokenStatistics.HighSeverity > 5
	
	// ALTO: Dropper con persistencia, múltiples técnicas de evasión
	hasHighIndicators := (semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence) ||
	                    (semantic.MaliciousIntent.DefenseEvasion && semantic.MaliciousIntent.SystemModification) ||
	                    semantic.EvasionTechniques.AntiForensic ||
	                    lexical.TokenStatistics.HighSeverity > 2 ||
	                    (semantic.RiskScore > 70)
	
	// MEDIO: Reconnaissance + exfiltración, técnicas sospechosas múltiples
	hasMediumIndicators := (semantic.MaliciousIntent.Reconnaissance && semantic.MaliciousIntent.DataExfiltration) ||
	                      semantic.MaliciousIntent.PayloadDownload ||
	                      semantic.MaliciousIntent.Persistence ||
	                      lexical.TokenStatistics.HighSeverity > 0 ||
	                      (semantic.RiskScore > 40)
	
	// BAJO: Técnicas individuales sospechosas, scripts con elementos cuestionables
	hasLowIndicators := semantic.MaliciousIntent.DefenseEvasion ||
	                   semantic.MaliciousIntent.SystemModification ||
	                   semantic.MaliciousIntent.Reconnaissance ||
	                   lexical.TokenStatistics.MediumSeverity > 8 ||
	                   (semantic.RiskScore > 20)
	
	// Determinar nivel basado en indicadores y puntaje con umbrales ajustados
	if hasCriticalIndicators && riskScore >= 70 {
		return "CRITICAL"
	} else if hasHighIndicators && riskScore >= 50 {
		return "HIGH"
	} else if hasMediumIndicators && riskScore >= 30 {
		return "MEDIUM"
	} else if hasLowIndicators && riskScore >= 15 {
		return "LOW"
	} else {
		return "MINIMAL"
	}
}

func (psa *PowerShellAnalyzer) generateRecommendations(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis, threatLevel string) []string {
	var recommendations []string
	
	// Para scripts legítimos, recomendaciones menos alarmantes
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		if lexical.TokenStatistics.HighSeverity > 0 {
			recommendations = append(recommendations, "ALERTA: Tokens críticos detectados en script aparentemente legítimo - revisar cuidadosamente")
		}
		if lexical.TokenStatistics.MediumSeverity > 10 {
			recommendations = append(recommendations, "Considerar simplificar el script para reducir complejidad")
		}
		if syntax.ComplexityScore > 100 {
			recommendations = append(recommendations, "Script complejo detectado - documentar funcionalidad para futura referencia")
		}
		
		// Si no hay recomendaciones específicas, dar una general
		if len(recommendations) == 0 {
			recommendations = append(recommendations, "Script parece legítimo - mantener monitoreo rutinario")
		}
		
		return recommendations
	}
	
	// Recomendaciones para scripts sospechosos/maliciosos - más agresivas
	if lexical.TokenStatistics.HighSeverity > 0 {
		recommendations = append(recommendations, "ACCIÓN INMEDIATA: Bloquear ejecución del script - tokens maliciosos críticos detectados")
	}
	
	if semantic.MaliciousIntent.PayloadDownload {
		recommendations = append(recommendations, "CRÍTICO: Descarga de payload detectada - aislar sistema y verificar comunicaciones de red")
	}
	
	if semantic.MaliciousIntent.Persistence {
		recommendations = append(recommendations, "ALTO RIESGO: Mecanismo de persistencia detectado - escanear tareas programadas y modificaciones del registro")
	}
	
	if semantic.MaliciousIntent.DefenseEvasion {
		recommendations = append(recommendations, "Técnicas de evasión detectadas - verificar políticas de ejecución y configuraciones de seguridad")
	}
	
	if lexical.ObfuscationLevel == "high" {
		recommendations = append(recommendations, "Alta ofuscación detectada - implementar técnicas avanzadas de deofuscación")
	}
	
	if syntax.ComplexityScore > 50 {
		recommendations = append(recommendations, "Estructura de script compleja detectada - aumentar monitoreo y registro")
	}
	
	if len(syntax.Anomalies) > 3 {
		recommendations = append(recommendations, "Múltiples anomalías sintácticas detectadas - posible intento de evasión")
	}
	
	// Recomendaciones basadas en análisis semántico
	if semantic.MaliciousIntent.DataExfiltration {
		recommendations = append(recommendations, "CRÍTICO: Exfiltración de datos detectada - aislar sistema y verificar violaciones de datos")
	}
	
	if semantic.EvasionTechniques.LogDeletion {
		recommendations = append(recommendations, "Eliminación de logs detectada - verificar logs de respaldo e implementar reenvío de logs")
	}
	
	if semantic.SystemImpact.RegistryChanges {
		recommendations = append(recommendations, "Modificaciones del registro detectadas - crear respaldo del registro y monitorear cambios")
	}
	
	// Recomendaciones generales basadas en nivel de amenaza
	if threatLevel == "CRITICAL" || threatLevel == "HIGH" {
		recommendations = append(recommendations, "Implementar segmentación de red y monitoreo mejorado")
		recommendations = append(recommendations, "Considerar activación del procedimiento de respuesta a incidentes")
	}
	
	if semantic.RiskScore > 70 {
		recommendations = append(recommendations, "Puntaje de riesgo alto - considerar análisis forense completo")
	}
	
	// Asegurar que recommendations no sea nil
	if recommendations == nil {
		recommendations = []string{}
	}
	
	return recommendations
}

func (psa *PowerShellAnalyzer) generateSummary(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis, threatLevel string) AnalysisSummary {
	var mainThreats []string
	var keyFindings []string
	
	// Para scripts legítimos, generar resumen apropiado
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		if lexical.TokenStatistics.HighSeverity > 0 {
			keyFindings = append(keyFindings, "Tokens críticos detectados requieren investigación")
			mainThreats = append(mainThreats, "Posible falso positivo en detección")
		}
		if syntax.ComplexityScore > 50 {
			keyFindings = append(keyFindings, "Script con complejidad moderada")
		}
		
		if len(keyFindings) == 0 {
			keyFindings = append(keyFindings, "Script administrativo estándar")
		}
		
		confidence := "Alta"
		if lexical.TokenStatistics.HighSeverity > 0 {
			confidence = "Media" // Reducir confianza si hay tokens críticos
		}
		
		return AnalysisSummary{
			MainThreats:    mainThreats,
			KeyFindings:    keyFindings,
			AttackVector:   "N/A - Script Legítimo",
			Confidence:     confidence,
			ActionRequired: "Monitoreo Rutinario",
		}
	}
	
	// Para scripts maliciosos, identificar amenazas principales
	if semantic.MaliciousIntent.DataExfiltration {
		mainThreats = append(mainThreats, "Exfiltración de Datos")
	}
	if semantic.MaliciousIntent.PrivilegeEscalation {
		mainThreats = append(mainThreats, "Escalación de Privilegios")
	}
	if semantic.MaliciousIntent.Persistence {
		mainThreats = append(mainThreats, "Mecanismo de Persistencia")
	}
	if semantic.MaliciousIntent.PayloadDownload {
		mainThreats = append(mainThreats, "Descarga de Malware")
	}
	if semantic.MaliciousIntent.DefenseEvasion {
		mainThreats = append(mainThreats, "Evasión de Defensas")
	}
	
	// Asegurar que mainThreats no sea nil
	if mainThreats == nil {
		mainThreats = []string{}
	}
	
	// Hallazgos clave
	if lexical.TokenStatistics.HighSeverity > 0 {
		keyFindings = append(keyFindings, "Tokens maliciosos críticos detectados")
	}
	if lexical.ObfuscationLevel == "high" {
		keyFindings = append(keyFindings, "Ofuscación de alto nivel empleada")
	}
	if len(semantic.EvasionTechniques.Techniques) > 2 {
		keyFindings = append(keyFindings, "Múltiples técnicas de evasión detectadas")
	}
	if semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence {
		keyFindings = append(keyFindings, "Dropper con persistencia detectado")
	}
	
	// Asegurar que keyFindings no sea nil
	if keyFindings == nil {
		keyFindings = []string{}
	}
	
	// Determinar vector de ataque
	attackVector := "Desconocido"
	if semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence {
		attackVector = "Dropper con Persistencia"
	} else if semantic.MaliciousIntent.PayloadDownload {
		attackVector = "Entrega de Payload Remoto"
	} else if semantic.MaliciousIntent.LateralMovement {
		attackVector = "Movimiento Lateral"
	} else if semantic.MaliciousIntent.PrivilegeEscalation {
		attackVector = "Escalación Local de Privilegios"
	} else if semantic.MaliciousIntent.DefenseEvasion {
		attackVector = "Evasión de Defensas"
	}
	
	// Determinar confianza basada en la evidencia
	confidence := "Baja"
	if lexical.TokenStatistics.HighSeverity > 2 && semantic.RiskScore > 70 {
		confidence = "Alta"
	} else if lexical.TokenStatistics.HighSeverity > 0 && semantic.RiskScore > 50 {
		confidence = "Media"
	} else if semantic.RiskScore > 40 {
		confidence = "Media"
	}
	
	// Acción requerida
	actionRequired := "Monitorear"
	switch threatLevel {
	case "CRITICAL":
		actionRequired = "Aislamiento e Investigación Inmediata"
	case "HIGH":
		actionRequired = "Bloquear e Investigar"
	case "MEDIUM":
		actionRequired = "Monitoreo Mejorado y Restricción"
	case "LOW":
		actionRequired = "Registrar y Monitorear"
	case "MINIMAL":
		actionRequired = "Monitoreo Rutinario"
	}
	
	return AnalysisSummary{
		MainThreats:    mainThreats,
		KeyFindings:    keyFindings,
		AttackVector:   attackVector,
		Confidence:     confidence,
		ActionRequired: actionRequired,
	}
}

func (psa *PowerShellAnalyzer) calculateScriptHash(script string) string {
	// Usar SHA-256 para un hash más robusto
	hash := sha256.Sum256([]byte(script))
	return fmt.Sprintf("%x", hash)[:16] // Primeros 16 caracteres del hash
}