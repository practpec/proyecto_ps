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
	
	// Calcular riesgo general y nivel de amenaza con mejor lógica
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
	// Para scripts legítimos, usar cálculo conservador
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		return psa.calculateLegitimateRisk(lexical, syntax, semantic)
	}
	
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
	
	// Riesgo del análisis semántico (50%)
	risk += int(float64(semantic.RiskScore) * 0.5)
	
	// Normalizar a escala 0-100
	if risk > 100 {
		risk = 100
	}
	
	return risk
}

func (psa *PowerShellAnalyzer) calculateLegitimateRisk(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis) int {
	risk := 0
	
	// Para scripts legítimos, solo contar tokens realmente críticos
	risk += lexical.TokenStatistics.HighSeverity * 5
	risk += lexical.TokenStatistics.MediumSeverity * 2
	
	// Agregar complejidad solo si es excesiva
	if syntax.ComplexityScore > 50 {
		risk += (syntax.ComplexityScore - 50) / 10
	}
	
	// Usar el riesgo semántico calculado (ya ajustado para scripts legítimos)
	risk += semantic.RiskScore / 2
	
	// Limitar el riesgo máximo para scripts legítimos
	if risk > 35 {
		risk = 35
	}
	
	return risk
}

func (psa *PowerShellAnalyzer) determineThreatLevel(riskScore int, semantic SemanticAnalysis, lexical LexicalResult) string {
	// Para scripts administrativos legítimos, usar lógica especial
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		if lexical.TokenStatistics.HighSeverity > 0 {
			return "LOW"
		}
		if lexical.TokenStatistics.MediumSeverity > 10 {
			return "LOW"
		}
		return "MINIMAL"
	}
	
	// Verificar indicadores críticos primero
	hasCriticalIndicators := semantic.MaliciousIntent.DataExfiltration || 
	                       semantic.MaliciousIntent.PrivilegeEscalation ||
	                       lexical.TokenStatistics.HighSeverity > 3
	
	hasHighIndicators := semantic.MaliciousIntent.Persistence || 
	                    semantic.EvasionTechniques.AntiForensic ||
	                    lexical.TokenStatistics.HighSeverity > 1
	
	hasMediumIndicators := semantic.MaliciousIntent.PayloadDownload || 
	                      semantic.MaliciousIntent.DefenseEvasion ||
	                      lexical.TokenStatistics.MediumSeverity > 5
	
	// Determinar nivel basado en indicadores y puntaje
	if hasCriticalIndicators && riskScore >= 70 {
		return "CRITICAL"
	} else if hasHighIndicators && riskScore >= 50 {
		return "HIGH"
	} else if hasMediumIndicators && riskScore >= 30 {
		return "MEDIUM"
	} else if riskScore >= 15 {
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
			recommendations = append(recommendations, "Revisar tokens marcados como críticos para verificar legitimidad")
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
	
	// Recomendaciones para scripts sospechosos/maliciosos
	if lexical.TokenStatistics.HighSeverity > 0 {
		recommendations = append(recommendations, "ACCIÓN INMEDIATA: Bloquear ejecución del script - tokens maliciosos críticos detectados")
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
	
	if semantic.MaliciousIntent.Persistence {
		recommendations = append(recommendations, "Mecanismo de persistencia detectado - escanear tareas programadas y modificaciones del registro")
	}
	
	if semantic.EvasionTechniques.LogDeletion {
		recommendations = append(recommendations, "Eliminación de logs detectada - verificar logs de respaldo e implementar reenvío de logs")
	}
	
	if semantic.SystemImpact.RegistryChanges {
		recommendations = append(recommendations, "Modificaciones del registro detectadas - crear respaldo del registro y monitorear cambios")
	}
	
	// Recomendaciones generales
	if semantic.RiskScore > 70 {
		recommendations = append(recommendations, "Implementar segmentación de red y monitoreo mejorado")
		recommendations = append(recommendations, "Considerar activación del procedimiento de respuesta a incidentes")
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
			keyFindings = append(keyFindings, "Algunos tokens marcados requieren revisión")
		}
		if syntax.ComplexityScore > 50 {
			keyFindings = append(keyFindings, "Script con complejidad moderada")
		}
		
		if len(keyFindings) == 0 {
			keyFindings = append(keyFindings, "Script administrativo estándar")
		}
		
		return AnalysisSummary{
			MainThreats:    []string{},
			KeyFindings:    keyFindings,
			AttackVector:   "N/A - Script Legítimo",
			Confidence:     "Alta",
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
	
	// Asegurar que mainThreats no sea nil
	if mainThreats == nil {
		mainThreats = []string{}
	}
	
	// Hallazgos clave
	if lexical.TokenStatistics.HighSeverity > 0 {
		keyFindings = append(keyFindings, "Tokens maliciosos críticos detectados")
	}
	if syntax.ObfuscationLevel == "high" {
		keyFindings = append(keyFindings, "Ofuscación de alto nivel empleada")
	}
	if len(semantic.EvasionTechniques.Techniques) > 2 {
		keyFindings = append(keyFindings, "Múltiples técnicas de evasión detectadas")
	}
	
	// Asegurar que keyFindings no sea nil
	if keyFindings == nil {
		keyFindings = []string{}
	}
	
	// Determinar vector de ataque
	attackVector := "Desconocido"
	if semantic.MaliciousIntent.PayloadDownload {
		attackVector = "Entrega de Payload Remoto"
	} else if semantic.MaliciousIntent.LateralMovement {
		attackVector = "Movimiento Lateral"
	} else if semantic.MaliciousIntent.PrivilegeEscalation {
		attackVector = "Escalación Local de Privilegios"
	}
	
	// Determinar confianza basada en la evidencia
	confidence := "Baja"
	if lexical.TokenStatistics.HighSeverity > 2 && semantic.RiskScore > 60 {
		confidence = "Alta"
	} else if lexical.TokenStatistics.HighSeverity > 0 || semantic.RiskScore > 40 {
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
		actionRequired = "Monitoreo Mejorado"
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