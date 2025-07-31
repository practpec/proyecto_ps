package main

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// NOTA: Este archivo es la versión NO OPTIMIZADA del orquestador del análisis.
// Llama a los componentes _unoptimized.

type PowerShellAnalyzer_Unoptimized struct {
	lexer            *Lexer_Unoptimized
	parser           *Parser_Unoptimized
	semanticAnalyzer *SemanticAnalyzer_Unoptimized
}

func NewPowerShellAnalyzer_Unoptimized() *PowerShellAnalyzer_Unoptimized {
	return &PowerShellAnalyzer_Unoptimized{
		lexer:            NewLexer_Unoptimized(),
		parser:           NewParser_Unoptimized(),
		semanticAnalyzer: NewSemanticAnalyzer_Unoptimized(),
	}
}

func (psa *PowerShellAnalyzer_Unoptimized) AnalyzeScript(script string) AnalysisResult {
	tokens := psa.lexer.Tokenize(script)
	lexicalResult := psa.buildLexicalResult(tokens)
	syntaxAnalysis := psa.parser.ParseSyntax(script, tokens)
	semanticAnalysis := psa.semanticAnalyzer.AnalyzeSemantics(script, tokens, syntaxAnalysis)
	overallRisk := psa.calculateOverallRisk(lexicalResult, syntaxAnalysis, semanticAnalysis)
	threatLevel := psa.determineThreatLevel(overallRisk, semanticAnalysis, lexicalResult)
	recommendations := psa.generateRecommendations(lexicalResult, syntaxAnalysis, semanticAnalysis, threatLevel)
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

func (psa *PowerShellAnalyzer_Unoptimized) buildLexicalResult(tokens []Token) LexicalResult {
	var criticalTokens []Token
	var suspiciousCount int
	tokenDistribution := make(map[string]int)
	highSeverity, mediumSeverity, lowSeverity := 0, 0, 0
	if tokens == nil { tokens = []Token{} }
	for _, token := range tokens {
		tokenDistribution[string(token.Type)]++
		if token.IsSuspicious {
			suspiciousCount++
			switch token.Severity {
			case "high":
				highSeverity++
				criticalTokens = append(criticalTokens, token)
			case "medium": mediumSeverity++
			case "low": lowSeverity++
			}
		}
	}
	obfuscationLevel := psa.determineObfuscationLevel(tokens)
	if criticalTokens == nil { criticalTokens = []Token{} }
	return LexicalResult{
		Tokens: tokens, SuspiciousCount: suspiciousCount, CriticalTokens: criticalTokens, ObfuscationLevel: obfuscationLevel,
		TokenStatistics: TokenStatistics{
			TotalTokens: len(tokens), SuspiciousTokens: suspiciousCount, HighSeverity: highSeverity,
			MediumSeverity: mediumSeverity, LowSeverity: lowSeverity, TokenDistribution: tokenDistribution,
		},
	}
}

func (psa *PowerShellAnalyzer_Unoptimized) determineObfuscationLevel(tokens []Token) string {
	obfuscationScore := 0
	for _, token := range tokens {
		switch token.Type {
		case BASE64_ENCODED: obfuscationScore += 3
		case OBFUSCATED_VAR: obfuscationScore += 2
		case SPECIAL_CHAR: obfuscationScore += 1
		}
	}
	if obfuscationScore == 0 { return "none" }
	if obfuscationScore < 3 { return "low" }
	if obfuscationScore < 8 { return "medium" }
	return "high"
}

func (psa *PowerShellAnalyzer_Unoptimized) calculateOverallRisk(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis) int {
	risk := 0
	lexicalRisk := (lexical.TokenStatistics.HighSeverity * 15) + (lexical.TokenStatistics.MediumSeverity * 8) + (lexical.TokenStatistics.LowSeverity * 3)
	risk += int(float64(lexicalRisk) * 0.3)
	syntaxRisk := syntax.ComplexityScore/10 + (len(syntax.Anomalies) * 8)
	if !syntax.IsValid { syntaxRisk += 15 }
	risk += int(float64(syntaxRisk) * 0.2)
	risk += int(float64(semantic.RiskScore) * 0.5)
	if risk > 100 { risk = 100 }
	return risk
}

func (psa *PowerShellAnalyzer_Unoptimized) determineThreatLevel(riskScore int, semantic SemanticAnalysis, lexical LexicalResult) string {
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		if lexical.TokenStatistics.HighSeverity > 0 { return "MEDIUM" }
		if lexical.TokenStatistics.MediumSeverity > 10 || semantic.RiskScore > 30 { return "LOW" }
		return "MINIMAL"
	}
	hasCriticalIndicators := semantic.MaliciousIntent.DataExfiltration || (semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence && semantic.EvasionTechniques.AntiForensic) || (semantic.EvasionTechniques.AMSIBypass && semantic.EvasionTechniques.LogDeletion) || lexical.TokenStatistics.HighSeverity > 5
	hasHighIndicators := (semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence) || (semantic.MaliciousIntent.DefenseEvasion && semantic.MaliciousIntent.SystemModification) || semantic.EvasionTechniques.AntiForensic || lexical.TokenStatistics.HighSeverity > 2 || (semantic.RiskScore > 70)
	hasMediumIndicators := (semantic.MaliciousIntent.Reconnaissance && semantic.MaliciousIntent.DataExfiltration) || semantic.MaliciousIntent.PayloadDownload || semantic.MaliciousIntent.Persistence || lexical.TokenStatistics.HighSeverity > 0 || (semantic.RiskScore > 40)
	hasLowIndicators := semantic.MaliciousIntent.DefenseEvasion || semantic.MaliciousIntent.SystemModification || semantic.MaliciousIntent.Reconnaissance || lexical.TokenStatistics.MediumSeverity > 8 || (semantic.RiskScore > 20)
	if hasCriticalIndicators && riskScore >= 70 { return "CRITICAL" }
	if hasHighIndicators && riskScore >= 50 { return "HIGH" }
	if hasMediumIndicators && riskScore >= 30 { return "MEDIUM" }
	if hasLowIndicators && riskScore >= 15 { return "LOW" }
	return "MINIMAL"
}

func (psa *PowerShellAnalyzer_Unoptimized) generateRecommendations(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis, threatLevel string) []string {
	var recommendations []string
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		if lexical.TokenStatistics.HighSeverity > 0 { recommendations = append(recommendations, "ALERTA: Tokens críticos detectados en script aparentemente legítimo - revisar cuidadosamente") }
		if lexical.TokenStatistics.MediumSeverity > 10 { recommendations = append(recommendations, "Considerar simplificar el script para reducir complejidad") }
		if syntax.ComplexityScore > 100 { recommendations = append(recommendations, "Script complejo detectado - documentar funcionalidad para futura referencia") }
		if len(recommendations) == 0 { recommendations = append(recommendations, "Script parece legítimo - mantener monitoreo rutinario") }
		return recommendations
	}
	if lexical.TokenStatistics.HighSeverity > 0 { recommendations = append(recommendations, "ACCIÓN INMEDIATA: Bloquear ejecución del script - tokens maliciosos críticos detectados") }
	if semantic.MaliciousIntent.PayloadDownload { recommendations = append(recommendations, "CRÍTICO: Descarga de payload detectada - aislar sistema y verificar comunicaciones de red") }
	if semantic.MaliciousIntent.Persistence { recommendations = append(recommendations, "ALTO RIESGO: Mecanismo de persistencia detectado - escanear tareas programadas y modificaciones del registro") }
	if semantic.MaliciousIntent.DefenseEvasion { recommendations = append(recommendations, "Técnicas de evasión detectadas - verificar políticas de ejecución y configuraciones de seguridad") }
	if lexical.ObfuscationLevel == "high" { recommendations = append(recommendations, "Alta ofuscación detectada - implementar técnicas avanzadas de deofuscación") }
	if syntax.ComplexityScore > 50 { recommendations = append(recommendations, "Estructura de script compleja detectada - aumentar monitoreo y registro") }
	if len(syntax.Anomalies) > 3 { recommendations = append(recommendations, "Múltiples anomalías sintácticas detectadas - posible intento de evasión") }
	if semantic.MaliciousIntent.DataExfiltration { recommendations = append(recommendations, "CRÍTICO: Exfiltración de datos detectada - aislar sistema y verificar violaciones de datos") }
	if semantic.EvasionTechniques.LogDeletion { recommendations = append(recommendations, "Eliminación de logs detectada - verificar logs de respaldo e implementar reenvío de logs") }
	if semantic.SystemImpact.RegistryChanges { recommendations = append(recommendations, "Modificaciones del registro detectadas - crear respaldo del registro y monitorear cambios") }
	if threatLevel == "CRITICAL" || threatLevel == "HIGH" {
		recommendations = append(recommendations, "Implementar segmentación de red y monitoreo mejorado")
		recommendations = append(recommendations, "Considerar activación del procedimiento de respuesta a incidentes")
	}
	if semantic.RiskScore > 70 { recommendations = append(recommendations, "Puntaje de riesgo alto - considerar análisis forense completo") }
	if recommendations == nil { recommendations = []string{} }
	return recommendations
}

func (psa *PowerShellAnalyzer_Unoptimized) generateSummary(lexical LexicalResult, syntax SyntaxAnalysis, semantic SemanticAnalysis, threatLevel string) AnalysisSummary {
	var mainThreats, keyFindings []string
	if semantic.ThreatCategory == "Script Administrativo Legítimo" {
		if lexical.TokenStatistics.HighSeverity > 0 {
			keyFindings = append(keyFindings, "Tokens críticos detectados requieren investigación")
			mainThreats = append(mainThreats, "Posible falso positivo en detección")
		}
		if syntax.ComplexityScore > 50 { keyFindings = append(keyFindings, "Script con complejidad moderada") }
		if len(keyFindings) == 0 { keyFindings = append(keyFindings, "Script administrativo estándar") }
		confidence := "Alta"
		if lexical.TokenStatistics.HighSeverity > 0 { confidence = "Media" }
		return AnalysisSummary{MainThreats: mainThreats, KeyFindings: keyFindings, AttackVector: "N/A - Script Legítimo", Confidence: confidence, ActionRequired: "Monitoreo Rutinario"}
	}
	if semantic.MaliciousIntent.DataExfiltration { mainThreats = append(mainThreats, "Exfiltración de Datos") }
	if semantic.MaliciousIntent.PrivilegeEscalation { mainThreats = append(mainThreats, "Escalación de Privilegios") }
	if semantic.MaliciousIntent.Persistence { mainThreats = append(mainThreats, "Mecanismo de Persistencia") }
	if semantic.MaliciousIntent.PayloadDownload { mainThreats = append(mainThreats, "Descarga de Malware") }
	if semantic.MaliciousIntent.DefenseEvasion { mainThreats = append(mainThreats, "Evasión de Defensas") }
	if mainThreats == nil { mainThreats = []string{} }
	if lexical.TokenStatistics.HighSeverity > 0 { keyFindings = append(keyFindings, "Tokens maliciosos críticos detectados") }
	if lexical.ObfuscationLevel == "high" { keyFindings = append(keyFindings, "Ofuscación de alto nivel empleada") }
	if len(semantic.EvasionTechniques.Techniques) > 2 { keyFindings = append(keyFindings, "Múltiples técnicas de evasión detectadas") }
	if semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence { keyFindings = append(keyFindings, "Dropper con persistencia detectado") }
	if keyFindings == nil { keyFindings = []string{} }
	attackVector := "Desconocido"
	if semantic.MaliciousIntent.PayloadDownload && semantic.MaliciousIntent.Persistence { attackVector = "Dropper con Persistencia" } else if semantic.MaliciousIntent.PayloadDownload { attackVector = "Entrega de Payload Remoto" } else if semantic.MaliciousIntent.LateralMovement { attackVector = "Movimiento Lateral" } else if semantic.MaliciousIntent.PrivilegeEscalation { attackVector = "Escalación Local de Privilegios" } else if semantic.MaliciousIntent.DefenseEvasion { attackVector = "Evasión de Defensas" }
	confidence := "Baja"
	if lexical.TokenStatistics.HighSeverity > 2 && semantic.RiskScore > 70 { confidence = "Alta" } else if (lexical.TokenStatistics.HighSeverity > 0 || semantic.RiskScore > 50) { confidence = "Media" }
	actionRequired := "Monitorear"
	switch threatLevel {
	case "CRITICAL": actionRequired = "Aislamiento e Investigación Inmediata"
	case "HIGH": actionRequired = "Bloquear e Investigar"
	case "MEDIUM": actionRequired = "Monitoreo Mejorado y Restricción"
	case "LOW": actionRequired = "Registrar y Monitorear"
	case "MINIMAL": actionRequired = "Monitoreo Rutinario"
	}
	return AnalysisSummary{MainThreats: mainThreats, KeyFindings: keyFindings, AttackVector: attackVector, Confidence: confidence, ActionRequired: actionRequired}
}

func (psa *PowerShellAnalyzer_Unoptimized) calculateScriptHash(script string) string {
	hash := sha256.Sum256([]byte(script))
	return fmt.Sprintf("%x", hash)[:16]
}
