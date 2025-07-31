package main

import (
	"regexp"
)

// NOTA: Este archivo es la versión NO OPTIMIZADA del parser.
// Se han reemplazado las funciones de la librería "strings" por implementaciones manuales
// para demostrar un menor rendimiento.

type Parser_Unoptimized struct {
	anomalyPatterns      map[string]string
	suspiciousPatterns   map[string]string
	obfuscationIndicators []string
}

func NewParser_Unoptimized() *Parser_Unoptimized {
	return &Parser_Unoptimized{
		anomalyPatterns: map[string]string{
			`(?i)invoke-expression\s*\(\s*\$null\s*\+\s*`: "Evasión por concatenación nula",
			`(?i)\$\w+\s*=\s*\$\w+\s*\+\s*\$\w+\s*\+\s*\$\w+`: "Concatenación excesiva de cadenas",
			`(?i)['"]\s*\+\s*['"]\s*\+\s*['"]`: "Fragmentación de cadenas",
			`(?i)\[\s*char\s*\]\s*\d+\s*\+`: "Ofuscación por código de caracteres",
			`(?i)\$\w+\[\s*\d+\.\.\d+\s*\]`: "Ofuscación por segmentación de arrays",
			`(?i)invoke\s*-\s*expression`: "Nombre de cmdlet fragmentado",
			`(?i)new\s*-\s*object`: "Creación de objeto fragmentada",
			`(?i)start\s*-\s*process`: "Inicio de proceso fragmentado",
			`(?i)-\w+\s+\$\w+\[\d+\]`: "Parámetro con indexación de array",
			`(?i)-\w+\s+\(\s*\$\w+\s*\)`: "Parámetro con paréntesis",
		},
		suspiciousPatterns: map[string]string{
			`\(\s*\(\s*\(\s*`: "Anidamiento excesivo de paréntesis",
			`\{\s*\{\s*\{\s*`: "Anidamiento excesivo de bloques",
			`foreach\s*\(\s*\$\w+\s*in\s*.*foreach`: "Bucles foreach anidados",
			`\$\w+\s*\+\s*\$\w+\s*\+\s*\$\w+\s*\+`: "Múltiple concatenación de cadenas",
			`\[\s*string\s*\]\s*\$\w+\s*\+`: "Concatenación con conversión de tipo",
			`\|\s*\%\s*\{\s*.*\|\s*\%`: "Pipeline complejo con ForEach anidado",
			`\|\s*where\s*\{\s*.*\|\s*select`: "Pipeline de filtrado complejo",
			`\&\s*\{\s*.*iex`: "Bloque de script con Invoke-Expression",
			`\&\s*\(\s*.*\)`: "Operador de ejecución ampersand",
		},
		obfuscationIndicators: []string{
			`\[\s*char\s*\]`, `\[\s*convert\s*\]`, `\[\s*system\.text\.encoding\s*\]`,
			`\[\s*system\.convert\s*\]`, `\$\w{1,3}\d*`, `['"]\s*\+\s*['"]`,
		},
	}
}

func (p *Parser_Unoptimized) ParseSyntax(script string, tokens []Token) SyntaxAnalysis {
	analysis := SyntaxAnalysis{
		IsValid:            p.isValidSyntax(script),
		Anomalies:          p.detectAnomalies(script),
		SuspiciousPatterns: p.detectSuspiciousPatterns(script),
		ObfuscationLevel:   p.calculateObfuscationLevel(script),
		ComplexityScore:    p.calculateComplexityScore(script, tokens),
	}
	return analysis
}

func (p *Parser_Unoptimized) isValidSyntax(script string) bool {
	if !p.isBalanced(script, '(', ')') { return false }
	if !p.isBalanced(script, '{', '}') { return false }
	if !p.isBalanced(script, '[', ']') { return false }
	if !p.areQuotesBalanced(script) { return false }
	return true
}

func (p *Parser_Unoptimized) isBalanced(script string, open, close rune) bool {
	count := 0
	for _, char := range script {
		if char == open {
			count++
		} else if char == close {
			count--
			if count < 0 { return false }
		}
	}
	return count == 0
}

func (p *Parser_Unoptimized) areQuotesBalanced(script string) bool {
	singleQuotes := 0
	doubleQuotes := 0
	for i, char := range script {
		if char == '\'' && (i == 0 || script[i-1] != '\\') {
			singleQuotes++
		} else if char == '"' && (i == 0 || script[i-1] != '\\') {
			doubleQuotes++
		}
	}
	return singleQuotes%2 == 0 && doubleQuotes%2 == 0
}

func (p *Parser_Unoptimized) detectAnomalies(script string) []SyntaxAnomaly {
	var anomalies []SyntaxAnomaly
	for pattern, description := range p.anomalyPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		for _, match := range matches {
			anomaly := SyntaxAnomaly{
				Type: "syntax_anomaly", Description: description, Position: match[0], Severity: p.getAnomalySeverity(description),
			}
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}

func (p *Parser_Unoptimized) detectSuspiciousPatterns(script string) []SuspiciousPattern {
	var patterns []SuspiciousPattern
	for pattern, description := range p.suspiciousPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(script, -1)
		if len(matches) > 0 {
			suspiciousPattern := SuspiciousPattern{
				Pattern: pattern, Description: description, Count: len(matches), RiskLevel: p.getPatternRiskLevel(description, len(matches)),
			}
			patterns = append(patterns, suspiciousPattern)
		}
	}
	if patterns == nil {
		patterns = []SuspiciousPattern{}
	}
	return patterns
}

func (p *Parser_Unoptimized) calculateObfuscationLevel(script string) string {
	obfuscationScore := 0
	for _, indicator := range p.obfuscationIndicators {
		re := regexp.MustCompile(indicator)
		matches := re.FindAllString(script, -1)
		obfuscationScore += len(matches)
	}
	if manualContains(script, "[char]") { obfuscationScore += 5 }
	if manualContains(script, "System.Convert") { obfuscationScore += 3 }
	varPattern := regexp.MustCompile(`\$[a-z]\b`)
	shortVars := varPattern.FindAllString(script, -1)
	obfuscationScore += len(shortVars)
	if obfuscationScore == 0 { return "none" }
	if obfuscationScore < 5 { return "low" }
	if obfuscationScore < 15 { return "medium" }
	return "high"
}

func (p *Parser_Unoptimized) calculateComplexityScore(script string, tokens []Token) int {
	score := len(script) / 100
	for _, token := range tokens {
		if token.IsSuspicious {
			switch token.Severity {
			case "high": score += 10
			case "medium": score += 5
			case "low": score += 2
			}
		}
	}
	score += p.calculateNestingLevel(script) * 2
	// Manual Count
	pipeCount := 0
	for _, r := range script {
		if r == '|' {
			pipeCount++
		}
	}
	score += pipeCount
	functionPattern := regexp.MustCompile(`(?i)function\s+\w+`)
	functions := functionPattern.FindAllString(script, -1)
	score += len(functions) * 3
	return score
}

func (p *Parser_Unoptimized) calculateNestingLevel(script string) int {
	maxLevel, currentLevel := 0, 0
	for _, char := range script {
		if char == '{' || char == '(' {
			currentLevel++
			if currentLevel > maxLevel { maxLevel = currentLevel }
		} else if char == '}' || char == ')' {
			currentLevel--
		}
	}
	return maxLevel
}

func (p *Parser_Unoptimized) getAnomalySeverity(description string) string {
	highSeverityIndicators := []string{"evasión", "ofuscación", "fragmentación"}
	lowerDesc := manualToLower(description)
	for _, indicator := range highSeverityIndicators {
		if manualContains(lowerDesc, indicator) { return "high" }
	}
	return "medium"
}

func (p *Parser_Unoptimized) getPatternRiskLevel(description string, count int) string {
	baseRisk := "low"
	lowerDesc := manualToLower(description)
	if manualContains(lowerDesc, "excesivo") || manualContains(lowerDesc, "complejo") {
		baseRisk = "medium"
	}
	if count > 3 {
		if baseRisk == "medium" { return "high" }
		return "medium"
	}
	return baseRisk
}
