package main

import (
	"regexp"
	"strings"
)

type SyntaxAnalysis struct {
	IsValid               bool               `json:"is_valid"`
	Anomalies            []SyntaxAnomaly    `json:"anomalies"`
	SuspiciousPatterns   []SuspiciousPattern `json:"suspicious_patterns"`
	ObfuscationLevel     string             `json:"obfuscation_level"`
	ComplexityScore      int                `json:"complexity_score"`
}

type SyntaxAnomaly struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Position    int    `json:"position"`
	Severity    string `json:"severity"`
}

type SuspiciousPattern struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Count       int    `json:"count"`
	RiskLevel   string `json:"risk_level"`
}

type Parser struct {
	anomalyPatterns      map[string]string
	suspiciousPatterns   map[string]string
	obfuscationIndicators []string
}

func NewParser() *Parser {
	return &Parser{
		anomalyPatterns: map[string]string{
			// Sintaxis incorrecta intencional
			`(?i)invoke-expression\s*\(\s*\$null\s*\+\s*`: "Evasión por concatenación nula",
			`(?i)\$\w+\s*=\s*\$\w+\s*\+\s*\$\w+\s*\+\s*\$\w+`: "Concatenación excesiva de cadenas",
			`(?i)['"]\s*\+\s*['"]\s*\+\s*['"]`: "Fragmentación de cadenas",
			`(?i)\[\s*char\s*\]\s*\d+\s*\+`: "Ofuscación por código de caracteres",
			`(?i)\$\w+\[\s*\d+\.\.\d+\s*\]`: "Ofuscación por segmentación de arrays",
			
			// Cmdlets fragmentados
			`(?i)invoke\s*-\s*expression`: "Nombre de cmdlet fragmentado",
			`(?i)new\s*-\s*object`: "Creación de objeto fragmentada",
			`(?i)start\s*-\s*process`: "Inicio de proceso fragmentado",
			
			// Parámetros anómalos
			`(?i)-\w+\s+\$\w+\[\d+\]`: "Parámetro con indexación de array",
			`(?i)-\w+\s+\(\s*\$\w+\s*\)`: "Parámetro con paréntesis",
		},
		
		suspiciousPatterns: map[string]string{
			// Anidamiento excesivo
			`\(\s*\(\s*\(\s*`: "Anidamiento excesivo de paréntesis",
			`\{\s*\{\s*\{\s*`: "Anidamiento excesivo de bloques",
			`foreach\s*\(\s*\$\w+\s*in\s*.*foreach`: "Bucles foreach anidados",
			
			// Concatenación sospechosa
			`\$\w+\s*\+\s*\$\w+\s*\+\s*\$\w+\s*\+`: "Múltiple concatenación de cadenas",
			`\[\s*string\s*\]\s*\$\w+\s*\+`: "Concatenación con conversión de tipo",
			
			// Pipes complejos
			`\|\s*\%\s*\{\s*.*\|\s*\%`: "Pipeline complejo con ForEach anidado",
			`\|\s*where\s*\{\s*.*\|\s*select`: "Pipeline de filtrado complejo",
			
			// Bloques de código sospechosos
			`\&\s*\{\s*.*iex`: "Bloque de script con Invoke-Expression",
			`\&\s*\(\s*.*\)`: "Operador de ejecución ampersand",
		},
		
		obfuscationIndicators: []string{
			`\[\s*char\s*\]`,
			`\[\s*convert\s*\]`,
			`\[\s*system\.text\.encoding\s*\]`,
			`\[\s*system\.convert\s*\]`,
			`\$\w{1,3}\d*`,
			`['"]\s*\+\s*['"]`,
		},
	}
}

func (p *Parser) ParseSyntax(script string, tokens []Token) SyntaxAnalysis {
	analysis := SyntaxAnalysis{
		IsValid:    p.isValidSyntax(script),
		Anomalies:  p.detectAnomalies(script),
		SuspiciousPatterns: p.detectSuspiciousPatterns(script),
		ObfuscationLevel: p.calculateObfuscationLevel(script),
		ComplexityScore: p.calculateComplexityScore(script, tokens),
	}
	
	return analysis
}

func (p *Parser) isValidSyntax(script string) bool {
	// Verificaciones básicas de sintaxis PowerShell
	
	// Verificar balance de paréntesis
	if !p.isBalanced(script, '(', ')') {
		return false
	}
	
	// Verificar balance de llaves
	if !p.isBalanced(script, '{', '}') {
		return false
	}
	
	// Verificar balance de corchetes
	if !p.isBalanced(script, '[', ']') {
		return false
	}
	
	// Verificar comillas balanceadas
	if !p.areQuotesBalanced(script) {
		return false
	}
	
	return true
}

func (p *Parser) isBalanced(script string, open, close rune) bool {
	count := 0
	for _, char := range script {
		if char == open {
			count++
		} else if char == close {
			count--
			if count < 0 {
				return false
			}
		}
	}
	return count == 0
}

func (p *Parser) areQuotesBalanced(script string) bool {
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

func (p *Parser) detectAnomalies(script string) []SyntaxAnomaly {
	var anomalies []SyntaxAnomaly
	
	for pattern, description := range p.anomalyPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		
		for _, match := range matches {
			anomaly := SyntaxAnomaly{
				Type:        "syntax_anomaly",
				Description: description,
				Position:    match[0],
				Severity:    p.getAnomalySeverity(description),
			}
			anomalies = append(anomalies, anomaly)
		}
	}
	
	return anomalies
}

func (p *Parser) detectSuspiciousPatterns(script string) []SuspiciousPattern {
	var patterns []SuspiciousPattern
	
	for pattern, description := range p.suspiciousPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(script, -1)
		
		if len(matches) > 0 {
			suspiciousPattern := SuspiciousPattern{
				Pattern:     pattern,
				Description: description,
				Count:       len(matches),
				RiskLevel:   p.getPatternRiskLevel(description, len(matches)),
			}
			patterns = append(patterns, suspiciousPattern)
		}
	}
	
	// Asegurar que patterns no sea nil
	if patterns == nil {
		patterns = []SuspiciousPattern{}
	}
	
	return patterns
}

func (p *Parser) calculateObfuscationLevel(script string) string {
	obfuscationScore := 0
	
	for _, indicator := range p.obfuscationIndicators {
		re := regexp.MustCompile(indicator)
		matches := re.FindAllString(script, -1)
		obfuscationScore += len(matches)
	}
	
	// Factores adicionales de ofuscación
	if strings.Contains(script, "[char]") {
		obfuscationScore += 5
	}
	
	if strings.Contains(script, "System.Convert") {
		obfuscationScore += 3
	}
	
	// Contar variables de una sola letra
	varPattern := regexp.MustCompile(`\$[a-z]\b`)
	shortVars := varPattern.FindAllString(script, -1)
	obfuscationScore += len(shortVars)
	
	// Determinar nivel
	if obfuscationScore == 0 {
		return "none"
	} else if obfuscationScore < 5 {
		return "low"
	} else if obfuscationScore < 15 {
		return "medium"
	} else {
		return "high"
	}
}

func (p *Parser) calculateComplexityScore(script string, tokens []Token) int {
	score := 0
	
	// Longitud del script
	score += len(script) / 100
	
	// Número de tokens sospechosos
	for _, token := range tokens {
		if token.IsSuspicious {
			switch token.Severity {
			case "high":
				score += 10
			case "medium":
				score += 5
			case "low":
				score += 2
			}
		}
	}
	
	// Anidamiento
	nestingLevel := p.calculateNestingLevel(script)
	score += nestingLevel * 2
	
	// Número de pipes
	pipeCount := strings.Count(script, "|")
	score += pipeCount
	
	// Funciones definidas
	functionPattern := regexp.MustCompile(`(?i)function\s+\w+`)
	functions := functionPattern.FindAllString(script, -1)
	score += len(functions) * 3
	
	return score
}

func (p *Parser) calculateNestingLevel(script string) int {
	maxLevel := 0
	currentLevel := 0
	
	for _, char := range script {
		if char == '{' || char == '(' {
			currentLevel++
			if currentLevel > maxLevel {
				maxLevel = currentLevel
			}
		} else if char == '}' || char == ')' {
			currentLevel--
		}
	}
	
	return maxLevel
}

func (p *Parser) getAnomalySeverity(description string) string {
	highSeverityIndicators := []string{
		"evasión", "ofuscación", "fragmentación",
	}
	
	lowerDesc := strings.ToLower(description)
	for _, indicator := range highSeverityIndicators {
		if strings.Contains(lowerDesc, indicator) {
			return "high"
		}
	}
	
	return "medium"
}

func (p *Parser) getPatternRiskLevel(description string, count int) string {
	baseRisk := "low"
	
	if strings.Contains(strings.ToLower(description), "excesivo") ||
	   strings.Contains(strings.ToLower(description), "complejo") {
		baseRisk = "medium"
	}
	
	if count > 3 {
		if baseRisk == "medium" {
			return "high"
		}
		return "medium"
	}
	
	return baseRisk
}