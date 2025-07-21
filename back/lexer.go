package main

import (
	"encoding/base64"
	"regexp"
	"strings"
)

type Token struct {
	Type     TokenType `json:"type"`
	Value    string    `json:"value"`
	Position int       `json:"position"`
	IsSuspicious bool  `json:"is_suspicious"`
	Severity string    `json:"severity"`
}

type TokenType string

const (
	// Tokens críticos maliciosos
	INVOKE_EXPRESSION   TokenType = "INVOKE_EXPRESSION"
	DOWNLOAD_STRING     TokenType = "DOWNLOAD_STRING"
	ENCODED_COMMAND     TokenType = "ENCODED_COMMAND"
	BYPASS              TokenType = "BYPASS"
	
	// Comandos PowerShell estándar
	CMDLET              TokenType = "CMDLET"
	PARAMETER           TokenType = "PARAMETER"
	VARIABLE            TokenType = "VARIABLE"
	STRING_LITERAL      TokenType = "STRING_LITERAL"
	PIPE                TokenType = "PIPE"
	
	// Ofuscación
	BASE64_ENCODED      TokenType = "BASE64_ENCODED"
	OBFUSCATED_VAR      TokenType = "OBFUSCATED_VAR"
	SPECIAL_CHAR        TokenType = "SPECIAL_CHAR"
	
	// Comandos sospechosos adicionales
	HIDDEN_WINDOW       TokenType = "HIDDEN_WINDOW"
	NO_PROFILE          TokenType = "NO_PROFILE"
	EXECUTION_POLICY    TokenType = "EXECUTION_POLICY"
	DOWNLOAD_FILE       TokenType = "DOWNLOAD_FILE"
	START_PROCESS       TokenType = "START_PROCESS"
	REGISTRY_KEY        TokenType = "REGISTRY_KEY"
	WMI_OBJECT          TokenType = "WMI_OBJECT"
	COMPRESS_ARCHIVE    TokenType = "COMPRESS_ARCHIVE"
	INVOKE_WEBREQUEST   TokenType = "INVOKE_WEBREQUEST"
	NET_WEBCLIENT       TokenType = "NET_WEBCLIENT"
	
	// Evasión y persistencia
	SCHEDULED_TASK      TokenType = "SCHEDULED_TASK"
	SERVICE_CREATION    TokenType = "SERVICE_CREATION"
	AUTORUN_KEY         TokenType = "AUTORUN_KEY"
	DISABLE_DEFENDER    TokenType = "DISABLE_DEFENDER"
	CLEAR_EVENTLOG      TokenType = "CLEAR_EVENTLOG"
	
	// Técnicas de ataque
	MIMIKATZ            TokenType = "MIMIKATZ"
	POWERSPLOIT         TokenType = "POWERSPLOIT"
	EMPIRE              TokenType = "EMPIRE"
	METASPLOIT          TokenType = "METASPLOIT"
	COBALT_STRIKE       TokenType = "COBALT_STRIKE"
	
	// Exfiltración
	MAIL_MESSAGE        TokenType = "MAIL_MESSAGE"
	FTP_UPLOAD          TokenType = "FTP_UPLOAD"
	HTTP_POST           TokenType = "HTTP_POST"
	DNS_EXFIL           TokenType = "DNS_EXFIL"
	
	// Anti-análisis
	SLEEP_DELAY         TokenType = "SLEEP_DELAY"
	RANDOM_DELAY        TokenType = "RANDOM_DELAY"
	ENVIRONMENT_CHECK   TokenType = "ENVIRONMENT_CHECK"
	DEBUGGER_CHECK      TokenType = "DEBUGGER_CHECK"
	
	UNKNOWN             TokenType = "UNKNOWN"
)

type Lexer struct {
	suspiciousPatterns map[string]TokenType
	obfuscationPatterns []string
	legitimateCommands map[string]bool
	contextualPatterns map[string][]string
}

func NewLexer() *Lexer {
	return &Lexer{
		suspiciousPatterns: map[string]TokenType{
			// CRÍTICO - Técnicas APT y evasión avanzada
			`(?i)amsi.*initfailed.*true`: INVOKE_EXPRESSION,
			`(?i)system\.management\.automation.*amsi`: INVOKE_EXPRESSION,
			`(?i)malicious-c2\.com|attacker-server\.com`: DOWNLOAD_FILE,
			`(?i)clear-eventlog.*security.*system`: CLEAR_EVENTLOG,
			`(?i)wevtutil.*cl.*powershell.*operational`: CLEAR_EVENTLOG,
			
			// CRÍTICO - Comandos maliciosos específicos
			`(?i)\binvoke-expression\b`: INVOKE_EXPRESSION,
			`(?i)\biex\b`: INVOKE_EXPRESSION,
			`(?i)system\.net\.webclient.*downloadstring`: DOWNLOAD_STRING,
			`(?i)new-object.*webclient.*downloadstring`: DOWNLOAD_STRING,
			
			// ALTO - Ofuscación y evasión
			`(?i)hxxp.*evil.*payload`: DOWNLOAD_FILE,
			`(?i)evil\.com|evil\[.*\]\.com`: DOWNLOAD_FILE,
			`(?i)downloadstring.*http.*payload`: DOWNLOAD_STRING,
			`(?i)register-scheduledtask.*runlevel.*highest`: SCHEDULED_TASK,
			`(?i)createnowindow.*true.*useshellexecute.*false`: HIDDEN_WINDOW,
			
			// ALTO - Variables ofuscadas específicas (patrones de los ejemplos)
			`(?i)\$[a-z]\d+\s*=\s*"[A-Z][a-z]{2}"`: OBFUSCATED_VAR,
			`(?i)\$[a-z]\d+\s*=\s*"[a-z]{2,4}-"`: OBFUSCATED_VAR,
			`(?i)\$[a-z]\d+[a-z]\d+[a-z]\d+\s*=`: OBFUSCATED_VAR,
			
			// MEDIO - Técnicas sospechosas pero comunes
			`(?i)set-executionpolicy.*bypass.*force`: BYPASS,
			`(?i)executionpolicy.*unrestricted.*force`: BYPASS,
			`(?i)windowstyle.*hidden.*noprofile`: HIDDEN_WINDOW,
			`(?i)get-process.*chrome|firefox|outlook`: START_PROCESS,
			`(?i)get-childitem.*password|credential|secret`: REGISTRY_KEY,
			
			// MEDIO - Persistencia básica
			`(?i)register-scheduledtask.*powershell`: SCHEDULED_TASK,
			`(?i)set-itemproperty.*run.*powershell`: AUTORUN_KEY,
			`(?i)currentversion\\run`: AUTORUN_KEY,
			
			// BAJO - Técnicas legítimas pero potencialmente sospechosas
			`(?i)set-executionpolicy.*process`: EXECUTION_POLICY,
			`(?i)webclient.*downloadstring.*config|update`: DOWNLOAD_STRING,
			`(?i)new-scheduledtask.*weekly|daily`: SCHEDULED_TASK,
			`(?i)invoke-webrequest.*config\.xml`: INVOKE_WEBREQUEST,
			
			// Patrones de ofuscación específicos basados en ejemplos
			`(?i)"[A-Z]"\s*\+\s*"[a-z]+"\s*\+\s*"[a-z-]+"`: OBFUSCATED_VAR,
			`(?i)replace\s*\(\s*"\[.*?\]"\s*,\s*".*?"\s*\)`: OBFUSCATED_VAR,
			`(?i)-join\s*\(.*tochararray.*sort.*random\)`: OBFUSCATED_VAR,
			`(?i)frombase64string.*frombase64string`: BASE64_ENCODED,
			
			// Técnicas de evasión específicas
			`(?i)remove-variable.*payload.*decoded.*erroraction`: CLEAR_EVENTLOG,
			`(?i)start-process.*hidden.*command`: START_PROCESS,
			`(?i)system\.diagnostics\.process.*start`: START_PROCESS,
			
			// Codificación y exfiltración
			`(?i)-encodedcommand\s+[A-Za-z0-9+/=]{20,}`: ENCODED_COMMAND,
			`(?i)-enc\s+[A-Za-z0-9+/=]{20,}`: ENCODED_COMMAND,
			`(?i)convertto-json.*compress.*base64`: BASE64_ENCODED,
			`(?i)uploadstring.*post.*data`: HTTP_POST,
			
			// Comandos estándar pero en contextos sospechosos
			`(?i)-(windowstyle\s+hidden|createnowindow)`: HIDDEN_WINDOW,
			`(?i)-windowstyle.*hidden`: HIDDEN_WINDOW,
			`(?i)-(noprofile|nop)\s`: NO_PROFILE,
			`(?i)-noprofile`: NO_PROFILE,
			
			// Herramientas y frameworks de ataque
			`(?i)invoke-mimikatz`: MIMIKATZ,
			`(?i)invoke-powersploit`: POWERSPLOIT,
			`(?i)empire\s+module`: EMPIRE,
			`(?i)metasploit.*payload`: METASPLOIT,
			`(?i)cobalt.*beacon`: COBALT_STRIKE,
			
			// Técnicas anti-análisis
			`(?i)get-process.*vmware|virtualbox|vbox`: ENVIRONMENT_CHECK,
			`(?i)checkremotedebugger|isdebuggerpresent`: DEBUGGER_CHECK,
		},
		
		// Comandos legítimos que NO deben ser marcados como sospechosos
		legitimateCommands: map[string]bool{
			"get-date": true,
			"write-host": true,
			"write-output": true,
			"test-path": true,
			"new-item": true,
			"copy-item": true,
			"remove-item": true,
			"get-childitem": true,
			"join-path": true,
			"split-path": true,
			"add-content": true,
			"out-file": true,
			"out-null": true,
			"measure-object": true,
			"sort-object": true,
			"where-object": true,
			"foreach-object": true,
			"select-object": true,
			"group-object": true,
			"write-logmessage": true,
			"start-documentbackup": true,
			"remove-oldbackups": true,
			"new-backupreport": true,
		},
		
		// Patrones contextuales - requieren contexto específico para ser sospechosos
		contextualPatterns: map[string][]string{
			"invoke-webrequest": {"http://", "https://", "ftp://"},
			"new-object": {"net.webclient", "system.net.webclient", "msxml2.xmlhttp"},
			"start-process": {"-windowstyle hidden", "-createnowindow"},
		},
		
		obfuscationPatterns: []string{
			`[A-Za-z0-9+/]{50,}={0,2}`, // Base64 largo (50+ chars)
			`\$[a-z]{1,2}\d*\s*=`,      // Variables muy cortas
			`[^\w\s\.\-]{5,}`,          // Caracteres especiales en secuencia
		},
	}
}

func (l *Lexer) Tokenize(script string) []Token {
	var tokens []Token
	
	// Detectar patrones sospechosos con contexto
	for pattern, tokenType := range l.suspiciousPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		
		for _, match := range matches {
			value := script[match[0]:match[1]]
			
			// Verificar si es un comando legítimo (más estricto)
			if l.isLegitimateCommand(value) && !l.isInMaliciousContext(value, script, match[0]) {
				continue
			}
			
			// Verificar contexto para patrones contextuales (más permisivo para detección)
			if !l.isInSuspiciousContext(value, script, match[0]) {
				continue
			}
			
			severity := l.getSeverity(tokenType)
			
			token := Token{
				Type:         tokenType,
				Value:        value,
				Position:     match[0],
				IsSuspicious: true,
				Severity:     severity,
			}
			tokens = append(tokens, token)
		}
	}
	
	// Detectar ofuscación verdadera
	tokens = append(tokens, l.detectRealObfuscation(script)...)
	
	// Detectar Base64 malicioso
	tokens = append(tokens, l.detectMaliciousBase64(script)...)
	
	return tokens
}

func (l *Lexer) isLegitimateCommand(value string) bool {
	// Extraer el comando principal
	cleaned := strings.ToLower(strings.TrimSpace(value))
	
	// Remover parámetros para obtener solo el comando
	parts := strings.Fields(cleaned)
	if len(parts) == 0 {
		return false
	}
	
	command := parts[0]
	
	// Remover guiones del inicio
	command = strings.TrimLeft(command, "-")
	
	return l.legitimateCommands[command]
}

// Nueva función para detectar contexto malicioso
func (l *Lexer) isInMaliciousContext(value string, script string, position int) bool {
	
	// Buscar contexto malicioso en ventana de 300 caracteres
	start := max(0, position-150)
	end := min(len(script), position+150)
	context := strings.ToLower(script[start:end])
	
	maliciousIndicators := []string{
		"evil.com", "malicious", "payload", "hxxp",
		"downloadstring", "webclient", "bypass", "hidden",
		"encodedcommand", "frombase64string", "remove-variable",
	}
	
	for _, indicator := range maliciousIndicators {
		if strings.Contains(context, indicator) {
			return true
		}
	}
	
	return false
}

func (l *Lexer) isInSuspiciousContext(value string, script string, position int) bool {
	lowerValue := strings.ToLower(value)
	
	// Para comandos contextuales, verificar si tienen contexto sospechoso
	for command, contexts := range l.contextualPatterns {
		if strings.Contains(lowerValue, command) {
			// Buscar contexto sospechoso en ventana de 200 caracteres
			start := max(0, position-100)
			end := min(len(script), position+100)
			context := strings.ToLower(script[start:end])
			
			hasSuspiciousContext := false
			for _, ctx := range contexts {
				if strings.Contains(context, ctx) {
					hasSuspiciousContext = true
					break
				}
			}
			
			if !hasSuspiciousContext {
				return false
			}
		}
	}
	
	return true
}

func (l *Lexer) detectRealObfuscation(script string) []Token {
	var tokens []Token
	
	for _, pattern := range l.obfuscationPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		
		for _, match := range matches {
			value := script[match[0]:match[1]]
			
			// Solo marcar como ofuscación si realmente parece sospechoso
			if l.isReallyObfuscated(value) {
				var tokenType TokenType
				if l.isBase64Like(value) {
					tokenType = BASE64_ENCODED
				} else if strings.HasPrefix(value, "$") {
					tokenType = OBFUSCATED_VAR
				} else {
					tokenType = SPECIAL_CHAR
				}
				
				token := Token{
					Type:         tokenType,
					Value:        value,
					Position:     match[0],
					IsSuspicious: true,
					Severity:     "medium",
				}
				tokens = append(tokens, token)
			}
		}
	}
	
	return tokens
}

func (l *Lexer) isReallyObfuscated(value string) bool {
	// No marcar variables normales como ofuscadas
	if strings.HasPrefix(value, "$") {
		// Variables como $env:, $_.Property, etc. son normales
		if strings.Contains(value, "env:") || 
		   strings.Contains(value, "_.") ||
		   strings.Contains(value, "SourcePath") ||
		   strings.Contains(value, "BackupPath") ||
		   strings.Contains(value, "RetentionDays") ||
		   len(value) > 5 { // Variables con nombres descriptivos
			return false
		}
	}
	
	// No marcar texto HTML/paths como ofuscación
	if strings.Contains(value, "<") || strings.Contains(value, ">") ||
	   strings.Contains(value, "\\") || strings.Contains(value, "/") {
		return false
	}
	
	return true
}

func (l *Lexer) detectMaliciousBase64(script string) []Token {
	var tokens []Token
	
	// Buscar strings que parezcan Base64 malicioso
	re := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	matches := re.FindAllStringIndex(script, -1)
	
	for _, match := range matches {
		value := script[match[0]:match[1]]
		
		// Intentar decodificar
		if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
			decodedStr := string(decoded)
			if l.containsSuspiciousContent(decodedStr) {
				token := Token{
					Type:         BASE64_ENCODED,
					Value:        value,
					Position:     match[0],
					IsSuspicious: true,
					Severity:     "high",
				}
				tokens = append(tokens, token)
			}
		}
	}
	
	return tokens
}

func (l *Lexer) isBase64Like(s string) bool {
	if len(s) < 20 {
		return false
	}
	
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

func (l *Lexer) containsSuspiciousContent(content string) bool {
	suspiciousKeywords := []string{
		"invoke-expression", "iex", "downloadstring", "bypass",
		"hidden", "noprofile", "encodedcommand", "mimikatz",
		"empire", "metasploit", "cobalt", "powersploit",
	}
	
	lowerContent := strings.ToLower(content)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(lowerContent, keyword) {
			return true
		}
	}
	
	return false
}

func (l *Lexer) getSeverity(tokenType TokenType) string {
	// CRÍTICO - Técnicas APT, evasión avanzada y ataques directos
	criticalSeverity := []TokenType{
		INVOKE_EXPRESSION, DOWNLOAD_STRING, ENCODED_COMMAND,
		MIMIKATZ, POWERSPLOIT, EMPIRE, METASPLOIT, COBALT_STRIKE,
		CLEAR_EVENTLOG, // Incluye anti-forense
	}
	
	// ALTO - Evasión, ofuscación y persistencia maliciosa
	highSeverity := []TokenType{
		NET_WEBCLIENT, OBFUSCATED_VAR, BASE64_ENCODED,
		SCHEDULED_TASK, AUTORUN_KEY, HIDDEN_WINDOW,
		START_PROCESS, // Cuando es con evasión
	}
	
	// MEDIO - Técnicas sospechosas pero no necesariamente maliciosas
	mediumSeverity := []TokenType{
		BYPASS, NO_PROFILE, DOWNLOAD_FILE,
		REGISTRY_KEY, INVOKE_WEBREQUEST,
		EXECUTION_POLICY,
	}
	
	// Verificar severidad crítica
	for _, t := range criticalSeverity {
		if t == tokenType {
			return "high" // Crítico se mapea a "high" en el sistema
		}
	}
	
	// Verificar severidad alta
	for _, t := range highSeverity {
		if t == tokenType {
			return "high"
		}
	}
	
	// Verificar severidad media
	for _, t := range mediumSeverity {
		if t == tokenType {
			return "medium"
		}
	}
	
	return "low"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}