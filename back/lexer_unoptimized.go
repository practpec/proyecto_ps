package main

import (
	"encoding/base64"
	"regexp"
)

// --- INICIO: Funciones manuales para reemplazar la librería "strings" ---
// Estas funciones son intencionalmente menos eficientes para la demostración.

func manualContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func manualToLower(s string) string {
	var result []rune
	for _, r := range s {
		if 'A' <= r && r <= 'Z' {
			result = append(result, r+32)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

func manualTrimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\n' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func manualFields(s string) []string {
	var fields []string
	var currentField []rune
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			if len(currentField) > 0 {
				fields = append(fields, string(currentField))
				currentField = []rune{}
			}
		} else {
			currentField = append(currentField, r)
		}
	}
	if len(currentField) > 0 {
		fields = append(fields, string(currentField))
	}
	return fields
}

func manualHasPrefix(s, prefix string) bool {
    if len(s) < len(prefix) {
        return false
    }
    return s[0:len(prefix)] == prefix
}

// --- FIN: Funciones manuales ---


// El resto del código es una adaptación del lexer original,
// usando las funciones manuales en lugar de las de la librería "strings".

type Lexer_Unoptimized struct {
	suspiciousPatterns map[string]TokenType
	obfuscationPatterns []string
	legitimateCommands map[string]bool
	contextualPatterns map[string][]string
}

func NewLexer_Unoptimized() *Lexer_Unoptimized {
	// La definición de patrones es idéntica a la versión optimizada.
	return &Lexer_Unoptimized{
		suspiciousPatterns: map[string]TokenType{
			`(?i)amsi.*initfailed.*true`: INVOKE_EXPRESSION,
			`(?i)system\.management\.automation.*amsi`: INVOKE_EXPRESSION,
			`(?i)malicious-c2\.com|attacker-server\.com`: DOWNLOAD_FILE,
			`(?i)clear-eventlog.*security.*system`: CLEAR_EVENTLOG,
			`(?i)wevtutil.*cl.*powershell.*operational`: CLEAR_EVENTLOG,
			`(?i)\binvoke-expression\b`: INVOKE_EXPRESSION,
			`(?i)\biex\b`: INVOKE_EXPRESSION,
			`(?i)system\.net\.webclient.*downloadstring`: DOWNLOAD_STRING,
			`(?i)new-object.*webclient.*downloadstring`: DOWNLOAD_STRING,
			`(?i)hxxp.*evil.*payload`: DOWNLOAD_FILE,
			`(?i)evil\.com|evil\[.*\]\.com`: DOWNLOAD_FILE,
			`(?i)downloadstring.*http.*payload`: DOWNLOAD_STRING,
			`(?i)register-scheduledtask.*runlevel.*highest`: SCHEDULED_TASK,
			`(?i)createnowindow.*true.*useshellexecute.*false`: HIDDEN_WINDOW,
			`(?i)\$[a-z]\d+\s*=\s*"[A-Z][a-z]{2}"`: OBFUSCATED_VAR,
			`(?i)\$[a-z]\d+\s*=\s*"[a-z]{2,4}-"`: OBFUSCATED_VAR,
			`(?i)\$[a-z]\d+[a-z]\d+[a-z]\d+\s*=`: OBFUSCATED_VAR,
			`(?i)set-executionpolicy.*bypass.*force`: BYPASS,
			`(?i)executionpolicy.*unrestricted.*force`: BYPASS,
			`(?i)windowstyle.*hidden.*noprofile`: HIDDEN_WINDOW,
			`(?i)get-process.*chrome|firefox|outlook`: START_PROCESS,
			`(?i)get-childitem.*password|credential|secret`: REGISTRY_KEY,
			`(?i)register-scheduledtask.*powershell`: SCHEDULED_TASK,
			`(?i)set-itemproperty.*run.*powershell`: AUTORUN_KEY,
			`(?i)currentversion\\run`: AUTORUN_KEY,
			`(?i)set-executionpolicy.*process`: EXECUTION_POLICY,
			`(?i)webclient.*downloadstring.*config|update`: DOWNLOAD_STRING,
			`(?i)new-scheduledtask.*weekly|daily`: SCHEDULED_TASK,
			`(?i)invoke-webrequest.*config\.xml`: INVOKE_WEBREQUEST,
			`(?i)"[A-Z]"\s*\+\s*"[a-z]+"\s*\+\s*"[a-z-]+"`: OBFUSCATED_VAR,
			`(?i)replace\s*\(\s*"\[.*?\]"\s*,\s*".*?"\s*\)`: OBFUSCATED_VAR,
			`(?i)-join\s*\(.*tochararray.*sort.*random\)`: OBFUSCATED_VAR,
			`(?i)frombase64string.*frombase64string`: BASE64_ENCODED,
			`(?i)remove-variable.*payload.*decoded.*erroraction`: CLEAR_EVENTLOG,
			`(?i)start-process.*hidden.*command`: START_PROCESS,
			`(?i)system\.diagnostics\.process.*start`: START_PROCESS,
			`(?i)-encodedcommand\s+[A-Za-z0-9+/=]{20,}`: ENCODED_COMMAND,
			`(?i)-enc\s+[A-Za-z0-9+/=]{20,}`: ENCODED_COMMAND,
			`(?i)convertto-json.*compress.*base64`: BASE64_ENCODED,
			`(?i)uploadstring.*post.*data`: HTTP_POST,
			`(?i)-(windowstyle\s+hidden|createnowindow)`: HIDDEN_WINDOW,
			`(?i)-windowstyle.*hidden`: HIDDEN_WINDOW,
			`(?i)-(noprofile|nop)\s`: NO_PROFILE,
			`(?i)-noprofile`: NO_PROFILE,
			`(?i)invoke-mimikatz`: MIMIKATZ,
			`(?i)invoke-powersploit`: POWERSPLOIT,
			`(?i)empire\s+module`: EMPIRE,
			`(?i)metasploit.*payload`: METASPLOIT,
			`(?i)cobalt.*strike`: COBALT_STRIKE,
			`(?i)get-process.*vmware|virtualbox|vbox`: ENVIRONMENT_CHECK,
			`(?i)checkremotedebugger|isdebuggerpresent`: DEBUGGER_CHECK,
		},
		legitimateCommands: map[string]bool{
			"get-date": true, "write-host": true, "write-output": true, "test-path": true, "new-item": true,
			"copy-item": true, "remove-item": true, "get-childitem": true, "join-path": true, "split-path": true,
			"add-content": true, "out-file": true, "out-null": true, "measure-object": true, "sort-object": true,
			"where-object": true, "foreach-object": true, "select-object": true, "group-object": true,
			"write-logmessage": true, "start-documentbackup": true, "remove-oldbackups": true, "new-backupreport": true,
		},
		contextualPatterns: map[string][]string{
			"invoke-webrequest": {"http://", "https://", "ftp://"},
			"new-object":        {"net.webclient", "system.net.webclient", "msxml2.xmlhttp"},
			"start-process":     {"-windowstyle hidden", "-createnowindow"},
		},
		obfuscationPatterns: []string{
			`[A-Za-z0-9+/]{50,}={0,2}`, // Base64 largo
			`\$[a-z]{1,2}\d*\s*=`,      // Variables cortas
			`[^\w\s\.\-]{5,}`,          // Caracteres especiales
		},
	}
}

func (l *Lexer_Unoptimized) Tokenize(script string) []Token {
	var tokens []Token
	for pattern, tokenType := range l.suspiciousPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		for _, match := range matches {
			value := script[match[0]:match[1]]
			if l.isLegitimateCommand(value) && !l.isInMaliciousContext(value, script, match[0]) {
				continue
			}
			if !l.isInSuspiciousContext(value, script, match[0]) {
				continue
			}
			severity := l.getSeverity(tokenType)
			token := Token{
				Type: tokenType, Value: value, Position: match[0], IsSuspicious: true, Severity: severity,
			}
			tokens = append(tokens, token)
		}
	}
	tokens = append(tokens, l.detectRealObfuscation(script)...)
	tokens = append(tokens, l.detectMaliciousBase64(script)...)
	return tokens
}

func (l *Lexer_Unoptimized) isLegitimateCommand(value string) bool {
	cleaned := manualToLower(manualTrimSpace(value))
	parts := manualFields(cleaned)
	if len(parts) == 0 {
		return false
	}
	command := parts[0]
	// Manual TrimLeft
	for len(command) > 0 && command[0] == '-' {
		command = command[1:]
	}
	return l.legitimateCommands[command]
}

func (l *Lexer_Unoptimized) isInMaliciousContext(value string, script string, position int) bool {
	start := max(0, position-150)
	end := min(len(script), position+150)
	context := manualToLower(script[start:end])
	maliciousIndicators := []string{
		"evil.com", "malicious", "payload", "hxxp", "downloadstring", "webclient",
		"bypass", "hidden", "encodedcommand", "frombase64string", "remove-variable",
	}
	for _, indicator := range maliciousIndicators {
		if manualContains(context, indicator) {
			return true
		}
	}
	return false
}

func (l *Lexer_Unoptimized) isInSuspiciousContext(value string, script string, position int) bool {
	lowerValue := manualToLower(value)
	for command, contexts := range l.contextualPatterns {
		if manualContains(lowerValue, command) {
			start := max(0, position-100)
			end := min(len(script), position+100)
			context := manualToLower(script[start:end])
			hasSuspiciousContext := false
			for _, ctx := range contexts {
				if manualContains(context, ctx) {
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

func (l *Lexer_Unoptimized) detectRealObfuscation(script string) []Token {
	var tokens []Token
	for _, pattern := range l.obfuscationPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		for _, match := range matches {
			value := script[match[0]:match[1]]
			if l.isReallyObfuscated(value) {
				var tokenType TokenType
				if l.isBase64Like(value) {
					tokenType = BASE64_ENCODED
				} else if manualHasPrefix(value, "$") {
					tokenType = OBFUSCATED_VAR
				} else {
					tokenType = SPECIAL_CHAR
				}
				token := Token{
					Type: tokenType, Value: value, Position: match[0], IsSuspicious: true, Severity: "medium",
				}
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

func (l *Lexer_Unoptimized) isReallyObfuscated(value string) bool {
	if manualHasPrefix(value, "$") {
		if manualContains(value, "env:") || manualContains(value, "_.") ||
			manualContains(value, "SourcePath") || manualContains(value, "BackupPath") ||
			manualContains(value, "RetentionDays") || len(value) > 5 {
			return false
		}
	}
	if manualContains(value, "<") || manualContains(value, ">") ||
		manualContains(value, "\\") || manualContains(value, "/") {
		return false
	}
	return true
}

func (l *Lexer_Unoptimized) detectMaliciousBase64(script string) []Token {
	var tokens []Token
	re := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	matches := re.FindAllStringIndex(script, -1)
	for _, match := range matches {
		value := script[match[0]:match[1]]
		if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
			decodedStr := string(decoded)
			if l.containsSuspiciousContent(decodedStr) {
				token := Token{
					Type: BASE64_ENCODED, Value: value, Position: match[0], IsSuspicious: true, Severity: "high",
				}
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

func (l *Lexer_Unoptimized) isBase64Like(s string) bool {
	if len(s) < 20 { return false }
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

func (l *Lexer_Unoptimized) containsSuspiciousContent(content string) bool {
	suspiciousKeywords := []string{
		"invoke-expression", "iex", "downloadstring", "bypass", "hidden", "noprofile",
		"encodedcommand", "mimikatz", "empire", "metasploit", "cobalt", "powersploit",
	}
	lowerContent := manualToLower(content)
	for _, keyword := range suspiciousKeywords {
		if manualContains(lowerContent, keyword) {
			return true
		}
	}
	return false
}

func (l *Lexer_Unoptimized) getSeverity(tokenType TokenType) string {
	criticalSeverity := []TokenType{
		INVOKE_EXPRESSION, DOWNLOAD_STRING, ENCODED_COMMAND, MIMIKATZ, POWERSPLOIT,
		EMPIRE, METASPLOIT, COBALT_STRIKE, CLEAR_EVENTLOG,
	}
	highSeverity := []TokenType{
		NET_WEBCLIENT, OBFUSCATED_VAR, BASE64_ENCODED, SCHEDULED_TASK,
		AUTORUN_KEY, HIDDEN_WINDOW, START_PROCESS,
	}
	mediumSeverity := []TokenType{
		BYPASS, NO_PROFILE, DOWNLOAD_FILE, REGISTRY_KEY, INVOKE_WEBREQUEST, EXECUTION_POLICY,
	}
	for _, t := range criticalSeverity { if t == tokenType { return "high" } }
	for _, t := range highSeverity { if t == tokenType { return "high" } }
	for _, t := range mediumSeverity { if t == tokenType { return "medium" } }
	return "low"
}
