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
}

func NewLexer() *Lexer {
	return &Lexer{
		suspiciousPatterns: map[string]TokenType{
			// Comandos críticos maliciosos
			`(?i)(invoke-expression|iex)`: INVOKE_EXPRESSION,
			`(?i)downloadstring`: DOWNLOAD_STRING,
			`(?i)(encodedcommand|enc)`: ENCODED_COMMAND,
			`(?i)(bypass|unrestricted)`: BYPASS,
			
			// Comandos sospechosos
			`(?i)(windowstyle\s+hidden|createnowindow)`: HIDDEN_WINDOW,
			`(?i)(noprofile|nop)`: NO_PROFILE,
			`(?i)executionpolicy`: EXECUTION_POLICY,
			`(?i)(downloadfile|webclient)`: DOWNLOAD_FILE,
			`(?i)start-process`: START_PROCESS,
			`(?i)(hkcu|hklm|registry)`: REGISTRY_KEY,
			`(?i)(get-wmiobject|gwmi)`: WMI_OBJECT,
			`(?i)compress-archive`: COMPRESS_ARCHIVE,
			`(?i)(invoke-webrequest|iwr|wget|curl)`: INVOKE_WEBREQUEST,
			`(?i)new-object.*net\.webclient`: NET_WEBCLIENT,
			
			// Persistencia y evasión
			`(?i)(new-scheduledtask|schtasks)`: SCHEDULED_TASK,
			`(?i)(new-service|sc\.exe)`: SERVICE_CREATION,
			`(?i)(currentversion\\run|userinit)`: AUTORUN_KEY,
			`(?i)(set-mppreference|defender)`: DISABLE_DEFENDER,
			`(?i)(clear-eventlog|wevtutil)`: CLEAR_EVENTLOG,
			
			// Herramientas de ataque conocidas
			`(?i)mimikatz`: MIMIKATZ,
			`(?i)powersploit`: POWERSPLOIT,
			`(?i)empire`: EMPIRE,
			`(?i)metasploit`: METASPLOIT,
			`(?i)(cobalt|beacon)`: COBALT_STRIKE,
			
			// Exfiltración
			`(?i)send-mailmessage`: MAIL_MESSAGE,
			`(?i)ftp.*upload`: FTP_UPLOAD,
			`(?i)invoke-restmethod.*post`: HTTP_POST,
			`(?i)nslookup.*txt`: DNS_EXFIL,
			
			// Anti-análisis
			`(?i)(start-sleep|sleep)`: SLEEP_DELAY,
			`(?i)get-random.*start-sleep`: RANDOM_DELAY,
			`(?i)(get-process.*vmware|virtualbox)`: ENVIRONMENT_CHECK,
			`(?i)(checkremotedebugger|isdebuggerpresent)`: DEBUGGER_CHECK,
		},
		obfuscationPatterns: []string{
			`[A-Za-z0-9+/]{20,}={0,2}`, // Base64
			`\$[a-z]{1,3}\d*`,          // Variables ofuscadas
			`[^\w\s]{3,}`,              // Caracteres especiales
		},
	}
}

func (l *Lexer) Tokenize(script string) []Token {
	var tokens []Token
	
	// Detectar patrones sospechosos
	for pattern, tokenType := range l.suspiciousPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		
		for _, match := range matches {
			value := script[match[0]:match[1]]
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
	
	// Detectar ofuscación
	tokens = append(tokens, l.detectObfuscation(script)...)
	
	// Detectar Base64
	tokens = append(tokens, l.detectBase64(script)...)
	
	return tokens
}

func (l *Lexer) detectObfuscation(script string) []Token {
	var tokens []Token
	
	for _, pattern := range l.obfuscationPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringIndex(script, -1)
		
		for _, match := range matches {
			value := script[match[0]:match[1]]
			
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
	
	return tokens
}

func (l *Lexer) detectBase64(script string) []Token {
	var tokens []Token
	
	// Buscar strings que parezcan Base64
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
		"powershell", "cmd", "invoke", "download", "execute",
		"bypass", "hidden", "noprofile", "encodedcommand",
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
	highSeverity := []TokenType{
		INVOKE_EXPRESSION, DOWNLOAD_STRING, ENCODED_COMMAND,
		MIMIKATZ, POWERSPLOIT, EMPIRE, METASPLOIT, COBALT_STRIKE,
		DISABLE_DEFENDER, CLEAR_EVENTLOG,
	}
	
	mediumSeverity := []TokenType{
		BYPASS, HIDDEN_WINDOW, NO_PROFILE, SCHEDULED_TASK,
		SERVICE_CREATION, AUTORUN_KEY, DOWNLOAD_FILE,
	}
	
	for _, t := range highSeverity {
		if t == tokenType {
			return "high"
		}
	}
	
	for _, t := range mediumSeverity {
		if t == tokenType {
			return "medium"
		}
	}
	
	return "low"
}