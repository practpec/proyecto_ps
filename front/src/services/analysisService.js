// Servicio para procesar y validar datos de análisis
export class AnalysisService {
  /**
   * Normaliza y valida los datos de resultado del análisis
   * @param {Object} result - Resultado crudo del análisis
   * @returns {Object} - Resultado normalizado y seguro
   */
  static normalizeAnalysisResult(result) {
    if (!result) {
      return this.getEmptyResult();
    }

    return {
      lexical_analysis: this.normalizeLexicalAnalysis(result.lexical_analysis),
      syntax_analysis: this.normalizeSyntaxAnalysis(result.syntax_analysis),
      semantic_analysis: this.normalizeSemanticAnalysis(result.semantic_analysis),
      summary: this.normalizeSummary(result.summary),
      recommendations: result.recommendations || [],
      threat_level: result.threat_level || 'MINIMAL',
      overall_risk: result.overall_risk || 0,
      timestamp: result.timestamp || new Date().toISOString(),
      script_hash: result.script_hash || ''
    };
  }

  /**
   * Normaliza el análisis léxico
   */
  static normalizeLexicalAnalysis(lexical) {
    return {
      critical_tokens: lexical?.critical_tokens || [],
      tokens: lexical?.tokens || [],
      suspicious_count: lexical?.suspicious_count || 0,
      obfuscation_level: lexical?.obfuscation_level || 'none',
      token_statistics: {
        total_tokens: lexical?.token_statistics?.total_tokens || 0,
        suspicious_tokens: lexical?.token_statistics?.suspicious_tokens || 0,
        high_severity: lexical?.token_statistics?.high_severity || 0,
        medium_severity: lexical?.token_statistics?.medium_severity || 0,
        low_severity: lexical?.token_statistics?.low_severity || 0,
        token_distribution: lexical?.token_statistics?.token_distribution || {}
      }
    };
  }

  /**
   * Normaliza el análisis sintáctico
   */
  static normalizeSyntaxAnalysis(syntax) {
    return {
      is_valid: syntax?.is_valid ?? true,
      complexity_score: syntax?.complexity_score || 0,
      obfuscation_level: syntax?.obfuscation_level || 'none',
      anomalies: syntax?.anomalies || [],
      suspicious_patterns: syntax?.suspicious_patterns || []
    };
  }

  /**
   * Normaliza el análisis semántico
   */
  static normalizeSemanticAnalysis(semantic) {
    return {
      threat_category: semantic?.threat_category || 'Unknown',
      risk_score: semantic?.risk_score || 0,
      malicious_intent: {
        payload_download: semantic?.malicious_intent?.payload_download || false,
        persistence: semantic?.malicious_intent?.persistence || false,
        privilege_escalation: semantic?.malicious_intent?.privilege_escalation || false,
        data_exfiltration: semantic?.malicious_intent?.data_exfiltration || false,
        system_modification: semantic?.malicious_intent?.system_modification || false,
        reconnaissance: semantic?.malicious_intent?.reconnaissance || false,
        lateral_movement: semantic?.malicious_intent?.lateral_movement || false,
        defense_evasion: semantic?.malicious_intent?.defense_evasion || false,
        details: semantic?.malicious_intent?.details || []
      },
      evasion_techniques: {
        anti_forensic: semantic?.evasion_techniques?.anti_forensic || false,
        log_deletion: semantic?.evasion_techniques?.log_deletion || false,
        process_hollowing: semantic?.evasion_techniques?.process_hollowing || false,
        amsi_bypass: semantic?.evasion_techniques?.amsi_bypass || false,
        powershell_logging: semantic?.evasion_techniques?.powershell_logging || false,
        timestomp: semantic?.evasion_techniques?.timestomp || false,
        techniques: semantic?.evasion_techniques?.techniques || []
      },
      system_impact: {
        file_system_changes: semantic?.system_impact?.file_system_changes || false,
        registry_changes: semantic?.system_impact?.registry_changes || false,
        network_activity: semantic?.system_impact?.network_activity || false,
        process_creation: semantic?.system_impact?.process_creation || false,
        service_modification: semantic?.system_impact?.service_modification || false,
        scheduled_tasks: semantic?.system_impact?.scheduled_tasks || false,
        impact_areas: semantic?.system_impact?.impact_areas || []
      },
      attack_chain: semantic?.attack_chain || []
    };
  }

  /**
   * Normaliza el resumen
   */
  static normalizeSummary(summary) {
    return {
      main_threats: summary?.main_threats || [],
      key_findings: summary?.key_findings || [],
      attack_vector: summary?.attack_vector || 'Unknown',
      confidence: summary?.confidence || 'Low',
      action_required: summary?.action_required || 'Monitor'
    };
  }

  /**
   * Retorna un resultado vacío por defecto
   */
  static getEmptyResult() {
    return {
      lexical_analysis: {
        critical_tokens: [],
        tokens: [],
        suspicious_count: 0,
        obfuscation_level: 'none',
        token_statistics: {
          total_tokens: 0,
          suspicious_tokens: 0,
          high_severity: 0,
          medium_severity: 0,
          low_severity: 0,
          token_distribution: {}
        }
      },
      syntax_analysis: {
        is_valid: true,
        complexity_score: 0,
        obfuscation_level: 'none',
        anomalies: [],
        suspicious_patterns: []
      },
      semantic_analysis: {
        threat_category: 'No Analysis',
        risk_score: 0,
        malicious_intent: {
          payload_download: false,
          persistence: false,
          privilege_escalation: false,
          data_exfiltration: false,
          system_modification: false,
          reconnaissance: false,
          lateral_movement: false,
          defense_evasion: false,
          details: []
        },
        evasion_techniques: {
          anti_forensic: false,
          log_deletion: false,
          process_hollowing: false,
          amsi_bypass: false,
          powershell_logging: false,
          timestomp: false,
          techniques: []
        },
        system_impact: {
          file_system_changes: false,
          registry_changes: false,
          network_activity: false,
          process_creation: false,
          service_modification: false,
          scheduled_tasks: false,
          impact_areas: []
        },
        attack_chain: []
      },
      summary: {
        main_threats: [],
        key_findings: [],
        attack_vector: 'Unknown',
        confidence: 'Low',
        action_required: 'Monitor'
      },
      recommendations: [],
      threat_level: 'MINIMAL',
      overall_risk: 0,
      timestamp: new Date().toISOString(),
      script_hash: ''
    };
  }

  /**
   * Calcula la puntuación de riesgo para cada fase
   */
  static getPhaseScore(phase, normalizedResult) {
    switch (phase) {
      case 'lexical': {
        const stats = normalizedResult.lexical_analysis.token_statistics;
        const lexicalRisk = (stats.high_severity * 10) + 
                           (stats.medium_severity * 5) + 
                           (stats.low_severity * 2);
        return Math.min(lexicalRisk, 100);
      }
      case 'syntax': {
        const syntax = normalizedResult.syntax_analysis;
        const syntaxRisk = syntax.complexity_score + 
                          (syntax.anomalies.length * 5) +
                          (!syntax.is_valid ? 20 : 0);
        return Math.min(syntaxRisk, 100);
      }
      case 'semantic':
        return normalizedResult.semantic_analysis.risk_score;
      default:
        return 0;
    }
  }

  /**
   * Determina el estado de una fase (crítico, advertencia, precaución, seguro)
   */
  static getPhaseStatus(phase, normalizedResult) {
    const score = this.getPhaseScore(phase, normalizedResult);
    
    if (score >= 70) {
      return { status: 'critical', color: 'text-red-600', severity: 'high' };
    }
    if (score >= 40) {
      return { status: 'warning', color: 'text-orange-600', severity: 'medium' };
    }
    if (score >= 20) {
      return { status: 'caution', color: 'text-yellow-600', severity: 'low' };
    }
    return { status: 'safe', color: 'text-green-600', severity: 'minimal' };
  }

  /**
   * Obtiene los colores para el nivel de amenaza
   */
  static getThreatLevelColors(level) {
    const colors = {
      'CRITICAL': {
        bg: 'bg-red-500',
        text: 'text-red-600',
        bgLight: 'bg-red-100',
        border: 'border-red-200'
      },
      'HIGH': {
        bg: 'bg-orange-500',
        text: 'text-orange-600',
        bgLight: 'bg-orange-100',
        border: 'border-orange-200'
      },
      'MEDIUM': {
        bg: 'bg-yellow-500',
        text: 'text-yellow-600',
        bgLight: 'bg-yellow-100',
        border: 'border-yellow-200'
      },
      'LOW': {
        bg: 'bg-blue-500',
        text: 'text-blue-600',
        bgLight: 'bg-blue-100',
        border: 'border-blue-200'
      },
      'MINIMAL': {
        bg: 'bg-green-500',
        text: 'text-green-600',
        bgLight: 'bg-green-100',
        border: 'border-green-200'
      }
    };
    return colors[level] || colors['MINIMAL'];
  }

  /**
   * Obtiene colores por severidad
   */
  static getSeverityColors(severity) {
    const colors = {
      high: 'text-red-600 bg-red-100',
      medium: 'text-orange-600 bg-orange-100',
      low: 'text-blue-600 bg-blue-100'
    };
    return colors[severity] || 'text-gray-600 bg-gray-100';
  }

  /**
   * Formatea el tipo de token para mostrar
   */
  static formatTokenType(type) {
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Cuenta las intenciones maliciosas activas
   */
  static countMaliciousIntents(maliciousIntent) {
    return Object.entries(maliciousIntent)
      .filter(([key, value]) => key !== 'details' && typeof value === 'boolean' && value)
      .length;
  }

  /**
   * Verifica si una recomendación es urgente
   */
  static isUrgentRecommendation(recommendation) {
    const urgentKeywords = ['ACCIÓN INMEDIATA', 'CRÍTICO', 'CRITICAL', 'IMMEDIATE'];
    return urgentKeywords.some(keyword => 
      recommendation.toUpperCase().includes(keyword)
    );
  }

  /**
   * Calcula el porcentaje de riesgo limitado a 100
   */
  static getRiskPercentage(score) {
    return Math.min(Math.max(score || 0, 0), 100);
  }

  /**
   * Obtiene información de íconos para intenciones maliciosas
   */
  static getIntentIconInfo(intentType) {
    const iconMap = {
      payload_download: 'Download',
      persistence: 'Key',
      privilege_escalation: 'TrendingUp',
      data_exfiltration: 'Database',
      reconnaissance: 'Eye',
      defense_evasion: 'Shield',
      system_modification: 'Settings',
      lateral_movement: 'Network'
    };
    return iconMap[intentType] || 'Activity';
  }

  /**
   * Valida si el resultado tiene datos suficientes para mostrar
   */
  static hasValidData(result) {
    if (!result) return false;
    
    const normalized = this.normalizeAnalysisResult(result);
    
    // Verificar si hay al menos algunos datos básicos
    return normalized.lexical_analysis.token_statistics.total_tokens > 0 ||
           normalized.syntax_analysis.anomalies.length > 0 ||
           normalized.semantic_analysis.risk_score > 0 ||
           normalized.recommendations.length > 0;
  }
}

export default AnalysisService;