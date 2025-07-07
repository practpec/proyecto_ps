import React, { useState } from 'react';
import { 
  ChevronDown, 
  ChevronRight, 
  Code, 
  AlertTriangle, 
  Brain,
  FileText,
  Shield,
  Target,
  CheckCircle,
  XCircle,
  Info
} from 'lucide-react';

const AnalysisResults = ({ result }) => {
  const [expandedSections, setExpandedSections] = useState({
    lexical: true,
    syntax: false,
    semantic: false,
    recommendations: false,
    attackChain: false
  });

  // Validaciones defensivas para evitar errores de null/undefined
  const safeResult = {
    ...result,
    lexical_analysis: {
      ...result.lexical_analysis,
      critical_tokens: result.lexical_analysis?.critical_tokens || [],
      token_statistics: {
        ...result.lexical_analysis?.token_statistics,
        token_distribution: result.lexical_analysis?.token_statistics?.token_distribution || {}
      }
    },
    syntax_analysis: {
      ...result.syntax_analysis,
      anomalies: result.syntax_analysis?.anomalies || [],
      suspicious_patterns: result.syntax_analysis?.suspicious_patterns || []
    },
    semantic_analysis: {
      ...result.semantic_analysis,
      evasion_techniques: {
        ...result.semantic_analysis?.evasion_techniques,
        techniques: result.semantic_analysis?.evasion_techniques?.techniques || []
      },
      attack_chain: result.semantic_analysis?.attack_chain || [],
      system_impact: result.semantic_analysis?.system_impact || {}
    },
    recommendations: result.recommendations || []
  };

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const getSeverityColor = (severity) => {
    const colors = {
      high: 'text-red-600 bg-red-100',
      medium: 'text-orange-600 bg-orange-100',
      low: 'text-blue-600 bg-blue-100'
    };
    return colors[severity] || 'text-gray-600 bg-gray-100';
  };

  const getTokenTypeDisplay = (type) => {
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const CollapsibleSection = ({ title, icon: Icon, isExpanded, onToggle, children, badge }) => (
    <div className="bg-white rounded-lg shadow-sm border mb-4">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-center space-x-3">
          <Icon className="w-5 h-5 text-gray-600" />
          <h3 className="text-lg font-medium text-gray-900">{title}</h3>
          {badge && (
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${badge.color}`}>
              {badge.text}
            </span>
          )}
        </div>
        {isExpanded ? (
          <ChevronDown className="w-5 h-5 text-gray-400" />
        ) : (
          <ChevronRight className="w-5 h-5 text-gray-400" />
        )}
      </button>
      
      {isExpanded && (
        <div className="px-4 pb-4 border-t border-gray-100">
          {children}
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Análisis Léxico */}
      <CollapsibleSection
        title="Análisis Léxico"
        icon={Code}
        isExpanded={expandedSections.lexical}
        onToggle={() => toggleSection('syntax')}
        badge={{
          text: `${safeResult.syntax_analysis.anomalies.length} anomalías`,
          color: safeResult.syntax_analysis.anomalies.length > 0 ? 'text-orange-600 bg-orange-100' : 'text-green-600 bg-green-100'
        }}
      >
        <div className="space-y-4 mt-4">
          {/* Estado de sintaxis */}
          <div className="flex items-center space-x-2 p-3 rounded-lg bg-gray-50">
            {safeResult.syntax_analysis.is_valid ? (
              <CheckCircle className="w-5 h-5 text-green-600" />
            ) : (
              <XCircle className="w-5 h-5 text-red-600" />
            )}
            <span className="text-sm font-medium">
              Sintaxis {safeResult.syntax_analysis.is_valid ? 'Válida' : 'Inválida'}
            </span>
          </div>

          {/* Anomalías sintácticas */}
          {safeResult.syntax_analysis.anomalies.length > 0 && (
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Anomalías Detectadas</h4>
              <div className="space-y-2">
                {safeResult.syntax_analysis.anomalies.map((anomaly, index) => (
                  <div key={index} className="p-3 bg-orange-50 rounded-lg">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="text-sm font-medium text-orange-800">{anomaly.description}</div>
                        <div className="text-xs text-orange-600 mt-1">Posición: {anomaly.position}</div>
                      </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(anomaly.severity)}`}>
                        {anomaly.severity.toUpperCase()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Patrones sospechosos */}
          {safeResult.syntax_analysis.suspicious_patterns.length > 0 && (
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Patrones Sospechosos</h4>
              <div className="space-y-2">
                {safeResult.syntax_analysis.suspicious_patterns.map((pattern, index) => (
                  <div key={index} className="p-3 bg-yellow-50 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-medium text-yellow-800">{pattern.description}</div>
                        <div className="text-xs text-yellow-600">Encontrado {pattern.count} veces</div>
                      </div>
                      <span className="text-xs font-medium text-yellow-800 uppercase">
                        {pattern.risk_level}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Métricas de complejidad */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-blue-50 rounded-lg text-center">
              <div className="text-lg font-bold text-blue-600">{safeResult.syntax_analysis.complexity_score || 0}</div>
              <div className="text-xs text-blue-800">Puntuación de Complejidad</div>
            </div>
            <div className="p-3 bg-purple-50 rounded-lg text-center">
              <div className="text-lg font-bold text-purple-600">{(safeResult.syntax_analysis.obfuscation_level || 'none').toUpperCase()}</div>
              <div className="text-xs text-purple-800">Nivel de Ofuscación</div>
            </div>
          </div>
        </div>
      </CollapsibleSection>

      {/* Análisis Semántico */}
      <CollapsibleSection
        title="Análisis Semántico"
        icon={Brain}
        isExpanded={expandedSections.semantic}
        onToggle={() => toggleSection('semantic')}
        badge={{
          text: safeResult.semantic_analysis.threat_category || 'Análisis Semántico',
          color: 'text-purple-600 bg-purple-100'
        }}
      >
        <div className="space-y-4 mt-4">
          {/* Técnicas de evasión */}
          {safeResult.semantic_analysis.evasion_techniques.techniques.length > 0 && (
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Técnicas de Evasión</h4>
              <div className="grid grid-cols-2 gap-2">
                {safeResult.semantic_analysis.evasion_techniques.techniques.map((technique, index) => (
                  <div key={index} className="flex items-center space-x-2 p-2 bg-red-50 rounded">
                    <Shield className="w-4 h-4 text-red-600" />
                    <span className="text-sm text-red-800">
                      {technique.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Impacto en el sistema */}
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Impacto en el Sistema</h4>
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(safeResult.semantic_analysis.system_impact).map(([key, value]) => {
                if (key === 'impact_areas' || typeof value !== 'boolean') return null;
                
                return (
                  <div key={key} className={`flex items-center space-x-2 p-2 rounded ${
                    value ? 'bg-red-50' : 'bg-gray-50'
                  }`}>
                    {value ? (
                      <XCircle className="w-4 h-4 text-red-600" />
                    ) : (
                      <CheckCircle className="w-4 h-4 text-gray-400" />
                    )}
                    <span className={`text-sm ${value ? 'text-red-800' : 'text-gray-600'}`}>
                      {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Puntuación de riesgo semántico */}
          <div className="p-4 bg-gradient-to-r from-red-50 to-orange-50 rounded-lg">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-900">Puntuación de Riesgo Semántico</span>
              <span className="text-2xl font-bold text-red-600">{safeResult.semantic_analysis.risk_score || 0}/100</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
              <div 
                className="bg-gradient-to-r from-red-500 to-orange-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(safeResult.semantic_analysis.risk_score || 0, 100)}%` }}
              ></div>
            </div>
          </div>
        </div>
      </CollapsibleSection>

      {/* Cadena de ataque */}
      {safeResult.semantic_analysis.attack_chain.length > 0 && (
        <CollapsibleSection
          title="Cadena de Ataque (MITRE ATT&CK)"
          icon={Target}
          isExpanded={expandedSections.attackChain}
          onToggle={() => toggleSection('attackChain')}
          badge={{
            text: `${safeResult.semantic_analysis.attack_chain.length} fases`,
            color: 'text-red-600 bg-red-100'
          }}
        >
          <div className="space-y-3 mt-4">
            {safeResult.semantic_analysis.attack_chain.map((step, index) => (
              <div key={index} className="relative">
                <div className="flex items-start space-x-4 p-4 bg-red-50 rounded-lg">
                  <div className="flex-shrink-0 w-8 h-8 bg-red-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                    {index + 1}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <h5 className="font-medium text-red-900">{step.phase}</h5>
                      <span className="px-2 py-1 bg-red-200 text-red-800 text-xs rounded font-mono">
                        {step.mitre_att || 'N/A'}
                      </span>
                    </div>
                    <div className="text-sm text-red-800 font-medium mb-1">{step.technique}</div>
                    <div className="text-sm text-red-700">{step.description}</div>
                  </div>
                </div>
                {index < safeResult.semantic_analysis.attack_chain.length - 1 && (
                  <div className="flex justify-center py-2">
                    <ChevronDown className="w-5 h-5 text-red-400" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Recomendaciones */}
      <CollapsibleSection
        title="Recomendaciones de Seguridad"
        icon={Info}
        isExpanded={expandedSections.recommendations}
        onToggle={() => toggleSection('recommendations')}
        badge={{
          text: `${safeResult.recommendations.length} recomendaciones`,
          color: 'text-blue-600 bg-blue-100'
        }}
      >
        <div className="space-y-3 mt-4">
          {safeResult.recommendations.map((recommendation, index) => {
            const isUrgent = recommendation.includes('IMMEDIATE') || recommendation.includes('CRITICAL');
            
            return (
              <div key={index} className={`p-3 rounded-lg border-l-4 ${
                isUrgent 
                  ? 'bg-red-50 border-red-400' 
                  : 'bg-blue-50 border-blue-400'
              }`}>
                <div className="flex items-start space-x-2">
                  {isUrgent ? (
                    <AlertTriangle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
                  ) : (
                    <Info className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                  )}
                  <span className={`text-sm ${isUrgent ? 'text-red-800' : 'text-blue-800'}`}>
                    {recommendation}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </CollapsibleSection>
    </div>
  );
};

export default AnalysisResults;