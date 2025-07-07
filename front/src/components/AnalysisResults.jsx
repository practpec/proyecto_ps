import React, { useState } from 'react';
import { 
  ChevronDown, 
  ChevronRight, 
  Code, 
  AlertTriangle, 
  Brain,
  Shield,
  Target,
  CheckCircle,
  XCircle,
  Info,
  Search
} from 'lucide-react';
import AnalysisService from '../services/analysisService';

const AnalysisResults = ({ result }) => {
  const [expandedSections, setExpandedSections] = useState({
    lexical: true,
    syntax: true,
    semantic: true,
    recommendations: false,
    attackChain: false
  });

  // Validación inicial para evitar errores si result es null/undefined
  if (!result) {
    return (
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="text-center text-gray-500">
          <p>No hay resultados de análisis disponibles</p>
        </div>
      </div>
    );
  }

  // Normalizar los datos usando el servicio
  const safeResult = AnalysisService.normalizeAnalysisResult(result);

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const CollapsibleSection = ({ title, icon: Icon, isExpanded, onToggle, children, badge, colorScheme = 'blue' }) => {
    const colorClasses = {
      blue: 'text-blue-600 bg-blue-50 border-blue-200',
      orange: 'text-orange-600 bg-orange-50 border-orange-200',
      purple: 'text-purple-600 bg-purple-50 border-purple-200',
      green: 'text-green-600 bg-green-50 border-green-200',
      red: 'text-red-600 bg-red-50 border-red-200'
    };

    const hoverClasses = {
      blue: 'hover:bg-blue-50',
      orange: 'hover:bg-orange-50',
      purple: 'hover:bg-purple-50',
      green: 'hover:bg-green-50',
      red: 'hover:bg-red-50'
    };

    return (
      <div className="bg-white rounded-lg shadow-sm border mb-6">
        <button
          onClick={onToggle}
          className={`w-full flex items-center justify-between p-4 text-left ${hoverClasses[colorScheme]} transition-colors rounded-t-lg`}
        >
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg ${colorClasses[colorScheme]}`}>
              <Icon className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold text-gray-900">{title}</h3>
            {badge && (
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${badge.color}`}>
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
          <div className="px-6 pb-6 border-t border-gray-100">
            {children}
          </div>
        )}
      </div>
    );
  };

  // Componente para mostrar tokens críticos
  const CriticalTokensList = ({ tokens }) => (
    <div>
      <h4 className="font-semibold text-gray-900 mb-3">Tokens Críticos Detectados</h4>
      <div className="space-y-2">
        {tokens.slice(0, 10).map((token, index) => (
          <div key={index} className="p-3 bg-red-50 rounded-lg border border-red-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="font-mono text-sm bg-red-100 px-2 py-1 rounded">
                  {token.value}
                </span>
                <span className="text-sm text-red-700">
                  {AnalysisService.formatTokenType(token.type)}
                </span>
              </div>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${AnalysisService.getSeverityColors(token.severity)}`}>
                {token.severity?.toUpperCase()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  // Componente para mostrar anomalías sintácticas
  const SyntaxAnomaliesList = ({ anomalies }) => (
    <div>
      <h4 className="font-semibold text-gray-900 mb-3">Anomalías Detectadas</h4>
      <div className="space-y-2">
        {anomalies.map((anomaly, index) => (
          <div key={index} className="p-3 bg-orange-50 rounded-lg border border-orange-200">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="text-sm font-medium text-orange-800">{anomaly.description}</div>
                <div className="text-xs text-orange-600 mt-1">Posición: {anomaly.position}</div>
              </div>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${AnalysisService.getSeverityColors(anomaly.severity)}`}>
                {anomaly.severity?.toUpperCase()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  // Componente para mostrar patrones sospechosos
  const SuspiciousPatternsList = ({ patterns }) => (
    <div>
      <h4 className="font-semibold text-gray-900 mb-3">Patrones Sospechosos</h4>
      <div className="space-y-2">
        {patterns.map((pattern, index) => (
          <div key={index} className="p-3 bg-yellow-50 rounded-lg border border-yellow-200">
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
  );

  // Componente para mostrar intenciones maliciosas
  const MaliciousIntentGrid = ({ maliciousIntent }) => (
    <div>
      <h4 className="font-semibold text-gray-900 mb-3">Intenciones Maliciosas Detectadas</h4>
      <div className="grid grid-cols-2 gap-2">
        {Object.entries(maliciousIntent).map(([key, value]) => {
          if (key === 'details' || typeof value !== 'boolean') return null;
          
          return (
            <div key={key} className={`flex items-center space-x-2 p-3 rounded ${
              value ? 'bg-red-50 border border-red-200' : 'bg-gray-50'
            }`}>
              {value ? (
                <XCircle className="w-4 h-4 text-red-600" />
              ) : (
                <CheckCircle className="w-4 h-4 text-gray-400" />
              )}
              <span className={`text-sm ${value ? 'text-red-800 font-medium' : 'text-gray-600'}`}>
                {AnalysisService.formatTokenType(key)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );

  // Componente para mostrar técnicas de evasión
  const EvasionTechniquesList = ({ techniques }) => (
    <div>
      <h4 className="font-semibold text-gray-900 mb-3">Técnicas de Evasión</h4>
      <div className="grid grid-cols-2 gap-2">
        {techniques.map((technique, index) => (
          <div key={index} className="flex items-center space-x-2 p-2 bg-red-50 rounded border border-red-200">
            <Shield className="w-4 h-4 text-red-600" />
            <span className="text-sm text-red-800 font-medium">
              {AnalysisService.formatTokenType(technique)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );

  // Componente para mostrar impacto en el sistema
  const SystemImpactGrid = ({ systemImpact }) => (
    <div>
      <h4 className="font-semibold text-gray-900 mb-3">Impacto en el Sistema</h4>
      <div className="grid grid-cols-2 gap-2">
        {Object.entries(systemImpact).map(([key, value]) => {
          if (key === 'impact_areas' || typeof value !== 'boolean') return null;
          
          return (
            <div key={key} className={`flex items-center space-x-2 p-2 rounded ${
              value ? 'bg-orange-50 border border-orange-200' : 'bg-gray-50'
            }`}>
              {value ? (
                <AlertTriangle className="w-4 h-4 text-orange-600" />
              ) : (
                <CheckCircle className="w-4 h-4 text-gray-400" />
              )}
              <span className={`text-sm ${value ? 'text-orange-800 font-medium' : 'text-gray-600'}`}>
                {AnalysisService.formatTokenType(key)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* 1. ANÁLISIS LÉXICO */}
      <CollapsibleSection
        title="1. Análisis Léxico"
        icon={Search}
        isExpanded={expandedSections.lexical}
        onToggle={() => toggleSection('lexical')}
        colorScheme="blue"
        badge={{
          text: `${safeResult.lexical_analysis.token_statistics.suspicious_tokens} tokens sospechosos`,
          color: safeResult.lexical_analysis.token_statistics.suspicious_tokens > 0 
            ? 'text-red-600 bg-red-100' 
            : 'text-green-600 bg-green-100'
        }}
      >
        <div className="space-y-6 mt-6">
          {/* Descripción */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-start space-x-2">
              <Info className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-blue-800">
                <p className="font-medium mb-1">Análisis de tokens y patrones:</p>
                <p>Identifica palabras clave, comandos sospechosos y patrones de ofuscación en el código.</p>
              </div>
            </div>
          </div>

          {/* Estadísticas de tokens */}
          <div>
            <h4 className="font-semibold text-gray-900 mb-3">Estadísticas de Tokens</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 bg-gray-50 rounded-lg text-center">
                <div className="text-lg font-bold text-gray-600">
                  {safeResult.lexical_analysis.token_statistics.total_tokens}
                </div>
                <div className="text-xs text-gray-800">Total Tokens</div>
              </div>
              <div className="p-3 bg-red-50 rounded-lg text-center">
                <div className="text-lg font-bold text-red-600">
                  {safeResult.lexical_analysis.token_statistics.high_severity}
                </div>
                <div className="text-xs text-red-800">Alta Severidad</div>
              </div>
              <div className="p-3 bg-orange-50 rounded-lg text-center">
                <div className="text-lg font-bold text-orange-600">
                  {safeResult.lexical_analysis.token_statistics.medium_severity}
                </div>
                <div className="text-xs text-orange-800">Media Severidad</div>
              </div>
              <div className="p-3 bg-blue-50 rounded-lg text-center">
                <div className="text-lg font-bold text-blue-600">
                  {safeResult.lexical_analysis.token_statistics.low_severity}
                </div>
                <div className="text-xs text-blue-800">Baja Severidad</div>
              </div>
            </div>
          </div>

          {/* Tokens críticos */}
          {safeResult.lexical_analysis.critical_tokens.length > 0 && (
            <CriticalTokensList tokens={safeResult.lexical_analysis.critical_tokens} />
          )}

          {/* Nivel de ofuscación */}
          <div className="p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-900">Nivel de Ofuscación</span>
              <span className="text-xl font-bold text-blue-600">
                {safeResult.lexical_analysis.obfuscation_level.toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      </CollapsibleSection>

      {/* 2. ANÁLISIS SINTÁCTICO */}
      <CollapsibleSection
        title="2. Análisis Sintáctico"
        icon={Code}
        isExpanded={expandedSections.syntax}
        onToggle={() => toggleSection('syntax')}
        colorScheme="orange"
        badge={{
          text: `${safeResult.syntax_analysis.anomalies.length} anomalías`,
          color: safeResult.syntax_analysis.anomalies.length > 0 
            ? 'text-orange-600 bg-orange-100' 
            : 'text-green-600 bg-green-100'
        }}
      >
        <div className="space-y-6 mt-6">
          {/* Descripción */}
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <div className="flex items-start space-x-2">
              <Info className="w-5 h-5 text-orange-600 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-orange-800">
                <p className="font-medium mb-1">Análisis de estructura y sintaxis:</p>
                <p>Evalúa la validez del código, detecta anomalías sintácticas y patrones de evasión estructurales.</p>
              </div>
            </div>
          </div>

          {/* Estado de sintaxis */}
          <div className="flex items-center space-x-2 p-4 rounded-lg bg-gray-50">
            {safeResult.syntax_analysis.is_valid ? (
              <CheckCircle className="w-6 h-6 text-green-600" />
            ) : (
              <XCircle className="w-6 h-6 text-red-600" />
            )}
            <span className="text-lg font-medium">
              Sintaxis {safeResult.syntax_analysis.is_valid ? 'Válida' : 'Inválida'}
            </span>
          </div>

          {/* Métricas de complejidad */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-orange-50 rounded-lg text-center">
              <div className="text-2xl font-bold text-orange-600">
                {safeResult.syntax_analysis.complexity_score}
              </div>
              <div className="text-sm text-orange-800">Puntuación de Complejidad</div>
            </div>
            <div className="p-4 bg-purple-50 rounded-lg text-center">
              <div className="text-2xl font-bold text-purple-600">
                {safeResult.syntax_analysis.obfuscation_level.toUpperCase()}
              </div>
              <div className="text-sm text-purple-800">Ofuscación Sintáctica</div>
            </div>
          </div>

          {/* Anomalías sintácticas */}
          {safeResult.syntax_analysis.anomalies.length > 0 && (
            <SyntaxAnomaliesList anomalies={safeResult.syntax_analysis.anomalies} />
          )}

          {/* Patrones sospechosos */}
          {safeResult.syntax_analysis.suspicious_patterns.length > 0 && (
            <SuspiciousPatternsList patterns={safeResult.syntax_analysis.suspicious_patterns} />
          )}
        </div>
      </CollapsibleSection>

      {/* 3. ANÁLISIS SEMÁNTICO */}
      <CollapsibleSection
        title="3. Análisis Semántico"
        icon={Brain}
        isExpanded={expandedSections.semantic}
        onToggle={() => toggleSection('semantic')}
        colorScheme="purple"
        badge={{
          text: safeResult.semantic_analysis.threat_category,
          color: 'text-purple-600 bg-purple-100'
        }}
      >
        <div className="space-y-6 mt-6">
          {/* Descripción */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <div className="flex items-start space-x-2">
              <Info className="w-5 h-5 text-purple-600 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-purple-800">
                <p className="font-medium mb-1">Análisis de comportamiento y significado:</p>
                <p>Evalúa la intención maliciosa, técnicas de evasión e impacto potencial en el sistema.</p>
              </div>
            </div>
          </div>

          {/* Puntuación de riesgo semántico */}
          <div className="p-4 bg-gradient-to-r from-purple-50 to-pink-50 rounded-lg">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-900">Puntuación de Riesgo Semántico</span>
              <span className="text-2xl font-bold text-purple-600">
                {safeResult.semantic_analysis.risk_score}/100
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-3 mt-2">
              <div 
                className="bg-gradient-to-r from-purple-500 to-pink-500 h-3 rounded-full transition-all duration-500"
                style={{ width: `${AnalysisService.getRiskPercentage(safeResult.semantic_analysis.risk_score)}%` }}
              ></div>
            </div>
          </div>

          {/* Intenciones maliciosas */}
          <MaliciousIntentGrid maliciousIntent={safeResult.semantic_analysis.malicious_intent} />

          {/* Técnicas de evasión */}
          {safeResult.semantic_analysis.evasion_techniques.techniques.length > 0 && (
            <EvasionTechniquesList techniques={safeResult.semantic_analysis.evasion_techniques.techniques} />
          )}

          {/* Impacto en el sistema */}
          <SystemImpactGrid systemImpact={safeResult.semantic_analysis.system_impact} />
        </div>
      </CollapsibleSection>

      {/* Cadena de ataque */}
      {safeResult.semantic_analysis.attack_chain.length > 0 && (
        <CollapsibleSection
          title="Cadena de Ataque (MITRE ATT&CK)"
          icon={Target}
          isExpanded={expandedSections.attackChain}
          onToggle={() => toggleSection('attackChain')}
          colorScheme="red"
          badge={{
            text: `${safeResult.semantic_analysis.attack_chain.length} fases`,
            color: 'text-red-600 bg-red-100'
          }}
        >
          <div className="space-y-3 mt-6">
            {safeResult.semantic_analysis.attack_chain.map((step, index) => (
              <div key={index} className="relative">
                <div className="flex items-start space-x-4 p-4 bg-red-50 rounded-lg border border-red-200">
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
        colorScheme="green"
        badge={{
          text: `${safeResult.recommendations.length} recomendaciones`,
          color: 'text-green-600 bg-green-100'
        }}
      >
        <div className="space-y-3 mt-6">
          {safeResult.recommendations.map((recommendation, index) => {
            const isUrgent = AnalysisService.isUrgentRecommendation(recommendation);
            
            return (
              <div key={index} className={`p-4 rounded-lg border-l-4 ${
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