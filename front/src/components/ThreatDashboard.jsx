
import React from 'react';
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Target, 
  Eye, 
  Download,
  Key,
  Database,
  Activity,
  Clock
} from 'lucide-react';

const ThreatDashboard = ({ result }) => {
  // Validaciones defensivas
  const safeResult = {
    ...result,
    lexical_analysis: {
      ...result.lexical_analysis,
      token_statistics: {
        high_severity: result.lexical_analysis?.token_statistics?.high_severity || 0,
        medium_severity: result.lexical_analysis?.token_statistics?.medium_severity || 0,
        low_severity: result.lexical_analysis?.token_statistics?.low_severity || 0,
        ...result.lexical_analysis?.token_statistics
      }
    },
    syntax_analysis: {
      complexity_score: result.syntax_analysis?.complexity_score || 0,
      ...result.syntax_analysis
    },
    semantic_analysis: {
      ...result.semantic_analysis,
      malicious_intent: result.semantic_analysis?.malicious_intent || {},
      threat_category: result.semantic_analysis?.threat_category || 'Unknown'
    },
    summary: {
      main_threats: result.summary?.main_threats || [],
      attack_vector: result.summary?.attack_vector || 'Unknown',
      confidence: result.summary?.confidence || 'Low',
      action_required: result.summary?.action_required || 'Monitor',
      ...result.summary
    },
    threat_level: result.threat_level || 'MINIMAL',
    overall_risk: result.overall_risk || 0,
    timestamp: result.timestamp || new Date().toISOString()
  };
  const getThreatLevelColor = (level) => {
    const colors = {
      'CRITICAL': 'bg-red-500',
      'HIGH': 'bg-orange-500',
      'MEDIUM': 'bg-yellow-500',
      'LOW': 'bg-blue-500',
      'MINIMAL': 'bg-green-500'
    };
    return colors[level] || 'bg-gray-500';
  };

  const getRiskPercentage = (score) => {
    return Math.min(score, 100);
  };

  const getIntentIcon = (intentType) => {
    const icons = {
      payload_download: Download,
      persistence: Key,
      privilege_escalation: TrendingUp,
      data_exfiltration: Database,
      reconnaissance: Eye,
      defense_evasion: Shield
    };
    return icons[intentType] || Activity;
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <Shield className="w-6 h-6 text-blue-600" />
          <h2 className="text-xl font-semibold text-gray-900">
            Dashboard de Amenazas
          </h2>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <Clock className="w-4 h-4" />
          <span>{new Date(result.timestamp).toLocaleString('es-ES')}</span>
        </div>
      </div>

      {/* Nivel de amenaza principal */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="md:col-span-1">
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-600">Nivel de Amenaza</span>
              <AlertTriangle className={`w-5 h-5 ${result.threat_level === 'CRITICAL' ? 'text-red-600' : 
                result.threat_level === 'HIGH' ? 'text-orange-600' :
                result.threat_level === 'MEDIUM' ? 'text-yellow-600' :
                result.threat_level === 'LOW' ? 'text-blue-600' : 'text-green-600'}`} />
            </div>
            <div className={`inline-flex px-3 py-1 rounded-full text-sm font-bold text-white ${getThreatLevelColor(result.threat_level)}`}>
              {result.threat_level}
            </div>
          </div>
        </div>

        <div className="md:col-span-2">
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-600">Puntuación de Riesgo</span>
              <TrendingUp className="w-5 h-5 text-gray-600" />
            </div>
            <div className="flex items-center space-x-3">
              <div className="flex-1 bg-gray-200 rounded-full h-3">
                <div 
                  className={`h-3 rounded-full transition-all duration-500 ${getThreatLevelColor(safeResult.threat_level)}`}
                  style={{ width: `${getRiskPercentage(safeResult.overall_risk)}%` }}
                ></div>
              </div>
              <span className="text-lg font-bold text-gray-900">
                {safeResult.overall_risk}/100
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Resumen ejecutivo */}
      <div className="mb-6">
        <h3 className="text-lg font-medium text-gray-900 mb-3">Resumen Ejecutivo</h3>
        <div className="bg-blue-50 rounded-lg p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-blue-900 mb-1">Categoría de Amenaza</div>
              <div className="text-blue-800">{result.semantic_analysis.threat_category}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-blue-900 mb-1">Vector de Ataque</div>
              <div className="text-blue-800">{result.summary.attack_vector}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-blue-900 mb-1">Nivel de Confianza</div>
              <div className="text-blue-800">{result.summary.confidence}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-blue-900 mb-1">Acción Requerida</div>
              <div className="text-blue-800 font-medium">{result.summary.action_required}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Intenciones maliciosas detectadas */}
      <div className="mb-6">
        <h3 className="text-lg font-medium text-gray-900 mb-3">Intenciones Maliciosas</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.entries(safeResult.semantic_analysis.malicious_intent).map(([key, value]) => {
            if (key === 'details' || typeof value !== 'boolean') return null;
            
            const IconComponent = getIntentIcon(key);
            const isActive = value;
            
            return (
              <div
                key={key}
                className={`p-3 rounded-lg border-2 transition-all ${
                  isActive 
                    ? 'border-red-200 bg-red-50' 
                    : 'border-gray-200 bg-gray-50'
                }`}
              >
                <div className="flex items-center space-x-2">
                  <IconComponent 
                    className={`w-4 h-4 ${isActive ? 'text-red-600' : 'text-gray-400'}`} 
                  />
                  <span className={`text-xs font-medium ${
                    isActive ? 'text-red-800' : 'text-gray-600'
                  }`}>
                    {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </span>
                </div>
                {isActive && (
                  <div className="mt-1">
                    <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Estadísticas de tokens */}
      <div className="mb-6">
        <h3 className="text-lg font-medium text-gray-900 mb-3">Análisis Léxico</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-red-50 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-red-600">
              {safeResult.lexical_analysis.token_statistics.high_severity}
            </div>
            <div className="text-xs text-red-800">Tokens Críticos</div>
          </div>
          <div className="bg-orange-50 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-orange-600">
              {safeResult.lexical_analysis.token_statistics.medium_severity}
            </div>
            <div className="text-xs text-orange-800">Severidad Media</div>
          </div>
          <div className="bg-blue-50 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-blue-600">
              {safeResult.lexical_analysis.token_statistics.low_severity}
            </div>
            <div className="text-xs text-blue-800">Severidad Baja</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-gray-600">
              {safeResult.syntax_analysis.complexity_score}
            </div>
            <div className="text-xs text-gray-800">Complejidad</div>
          </div>
        </div>
      </div>

      {/* Amenazas principales */}
      {safeResult.summary.main_threats.length > 0 && (
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-3">Amenazas Principales</h3>
          <div className="space-y-2">
            {safeResult.summary.main_threats.map((threat, index) => (
              <div key={index} className="flex items-center space-x-3 p-3 bg-red-50 rounded-lg">
                <Target className="w-5 h-5 text-red-600" />
                <span className="text-red-800 font-medium">{threat}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timestamp */}
      <div className="flex items-center space-x-2 text-sm text-gray-500">
        <Clock className="w-4 h-4" />
        <span>Análisis completado: {new Date(safeResult.timestamp).toLocaleString('es-ES')}</span>
      </div>
    </div>
  );
};

export default ThreatDashboard;