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
  Clock,
  Search,
  Code,
  Brain,
  CheckCircle,
  XCircle
} from 'lucide-react';
import AnalysisService from '../services/analysisService';

const ThreatDashboard = ({ result }) => {
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

  const getIntentIcon = (intentType) => {
    const iconName = AnalysisService.getIntentIconInfo(intentType);
    const icons = {
      Download,
      Key,
      TrendingUp,
      Database,
      Eye,
      Shield,
      Activity
    };
    return icons[iconName] || Activity;
  };

  const getPhaseIcon = (phase) => {
    const icons = { lexical: Search, syntax: Code, semantic: Brain };
    return icons[phase] || Activity;
  };

  const getPhaseStatusIcon = (status) => {
    return status === 'safe' ? CheckCircle : XCircle;
  };

  const PhaseCard = ({ phase, title, colorScheme }) => {
    const score = AnalysisService.getPhaseScore(phase, safeResult);
    const status = AnalysisService.getPhaseStatus(phase, safeResult);
    const percentage = AnalysisService.getRiskPercentage(score);
    const PhaseIcon = getPhaseIcon(phase);
    const StatusIcon = getPhaseStatusIcon(status.status);

    const colorClasses = {
      blue: 'from-blue-50 to-blue-100 border-blue-200',
      orange: 'from-orange-50 to-orange-100 border-orange-200',
      purple: 'from-purple-50 to-purple-100 border-purple-200'
    };

    const iconColors = {
      blue: 'text-blue-600',
      orange: 'text-orange-600',
      purple: 'text-purple-600'
    };

    const barColors = {
      blue: 'bg-blue-600',
      orange: 'bg-orange-600',
      purple: 'bg-purple-600'
    };

    const getPhaseSpecificData = () => {
      switch (phase) {
        case 'lexical':
          return {
            metric1: { label: 'Tokens Sospechosos', value: safeResult.lexical_analysis.token_statistics.suspicious_tokens },
            metric2: { label: 'Ofuscación', value: safeResult.lexical_analysis.obfuscation_level.toUpperCase() }
          };
        case 'syntax':
          return {
            metric1: { label: 'Sintaxis', value: safeResult.syntax_analysis.is_valid ? 'Válida' : 'Inválida' },
            metric2: { label: 'Anomalías', value: safeResult.syntax_analysis.anomalies.length }
          };
        case 'semantic':
          return {
            metric1: { 
              label: 'Categoría', 
              value: safeResult.semantic_analysis.threat_category.length > 12 
                ? safeResult.semantic_analysis.threat_category.substring(0, 12) + '...'
                : safeResult.semantic_analysis.threat_category
            },
            metric2: { 
              label: 'Intenciones', 
              value: AnalysisService.countMaliciousIntents(safeResult.semantic_analysis.malicious_intent)
            }
          };
        default:
          return { metric1: { label: '', value: '' }, metric2: { label: '', value: '' } };
      }
    };

    const phaseData = getPhaseSpecificData();

    return (
      <div className={`bg-gradient-to-br ${colorClasses[colorScheme]} rounded-lg p-4 border`}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <PhaseIcon className={`w-5 h-5 ${iconColors[colorScheme]}`} />
            <h3 className={`font-semibold ${iconColors[colorScheme].replace('text-', 'text-').replace('-600', '-900')}`}>
              {title}
            </h3>
          </div>
          <StatusIcon className={`w-5 h-5 ${status.color}`} />
        </div>
        
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className={iconColors[colorScheme].replace('-600', '-700')}>
              {phaseData.metric1.label}:
            </span>
            <span className={`font-semibold ${
              phase === 'syntax' && phaseData.metric1.value === 'Inválida' 
                ? 'text-red-600' 
                : phase === 'syntax' && phaseData.metric1.value === 'Válida'
                ? 'text-green-600'
                : iconColors[colorScheme].replace('-600', '-900')
            }`}>
              {phaseData.metric1.value}
            </span>
          </div>
          
          <div className="flex justify-between text-sm">
            <span className={iconColors[colorScheme].replace('-600', '-700')}>
              {phaseData.metric2.label}:
            </span>
            <span className={`font-semibold ${iconColors[colorScheme].replace('-600', '-900')}`}>
              {phaseData.metric2.value}
            </span>
          </div>
          
          <div className={`w-full ${colorScheme === 'blue' ? 'bg-blue-200' : colorScheme === 'orange' ? 'bg-orange-200' : 'bg-purple-200'} rounded-full h-2`}>
            <div 
              className={`${barColors[colorScheme]} h-2 rounded-full transition-all duration-500`}
              style={{ width: `${percentage}%` }}
            ></div>
          </div>
          
          <div className={`text-right text-xs ${iconColors[colorScheme]} font-medium`}>
            {score}/100
          </div>
        </div>
      </div>
    );
  };

  const threatColors = AnalysisService.getThreatLevelColors(safeResult.threat_level);

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
          <span>{new Date(safeResult.timestamp).toLocaleString('es-ES')}</span>
        </div>
      </div>

      {/* Resumen de las 3 fases */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <PhaseCard phase="lexical" title="Análisis Léxico" colorScheme="blue" />
        <PhaseCard phase="syntax" title="Análisis Sintáctico" colorScheme="orange" />
        <PhaseCard phase="semantic" title="Análisis Semántico" colorScheme="purple" />
      </div>

      {/* Nivel de amenaza principal */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-600">Nivel de Amenaza General</span>
            <AlertTriangle className={`w-5 h-5 ${threatColors.text}`} />
          </div>
          <div className={`inline-flex px-4 py-2 rounded-full text-lg font-bold text-white ${threatColors.bg}`}>
            {safeResult.threat_level}
          </div>
        </div>

        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-600">Puntuación de Riesgo Global</span>
            <TrendingUp className="w-5 h-5 text-gray-600" />
          </div>
          <div className="flex items-center space-x-3">
            <div className="flex-1 bg-gray-200 rounded-full h-4">
              <div 
                className={`h-4 rounded-full transition-all duration-500 ${threatColors.bg}`}
                style={{ width: `${AnalysisService.getRiskPercentage(safeResult.overall_risk)}%` }}
              ></div>
            </div>
            <span className="text-xl font-bold text-gray-900">
              {safeResult.overall_risk}/100
            </span>
          </div>
        </div>
      </div>

      {/* Resumen ejecutivo */}
      <div className="mb-6">
        <h3 className="text-lg font-medium text-gray-900 mb-3">Resumen Ejecutivo</h3>
        <div className="bg-blue-50 rounded-lg p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-blue-900 mb-1">Vector de Ataque</div>
              <div className="text-blue-800">{safeResult.summary.attack_vector}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-blue-900 mb-1">Nivel de Confianza</div>
              <div className="text-blue-800">{safeResult.summary.confidence}</div>
            </div>
            <div className="md:col-span-2">
              <div className="text-sm font-medium text-blue-900 mb-1">Acción Requerida</div>
              <div className="text-blue-800 font-medium">{safeResult.summary.action_required}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Amenazas principales */}
      {safeResult.summary.main_threats.length > 0 && (
        <div className="mb-4">
          <h3 className="text-lg font-medium text-gray-900 mb-3">Amenazas Principales</h3>
          <div className="space-y-2">
            {safeResult.summary.main_threats.slice(0, 3).map((threat, index) => (
              <div key={index} className="flex items-center space-x-3 p-3 bg-red-50 rounded-lg border border-red-200">
                <Target className="w-5 h-5 text-red-600" />
                <span className="text-red-800 font-medium">{threat}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatDashboard;