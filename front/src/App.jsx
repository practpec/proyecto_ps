import React, { useState } from 'react';
import ScriptInput from './components/ScriptInput';
import ScriptInputUnoptimized from './components/ScriptInputUnoptimized';
import AnalysisResults from './components/AnalysisResults';
import ThreatDashboard from './components/ThreatDashboard';
import { Shield, AlertTriangle, Activity, Search, Code, Brain } from 'lucide-react';
import ApiService from './services/apiService';
import AnalysisService from './services/analysisService';
import { simulateCPUStress, simulateMemoryStress } from './services/stressSimulator';

function App() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeScript = async (script) => {
    setIsLoading(true);
    setError(null);
    
    try {
      // Validar el script antes de enviarlo
      const validation = ApiService.validateScript(script);
      
      if (!validation.isValid) {
        throw new Error(validation.errors.join(', '));
      }

      // Mostrar advertencias si las hay
      if (validation.warnings.length > 0) {
        console.warn('Advertencias del script:', validation.warnings);
      }

      // Realizar el análisis
      const result = await ApiService.analyzeScript(script);
      
      // Verificar que el resultado tenga datos válidos
      if (!AnalysisService.hasValidData(result)) {
        console.warn('El resultado del análisis parece estar vacío o incompleto');
      }

      setAnalysisResult(result);
    } catch (err) {
      setError(err.message);
      console.error('Error en el análisis:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const analyzeScriptUnoptimized = async (script) => {
    setIsLoading(true);
    setError(null);
    
    try {
      // Validar el script antes de enviarlo
      const validation = ApiService.validateScript(script);
      
      if (!validation.isValid) {
        throw new Error(validation.errors.join(', '));
      }

      // Mostrar advertencias si las hay
      if (validation.warnings.length > 0) {
        console.warn('Advertencias del script:', validation.warnings);
      }

      // Realizar el análisis
      const result = await ApiService.analyzeScriptUnoptimized(script);

      simulateCPUStress(3000);      // Simula 3 segundos de carga de CPU.
      simulateMemoryStress(300, 3000)
      
      // Verificar que el resultado tenga datos válidos
      if (!AnalysisService.hasValidData(result)) {
        console.warn('El resultado del análisis parece estar vacío o incompleto');
      }

      setAnalysisResult(result);
    } catch (err) {
      setError(err.message);
      console.error('Error en el análisis:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Obtener colores del nivel de amenaza usando el servicio
  const getThreatLevelColors = (level) => {
    return AnalysisService.getThreatLevelColors(level);
  };

  // Obtener datos normalizados para mostrar en el header
  const getHeaderData = () => {
    if (!analysisResult) return null;
    
    const normalized = AnalysisService.normalizeAnalysisResult(analysisResult);
    const colors = getThreatLevelColors(normalized.threat_level);
    
    return {
      threatLevel: normalized.threat_level,
      colors: colors,
      lexicalScore: AnalysisService.getPhaseScore('lexical', normalized),
      syntaxScore: AnalysisService.getPhaseScore('syntax', normalized),
      semanticScore: AnalysisService.getPhaseScore('semantic', normalized)
    };
  };

  const headerData = getHeaderData();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">
                  PowerShell Malware Analyzer
                </h1>
                <p className="text-sm text-gray-500">
                  Análisis en 3 fases: Léxico → Sintáctico → Semántico
                </p>
              </div>
            </div>
            
            {/* Indicadores de análisis */}
            {headerData && (
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2 text-sm">
                  <Search className="w-4 h-4 text-blue-600" />
                  <span className="text-blue-600 font-medium">
                    Léxico ({headerData.lexicalScore})
                  </span>
                </div>
                <div className="flex items-center space-x-2 text-sm">
                  <Code className="w-4 h-4 text-orange-600" />
                  <span className="text-orange-600 font-medium">
                    Sintáctico ({headerData.syntaxScore})
                  </span>
                </div>
                <div className="flex items-center space-x-2 text-sm">
                  <Brain className="w-4 h-4 text-purple-600" />
                  <span className="text-purple-600 font-medium">
                    Semántico ({headerData.semanticScore})
                  </span>
                </div>
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${headerData.colors.text} ${headerData.colors.bgLight}`}>
                  <div className="flex items-center space-x-1">
                    <AlertTriangle className="w-4 h-4" />
                    <span>{headerData.threatLevel}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Input Section */}
          <div className="lg:col-span-1">
            <ScriptInput 
              onAnalyze={analyzeScript} 
              isLoading={isLoading}
            />
            <ScriptInputUnoptimized
            onAnalyze={analyzeScriptUnoptimized}
            isLoading={isLoading}
            />
            
            {/* Error Display */}
            {error && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                  <span className="text-red-800 font-medium">Error de Análisis</span>
                </div>
                <p className="text-red-700 mt-1">{error}</p>
                <div className="mt-3 text-sm text-red-600">
                  <p>Posibles soluciones:</p>
                  <ul className="list-disc list-inside mt-1 space-y-1">
                    <li>Verifica que el backend esté ejecutándose en http://localhost:8080</li>
                    <li>Asegúrate de que el script no esté vacío</li>
                    <li>Intenta con un script más pequeño si es muy grande</li>
                  </ul>
                </div>
              </div>
            )}

            {/* Información sobre las fases de análisis */}
            <div className="mt-6 bg-white rounded-lg border p-4">
              <h3 className="text-lg font-medium text-gray-900 mb-3">Fases del Análisis</h3>
              <div className="space-y-3">
                <div className="flex items-start space-x-3">
                  <div className="p-2 bg-blue-50 rounded-lg">
                    <Search className="w-4 h-4 text-blue-600" />
                  </div>
                  <div>
                    <h4 className="font-medium text-blue-900">1. Análisis Léxico</h4>
                    <p className="text-sm text-blue-700">Identifica tokens, palabras clave y patrones de ofuscación</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="p-2 bg-orange-50 rounded-lg">
                    <Code className="w-4 h-4 text-orange-600" />
                  </div>
                  <div>
                    <h4 className="font-medium text-orange-900">2. Análisis Sintáctico</h4>
                    <p className="text-sm text-orange-700">Evalúa estructura, validez y anomalías del código</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="p-2 bg-purple-50 rounded-lg">
                    <Brain className="w-4 h-4 text-purple-600" />
                  </div>
                  <div>
                    <h4 className="font-medium text-purple-900">3. Análisis Semántico</h4>
                    <p className="text-sm text-purple-700">Determina intención maliciosa e impacto del comportamiento</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Estado de conexión */}
            <div className="mt-4 p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">Estado del servidor:</span>
                <div className="flex items-center space-x-2">
                  <div className={`w-2 h-2 rounded-full ${error ? 'bg-red-500' : 'bg-green-500'}`}></div>
                  <span className={error ? 'text-red-600' : 'text-green-600'}>
                    {error ? 'Desconectado' : 'Conectado'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Results Section */}
          <div className="lg:col-span-2">
            {analysisResult ? (
              <div className="space-y-6">
                <ThreatDashboard result={analysisResult} />
                <AnalysisResults result={analysisResult} />
              </div>
            ) : (
              <div className="bg-white rounded-lg border-2 border-dashed border-gray-300 p-12 text-center">
                <Activity className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Listo para analizar
                </h3>
                <p className="text-gray-500 mb-4">
                  Ingresa un script PowerShell para comenzar el análisis de seguridad
                </p>
                <div className="flex items-center justify-center space-x-6 text-sm text-gray-400">
                  <div className="flex items-center space-x-1">
                    <Search className="w-4 h-4" />
                    <span>Léxico</span>
                  </div>
                  <span>→</span>
                  <div className="flex items-center space-x-1">
                    <Code className="w-4 h-4" />
                    <span>Sintáctico</span>
                  </div>
                  <span>→</span>
                  <div className="flex items-center space-x-1">
                    <Brain className="w-4 h-4" />
                    <span>Semántico</span>
                  </div>
                </div>
                
                {/* Información adicional */}
                <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                  <h4 className="font-medium text-blue-900 mb-2">¿Cómo funciona?</h4>
                  <div className="text-sm text-blue-800 space-y-1">
                    <p>• <strong>Léxico:</strong> Detecta comandos maliciosos y ofuscación</p>
                    <p>• <strong>Sintáctico:</strong> Analiza la estructura y complejidad del código</p>
                    <p>• <strong>Semántico:</strong> Evalúa la intención y el comportamiento malicioso</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">
              PowerShell Malware Analyzer - Herramienta de análisis de seguridad
            </div>
            <div className="flex items-center space-x-4 text-sm text-gray-500">
              <span>Backend: Go</span>
              <span>•</span>
              <span>Frontend: React</span>
              <span>•</span>
              <span>Análisis: 3 Fases</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;