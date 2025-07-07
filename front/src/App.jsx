import React, { useState } from 'react';
import ScriptInput from './components/ScriptInput';
import AnalysisResults from './components/AnalysisResults';
import ThreatDashboard from './components/ThreatDashboard';
import { Shield, AlertTriangle, Activity } from 'lucide-react';

function App() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeScript = async (script) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8080/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ script }),
      });

      if (!response.ok) {
        throw new Error('Error al analizar el script');
      }

      const result = await response.json();
      setAnalysisResult(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const getThreatLevelColor = (level) => {
    const colors = {
      'CRITICAL': 'text-red-600 bg-red-100',
      'HIGH': 'text-orange-600 bg-orange-100',
      'MEDIUM': 'text-yellow-600 bg-yellow-100',
      'LOW': 'text-blue-600 bg-blue-100',
      'MINIMAL': 'text-green-600 bg-green-100'
    };
    return colors[level] || 'text-gray-600 bg-gray-100';
  };

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
                  Análisis avanzado de scripts PowerShell maliciosos
                </p>
              </div>
            </div>
            
            {analysisResult && (
              <div className="flex items-center space-x-2">
                <div className={`px-3 py-1 rounded-full text-sm font-medium ${getThreatLevelColor(analysisResult.threat_level)}`}>
                  <div className="flex items-center space-x-1">
                    <AlertTriangle className="w-4 h-4" />
                    <span>{analysisResult.threat_level}</span>
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
            
            {error && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                  <span className="text-red-800 font-medium">Error</span>
                </div>
                <p className="text-red-700 mt-1">{error}</p>
              </div>
            )}
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
                <p className="text-gray-500">
                  Ingresa un script PowerShell para comenzar el análisis de seguridad
                </p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;