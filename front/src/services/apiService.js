// Servicio para manejar las llamadas a la API
export class ApiService {
  static BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080';

  /**
   * Realiza el análisis de un script PowerShell
   * @param {string} script - El script a analizar
   * @returns {Promise<Object>} - Resultado del análisis
   */
  static async analyzeScript(script) {
    if (!script || typeof script !== 'string') {
      throw new Error('El script debe ser una cadena de texto válida');
    }

    if (script.trim().length === 0) {
      throw new Error('El script no puede estar vacío');
    }

    try {
      const response = await fetch(`${this.BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ script: script.trim() }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(this.getErrorMessage(response.status, errorText));
      }

      const result = await response.json();
      return result;
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('No se puede conectar con el servidor. Verifica que el backend esté ejecutándose.');
      }
      throw error;
    }
  }

  /**
   * Verifica el estado de salud del API
   * @returns {Promise<Object>} - Estado del servidor
   */
  static async checkHealth() {
    try {
      const response = await fetch(`${this.BASE_URL}/api/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Error en el servidor: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('No se puede conectar con el servidor');
      }
      throw error;
    }
  }

  /**
   * Obtiene un mensaje de error apropiado basado en el código de estado
   * @param {number} status - Código de estado HTTP
   * @param {string} errorText - Texto de error del servidor
   * @returns {string} - Mensaje de error formateado
   */
  static getErrorMessage(status, errorText) {
    switch (status) {
      case 400:
        return 'El script enviado tiene un formato inválido';
      case 401:
        return 'No tienes autorización para realizar esta acción';
      case 403:
        return 'Acceso denegado al servicio de análisis';
      case 404:
        return 'El servicio de análisis no está disponible';
      case 413:
        return 'El script es demasiado grande para procesar';
      case 429:
        return 'Demasiadas solicitudes. Intenta de nuevo en unos momentos';
      case 500:
        return 'Error interno del servidor durante el análisis';
      case 502:
        return 'El servidor de análisis no está disponible';
      case 503:
        return 'El servicio de análisis está temporalmente no disponible';
      case 504:
        return 'El análisis tomó demasiado tiempo. Intenta con un script más pequeño';
      default:
        return errorText || `Error del servidor (${status})`;
    }
  }

  /**
   * Valida un script antes de enviarlo
   * @param {string} script - Script a validar
   * @returns {Object} - Resultado de la validación
   */
  static validateScript(script) {
    const validation = {
      isValid: true,
      errors: [],
      warnings: []
    };

    if (!script) {
      validation.isValid = false;
      validation.errors.push('El script no puede estar vacío');
      return validation;
    }

    if (typeof script !== 'string') {
      validation.isValid = false;
      validation.errors.push('El script debe ser texto');
      return validation;
    }

    const trimmedScript = script.trim();
    
    if (trimmedScript.length === 0) {
      validation.isValid = false;
      validation.errors.push('El script no puede estar vacío');
      return validation;
    }

    // Verificar tamaño máximo (1MB)
    const maxSize = 1024 * 1024; // 1MB
    if (trimmedScript.length > maxSize) {
      validation.isValid = false;
      validation.errors.push(`El script es demasiado grande (máximo ${maxSize} caracteres)`);
      return validation;
    }

    // Advertencias
    if (trimmedScript.length > 100000) { // 100KB
      validation.warnings.push('El script es muy grande, el análisis puede tomar más tiempo');
    }

    if (!/powershell|ps1|\$|get-|set-|new-|invoke-/i.test(trimmedScript)) {
      validation.warnings.push('El script no parece ser código PowerShell válido');
    }

    return validation;
  }

  /**
   * Obtiene estadísticas básicas del script
   * @param {string} script - Script a analizar
   * @returns {Object} - Estadísticas del script
   */
  static getScriptStats(script) {
    if (!script || typeof script !== 'string') {
      return {
        characters: 0,
        lines: 0,
        words: 0,
        isEmpty: true
      };
    }

    const trimmedScript = script.trim();
    
    return {
      characters: script.length,
      lines: script.split('\n').length,
      words: trimmedScript.split(/\s+/).filter(word => word.length > 0).length,
      isEmpty: trimmedScript.length === 0
    };
  }
}

export default ApiService;