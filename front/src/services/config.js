// Configuración centralizada de la aplicación
export const CONFIG = {
  // Configuración de la API
  API: {
    BASE_URL: process.env.REACT_APP_API_URL || 'http://localhost:8080',
    ENDPOINTS: {
      ANALYZE: '/api/analyze',
      HEALTH: '/api/health'
    },
    TIMEOUTS: {
      ANALYZE: 30000, // 30 segundos
      HEALTH: 5000    // 5 segundos
    },
    RETRY_ATTEMPTS: 3
  },

  // Límites de validación
  VALIDATION: {
    MAX_SCRIPT_SIZE: 1024 * 1024, // 1MB
    WARNING_SIZE: 100 * 1024,     // 100KB
    MIN_SCRIPT_LENGTH: 1,
    MAX_TOKENS_DISPLAY: 10,
    MAX_THREATS_DISPLAY: 3
  },

  // Configuración de UI
  UI: {
    ANIMATION_DURATION: 500,
    DEBOUNCE_DELAY: 300,
    TOAST_DURATION: 5000,
    DEFAULT_EXPANDED_SECTIONS: {
      lexical: true,
      syntax: true,
      semantic: true,
      recommendations: false,
      attackChain: false
    }
  },

  // Niveles de amenaza y sus configuraciones
  THREAT_LEVELS: {
    CRITICAL: {
      threshold: 80,
      color: {
        bg: 'bg-red-500',
        text: 'text-red-600',
        bgLight: 'bg-red-100',
        border: 'border-red-200'
      }
    },
    HIGH: {
      threshold: 60,
      color: {
        bg: 'bg-orange-500',
        text: 'text-orange-600',
        bgLight: 'bg-orange-100',
        border: 'border-orange-200'
      }
    },
    MEDIUM: {
      threshold: 40,
      color: {
        bg: 'bg-yellow-500',
        text: 'text-yellow-600',
        bgLight: 'bg-yellow-100',
        border: 'border-yellow-200'
      }
    },
    LOW: {
      threshold: 20,
      color: {
        bg: 'bg-blue-500',
        text: 'text-blue-600',
        bgLight: 'bg-blue-100',
        border: 'border-blue-200'
      }
    },
    MINIMAL: {
      threshold: 0,
      color: {
        bg: 'bg-green-500',
        text: 'text-green-600',
        bgLight: 'bg-green-100',
        border: 'border-green-200'
      }
    }
  },

  // Configuración de fases de análisis
  ANALYSIS_PHASES: {
    LEXICAL: {
      name: 'Análisis Léxico',
      description: 'Identifica tokens, palabras clave y patrones de ofuscación',
      icon: 'Search',
      color: 'blue',
      weight: 0.3 // Para cálculo de riesgo general
    },
    SYNTAX: {
      name: 'Análisis Sintáctico',
      description: 'Evalúa estructura, validez y anomalías del código',
      icon: 'Code',
      color: 'orange',
      weight: 0.2
    },
    SEMANTIC: {
      name: 'Análisis Semántico',
      description: 'Determina intención maliciosa e impacto del comportamiento',
      icon: 'Brain',
      color: 'purple',
      weight: 0.5
    }
  },

  // Configuración de severidad
  SEVERITY: {
    HIGH: {
      color: 'text-red-600 bg-red-100',
      weight: 10
    },
    MEDIUM: {
      color: 'text-orange-600 bg-orange-100',
      weight: 5
    },
    LOW: {
      color: 'text-blue-600 bg-blue-100',
      weight: 2
    }
  },

  // Palabras clave para identificar recomendaciones urgentes
  URGENT_KEYWORDS: [
    'ACCIÓN INMEDIATA',
    'CRÍTICO',
    'CRITICAL',
    'IMMEDIATE',
    'URGENT',
    'BLOQUEAR',
    'AISLAR'
  ],

  // Mapeo de iconos para intenciones maliciosas
  INTENT_ICONS: {
    payload_download: 'Download',
    persistence: 'Key',
    privilege_escalation: 'TrendingUp',
    data_exfiltration: 'Database',
    reconnaissance: 'Eye',
    defense_evasion: 'Shield',
    system_modification: 'Settings',
    lateral_movement: 'Network'
  },

  // Mensajes de error por defecto
  ERROR_MESSAGES: {
    NETWORK_ERROR: 'No se puede conectar con el servidor. Verifica que el backend esté ejecutándose.',
    VALIDATION_ERROR: 'El script tiene errores de validación',
    SERVER_ERROR: 'Error interno del servidor',
    TIMEOUT_ERROR: 'El análisis tomó demasiado tiempo',
    UNKNOWN_ERROR: 'Ha ocurrido un error inesperado'
  },

  // Configuración de desarrollo
  DEV: {
    LOG_LEVEL: process.env.NODE_ENV === 'development' ? 'debug' : 'error',
    ENABLE_PERFORMANCE_METRICS: process.env.NODE_ENV === 'development',
    SHOW_DEBUG_INFO: process.env.NODE_ENV === 'development'
  }
};

// Función helper para obtener configuración anidada
export const getConfig = (path) => {
  return path.split('.').reduce((obj, key) => obj?.[key], CONFIG);
};

// Función helper para verificar si estamos en desarrollo
export const isDevelopment = () => {
  return process.env.NODE_ENV === 'development';
};

// Función helper para logging condicional
export const devLog = (message, ...args) => {
  if (isDevelopment()) {
    console.log(`[DEV] ${message}`, ...args);
  }
};

export default CONFIG;