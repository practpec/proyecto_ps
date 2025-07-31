package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

// NOTA: Este es ahora el único punto de entrada para ambas versiones.
func main() {
	r := mux.NewRouter()

	// Rutas de la API
	api := r.PathPrefix("/api").Subrouter()

	// Endpoint para la versión OPTIMIZADA
	api.HandleFunc("/analyze", analyzeScriptHandler_Optimized).Methods("POST")

	// Endpoint para la versión NO OPTIMIZADA
	api.HandleFunc("/analyze-unoptimized", analyzeScriptHandler_Unoptimized).Methods("POST")

	api.HandleFunc("/health", healthHandler).Methods("GET")

	// Configuración de CORS
	corsObj := handlers.AllowedOrigins([]string{"*"})
	corsHeaders := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	corsMethods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	fmt.Printf("Servidor unificado ejecutándose en puerto %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handlers.CORS(corsObj, corsHeaders, corsMethods)(r)))
}

// Handler que llama al analizador OPTIMIZADO
func analyzeScriptHandler_Optimized(w http.ResponseWriter, r *http.Request) {
	var request AnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Llama a la lógica optimizada
	analyzer := NewPowerShellAnalyzer()
	result := analyzer.AnalyzeScript(request.Script)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Handler que llama al analizador NO OPTIMIZADO
func analyzeScriptHandler_Unoptimized(w http.ResponseWriter, r *http.Request) {
	var request AnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Se crea una instancia del analizador NO OPTIMIZADO.
	analyzer := NewPowerShellAnalyzer_Unoptimized()
	result := analyzer.AnalyzeScript(request.Script)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

// Struct de la petición (común para ambos)
type AnalysisRequest struct {
	Script string `json:"script"`
}
