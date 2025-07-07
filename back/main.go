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

func main() {
	r := mux.NewRouter()

	// Rutas de la API
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/analyze", analyzeScriptHandler).Methods("POST")
	api.HandleFunc("/health", healthHandler).Methods("GET")

	// CORS
	corsObj := handlers.AllowedOrigins([]string{"*"})
	corsHeaders := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	corsMethods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Servidor ejecutándose en puerto %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handlers.CORS(corsObj, corsHeaders, corsMethods)(r)))
}

func analyzeScriptHandler(w http.ResponseWriter, r *http.Request) {
	var request AnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	analyzer := NewPowerShellAnalyzer()
	result := analyzer.AnalyzeScript(request.Script)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

type AnalysisRequest struct {
	Script string `json:"script"`
}