package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	protoDir     = flag.String("proto-dir", "", "Directory containing .proto files")
	listenAddr   = flag.String("addr", "localhost", "Address to listen on")
	listenPort   = flag.Int("port", 3000, "Port to listen on")
	logLevel     = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	liveReload   = flag.Bool("live-reload", false, "Enable live reloading of proto files")
	mkcertHost   = flag.String("mkcert", "", "Enable HTTPS with mkcert for specified hostname")
	messageTypes map[string]*desc.MessageDescriptor
	log          *logrus.Logger
	protoMutex   sync.RWMutex
)

const (
	HeaderDestHost    = "X-J2P-Destination-Host"
	HeaderReqMsgType  = "X-J2P-Request-Message-Type"
	HeaderRespMsgType = "X-J2P-Response-Message-Type"
	HeaderMethodType  = "X-J2P-Method-Type"
)

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	Field   string `json:"field,omitempty"`
}

func init() {
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	messageTypes = make(map[string]*desc.MessageDescriptor)
}

func main() {
	flag.Parse()

	// Print usage if no arguments provided
	if len(os.Args) == 1 {
		fmt.Println("Json2Protobuf - A local JSON to Protocol Buffers proxy")
		fmt.Println("\nUsage:")
		fmt.Println("  json2protobuf --proto-dir=/path/to/protos [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		return
	}

	// Configure logger
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.Fatal("Invalid log level: ", err)
	}
	log.SetLevel(level)

	// Validate proto directory
	if *protoDir == "" {
		log.Fatal("Proto directory is required")
	}

	// Load proto files
	if err := loadProtoFiles(*protoDir); err != nil {
		log.Fatalf("Failed to load proto files: %v", err)
	}

	// Set up live reload if enabled
	if *liveReload {
		go watchProtoFiles(*protoDir)
	}

	// Handle HTTPS with mkcert
	if *mkcertHost != "" {
		if err := setupMkcertHTTPS(*mkcertHost, *listenAddr, *listenPort); err != nil {
			log.Fatalf("Failed to setup HTTPS with mkcert: %v", err)
		}
		return
	}

	// Set up HTTP server
	setupHTTPServer(*listenAddr, *listenPort)
}

func setupMkcertHTTPS(hostname, addr string, port int) error {
	// Check if mkcert is installed
	cmd := exec.Command("mkcert", "-version")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error: mkcert is not installed.")
		fmt.Println("Please install mkcert first. You can do this with:")
		fmt.Println("  - For macOS (Homebrew): brew install mkcert")
		fmt.Println("  - For Windows (Chocolatey): choco install mkcert")
		fmt.Println("  - For Linux: check mkcert GitHub repository for installation instructions")
		return fmt.Errorf("mkcert not installed")
	}

	// Generate hosts file entry suggestion
	hostsEntry := fmt.Sprintf("127.0.0.1 %s", hostname)
	fmt.Println("⚠️ Important: Please add the following line to your hosts file:")
	fmt.Println(hostsEntry)
	fmt.Println("\nYou can usually do this by editing:")
	fmt.Println("  - macOS/Linux: /etc/hosts")
	fmt.Println("  - Windows: C:\\Windows\\System32\\drivers\\etc\\hosts")

	// Locate certificate files
	cmd = exec.Command("mkcert", "-CAROOT")
	caRoot, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get mkcert root: %v", err)
	}

	caRootPath := strings.TrimSpace(string(caRoot))
	certPath := filepath.Join(caRootPath, fmt.Sprintf("%s+1.pem", hostname))
	keyPath := filepath.Join(caRootPath, fmt.Sprintf("%s+1-key.pem", hostname))

	// Generate certificates
	cmd = exec.Command("mkcert", "-cert-file", certPath, "-key-file", keyPath, hostname)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate certificates: %v", err)
	}

	// Serve HTTPS
	endpoint := fmt.Sprintf("%s:%d", addr, port)
	log.Infof("Starting HTTPS JSON to Protobuf proxy on https://%s", endpoint)

	http.HandleFunc("/", handleRequest)
	return http.ListenAndServeTLS(endpoint, certPath, keyPath, nil)
}

func setupHTTPServer(addr string, port int) {
	endpoint := fmt.Sprintf("%s:%d", addr, port)
	log.Infof("Starting HTTP JSON to Protobuf proxy on http://%s", endpoint)

	http.HandleFunc("/", handleRequest)
	if err := http.ListenAndServe(endpoint, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// watchProtoFiles sets up a file watcher for the proto directory
func watchProtoFiles(dir string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("Failed to create file watcher: %v", err)
		return
	}
	defer watcher.Close()

	// Watch the entire directory recursively
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})

	if err != nil {
		log.Errorf("Error setting up file watcher: %v", err)
		return
	}

	log.Info("Starting live reload for proto files")

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Only reload on write events for .proto files
			if event.Op&fsnotify.Write == fsnotify.Write && strings.HasSuffix(event.Name, ".proto") {
				log.Infof("Detected change in proto file: %s", event.Name)
				if err := safeReloadProtoFiles(dir); err != nil {
					log.Warnf("Failed to reload proto files: %v", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Errorf("File watcher error: %v", err)
		}
	}
}

// safeReloadProtoFiles attempts to reload proto files with error handling
func safeReloadProtoFiles(dir string) error {
	// Create temporary storage for new message types
	tempMessageTypes := make(map[string]*desc.MessageDescriptor)

	// Find all .proto files
	var protoFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".proto") {
			protoFiles = append(protoFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking proto directory: %w", err)
	}

	if len(protoFiles) == 0 {
		return fmt.Errorf("no .proto files found in %s", dir)
	}

	// Parse proto files
	parser := protoparse.Parser{
		ImportPaths: []string{dir},
	}

	// Get relative paths for the parser
	var relProtoFiles []string
	for _, file := range protoFiles {
		relPath, err := filepath.Rel(dir, file)
		if err != nil {
			return fmt.Errorf("error getting relative path for %s: %w", file, err)
		}
		relProtoFiles = append(relProtoFiles, relPath)
	}

	// Attempt to parse the files without locking
	parsedFileDescs, err := parser.ParseFiles(relProtoFiles...)
	if err != nil {
		// Log the specific parsing errors but don't terminate
		log.Warnf("Proto file parsing errors: %v", err)
		return err
	}

	// Build a map of message types
	for _, fd := range parsedFileDescs {
		for _, mt := range fd.GetMessageTypes() {
			// Store both with and without package name for convenience
			fullName := mt.GetFullyQualifiedName()
			tempMessageTypes[fullName] = mt

			// Also store with just the message name for convenience
			shortName := mt.GetName()
			tempMessageTypes[shortName] = mt

			log.Debugf("Registered message type: %s", fullName)
		}
	}

	// Use mutex to safely update global variables
	protoMutex.Lock()
	defer protoMutex.Unlock()

	// Update global variables
	messageTypes = tempMessageTypes

	log.Infof("Successfully reloaded %d message types from proto files", len(messageTypes))
	return nil
}

// Modified loadProtoFiles to match the new pattern
func loadProtoFiles(dir string) error {
	// Utilize the safeReloadProtoFiles function
	return safeReloadProtoFiles(dir)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Use read mutex to safely access message types
	protoMutex.RLock()
	defer protoMutex.RUnlock()

	destHost := r.Header.Get(HeaderDestHost)
	reqMsgType := r.Header.Get(HeaderReqMsgType)
	respMsgType := r.Header.Get(HeaderRespMsgType)
	methodType := r.Header.Get(HeaderMethodType)

	// Log the incoming request
	log.WithFields(logrus.Fields{
		"method":              r.Method,
		"destHost":            destHost,
		"reqMessageType":      reqMsgType,
		"responseMessageType": respMsgType,
		"methodType":          methodType,
	}).Info("Received request")

	// Validate required headers
	if destHost == "" {
		sendError(w, http.StatusBadRequest, "Missing destination host",
			"Header "+HeaderDestHost+" is required", "")
		return
	}

	// Read the request body (if present)
	var body []byte
	var err error
	var hasBody bool

	// Check if this request method typically has a body
	hasBody = r.Method != "GET" && r.Method != "HEAD" && r.ContentLength != 0

	if hasBody {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			sendError(w, http.StatusBadRequest, "Failed to read request body", err.Error(), "")
			return
		}
		defer r.Body.Close()
	}

	var protoData []byte

	// Only process body if it exists and has content
	if hasBody && len(body) > 0 {
		// Now validate message type since we have a body to convert
		if reqMsgType == "" {
			sendError(w, http.StatusBadRequest, "Missing message type",
				"Header "+HeaderReqMsgType+" is required for requests with a body", "")
			return
		}

		// Find the message descriptor
		msgDesc, ok := messageTypes[reqMsgType]
		if !ok {
			sendError(w, http.StatusBadRequest, "Unknown message type",
				"Message type "+reqMsgType+" not found in proto definitions", "")
			return
		}

		// Convert JSON to Protobuf
		msg := dynamic.NewMessage(msgDesc)
		if err := json.Unmarshal(body, &msg); err != nil {
			// Try to extract field information from the error message
			field := extractFieldFromError(err.Error())
			sendError(w, http.StatusBadRequest, "Invalid JSON", err.Error(), field)
			return
		}

		// Serialize to protobuf
		protoData, err = msg.Marshal()
		if err != nil {
			sendError(w, http.StatusInternalServerError, "Failed to marshal protobuf", err.Error(), "")
			return
		}
	}

	// Prepare forward request
	// Ensure the destination host has the correct protocol prefix
	if !strings.HasPrefix(destHost, "http://") && !strings.HasPrefix(destHost, "https://") {
		destHost = "http://" + destHost
	}

	if methodType == "" {
		methodType = r.Method
	}

	// Create the request with or without body
	var forwardReq *http.Request
	if hasBody && len(protoData) > 0 {
		forwardReq, err = http.NewRequest(
			methodType,
			destHost+r.URL.Path+"?"+r.URL.RawQuery, // Include query parameters
			bytes.NewReader(protoData),
		)

		if err != nil {
			sendError(w, http.StatusInternalServerError, "Failed to create forward request", err.Error(), "")
			return
		}

		// Set content type for protobuf
		forwardReq.Header.Set("Content-Type", "application/protobuf")
	} else {
		forwardReq, err = http.NewRequest(
			methodType,
			destHost+r.URL.Path+"?"+r.URL.RawQuery, // Include query parameters
			nil, // No body
		)
	}

	if err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to create forward request", err.Error(), "")
		return
	}

	// Copy allowed headers
	for key, values := range r.Header {
		// Skip our custom headers
		if key == HeaderDestHost || key == HeaderReqMsgType || key == HeaderMethodType || key == HeaderRespMsgType {
			continue
		}
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}

	// Set content type for protobuf
	forwardReq.Header.Set("Content-Type", "application/protobuf")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(forwardReq)
	if err != nil {
		sendError(w, http.StatusBadGateway, "Failed to forward request", err.Error(), "")
		return
	}
	defer resp.Body.Close()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to read response body", err.Error(), "")
		return
	}

	// Process response based on respMsgType
	if respMsgType != "" {
		// Check if we have this message type
		respMsgDesc, ok := messageTypes[respMsgType]
		if !ok {
			sendError(w, http.StatusBadRequest, "Unknown response message type",
				"Response message type "+respMsgType+" not found in proto definitions", "")
			return
		}

		// Try to decode the protobuf response
		respMsg := dynamic.NewMessage(respMsgDesc)
		if err := respMsg.Unmarshal(respBody); err != nil {
			sendError(w, http.StatusInternalServerError, "Failed to unmarshal response protobuf",
				"Could not decode response from server: "+err.Error(), "")
			return
		}

		// Convert to JSON
		jsonData, err := respMsg.MarshalJSON()
		if err != nil {
			sendError(w, http.StatusInternalServerError, "Failed to marshal response to JSON", err.Error(), "")
			return
		}

		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(jsonData)

		log.WithFields(logrus.Fields{
			"statusCode": resp.StatusCode,
			"bodySize":   len(jsonData),
			"converted":  true,
		}).Info("Request completed with response conversion")
		return
	}

	// if no response message type present

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Send the response
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	log.WithFields(logrus.Fields{
		"statusCode": resp.StatusCode,
		"bodySize":   len(respBody),
	}).Info("Request completed")
}

// Helper function to extract field name from error message
func extractFieldFromError(errMsg string) string {
	// Common patterns in JSON unmarshaling errors
	// Example: "json: unknown field \"user_name\""
	if strings.Contains(errMsg, "unknown field") {
		parts := strings.Split(errMsg, "\"")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	// Example: "json: cannot unmarshal string into Go struct field User.age of type int"
	if strings.Contains(errMsg, "cannot unmarshal") && strings.Contains(errMsg, "into Go struct field") {
		parts := strings.Split(errMsg, "Go struct field ")
		if len(parts) >= 2 {
			fieldParts := strings.Split(parts[1], " ")
			if len(fieldParts) >= 1 {
				return fieldParts[0]
			}
		}
	}

	// Example: "required field \"name\" not set"
	if strings.Contains(errMsg, "required field") && strings.Contains(errMsg, "not set") {
		parts := strings.Split(errMsg, "\"")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	return ""
}

func sendError(w http.ResponseWriter, status int, err string, details string, field string) {
	log.WithFields(logrus.Fields{
		"status":  status,
		"error":   err,
		"details": details,
		"field":   field,
	}).Error("Error handling request")

	resp := ErrorResponse{
		Error:   err,
		Message: "JSON to Protobuf conversion failed",
		Details: details,
		Field:   field,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
