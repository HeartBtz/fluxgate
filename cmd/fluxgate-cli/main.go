// FluxGate CLI — client en ligne de commande pour interagir avec un serveur FluxGate.
//
// Commandes disponibles :
//   - upload  : Upload d'un fichier avec barre de progression
//   - link    : Création d'un lien de téléchargement (public, privé, signé)
//   - login   : Authentification et obtention d'un token JWT
//   - files   : Listage des fichiers de l'utilisateur
//   - delete  : Suppression d'un fichier
//   - version : Affichage de la version
//
// Authentification via clé API (-key) ou token JWT (-token), ou via
// les variables d'environnement FLUXGATE_API_KEY / FLUXGATE_TOKEN.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	Version = "dev"
)

func main() {
	// Subcommands
	uploadCmd := flag.NewFlagSet("upload", flag.ExitOnError)
	linkCmd := flag.NewFlagSet("link", flag.ExitOnError)
	loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
	filesCmd := flag.NewFlagSet("files", flag.ExitOnError)
	deleteCmd := flag.NewFlagSet("delete", flag.ExitOnError)

	// Upload flags
	uploadServer := uploadCmd.String("server", envOr("FLUXGATE_SERVER", "http://localhost:8080"), "FluxGate server URL")
	uploadKey := uploadCmd.String("key", envOr("FLUXGATE_API_KEY", ""), "API key for authentication")
	uploadToken := uploadCmd.String("token", envOr("FLUXGATE_TOKEN", ""), "JWT token for authentication")
	uploadChunkMiB := uploadCmd.Int("chunk-size", 64, "Chunk size in MiB (1-256)")
	uploadSession := uploadCmd.String("session", "", "Resume an existing upload session ID")

	// Link flags
	linkServer := linkCmd.String("server", envOr("FLUXGATE_SERVER", "http://localhost:8080"), "FluxGate server URL")
	linkKey := linkCmd.String("key", envOr("FLUXGATE_API_KEY", ""), "API key")
	linkToken := linkCmd.String("token", envOr("FLUXGATE_TOKEN", ""), "JWT token")
	linkFileID := linkCmd.String("file", "", "File ID to create link for")
	linkType := linkCmd.String("type", "public", "Link type: public|private|signed")
	linkExpiry := linkCmd.String("expires", "7d", "Link expiration: 1h|24h|7d|30d|90d")
	linkPassword := linkCmd.String("password", "", "Password for private links")

	// Login flags
	loginServer := loginCmd.String("server", envOr("FLUXGATE_SERVER", "http://localhost:8080"), "FluxGate server URL")
	loginUser := loginCmd.String("user", "", "Username")
	loginPass := loginCmd.String("pass", "", "Password")

	// Files flags
	filesServer := filesCmd.String("server", envOr("FLUXGATE_SERVER", "http://localhost:8080"), "FluxGate server URL")
	filesKey := filesCmd.String("key", envOr("FLUXGATE_API_KEY", ""), "API key")
	filesToken := filesCmd.String("token", envOr("FLUXGATE_TOKEN", ""), "JWT token")

	// Delete flags
	deleteServer := deleteCmd.String("server", envOr("FLUXGATE_SERVER", "http://localhost:8080"), "FluxGate server URL")
	deleteKey := deleteCmd.String("key", envOr("FLUXGATE_API_KEY", ""), "API key")
	deleteToken := deleteCmd.String("token", envOr("FLUXGATE_TOKEN", ""), "JWT token")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "upload":
		mustParse(uploadCmd, os.Args[2:])
		if uploadCmd.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: fluxgate-cli upload [flags] <file>")
			os.Exit(1)
		}
		doUpload(*uploadServer, authHeader(*uploadKey, *uploadToken), uploadCmd.Arg(0), *uploadSession, *uploadChunkMiB)

	case "link":
		mustParse(linkCmd, os.Args[2:])
		if *linkFileID == "" {
			fmt.Fprintln(os.Stderr, "Usage: fluxgate-cli link [flags] -file <file_id>")
			os.Exit(1)
		}
		doCreateLink(*linkServer, authHeader(*linkKey, *linkToken), *linkFileID, *linkType, *linkExpiry, *linkPassword)

	case "login":
		mustParse(loginCmd, os.Args[2:])
		if *loginUser == "" || *loginPass == "" {
			fmt.Fprintln(os.Stderr, "Usage: fluxgate-cli login -user <username> -pass <password>")
			os.Exit(1)
		}
		doLogin(*loginServer, *loginUser, *loginPass)

	case "files":
		mustParse(filesCmd, os.Args[2:])
		doListFiles(*filesServer, authHeader(*filesKey, *filesToken))

	case "delete":
		mustParse(deleteCmd, os.Args[2:])
		if deleteCmd.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: fluxgate-cli delete [flags] <file_id>")
			os.Exit(1)
		}
		doDelete(*deleteServer, authHeader(*deleteKey, *deleteToken), deleteCmd.Arg(0))

	case "version":
		fmt.Printf("fluxgate-cli %s\n", Version)

	default:
		printUsage()
		os.Exit(1)
	}
}

func mustParse(flags *flag.FlagSet, args []string) {
	if err := flags.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `FluxGate CLI — File Distribution Client (v%s)

Usage: fluxgate-cli <command> [flags] [args]

Commands:
  upload   Upload a file
  link     Create a download link
  login    Login and get JWT token
  files    List your files
  delete   Delete a file
  version  Show version

Environment:
  FLUXGATE_SERVER   Server URL (default: http://localhost:8080)
  FLUXGATE_API_KEY  API key for authentication
  FLUXGATE_TOKEN    JWT token for authentication

Examples:
  fluxgate-cli login -server https://files.example.com -user admin -pass secret
  fluxgate-cli upload -key "fg_abc123..." myfile.zip
  fluxgate-cli link -file "uuid-here" -type public -expires 7d
  fluxgate-cli files
  fluxgate-cli delete "file-uuid"

`, Version)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func authHeader(apiKey, token string) string {
	if apiKey != "" {
		return "ApiKey " + apiKey
	}
	if token != "" {
		return "Bearer " + token
	}
	return ""
}

// Upload with progress bar
type uploadInitResponse struct {
	SessionID string `json:"session_id"`
	ChunkSize int    `json:"chunk_size"`
}

type uploadStatusResponse struct {
	SessionID     string `json:"session_id"`
	Filename      string `json:"filename"`
	UploadedBytes int64  `json:"uploaded_bytes"`
	TotalSize     int64  `json:"total_size"`
	ChunkSize     int    `json:"chunk_size"`
}

func uploadHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 20
	transport.MaxIdleConnsPerHost = 10
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 2 * time.Minute
	return &http.Client{Transport: transport}
}

// doUpload uses resumable chunks for every file. Besides surviving network
// interruptions, this keeps each public proxy request comfortably bounded.
func doUpload(server, auth, filePath, resumeSession string, requestedChunkMiB int) {
	f, err := os.Open(filePath) // #nosec G304 -- opening the CLI path explicitly supplied by its local user is intended
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot open file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot stat file: %v\n", err)
		os.Exit(1)
	}

	filename := filepath.Base(filePath)
	totalSize := stat.Size()
	if !stat.Mode().IsRegular() || totalSize <= 0 {
		fmt.Fprintln(os.Stderr, "Error: upload source must be a non-empty regular file")
		os.Exit(1)
	}
	if requestedChunkMiB < 1 || requestedChunkMiB > 256 {
		fmt.Fprintln(os.Stderr, "Error: -chunk-size must be between 1 and 256 MiB")
		os.Exit(1)
	}

	fmt.Printf("Uploading: %s (%s)\n", filename, humanizeBytes(totalSize))

	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	baseURL := strings.TrimRight(server, "/")
	client := uploadHTTPClient()
	var status uploadStatusResponse
	if resumeSession != "" {
		status, err = getUploadStatus(client, baseURL, auth, resumeSession)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot resume session: %v\n", err)
			os.Exit(1)
		}
		if status.TotalSize != totalSize || status.Filename != filename {
			fmt.Fprintln(os.Stderr, "Error: local file does not match the upload session")
			os.Exit(1)
		}
		fmt.Printf("Resuming session %s at %s\n", status.SessionID, humanizeBytes(status.UploadedBytes))
	} else {
		status, err = initUpload(client, baseURL, auth, filename, mimeType, totalSize, requestedChunkMiB*1024*1024)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot initialize upload: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Session: %s (resume with -session %s)\n", status.SessionID, status.SessionID)
	}

	progress := &progressReader{total: totalSize, read: status.UploadedBytes, startTime: time.Now()}
	offset := status.UploadedBytes
	for offset < totalSize {
		next, err := uploadChunkWithRetry(client, baseURL, auth, f, status.SessionID, offset, int64(status.ChunkSize), totalSize, progress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError: upload paused: %v\nResume with: fluxgate-cli upload -session %s %q\n", err, status.SessionID, filePath)
			os.Exit(1)
		}
		if next <= offset {
			fmt.Fprintln(os.Stderr, "\nError: server returned an invalid upload offset")
			os.Exit(1)
		}
		offset = next
	}

	result, err := completeUpload(client, baseURL, auth, status.SessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: finalization failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	fmt.Println("✓ Upload successful!")
	if id, ok := result["id"].(string); ok {
		fmt.Printf("  File ID: %s\n", id)
	}
	if name, ok := result["original_name"].(string); ok {
		fmt.Printf("  Name:    %s\n", name)
	}
	if hash, ok := result["sha256"].(string); ok {
		fmt.Printf("  SHA256:  %s\n", hash)
	}
}

func initUpload(client *http.Client, baseURL, auth, filename, mimeType string, totalSize int64, chunkSize int) (uploadStatusResponse, error) {
	payload, err := json.Marshal(map[string]any{
		"filename": filename, "mime_type": mimeType, "total_size": totalSize, "chunk_size": chunkSize,
	})
	if err != nil {
		return uploadStatusResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/files/upload/init", bytes.NewReader(payload))
	if err != nil {
		return uploadStatusResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	setAuth(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		return uploadStatusResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return uploadStatusResponse{}, httpResponseError(resp)
	}
	var init uploadInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&init); err != nil {
		return uploadStatusResponse{}, err
	}
	return uploadStatusResponse{
		SessionID: init.SessionID, Filename: filename, TotalSize: totalSize,
		ChunkSize: init.ChunkSize,
	}, nil
}

func getUploadStatus(client *http.Client, baseURL, auth, sessionID string) (uploadStatusResponse, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/files/upload/"+sessionID, nil)
	if err != nil {
		return uploadStatusResponse{}, err
	}
	setAuth(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		return uploadStatusResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return uploadStatusResponse{}, httpResponseError(resp)
	}
	var status uploadStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return uploadStatusResponse{}, err
	}
	return status, nil
}

func uploadChunkWithRetry(client *http.Client, baseURL, auth string, file *os.File, sessionID string, offset, chunkSize, totalSize int64, progress *progressReader) (int64, error) {
	const maxAttempts = 5
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		length := min(chunkSize, totalSize-offset)
		progress.reader = io.NewSectionReader(file, offset, length)
		progress.read = offset
		req, err := http.NewRequest(http.MethodPatch, baseURL+"/api/v1/files/upload/"+sessionID, progress)
		if err != nil {
			return offset, err
		}
		req.ContentLength = length
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Upload-Offset", fmt.Sprintf("%d", offset))
		setAuth(req, auth)
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			if resp.StatusCode == http.StatusNoContent {
				next := resp.Header.Get("Upload-Offset")
				_ = resp.Body.Close()
				var parsed int64
				if _, err := fmt.Sscan(next, &parsed); err != nil {
					return offset, fmt.Errorf("invalid Upload-Offset response %q", next)
				}
				return parsed, nil
			}
			requestErr = httpResponseError(resp)
			_ = resp.Body.Close()
		}
		if attempt == maxAttempts {
			return offset, requestErr
		}
		status, statusErr := getUploadStatus(client, baseURL, auth, sessionID)
		if statusErr == nil && status.UploadedBytes > offset {
			return status.UploadedBytes, nil
		}
		time.Sleep(time.Duration(1<<(attempt-1)) * time.Second)
	}
	return offset, fmt.Errorf("chunk upload failed")
}

func completeUpload(client *http.Client, baseURL, auth, sessionID string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/files/upload/"+sessionID+"/complete", nil)
	if err != nil {
		return nil, err
	}
	setAuth(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, httpResponseError(resp)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func setAuth(req *http.Request, auth string) {
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
}

func httpResponseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func doCreateLink(server, auth, fileID, linkType, expires, password string) {
	payload := map[string]interface{}{
		"file_id":    fileID,
		"link_type":  linkType,
		"expires_in": expires,
	}
	if password != "" {
		payload["password"] = password
	}

	body, _ := json.Marshal(payload)
	url := strings.TrimRight(server, "/") + "/api/v1/links"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid server response: %v\n", err)
		return
	}

	fmt.Println("✓ Download link created!")
	if url, ok := result["direct_url"].(string); ok {
		fmt.Printf("\n  Direct URL:\n  %s\n", url)
		fmt.Printf("\n  wget %s\n", url)
		fmt.Printf("  curl -OJ %s\n", url)
	}
	if url, ok := result["url"].(string); ok && result["direct_url"] == nil {
		fmt.Printf("\n  URL: %s\n", url)
	}
	if signed, ok := result["signed_url"].(string); ok && signed != "" {
		fmt.Printf("\n  Signed URL:\n  %s\n", signed)
	}
}

func doLogin(server, username, password string) {
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	url := strings.TrimRight(server, "/") + "/api/v1/auth/login"
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Login failed: %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid server response: %v\n", err)
		return
	}

	if token, ok := result["token"].(string); ok {
		fmt.Println("✓ Login successful!")
		fmt.Printf("\nexport FLUXGATE_TOKEN=\"%s\"\n", token)
		fmt.Printf("\nToken expires in: %.0f seconds\n", result["expires_in"])
	}
}

func doListFiles(server, auth string) {
	url := strings.TrimRight(server, "/") + "/api/v1/files"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid server response: %v\n", err)
		return
	}

	files, ok := result["files"].([]interface{})
	if !ok || len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	fmt.Printf("%-38s %-30s %12s  %s\n", "ID", "NAME", "SIZE", "UPLOADED")
	fmt.Println(strings.Repeat("-", 95))
	for _, f := range files {
		file, ok := f.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := file["id"].(string)
		name, _ := file["original_name"].(string)
		size := int64(0)
		if s, ok := file["size_bytes"].(float64); ok {
			size = int64(s)
		}
		created := ""
		if c, ok := file["created_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, c); err == nil {
				created = t.Format("2006-01-02 15:04")
			} else {
				created = c
				if len(created) > 16 {
					created = created[:16]
				}
			}
		}
		if len(name) > 28 {
			name = name[:25] + "..."
		}
		fmt.Printf("%-38s %-30s %12s  %s\n", id, name, humanizeBytes(size), created)
	}
}

func doDelete(server, auth, fileID string) {
	url := strings.TrimRight(server, "/") + "/api/v1/files/" + fileID
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}

	fmt.Printf("✓ File %s deleted.\n", fileID)
}

// Progress reader with terminal output
type progressReader struct {
	reader    io.Reader
	total     int64
	read      int64
	startTime time.Time
	lastPrint time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)

	if time.Since(pr.lastPrint) > 100*time.Millisecond || err == io.EOF {
		pr.lastPrint = time.Now()
		pct := float64(pr.read) / float64(pr.total) * 100
		elapsed := time.Since(pr.startTime).Seconds()
		speed := float64(pr.read) / elapsed

		bar := progressBar(pct, 30)
		fmt.Fprintf(os.Stderr, "\r  %s %5.1f%% %s/s   ",
			bar, pct, humanizeBytes(int64(speed)))
	}
	return n, err
}

func progressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func humanizeBytes(b int64) string {
	const unit = 1024
	sizes := []string{"B", "KB", "MB", "GB", "TB"}
	if b == 0 {
		return "0 B"
	}
	i := 0
	size := float64(b)
	for size >= float64(unit) && i < len(sizes)-1 {
		size /= float64(unit)
		i++
	}
	return fmt.Sprintf("%.1f %s", size, sizes[i])
}
