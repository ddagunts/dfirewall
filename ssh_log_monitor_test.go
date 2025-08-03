package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestLoadSSHLogConfiguration(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		config      *SSHLogConfig
		expectError bool
	}{
		{
			name: "Valid SSH log configuration",
			config: &SSHLogConfig{
				Enabled: true,
				Servers: []SSHServer{
					{
						Name:     "test-server",
						Host:     "192.168.1.100",
						Port:     22,
						Username: "testuser",
						AuthMethod: "key",
						PrivateKeyPath: "/home/user/.ssh/id_rsa",
						Enabled:  true,
						LogFiles: []SSHLogFile{
							{
								Path:    "/var/log/auth.log",
								IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
								Enabled: true,
								DefaultTTL: 3600,
							},
						},
					},
				},
				GlobalDefaults: SSHDefaults{
					Port:              22,
					ConnectionTimeout: 30,
					KeepAlive:        30,
					MaxRetries:       3,
					AuthMethod:       "key",
					BufferSize:       4096,
					MaxLineLength:    1024,
					ProcessInterval:  1,
					DefaultTTL:       3600,
				},
				RetryConfig: SSHRetryConfig{
					InitialDelay:          5,
					MaxDelay:             300,
					BackoffMultiplier:    2.0,
					MaxReconnectAttempts: 10,
					ReconnectInterval:    60,
					HealthCheckInterval:  300,
				},
			},
			expectError: false,
		},
		{
			name: "Empty servers configuration",
			config: &SSHLogConfig{
				Enabled: true,
				Servers: []SSHServer{},
			},
			expectError: true,
		},
		{
			name: "Invalid auth method",
			config: &SSHLogConfig{
				Enabled: true,
				Servers: []SSHServer{
					{
						Name:       "test-server",
						Host:       "192.168.1.100",
						Username:   "testuser",
						AuthMethod: "invalid",
						LogFiles: []SSHLogFile{
							{
								Path:    "/var/log/auth.log",
								IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
								Enabled: true,
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "Missing required fields",
			config: &SSHLogConfig{
				Enabled: true,
				Servers: []SSHServer{
					{
						Name: "test-server",
						// Missing Host and Username
						LogFiles: []SSHLogFile{
							{
								Path:    "/var/log/auth.log",
								IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
								Enabled: true,
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "Invalid IP regex",
			config: &SSHLogConfig{
				Enabled: true,
				Servers: []SSHServer{
					{
						Name:       "test-server",
						Host:       "192.168.1.100",
						Username:   "testuser",
						AuthMethod: "key",
						PrivateKeyPath: "/home/user/.ssh/id_rsa",
						LogFiles: []SSHLogFile{
							{
								Path:    "/var/log/auth.log",
								IPRegex: "[invalid regex",
								Enabled: true,
							},
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFile := filepath.Join(tempDir, "ssh_config.json")
			configData, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatalf("Failed to marshal config: %v", err)
			}

			err = os.WriteFile(configFile, configData, 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			_, err = loadSSHLogConfiguration(configFile)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSSHServer(t *testing.T) {
	tests := []struct {
		name        string
		server      SSHServer
		expectError bool
	}{
		{
			name: "Valid server with key auth",
			server: SSHServer{
				Name:           "test-server",
				Host:           "192.168.1.100",
				Username:       "testuser",
				AuthMethod:     "key",
				PrivateKeyPath: "/home/user/.ssh/id_rsa",
				LogFiles: []SSHLogFile{
					{
						Path:    "/var/log/auth.log",
						IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
						Enabled: true,
					},
				},
			},
			expectError: false,
		},
		{
			name: "Valid server with password auth",
			server: SSHServer{
				Name:       "test-server",
				Host:       "192.168.1.100",
				Username:   "testuser",
				AuthMethod: "password",
				Password:   "testpass",
				LogFiles: []SSHLogFile{
					{
						Path:    "/var/log/auth.log",
						IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
						Enabled: true,
					},
				},
			},
			expectError: false,
		},
		{
			name: "Missing name",
			server: SSHServer{
				Host:       "192.168.1.100",
				Username:   "testuser",
				AuthMethod: "key",
				PrivateKeyPath: "/home/user/.ssh/id_rsa",
				LogFiles: []SSHLogFile{
					{
						Path:    "/var/log/auth.log",
						IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
						Enabled: true,
					},
				},
			},
			expectError: true,
		},
		{
			name: "Password auth without password",
			server: SSHServer{
				Name:       "test-server",
				Host:       "192.168.1.100",
				Username:   "testuser",
				AuthMethod: "password",
				LogFiles: []SSHLogFile{
					{
						Path:    "/var/log/auth.log",
						IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
						Enabled: true,
					},
				},
			},
			expectError: true,
		},
		{
			name: "Key auth without key",
			server: SSHServer{
				Name:       "test-server",
				Host:       "192.168.1.100",
				Username:   "testuser",
				AuthMethod: "key",
				LogFiles: []SSHLogFile{
					{
						Path:    "/var/log/auth.log",
						IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
						Enabled: true,
					},
				},
			},
			expectError: true,
		},
		{
			name: "No log files",
			server: SSHServer{
				Name:           "test-server",
				Host:           "192.168.1.100",
				Username:       "testuser",
				AuthMethod:     "key",
				PrivateKeyPath: "/home/user/.ssh/id_rsa",
				LogFiles:       []SSHLogFile{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSHServer(&tt.server)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSSHLogFile(t *testing.T) {
	tests := []struct {
		name        string
		logFile     SSHLogFile
		expectError bool
	}{
		{
			name: "Valid log file",
			logFile: SSHLogFile{
				Path:    "/var/log/auth.log",
				IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				Enabled: true,
			},
			expectError: false,
		},
		{
			name: "Valid log file with domain regex",
			logFile: SSHLogFile{
				Path:        "/var/log/auth.log",
				IPRegex:     `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				DomainRegex: `([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
				Enabled:     true,
			},
			expectError: false,
		},
		{
			name: "Valid log file with filters",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "sshd",
				ExcludeFilter: "internal",
				Enabled:       true,
			},
			expectError: false,
		},
		{
			name: "Missing path",
			logFile: SSHLogFile{
				IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "Missing IP regex",
			logFile: SSHLogFile{
				Path:    "/var/log/auth.log",
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "Invalid IP regex",
			logFile: SSHLogFile{
				Path:    "/var/log/auth.log",
				IPRegex: "[invalid regex",
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "Invalid domain regex",
			logFile: SSHLogFile{
				Path:        "/var/log/auth.log",
				IPRegex:     `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				DomainRegex: "[invalid regex",
				Enabled:     true,
			},
			expectError: true,
		},
		{
			name: "Invalid include filter",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "[invalid regex",
				Enabled:       true,
			},
			expectError: true,
		},
		{
			name: "Invalid exclude filter",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				ExcludeFilter: "[invalid regex",
				Enabled:       true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSHLogFile(&tt.logFile)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestApplySSHLogDefaults(t *testing.T) {
	config := &SSHLogConfig{
		Servers: []SSHServer{
			{
				Name:       "test-server",
				Host:       "192.168.1.100",
				Username:   "testuser",
				AuthMethod: "key",
				LogFiles: []SSHLogFile{
					{
						Path:    "/var/log/auth.log",
						IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
						Enabled: true,
					},
				},
			},
		},
	}

	applySSHLogDefaults(config)

	// Check global defaults
	if config.GlobalDefaults.Port != 22 {
		t.Errorf("Expected default port 22, got %d", config.GlobalDefaults.Port)
	}
	if config.GlobalDefaults.ConnectionTimeout != 30 {
		t.Errorf("Expected default connection timeout 30, got %d", config.GlobalDefaults.ConnectionTimeout)
	}
	if config.GlobalDefaults.AuthMethod != "key" {
		t.Errorf("Expected default auth method 'key', got %s", config.GlobalDefaults.AuthMethod)
	}

	// Check server defaults applied
	server := &config.Servers[0]
	if server.Port != 22 {
		t.Errorf("Expected server port 22, got %d", server.Port)
	}
	if server.ConnectionTimeout != 30 {
		t.Errorf("Expected server connection timeout 30, got %d", server.ConnectionTimeout)
	}

	// Check log file defaults applied
	logFile := &server.LogFiles[0]
	if logFile.BufferSize != 4096 {
		t.Errorf("Expected log file buffer size 4096, got %d", logFile.BufferSize)
	}
	if logFile.DefaultTTL != 3600 {
		t.Errorf("Expected log file default TTL 3600, got %d", logFile.DefaultTTL)
	}

	// Check retry config defaults
	if config.RetryConfig.InitialDelay != 5 {
		t.Errorf("Expected retry initial delay 5, got %d", config.RetryConfig.InitialDelay)
	}
	if config.RetryConfig.BackoffMultiplier != 2.0 {
		t.Errorf("Expected retry backoff multiplier 2.0, got %f", config.RetryConfig.BackoffMultiplier)
	}
}

func TestCreateLogFileMonitor(t *testing.T) {
	// Create a mock SSH monitor
	config := &SSHServer{
		Name:     "test-server",
		Host:     "192.168.1.100",
		Username: "testuser",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := &SSHMonitor{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	tests := []struct {
		name        string
		logFile     SSHLogFile
		expectError bool
	}{
		{
			name: "Valid log file monitor",
			logFile: SSHLogFile{
				Path:    "/var/log/auth.log",
				IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				Enabled: true,
			},
			expectError: false,
		},
		{
			name: "Log file monitor with domain regex",
			logFile: SSHLogFile{
				Path:        "/var/log/auth.log",
				IPRegex:     `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				DomainRegex: `([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
				Enabled:     true,
			},
			expectError: false,
		},
		{
			name: "Log file monitor with filters",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "sshd",
				ExcludeFilter: "internal",
				Enabled:       true,
			},
			expectError: false,
		},
		{
			name: "Invalid IP regex",
			logFile: SSHLogFile{
				Path:    "/var/log/auth.log",
				IPRegex: "[invalid regex",
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileMonitor, err := monitor.createLogFileMonitor(&tt.logFile)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && fileMonitor == nil {
				t.Errorf("Expected log file monitor but got nil")
			}
		})
	}
}

func TestLogFileMonitorShouldProcessLine(t *testing.T) {
	tests := []struct {
		name        string
		logFile     SSHLogFile
		line        string
		shouldProcess bool
	}{
		{
			name: "No filters - should process",
			logFile: SSHLogFile{
				Path:    "/var/log/auth.log",
				IPRegex: `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
			},
			line:          "Jan 1 12:00:00 server sshd[1234]: Failed login from 192.168.1.1",
			shouldProcess: true,
		},
		{
			name: "Include filter matches - should process",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "sshd",
			},
			line:          "Jan 1 12:00:00 server sshd[1234]: Failed login from 192.168.1.1",
			shouldProcess: true,
		},
		{
			name: "Include filter doesn't match - should not process",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "sshd",
			},
			line:          "Jan 1 12:00:00 server httpd[1234]: Request from 192.168.1.1",
			shouldProcess: false,
		},
		{
			name: "Exclude filter matches - should not process",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				ExcludeFilter: "internal",
			},
			line:          "Jan 1 12:00:00 server sshd[1234]: internal authentication from 192.168.1.1",
			shouldProcess: false,
		},
		{
			name: "Exclude filter doesn't match - should process",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				ExcludeFilter: "internal",
			},
			line:          "Jan 1 12:00:00 server sshd[1234]: Failed login from 192.168.1.1",
			shouldProcess: true,
		},
		{
			name: "Both filters - include matches, exclude doesn't - should process",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "sshd",
				ExcludeFilter: "internal",
			},
			line:          "Jan 1 12:00:00 server sshd[1234]: Failed login from 192.168.1.1",
			shouldProcess: true,
		},
		{
			name: "Both filters - include matches, exclude matches - should not process",
			logFile: SSHLogFile{
				Path:          "/var/log/auth.log",
				IPRegex:       `(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)`,
				IncludeFilter: "sshd",
				ExcludeFilter: "internal",
			},
			line:          "Jan 1 12:00:00 server sshd[1234]: internal authentication from 192.168.1.1",
			shouldProcess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor := &LogFileMonitor{
				config: &tt.logFile,
			}

			// Compile regex patterns
			var err error
			if tt.logFile.IncludeFilter != "" {
				monitor.includeRegex, err = regexp.Compile(tt.logFile.IncludeFilter)
				if err != nil {
					t.Fatalf("Failed to compile include regex: %v", err)
				}
			}
			if tt.logFile.ExcludeFilter != "" {
				monitor.excludeRegex, err = regexp.Compile(tt.logFile.ExcludeFilter)
				if err != nil {
					t.Fatalf("Failed to compile exclude regex: %v", err)
				}
			}

			result := monitor.shouldProcessLine(tt.line)
			if result != tt.shouldProcess {
				t.Errorf("Expected shouldProcessLine to return %v, got %v", tt.shouldProcess, result)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "No duplicates",
			input:    []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			expected: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name:     "With duplicates",
			input:    []string{"192.168.1.1", "192.168.1.2", "192.168.1.1", "192.168.1.3", "192.168.1.2"},
			expected: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name:     "Empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Single element",
			input:    []string{"192.168.1.1"},
			expected: []string{"192.168.1.1"},
		},
		{
			name:     "All duplicates",
			input:    []string{"192.168.1.1", "192.168.1.1", "192.168.1.1"},
			expected: []string{"192.168.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDuplicates(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected length %d, got %d", len(tt.expected), len(result))
				return
			}

			// Create maps to compare regardless of order
			expectedMap := make(map[string]bool)
			for _, item := range tt.expected {
				expectedMap[item] = true
			}

			resultMap := make(map[string]bool)
			for _, item := range result {
				resultMap[item] = true
			}

			for item := range expectedMap {
				if !resultMap[item] {
					t.Errorf("Expected item %s not found in result", item)
				}
			}

			for item := range resultMap {
				if !expectedMap[item] {
					t.Errorf("Unexpected item %s found in result", item)
				}
			}
		})
	}
}

func TestSanitizeForDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Path with slashes",
			input:    "/var/log/auth.log",
			expected: "var-log-auth-log",
		},
		{
			name:     "Path with special characters",
			input:    "/var/log/auth.log.1.gz",
			expected: "var-log-auth-log-1-gz",
		},
		{
			name:     "Simple name",
			input:    "logfile",
			expected: "logfile",
		},
		{
			name:     "With spaces and underscores",
			input:    "my log_file name",
			expected: "my-log-file-name",
		},
		{
			name:     "Leading/trailing hyphens",
			input:    "-test-file-",
			expected: "test-file",
		},
		{
			name:     "Very long string",
			input:    "this_is_a_very_long_filename_that_should_be_truncated_to_fifty_characters_maximum",
			expected: "this-is-a-very-long-filename-that-should-be-truncat",
		},
		{
			name:     "Mixed case",
			input:    "LogFile.TXT",
			expected: "logfile-txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForDomain(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetSSHLogMonitorStatus(t *testing.T) {
	// Reset global state
	sshMonitors = make(map[string]*SSHMonitor)
	sshLogConfig = &SSHLogConfig{
		Enabled: true,
	}

	// Test empty monitors
	status := getSSHLogMonitorStatus()
	if !status.Enabled {
		t.Errorf("Expected status to be enabled")
	}
	if status.ActiveServers != 0 {
		t.Errorf("Expected 0 active servers, got %d", status.ActiveServers)
	}

	// Add a mock monitor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := &SSHMonitor{
		config: &SSHServer{
			Name: "test-server",
			LogFiles: []SSHLogFile{
				{Path: "/var/log/auth.log"},
				{Path: "/var/log/syslog"},
			},
		},
		ctx:    ctx,
		cancel: cancel,
		status: &SSHServerStatus{
			Name:           "test-server",
			Connected:      true,
			LogFilesActive: 2,
			LinesProcessed: 100,
			IPsExtracted:   50,
			LastActivity:   time.Now(),
		},
	}

	sshMonitorMutex.Lock()
	sshMonitors["test-server"] = monitor
	sshMonitorMutex.Unlock()

	status = getSSHLogMonitorStatus()
	if status.ActiveServers != 1 {
		t.Errorf("Expected 1 active server, got %d", status.ActiveServers)
	}
	if status.TotalLogFiles != 2 {
		t.Errorf("Expected 2 total log files, got %d", status.TotalLogFiles)
	}
	if status.ActiveLogFiles != 2 {
		t.Errorf("Expected 2 active log files, got %d", status.ActiveLogFiles)
	}

	serverStatus, exists := status.ServerStatuses["test-server"]
	if !exists {
		t.Errorf("Expected server status for test-server")
	}
	if !serverStatus.Connected {
		t.Errorf("Expected server to be connected")
	}
	if serverStatus.LinesProcessed != 100 {
		t.Errorf("Expected 100 lines processed, got %d", serverStatus.LinesProcessed)
	}

	// Clean up
	sshMonitors = make(map[string]*SSHMonitor)
	sshLogConfig = nil
}

// Mock Redis client for testing
type mockRedisClient struct {
	data map[string]string
	ttls map[string]time.Duration
}

func (m *mockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if m.data == nil {
		m.data = make(map[string]string)
	}
	if m.ttls == nil {
		m.ttls = make(map[string]time.Duration)
	}
	m.data[key] = value.(string)
	m.ttls[key] = expiration
	
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func (m *mockRedisClient) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	if m.data == nil {
		m.data = make(map[string]string)
	}
	
	count := int64(0)
	for _, key := range keys {
		if _, exists := m.data[key]; exists {
			count++
		}
	}
	
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(count)
	return cmd
}

func TestProcessExtractedData(t *testing.T) {
	// This is a more complex test that would require mocking SSH connections
	// For now, we'll test the data processing logic separately
	t.Skip("Integration test - requires SSH server setup")
}