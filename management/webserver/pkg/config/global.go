package config

type Config struct {
	Log          LogConfig
	DB           DBConfig
	Server       ServerConfig
	Detector     DetectorConfig
	Telemetry    TelemetryConfig
	GPRC         GRPCConfig
	PlatformAddr string
	MgtResDir    string
	NgxResDir    string
}

func DefaultGlobalConfig() Config {
	return Config{
		Log:          DefaultLogConfig(),
		DB:           DefaultDBConfig(),
		Server:       DefaultServerConfig(),
		Detector:     DefaultDetectorConfig(),
		Telemetry:    DefaultTelemetryConfig(),
		GPRC:         DefaultGRPCConfig(),
		PlatformAddr: "", // HiTechCloud WAF: set platform_addr in config.yml to enable upgrade tips
		MgtResDir:    "/resources/management",
		NgxResDir:    "/resources/nginx",
	}
}
