package config

import (
	"fmt"
	"net/url"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	AppEnv string `env:"KEYLOG_APP_ENV" envDefault:"development"`

	Logger   Logger
	HTTP     HTTP
	Log      Log
	Submit   Submit
	Postgres Postgres
}

type Logger struct {
	Level  string `env:"KEYLOG_LOG_LEVEL"  envDefault:"info"`
	Format string `env:"KEYLOG_LOG_FORMAT" envDefault:"json"`
}

type HTTP struct {
	Addr            string        `env:"KEYLOG_HTTP_ADDR"             envDefault:":8091"`
	WellKnownPath   string        `env:"KEYLOG_WELL_KNOWN_PATH"`
	ReadTimeout     time.Duration `env:"KEYLOG_HTTP_READ_TIMEOUT"     envDefault:"10s"`
	WriteTimeout    time.Duration `env:"KEYLOG_HTTP_WRITE_TIMEOUT"    envDefault:"15s"`
	ShutdownTimeout time.Duration `env:"KEYLOG_HTTP_SHUTDOWN_TIMEOUT" envDefault:"30s"`
}

type Log struct {
	Path               string        `env:"KEYLOG_LOG_PATH"               envDefault:"./dev-log"`
	Origin             string        `env:"KEYLOG_ORIGIN,required"`
	NoteKeyPath        string        `env:"KEYLOG_NOTE_KEY_PATH"`
	NoteVerifierKey    string        `env:"KEYLOG_NOTE_VERIFIER_KEY"`
	VRFKeyPath         string        `env:"KEYLOG_VRF_KEY_PATH"`
	WitnessPolicyPath  string        `env:"KEYLOG_WITNESS_POLICY_PATH"`
	CheckpointInterval time.Duration `env:"KEYLOG_CHECKPOINT_INTERVAL"    envDefault:"1s"`
	MaxCosignatureAge  time.Duration `env:"KEYLOG_MAX_COSIGNATURE_AGE"    envDefault:"25h"`
	IntegrationTimeout time.Duration `env:"KEYLOG_INTEGRATION_TIMEOUT"    envDefault:"30s"`
	SweepInterval      time.Duration `env:"KEYLOG_SWEEP_INTERVAL"         envDefault:"1s"`
	SweepBatch         int           `env:"KEYLOG_SWEEP_BATCH"            envDefault:"64"`
}

type Submit struct {
	Tokens       []string `env:"KEYLOG_SUBMIT_TOKENS,unset" envSeparator:","`
	MaxBodyBytes int64    `env:"KEYLOG_SUBMIT_MAX_BODY_BYTES" envDefault:"65536"`
}

type Postgres struct {
	Host            string        `env:"KEYLOG_POSTGRES_HOST"              envDefault:"127.0.0.1"`
	Port            int           `env:"KEYLOG_POSTGRES_PORT"              envDefault:"5432"`
	User            string        `env:"KEYLOG_POSTGRES_USER,required"`
	Password        string        `env:"KEYLOG_POSTGRES_PASSWORD,required,unset"`
	Database        string        `env:"KEYLOG_POSTGRES_DB,required"`
	SSLMode         string        `env:"KEYLOG_POSTGRES_SSLMODE"           envDefault:"disable"`
	MaxOpenConns    int           `env:"KEYLOG_POSTGRES_MAX_OPEN_CONNS"    envDefault:"10"`
	MaxIdleConns    int           `env:"KEYLOG_POSTGRES_MAX_IDLE_CONNS"    envDefault:"2"`
	ConnMaxLifetime time.Duration `env:"KEYLOG_POSTGRES_CONN_MAX_LIFETIME" envDefault:"30m"`
}

func (p Postgres) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(p.User, p.Password),
		Host:     fmt.Sprintf("%s:%d", p.Host, p.Port),
		Path:     p.Database,
		RawQuery: "sslmode=" + url.QueryEscape(p.SSLMode),
	}
	return u.String()
}

func Load() (Config, error) {
	_ = godotenv.Load(".env")
	return env.ParseAs[Config]()
}
