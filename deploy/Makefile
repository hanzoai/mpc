# Lux MPC/KMS Deployment Makefile
#
# Usage:
#   make setup     - Create config files and directories
#   make up        - Start all services
#   make down      - Stop all services
#   make logs      - View logs
#   make backup    - Trigger manual backup
#   make restore   - Restore from backup

.PHONY: all setup up down logs backup restore clean keygen status monitoring

# Configuration
COMPOSE_FILE := compose.yml
PROJECT_NAME := lux-mpc

# Default target
all: setup up

# ============================================================
# SETUP
# ============================================================

setup: dirs config
	@echo "Setup complete. Run 'make up' to start services."

dirs:
	@mkdir -p config/mpc/node-{0,1,2}
	@mkdir -p config/kms
	@mkdir -p config/minio
	@mkdir -p config/postgres
	@mkdir -p config/prometheus
	@mkdir -p config/grafana/dashboards
	@mkdir -p config/grafana/datasources
	@mkdir -p data/backups
	@chmod -R 700 config/

config: config/minio/backup-lifecycle.json config/postgres/init.sql config/prometheus/prometheus.yml
	@echo "Configuration files created."

config/minio/backup-lifecycle.json:
	@echo '{"Rules":[{"ID":"backup-expiration","Status":"Enabled","Expiration":{"Days":30},"Filter":{"Prefix":"backups/"}}]}' > $@

config/postgres/init.sql:
	@cat > $@ << 'EOF'
-- Lux KMS Database Initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS mpc;
CREATE SCHEMA IF NOT EXISTS kms;

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA mpc TO lux;
GRANT ALL PRIVILEGES ON SCHEMA kms TO lux;
EOF

config/prometheus/prometheus.yml:
	@cat > $@ << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'mpc-nodes'
    static_configs:
      - targets:
        - 'lux-mpc-0:6000'
        - 'lux-mpc-1:6001'
        - 'lux-mpc-2:6002'

  - job_name: 'kms'
    static_configs:
      - targets: ['lux-kms:8080']

  - job_name: 'nats'
    static_configs:
      - targets: ['lux-nats:8222']

  - job_name: 'consul'
    static_configs:
      - targets: ['lux-consul:8500']
EOF

# Generate encryption keys
gen-keys:
	@echo "Generating encryption keys..."
	@echo "BADGER_KEY_0=$$(openssl rand -hex 32)" >> .env
	@echo "BADGER_KEY_1=$$(openssl rand -hex 32)" >> .env
	@echo "BADGER_KEY_2=$$(openssl rand -hex 32)" >> .env
	@echo "KMS_ENCRYPTION_KEY=$$(openssl rand -hex 32)" >> .env
	@echo "JWT_SECRET=$$(openssl rand -hex 32)" >> .env
	@echo "Keys generated and saved to .env"

# ============================================================
# DEPLOYMENT
# ============================================================

up:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) up -d

up-monitoring:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) --profile monitoring up -d

down:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) down

stop:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) stop

restart: down up

logs:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) logs -f

logs-mpc:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) logs -f lux-mpc-0 lux-mpc-1 lux-mpc-2

logs-kms:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) logs -f lux-kms

status:
	@echo "=== Service Status ==="
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) ps
	@echo ""
	@echo "=== MPC Node Health ==="
	@curl -s http://localhost:6000/health 2>/dev/null || echo "MPC Node 0: DOWN"
	@curl -s http://localhost:6001/health 2>/dev/null || echo "MPC Node 1: DOWN"
	@curl -s http://localhost:6002/health 2>/dev/null || echo "MPC Node 2: DOWN"
	@echo ""
	@echo "=== KMS Health ==="
	@curl -s http://localhost:8080/health 2>/dev/null || echo "KMS: DOWN"
	@echo ""
	@echo "=== Consul Members ==="
	@docker exec lux-consul consul members 2>/dev/null || echo "Consul: DOWN"

# ============================================================
# MPC OPERATIONS
# ============================================================

keygen:
	@echo "Generating MPC keys..."
	docker exec lux-mpc-0 hanzo-mpc-cli keygen --wallet-id $(WALLET_ID) --threshold 2

sign:
	@echo "Initiating signing..."
	docker exec lux-mpc-0 hanzo-mpc-cli sign --wallet-id $(WALLET_ID) --message $(MESSAGE)

# ============================================================
# BACKUP OPERATIONS
# ============================================================

backup:
	@echo "Triggering manual backup..."
	@for node in 0 1 2; do \
		echo "Backing up MPC node $$node..."; \
		docker exec lux-mpc-$$node hanzo-mpc backup --s3; \
	done
	@echo "Backing up KMS..."
	docker exec lux-kms npm run backup
	@echo "Backup complete."

backup-local:
	@echo "Creating local backup..."
	@mkdir -p data/backups/$$(date +%Y%m%d)
	@for node in 0 1 2; do \
		docker exec lux-mpc-$$node hanzo-mpc backup --output /data/backup.bak; \
		docker cp lux-mpc-$$node:/data/backup.bak data/backups/$$(date +%Y%m%d)/mpc-node-$$node.bak; \
	done
	@docker exec lux-kms npm run backup:local
	@docker cp lux-kms:/app/data/backup.tar.gz data/backups/$$(date +%Y%m%d)/kms.tar.gz
	@echo "Local backup complete: data/backups/$$(date +%Y%m%d)/"

restore:
	@echo "Restoring from backup..."
	@read -p "Backup date (YYYYMMDD): " date; \
	for node in 0 1 2; do \
		echo "Restoring MPC node $$node..."; \
		docker cp data/backups/$$date/mpc-node-$$node.bak lux-mpc-$$node:/data/restore.bak; \
		docker exec lux-mpc-$$node hanzo-mpc restore --input /data/restore.bak; \
	done
	@echo "Restoring KMS..."
	@docker cp data/backups/$$date/kms.tar.gz lux-kms:/app/data/restore.tar.gz
	@docker exec lux-kms npm run restore
	@echo "Restore complete. Restart services with 'make restart'"

# List available backups in S3
list-backups:
	docker exec lux-minio mc ls myminio/mpc-backups --recursive
	docker exec lux-minio mc ls myminio/kms-backups --recursive

# ============================================================
# MAINTENANCE
# ============================================================

clean:
	docker compose -f $(COMPOSE_FILE) -p $(PROJECT_NAME) down -v
	rm -rf data/backups/*

prune:
	docker system prune -f
	docker volume prune -f

# Shell into containers
shell-mpc-0:
	docker exec -it lux-mpc-0 /bin/sh

shell-mpc-1:
	docker exec -it lux-mpc-1 /bin/sh

shell-mpc-2:
	docker exec -it lux-mpc-2 /bin/sh

shell-kms:
	docker exec -it lux-kms /bin/sh

shell-db:
	docker exec -it lux-postgres psql -U lux -d luxkms

# ============================================================
# DEVELOPMENT
# ============================================================

build:
	@echo "Building MPC binary..."
	cd .. && make build
	@echo "Building KMS..."
	cd ../../kms && npm run build

build-images:
	@echo "Building Docker images..."
	docker build -t ghcr.io/luxfi/mpc:latest ..
	docker build -t ghcr.io/luxfi/kms:latest ../../kms

push-images:
	docker push ghcr.io/luxfi/mpc:latest
	docker push ghcr.io/luxfi/kms:latest

# ============================================================
# TESTING
# ============================================================

test-keygen:
	@echo "Testing key generation..."
	docker exec lux-mpc-0 hanzo-mpc-cli keygen \
		--wallet-id test-wallet-$$(date +%s) \
		--threshold 2 \
		--verbose

test-signing:
	@echo "Testing signing..."
	docker exec lux-mpc-0 hanzo-mpc-cli sign \
		--wallet-id $(WALLET_ID) \
		--message "test message $$(date +%s)" \
		--verbose

health-check:
	@echo "Running health checks..."
	@curl -sf http://localhost:6000/health && echo "MPC-0: OK" || echo "MPC-0: FAIL"
	@curl -sf http://localhost:6001/health && echo "MPC-1: OK" || echo "MPC-1: FAIL"
	@curl -sf http://localhost:6002/health && echo "MPC-2: OK" || echo "MPC-2: FAIL"
	@curl -sf http://localhost:8080/health && echo "KMS: OK" || echo "KMS: FAIL"
	@curl -sf http://localhost:4222 && echo "NATS: OK" || echo "NATS: FAIL"
	@curl -sf http://localhost:8500/v1/status/leader && echo "Consul: OK" || echo "Consul: FAIL"
	@curl -sf http://localhost:9000/minio/health/live && echo "MinIO: OK" || echo "MinIO: FAIL"

# ============================================================
# HELP
# ============================================================

help:
	@echo "Lux MPC/KMS Deployment"
	@echo ""
	@echo "Setup:"
	@echo "  make setup        - Create config files and directories"
	@echo "  make gen-keys     - Generate encryption keys"
	@echo ""
	@echo "Deployment:"
	@echo "  make up           - Start all services"
	@echo "  make up-monitoring - Start with Prometheus/Grafana"
	@echo "  make down         - Stop all services"
	@echo "  make restart      - Restart all services"
	@echo "  make status       - Show service status"
	@echo ""
	@echo "Logs:"
	@echo "  make logs         - View all logs"
	@echo "  make logs-mpc     - View MPC node logs"
	@echo "  make logs-kms     - View KMS logs"
	@echo ""
	@echo "MPC Operations:"
	@echo "  make keygen WALLET_ID=xxx    - Generate new MPC keys"
	@echo "  make sign WALLET_ID=xxx MESSAGE=xxx - Sign a message"
	@echo ""
	@echo "Backup/Restore:"
	@echo "  make backup       - Trigger S3 backup"
	@echo "  make backup-local - Create local backup"
	@echo "  make restore      - Restore from backup"
	@echo "  make list-backups - List S3 backups"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean        - Remove all data"
	@echo "  make prune        - Clean Docker resources"
	@echo "  make shell-mpc-0  - Shell into MPC node 0"
	@echo "  make shell-kms    - Shell into KMS"
	@echo "  make shell-db     - PostgreSQL shell"
	@echo ""
	@echo "Development:"
	@echo "  make build        - Build binaries"
	@echo "  make build-images - Build Docker images"
	@echo "  make test-keygen  - Test key generation"
	@echo "  make health-check - Run health checks"
