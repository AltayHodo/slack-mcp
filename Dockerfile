FROM python:3.11-slim

# Disable colours/progress in CI
ENV NO_COLOR=1 CI=true TERM=dumb

# Install uv for dependency management
RUN pip install uv

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY pyproject.toml uv.lock ./

# Copy the rest of the application (needed for editable install)
COPY . .

# Install dependencies
RUN uv --quiet sync --frozen

# OAuth state persistence (always pass SLACK_MCP_ENCRYPTION_KEY):
#  - Production: set SLACK_MCP_DATABASE_URL to a managed Postgres DSN. State
#    lives in the database; no volume needed and the container stays stateless,
#    so this scales to multiple replicas.
#  - SQLite fallback (single instance): when SLACK_MCP_DATABASE_URL is unset the
#    DB is a file under /app/data — mount a volume there or state is lost on
#    container replacement: docker run -v slack-mcp-data:/app/data ... slack-mcp
RUN mkdir -p /app/data
VOLUME /app/data

# Expose port for HTTP transport
EXPOSE 8001

# Run the server using uv run to use the virtual environment
CMD ["uv", "run", "python", "main.py"]
