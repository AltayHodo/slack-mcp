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

# OAuth state database lives here (SLACK_MCP_DB_PATH defaults to
# ./data/slack-mcp.db). Mount a volume at /app/data and pass
# SLACK_MCP_ENCRYPTION_KEY, or state is lost on container replacement:
#   docker run -v slack-mcp-data:/app/data -e SLACK_MCP_ENCRYPTION_KEY=... slack-mcp
RUN mkdir -p /app/data
VOLUME /app/data

# Expose port for HTTP transport
EXPOSE 8001

# Run the server using uv run to use the virtual environment
CMD ["uv", "run", "python", "main.py"]
