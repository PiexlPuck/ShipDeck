FROM node:20-alpine

# Install Docker CLI, Docker Compose plugin, Git, and OpenSSH client
RUN apk add --no-cache \
    docker-cli \
    docker-cli-compose \
    git \
    openssh-client

# Set working directory
WORKDIR /app

# Copy package dependencies
COPY package*.json ./

# Install npm dependencies
RUN npm ci --only=production

# Copy application files
COPY server.js ./
COPY index.html ./
COPY auth_instructions.md ./

# Expose port (default 3000)
EXPOSE 3000

# Start server
CMD ["node", "server.js"]
