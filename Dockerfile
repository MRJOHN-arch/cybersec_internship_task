# Use node-slim to keep the image size small
FROM node:18-slim

# Install build tools for native modules like bcrypt/sqlite3
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy dependency files first to leverage Docker layer caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# SECURITY: Change ownership of /app to the non-root 'node' user
RUN chown -R node:node /app

# Switch to the non-root user for execution
USER node

# Expose the application port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
