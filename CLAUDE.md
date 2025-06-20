# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Local Development with Docker
```bash
# Start all services (recommended for development)
docker-compose up

# Build and run in detached mode
docker-compose up -d --build
```

### Direct Go Build
```bash
# Install dependencies (using old GOPATH method)
go get github.com/gorilla/sessions
go get golang.org/x/crypto/bcrypt
go get github.com/globalsign/mgo

# Build the application
go build main.go

# Run with required environment variables
MONGODB_URI="mongodb://localhost:27017/clock" SECRET="your-secret-key" ./main
```

### Required Environment Variables
- `MONGODB_URI`: MongoDB connection string (e.g., `mongodb://mongo:27017/clock` for Docker)
- `SECRET`: Session secret for cookie store

## Architecture Overview

### Service Architecture
The application runs as a microservices setup with:
1. **Nginx** (port 3000) - Reverse proxy routing:
   - `/` → Frontend service (React app from GitLab registry)
   - `/api/*` → Backend service (this Go application)
2. **Backend** - Go REST API serving on port 3000 internally
3. **MongoDB 3.5** - Data persistence on port 27017

### Data Models
- **User**: Stores email, username (case-insensitive via cleanUsername), bcrypt-hashed password
- **Time**: Alarm times linked to users via OwnerID, includes hours/minutes/seconds, AM/PM flag, and active days array

### API Endpoints
All endpoints return JSON and include CORS headers for cross-origin requests:
- Authentication: `/api/login`, `/api/logout`, `/api/loginstatus`
- User Management: `/api/newuser`, `/api/deleteuser`
- Alarm Management: `/api/newtime`, `/api/edittime`, `/api/deletetime`

### Session Management
Uses Gorilla sessions with cookie store. Session cookie contains user ID after successful login.

### Deployment
- **Development branch** → Deploys to dev environment
- **Master branch** → Deploys to production
- Deployment triggered via webhook to `https://clock.connorpeshek.me/updateback`

## Important Notes
- Go version 1.10 is used (outdated - consider upgrading)
- No go.mod file - uses old GOPATH dependency management
- No tests exist in the codebase
- Frontend is served from `/public` directory (for standalone mode) or via separate container