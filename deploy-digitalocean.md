# DigitalOcean Deployment Guide

## 🚀 Deploy QuantumNet to DigitalOcean

### Step 1: Create DigitalOcean Droplet
1. **Sign up**: https://www.digitalocean.com/
2. **Create Droplet**:
   - **OS**: Ubuntu 20.04 LTS
   - **Size**: Basic $6/month (1GB RAM, 1 CPU)
   - **Region**: Choose closest to your users
   - **Authentication**: SSH Key (recommended)

### Step 2: Connect to Your Droplet
```bash
# Replace with your droplet IP
ssh root@YOUR_DROPLET_IP

# Or if using SSH key:
ssh -i ~/.ssh/your_key root@YOUR_DROPLET_IP
```

### Step 3: Deploy QuantumNet
```bash
# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
apt install docker-compose -y

# Clone QuantumNet
git clone https://github.com/Prateek-Jagadish/QuantumNet.git
cd QuantumNet

# Deploy with Docker
docker-compose up -d

# Check status
docker-compose ps
```

### Step 4: Configure Domain (Optional)
```bash
# Install Nginx
apt install nginx -y

# Configure domain
# Edit /etc/nginx/sites-available/default
# Add your domain configuration

# Install SSL with Let's Encrypt
apt install certbot python3-certbot-nginx -y
certbot --nginx -d yourdomain.com
```

### Step 5: Access Your Application
- **HTTP**: http://YOUR_DROPLET_IP:5000
- **HTTPS**: https://yourdomain.com (if configured)

## 🔧 Configuration Files

### Environment Variables
Create `.env` file:
```bash
FLASK_ENV=production
DATABASE_URL=postgresql://quantumnet:password@db:5432/quantumnet
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-secret-key-here
```

### Nginx Configuration
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 💰 Cost Breakdown
- **Droplet**: $6/month (1GB RAM)
- **Domain**: $12/year (optional)
- **SSL**: Free (Let's Encrypt)
- **Total**: ~$6-7/month

## 🚀 Scaling Options
- **Upgrade Droplet**: $12/month (2GB RAM) for more users
- **Load Balancer**: $12/month for high availability
- **Managed Database**: $15/month for production database
