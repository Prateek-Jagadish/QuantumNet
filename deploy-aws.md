# AWS EC2 Deployment Guide

## 🚀 Deploy QuantumNet to AWS EC2

### Step 1: Create AWS Account
1. **Sign up**: https://aws.amazon.com/
2. **Free Tier**: Get 12 months free (t2.micro instance)

### Step 2: Launch EC2 Instance
1. **Go to**: EC2 Dashboard → Launch Instance
2. **Choose AMI**: Ubuntu Server 20.04 LTS
3. **Instance Type**: t2.micro (Free Tier eligible)
4. **Key Pair**: Create new or use existing
5. **Security Group**: 
   - SSH (22) from your IP
   - HTTP (80) from anywhere
   - HTTPS (443) from anywhere
   - Custom TCP (5000) from anywhere

### Step 3: Connect to EC2
```bash
# Download your key pair (.pem file)
# Make it executable
chmod 400 your-key.pem

# Connect to instance
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

### Step 4: Deploy QuantumNet
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo apt install docker-compose -y

# Clone and deploy
git clone https://github.com/Prateek-Jagadish/QuantumNet.git
cd QuantumNet
sudo docker-compose up -d

# Check status
sudo docker-compose ps
```

### Step 5: Configure Domain (Optional)
```bash
# Install Nginx
sudo apt install nginx -y

# Configure reverse proxy
sudo nano /etc/nginx/sites-available/quantumnet

# Add configuration:
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

# Enable site
sudo ln -s /etc/nginx/sites-available/quantumnet /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Install SSL
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yourdomain.com
```

## 🔧 Production Configuration

### Environment Variables
```bash
# Create .env file
sudo nano .env

# Add:
FLASK_ENV=production
DATABASE_URL=postgresql://quantumnet:password@db:5432/quantumnet
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-super-secret-key-here
```

### Security Hardening
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable

# Set up automatic updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

## 💰 Cost Breakdown (AWS Free Tier)
- **EC2 t2.micro**: FREE (12 months)
- **EBS Storage**: FREE (30GB)
- **Data Transfer**: FREE (1GB/month)
- **Domain**: $12/year (optional)
- **SSL**: FREE (Let's Encrypt)
- **Total**: $0-1/month (first year)

## 🚀 Scaling Options
- **t2.small**: $17/month (2GB RAM)
- **t2.medium**: $34/month (4GB RAM)
- **RDS Database**: $15/month (managed PostgreSQL)
- **Elastic Load Balancer**: $18/month
- **CloudFront CDN**: $1/month + data transfer

## 📊 Monitoring Setup
```bash
# Install monitoring tools
sudo apt install htop iotop nethogs -y

# Set up log rotation
sudo nano /etc/logrotate.d/quantumnet

# Add:
/var/log/quantumnet/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 ubuntu ubuntu
}
```
