# WhiteJaguars Wordpress Security guide
Techonology stack: Ubuntu 18 LTS + NGinX + PHP + Wordpress

## Installing Wordpress
1. Let's start by installing MySQL:
```
sudo apt install mysql-server -y

sudo mysql --user=root -e "CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
sudo mysql --user=root -e "GRANT ALL ON wordpress.* TO 'wordpressuser'@'localhost' IDENTIFIED BY 'your_super_secure_password_here';"
sudo mysql --user=root -e "FLUSH PRIVILEGES;"
```

2. Installing PHP:
```
sudo apt install php7.2-cli php7.2-fpm php7.2-mysql php7.2-json php7.2-opcache php7.2-mbstring php7.2-xml php7.2-gd php7.2-curl -y
```

3. Download Wordpress:
```
sudo mkdir -p /var/www/html/wpworkshop.wj.cr

cd /tmp
wget https://wordpress.org/latest.tar.gz

tar xf latest.tar.gz
rm latest.tar.gz
sudo mv /tmp/wordpress/* /var/www/html/wpworkshop.wj.cr/
sudo chown -R www-data: /var/www/html/wpworkshop.wj.cr
```

4. Installing NginX:
```
sudo apt install nginx -y
sudo systemctl enable nginx
sudo systemctl restart nginx

sudo touch /etc/nginx/sites-available/wpworkshop.wj.cr
echo "server {
    listen 80 default_server;
    # server_name wpworkshop.wj.cr;
    server_name _;

    root /var/www/html/wpworkshop.wj.cr;
    index index.php;

    # log files
    access_log /var/log/nginx/wpworkshop.wj.cr.access.log;
    error_log /var/log/nginx/wpworkshop.wj.cr.error.log;

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$args =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }

}
" | sudo tee -a /etc/nginx/sites-available/wpworkshop.wj.cr
sudo ln -s /etc/nginx/sites-available/wpworkshop.wj.cr /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

5. Installing Wordpress: http://{server_ip}
