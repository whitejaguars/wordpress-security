
# Install MySQL
sudo apt install mysql-server -y

sudo mysql --user=root -e "CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
sudo mysql --user=root -e "GRANT ALL ON wordpress.* TO 'wordpressuser'@'localhost' IDENTIFIED BY 's6hft#4hb2@jM9k468';"
sudo mysql --user=root -e "FLUSH PRIVILEGES;"

# PHP 7.2
sudo apt install php7.2-cli php7.2-fpm php7.2-mysql php7.2-json php7.2-opcache php7.2-mbstring php7.2-xml php7.2-gd php7.2-curl -y
# PHP 7.4
#sudo apt install software-properties-common
#sudo add-apt-repository ppa:ondrej/php
#sudo apt update
#sudo apt install php7.4-cli php7.4-fpm php7.4-mysql php7.4-json php7.4-opcache php7.4-mbstring php7.4-xml php7.4-gd php7.4-curl -y

# Wordpress 
sudo mkdir -p /var/www/html/wpworkshop.wj.cr

cd /tmp
wget https://wordpress.org/latest.tar.gz

tar xf latest.tar.gz
rm latest.tar.gz
sudo mv /tmp/wordpress/* /var/www/html/wpworkshop.wj.cr/
sudo chown -R www-data: /var/www/html/wpworkshop.wj.cr

# NGinx 
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