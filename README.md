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
# Keep in mind newer PHP versions are preferred, however you have to make sure it's supported by Wordpress
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
*Bonus*: You can just run the script `bash wp-base.sh` for automatically executing the steps from 1 to 4.
```
wget -O - https://raw.githubusercontent.com/whitejaguars/wordpress-security/master/wp-base.sh | bash
```

5. Installing Wordpress: http://{server_ip}
```
Database: wordpress
User: wordpressuser
Password: your_super_secure_password_here
```

6. Prepare NGinX for HTTPS and Let's Encrypt:
```
sudo pico /etc/nginx/sites-enabled/wpworkshop.wj.cr
```
Uncomment `server_name www.yourdomain.com yourdomain.com;` replacing 'wpworkshop.wj.cr' with your domain name, please make sure to have completed all the steps required for pointing the sub-domain to your server's IP address.
Comment `server_name _;`

7. Install Let's Encrypt:
```
sudo apt-get update
sudo apt-get install software-properties-common
sudo add-apt-repository universe
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update
sudo apt-get install certbot python-certbot-nginx
```
If everything went well then start the certbot wizard:
```
sudo certbot --nginx
# Answer the questions, it's very straight forward
```
Validate your configuration running `sudo nginx -t`

8. Security configuration in NGinX
Remove the file `readme.html`, this is a good practice for not exposing the Wordpress version and some other information useful from the attacker's perspective
```
sudo mv /var/www/html/wpworkshop.wj.cr/readme.html ~/readme.html
```
Add the following to the NGinX configuration for restricting the known weak ciphers and vulnerable protocols:
```
sudo pico /etc/nginx/nginx.conf
```
```
# WhiteJaguars Security Settings
ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
ssl_ecdh_curve secp384r1;
ssl_stapling on;
ssl_stapling_verify on;
```
Now, let's configure the security headers in your site's configuration file:
```
sudo pico /etc/nginx/sites-enabled/wpworkshop.wj.cr
```
Let's make it look like this (add just the section within `# WhiteJaguars Security Settings` comments:
```
server {
    server_name wpworkshop.wj.cr;
    #server_name _;
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
        try_files $uri $uri/ /index.php?$args =404;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    }
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/wpworkshop.wj.cr/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/wpworkshop.wj.cr/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
    # WhiteJaguars Security Settings - start
    server_tokens off;
    add_header Content-Security-Policy: "default-src 'self'; img-src 'self' https://i.imgur.com; object-src 'none'; script-src 'self'; style-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self’";
    add_header X-XSS-Protection: "1; mode=block";
    add_header X-Frame-Options: deny;
    add_header X-Content-Type-Options: nosniff;
    add_header Strict-Transport-Security: max-age=3600;
    location ~* \.(?:ico|css|js|gif|jpe?g|png|svg|woff|ttf|eot)$ {
       try_files $uri @rewriteapp;
       add_header Cache-Control "max-age=86400, public";
    }
    # WhiteJaguars Security Settings - end
}
server {
    if ($host = wpworkshop.wj.cr) {
        return 301 https://$host$request_uri;
    } # managed by Certbot
    listen 80 default_server;
    server_name wpworkshop.wj.cr;
    return 404; # managed by Certbot
}
```
Validate your configuration once again with `sudo nginx -t`

If everything's Ok, you can test your SSL configuration here and hopefully you'll get a nice A+
Keep in mind that you may have to adjust the Content Security Policy header depending on the plugins or modules installed, some may stop working so for that case you should take the time for testing configure that header properly as the code included here should be considered as an starting point.
```
https://www.ssllabs.com/ssltest/analyze.html?d=wpworkshop.wj.cr
```
We're not done yet, let's add more security to your PHP configuration.

9.PHP settings:
```
sudo pico /etc/php/7.2/fpm/php.ini
```
Validate the following options
```
expose_php = Off
enable_dl = Off
```
