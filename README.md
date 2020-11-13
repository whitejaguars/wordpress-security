# WhiteJaguars Wordpress Security guide
Techonology stack: Ubuntu 18 LTS + NGinX + PHP + Wordpress

This is part of a workshop we created for including security in Wordpress installations, the initial steps in this guide are standard commands for installing pre-requisites.

The sub-domain used for this guide is *wpworkshop.wj.cr*, just replace it with the one you're going to use.

Why using:
* Ubuntu 18 LTS: Becuase at this moment, the Let's encrypt certbot client is not supported in Ubuntu 20, this OS is also "friendly" which makes it a good fit for this workshop.
* NGinX: Some people think it has better performance than Apache, at the end feel free to use the one you feel more confortable with.
* PHP 7.2: Even if the desired option is installing the latest version for security reasons, the downside is that not always the latest version works perfectly with Wordpress, make sure to find good documentation about compatibility before chosing the PHP version.
* Wordpress: I don't need to explain this right ?

## Installing Wordpress

### 1. Let's start by installing MySQL:
Using a custom and difficult to guess username is recommended, also make sure the password is strong enough.
```
sudo apt install mysql-server -y

sudo mysql --user=root -e "CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
sudo mysql --user=root -e "GRANT ALL ON wordpress.* TO 'userdifficulttoguess'@'localhost' IDENTIFIED BY 'your_super_secure_password_here';"
sudo mysql --user=root -e "FLUSH PRIVILEGES;"
```
A few considerations:
* It's not recommended to install the Database engine in the same server, it would be preferred to have it installed in a server dedicated to the DB engine instead also in an isolated network.
* Access to the isolated network should be restricted at firewall level just allowing specific IP addresses and ports allowed denying everything else.
* Your DB server should not be installed in a DMZ (not exposed to internet)

### 2. Installing PHP:
Newer PHP versions are preferred, however you have to make sure the version you're about to install it's supported by Wordpress.
```
sudo apt install php7.2-cli php7.2-fpm php7.2-mysql php7.2-json php7.2-opcache php7.2-mbstring php7.2-xml php7.2-gd php7.2-curl -y
```

### 3. Download Wordpress:
Always download the latest version available, please remember Wordpress is the most attacked application of it's kind, you will always want it to be updated to the latest version available.
```
sudo mkdir -p /var/www/html/wpworkshop.wj.cr

cd /tmp
wget https://wordpress.org/latest.tar.gz

tar xf latest.tar.gz
rm latest.tar.gz
sudo mv /tmp/wordpress/* /var/www/html/wpworkshop.wj.cr/
sudo chown -R www-data: /var/www/html/wpworkshop.wj.cr
```

### 4. Installing NginX:
This is just the initial installation with no security at all at this point, we'll take care of that later in this guide.
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
    
    # WhiteJaguars Security settings for Wordpress
    include /etc/nginx/whitejaguars_nginx-wp_security.conf;

    location / {
        # For permalinks to work
        try_files $uri $uri/ /index.php?$args;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        set $path_info $fastcgi_path_info;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_index index.php;
        include fastcgi.conf;
        fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    }

    location ~ \.php$ {
        location ~ \wp-admin.php$ {
                include /etc/nginx/whitelist.conf;
                deny all;
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.2-fpm.sock;
        }
        location ~ \wp-login.php$ {
                include /etc/nginx/whitelist.conf;
                deny all;
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.2-fpm.sock;
        }
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }

}
" | sudo tee -a /etc/nginx/sites-available/wpworkshop.wj.cr
echo "
# Include te list of whitelisted IPs with access to WP-Login 
127.0.0.1
" | sudo tee -a /etc/nginx/whitelist.conf
sudo ln -s /etc/nginx/sites-available/wpworkshop.wj.cr /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```
*Bonus*: You can just run the script `bash wp-base.sh` for automatically executing the steps from 1 to 4.
```
wget -O - https://raw.githubusercontent.com/whitejaguars/wordpress-security/master/wp-base.sh | bash
```

### 5. Installing Wordpress
You should be able now to reach the installation page at http://{server_ip}.
*Considerations:*
* Do not use the standard 'admin' account, select one difficult to guess.
* Make sure your password is strong if you don't want to use the one already provided by the wizard.
```
Database: wordpress
User: userdifficulttoguess
Password: your_super_secure_password_here
```

### 6. Prepare NGinX for HTTPS and Let's Encrypt:
```
sudo pico /etc/nginx/sites-enabled/wpworkshop.wj.cr
```
Uncomment `server_name www.yourdomain.com yourdomain.com;` replacing 'wpworkshop.wj.cr' with your domain name, please make sure to have completed all the DNS steps required for pointing the sub-domain to your server's IP address.
Comment `server_name _;`

### 7. Install Let's Encrypt:
If you're using Ubuntu 18 LTS, this should work without problems.
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

### 8. Security configuration in NGinX
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
        # For permalinks to work
        try_files $uri $uri/ /index.php?$args;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        set $path_info $fastcgi_path_info;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_index index.php;
        include fastcgi.conf;
        fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    }
    location ~ \.php$ {
        location ~ \wp-admin.php$ {
                include /etc/nginx/whitelist.conf;
                deny all;
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.2-fpm.sock;
        }
        location ~ \wp-login.php$ {
                include /etc/nginx/whitelist.conf;
                deny all;
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.2-fpm.sock;
        }
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
    include /etc/nginx/whitejaguars_nginx-wp_security.conf;
    server_tokens off;
    add_header Content-Security-Policy "default-src 'self'; font-src 'self' https://fonts.gstatic.com; img-src 'self' https://i.imgur.com; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline' 'self' https://fonts.googleapis.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self'";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options deny;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy same-origin;
    add_header Feature-Policy "vibrate 'self'; usermedia *; sync-xhr 'self'";
    add_header Strict-Transport-Security max-age=3600;
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

### 9.PHP settings:
```
sudo pico /etc/php/7.2/fpm/php.ini
```
Validate the following options
```
expose_php = Off
enable_dl = Off
```

### 10.Stop user enumeration:

In
```
sudo pico /etc/nginx/sites-enabled/wpworkshop.wj.cr
```
Add
```
if ($args ~ "^/?author=([0-9]*)"){
    set $rule_0 1$rule_0;
}
if ($rule_0 = "1"){
     rewrite ^/$ http://wpworkshop.wj.cr/ permanent;
}
```

## Testing Wordpress Security

### Plugins

* Wordfence
* iThemes Security
* WPScan
* Sucuri Security

### Command line tools

* WPScan (Included in Kali linux)
` wpscan --url https://wpworkshop.wj.cr -e u`
* NMap scripts (Included in Kali linux)
`nmap -p 443 --script http-wordpress* wpworkshop.wj.cr`

### Web tools

* TLS\SSL security scanner: `https://www.ssllabs.com/ssltest/`
* Headers Security scanner: `https://securityheaders.com/`

### Web Pentesting tools

* [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload)
* [OWASP Zap](https://www.zaproxy.org/download/)

The slides in Spanish: [Guia Seguridad para Wordpress](https://github.com/whitejaguars/wordpress-security/blob/master/guia-seguridad-wordpress.pdf)

### Need help securing your site?

Reach out: 

* <https://www.whitejaguars.com>
* <info@whitejaguars.com>
