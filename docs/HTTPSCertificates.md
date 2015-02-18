# Managing memento nginx HTTPS Certificates

See the [clearwater-nginx document](https://github.com/Metaswitch/clearwater-nginx/blob/master/docs/HTTPSCertificates.md) on managing HTTPS certificates before reading this document.

memento's nginx config is generated during the install of the memento-nginx package by the [create-memento-nginx-config script](https://github.com/Metaswitch/memento/blob/master/memento-nginx.root/usr/share/clearwater/infrastructure/scripts/create-memento-nginx-config). This script assumes memento is using the self-signed certificate generated during the install of the clearwater-nginx package, namely nginx.crt, and the associated private key nginx.key. If you wish to use a different certificate and key, as described in the clearwater-nginx doc linked above, you will need to take the following steps once you've created your new certificate and key.

* Upload the key and certificate to your memento node.
* Run 'sudo nginx_dissite memento' to disable the memento site.
* Edit /etc/nginx/sites-available/memento to point to your new certificate and key.
* Run 'sudo nginx_ensite memento' to enable the memento site.
