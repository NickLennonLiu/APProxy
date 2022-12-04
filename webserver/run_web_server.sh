rm /var/lib/dpkg/lock*
apt install apache2 -y
cp index.html /var/www/html/index.html
cp -r statics /var/www/html/
systemctl start apache2