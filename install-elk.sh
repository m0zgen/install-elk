#!/bin/bash

HOSTNAME=`hostname`

cd /tmp
yum -y install wget firewalld epel-release
yum -y install nginx httpd-tools unzip
systemctl start firewalld
systemctl enable firewalld

wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u65-b17/jdk-8u65-linux-x64.rpm"
yum -y install jdk-8u65-linux-x64.rpm
#rm jdk-8u65-linux-x64.rpm
# yum install java-openjdk -y

rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch

cat > /etc/yum.repos.d/elasticsearch.repo <<EOF
[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF

yum -y install elasticsearch
mv /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.old
echo 'network.host: localhost' > /etc/elasticsearch/elasticsearch.yml
systemctl start elasticsearch
systemctl enable elasticsearch

cat > /etc/yum.repos.d/kibana.repo <<EOF
[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF

yum -y install kibana
mv /opt/kibana/config/kibana.yml /opt/kibana/config/kibana.yml.old
echo 'server.host: "localhost"' > /opt/kibana/config/kibana.yml
systemctl start kibana
systemctl enable kibana.service
htpasswd -c /etc/nginx/htpasswd.users kibanauser
setsebool -P httpd_can_network_connect 1
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.old

cat > /etc/nginx/nginx.conf <<EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/conf.d/*.conf;
}
EOF

cat > /etc/nginx/conf.d/kibana.conf <<EOF
server {
    listen 80;

    server_name $HOSTNAME;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;        
    }
}
EOF

systemctl start nginx
systemctl enable nginx
systemctl start kibana
systemctl restart nginx
firewall-cmd --zone=public --add-port=80/tcp --perm
firewall-cmd --reload

cat > /etc/yum.repos.d/logstash.repo <<EOF
[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF

yum -y install logstash

# See below for file generation for you
cd /etc/pki/tls/
openssl req -subj '/CN=$HOSTNAME/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt

cat > /etc/logstash/conf.d/02-beats-input.conf <<EOF
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
EOF

cat > /etc/logstash/conf.d/10-syslog-filter.conf <<EOF
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF

cat > /etc/logstash/conf.d/30-elasticsearch-output.conf <<EOF
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
EOF

service logstash configtest
systemctl restart logstash
systemctl enable logstash
cd /tmp
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
unzip beats-dashboards-*.zip
cd beats-dashboards-1.1.0
./load.sh
cd /tmp
curl -O https://raw.githubusercontent.com/elastic/filebeat/master/etc/filebeat.template.json
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat.template.json
firewall-cmd --zone=public --add-port=5044/tcp --perm
firewall-cmd --reload
systemctl restart logstash