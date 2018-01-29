<p align="center"><a href="/docs/full_graph.min.svg"><img src="/docs/full_graph.min.svg" width="300" align="center"></a></p>

# Phish Kit Collection

## Introduction

This is the code used in our experiment to collect phishing kits at scale. This requires integrations with phishing feed providers, which may need API keys or other credentials.

## Deploying to EC2

We ran our experiment using an Amazon EC2 instance. This are the basic commands to get up and running.

### Install the ELK Stack

First, you need to install Elasticsearch and Kibana
```
# Remove Java 1.7 in favor of Java 1.8
sudo yum install java-1.8.0
sudo yum remove java-1.7.0-openjdk

# Then, install Elasticsearch
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

echo '[elasticsearch-5.x]
name=Elasticsearch repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md' | sudo tee /etc/yum.repos.d/elasticsearch.repo > /dev/null

sudo yum install elasticsearch
sudo chkconfig --add elasticsearch

# Start Elasticsearch
sudo -i service elasticsearch start


# Install Kibana
echo '[kibana-5.x]
name=Kibana repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md' | sudo tee /etc/yum.repos.d/kibana.repo > /dev/null

sudo yum install kibana
sudo chkconfig --add kibana

# Start Kibana
sudo -i service kibana start
```

### Download the Code

To get the `phish_collect` code, clone the repository from Github:

```
git clone https://github.com/duo-labs/phish_collect.git
cd phish_collect
```

### Create our Indexes

To index values in Elasticsearch, we have to create our indexes. We can do that with this command:

```
curl -XPUT localhost:9200/samples -H "Content-Type: application/json" -d @es_index.json
```

### Install Python Requirements

Next, you need to install all the requirements:

```
virtualenv .env
source .env/bin/activate
pip install -r requirements.txt
```

### Make run script executable

```
chmod +x run.sh
```

### Setup the Crontab

Since we want to run the script every 10 minutes, we need to add the following to our crontab:

```
*/10 * * * * cd phish_collect && ./run.sh
```

That's all there is to it! Now new samples will be downloaded and indexed to Kibana.

## Using the Flask Server

We've added a simple Flask server to let you submit URLs from external sources. It only has one endpoint, `/`, that accepts the following `POST` parameters:

* `url` - The URL to process
* `pid` (optional) - The sample ID (default: `uuid4()`)
* `feed` (optional) - The feed (default: `server`)

The response is a JSON payload of `{"processing": true}`. The sample is processed in the background by a pool of workers.

To start the server, simply run `python server.py`. Configuration settings (interface and port) can be found in `config.toml`.

## License

```
BSD 3-Clause License

Copyright (c) 2017, Duo Labs
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
