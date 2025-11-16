# malspam-honeypot-project-util

Utils and notes from the execution of the Shiva honeypot

# Email generation

simply grab a bunch of names from a random name generator such as https://randomwordgenerator.com/name.php, insert those into
the name_formatter.py and update the domains within name_formatter.py to the target domains.

TODO:

- update name_formatter to take a generic list of domain names and corresponding formats
- update the name variable to just call a random name api

# Running Shiva in Google Cloud

First ensure any changes to Shiva has been completed, that a google cloud project with a billing account
is attached, and docker is installed on the machine. Start with a command prompt shell then run the
following commands:

```bash
gcloud init
gcloud auth configure-docker
// the following steps are to create the base compute instance and set up the firewall respectively
gcloud compute instances create-with-container shiva-smtp-receiver --container image=docker.io/library/ubuntu:20.04 --machine-type=e2-small --zone=australia-southeast1-a --tags=smtp-server --container-privileged --container-stdin --container-tty
gcloud compute firewall-rules create allow-smtp --direction=INGRESS --priority=1000 --network=default --action=ALLOW --rules=tcp:25 --source-ranges=0.0.0.0/0 --target-tags=smtp-server
// before continuing, ensure that an artifact repository has been created on the google cloud project
// in this example the artifact registry was called shiva-repo
cd c:\git\shiva\receiver
docker build -t australia-southeast1-docker.pkg.dev/malspam-honeypot-research/shiva-repo/shiva-smtp
./src
docker push australia-southeast1-docker.pkg.dev/malspam-honeypot-research/shiva-repo/shiva-smtp
gcloud compute instances update-container shiva-smtp-receiver --container-image=australia-southeast1 docker.pkg.dev/malspam-honeypot-research/shiva-repo/shiva-smtp --zone=australia-southeast1-a
```

## redirect port 25 to port 2525 (NOT PERSISTANT, PLEASE CHECK AFTER VM RESTART)

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525
```

## list all rules

```bash
sudo iptables -t nat -L
```

## Delete the VM

```bash
gcloud compute instances delete shiva-smtp-receiver --zone=australia-southeast1-a
```

## Delete firewall rule

```bash
gcloud compute firewall-rules delete allow-smtp
gcloud compute firewall-rules delete allow-smtp-receive
```

## list the firewall rules

```bash
gcloud compute firewall-rules list
```

## updates the permissions of the docker user to write to the tmp queue

```bash
docker exec -it a5d2f536159f id
sudo chown -R 1000:1000 /tmp/spam_queue
```

```bash
// ensure that the correct dns records exist (also check that the IP address of the MX record is pointing correctly, had an issue with ephemeral IP addresses)
nslookup -type=A mail.target-domain.one
nslookup -type=MX target-domain.one

// connect to the smtp server

// updates computer stored dns (dns record ttl can be managed on the DNS management system)
ipconfig /flushdns
```

## Use either command when determining if the target mail server domain is able to receive emails

```powershell
Test-NetConnection -ComputerName mail.target-domain.one -Port 25
```

```bash
telnet mail.target-domain.one 25
```

# Analysis of Logs (usage of log_analysis.py)

within vm running the Shiva receiver

```bash
sudo docker logs a5d2f536159f > logs.txt
realpath logs.txt
```

download the logs.txt using the path specified from the above command

To find all unique ips in a log file that contains all the current logs from my docker container for my
smtp server

```bash
grep -a -oE "\('[0-9]{1,3}(\.[0-9]{1,3}){3}',[[:space:]]*[0-9]+\)" logs.txt \
| grep -oE "[0-9]{1,3}(\.[0-9]{1,3}){3}" \
| sort -u > unique_IPs.txt
```

mv the file to IP_list.csv and remove any local IP address ranges (currently there doesn't exist any local
ip address ranges except for 127.0.0.1 which due to initial testing of the smtp server)

```bash
grep -Eo '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0
1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b' IP_list.csv
```

and hunt down that one 127.0.0.1

then used this tool to convert the IPs into analysed IPs with whether the IP's are malicious or not
https://github.com/ph1nx/VirusTotal-Bulk-IP-Scanner/tree/main

finally to use the log_analysis.py, update the CONFIG section and then run it

```bash
python log_analysis.py
```
