# Shodmon
The Shodan monitoring tools allows you to monitor shodan listed servers basis on the filter you select

## Usage
This tool can be used to monitor internet exposed surface, specifically speaking, your servers. Shodan scans the entire internet periodically and maps out details such as Ports open, type of service running, certificate details, organization to which the server belong, etc, all this to an IP Address. This is good for blue teamers to monitor your internet exposed servers and equalivalently good for red teamers to find loop holes onto exposed servers.

## Usecases
1. As a Blue teamer, you might have to keep an eye if your company puts a new server out on the web or to Map out your existing exposed surface. You might also want to keep check if any new port is opened, or content on the existing ports have changed.
2. As a Red teamer, you might want to keep an eye on exposed surface to find any loop holes, and simulate as attackers who are finding single instance of misconfiguration to enter in your network.

## Requirements
1. Shodan API Key 
- Create free account on shodan
- Get API Key
- Free Shodan account is enough to monitor a small number of servers (upto 100)

2. A Filter that shortlists servers that you want to monitor.
- It should cover any servers that are already exposed, as well as if something new pops up. 
- I prefer to use org:"YOUR ORG" filter, or ASN:"ASXXXXX" filter 

3. A Email account with SMTP Login VIA APIs
- Any email service which allows you to login via SMTP
- I used gmail and created an Isolated account

4. (OPTIONAL) If you like periodic Monitoring, you might want to run this script on Cloud.
- I used AWS Cloud as it was easiest to setup and **free** for one year!

5. Python 2.7.X and Internet Connection

## Setup Steps
1. Download the Python Script and DB
2. Get a Shodan API Key after creating a free account (Line 25)
3. Put the appropiate Shodan Query Here to get appropiate results in return (Line 110)
4. Put your sender's email address (Line 258)
5. Put reciever's email address (Line 259)
6. Enter Port number and SMTP Address of Mail server (Line 290)
7. Enter your Sender's email password for authentication (Line 297) 
8. Change line as per the frequency you want to send mails (Line 326)

## Customization:
- By Default, with above setup steps, the script will return you Tesla related Servers, and also maps a few of them.
- As per your Shodan Query (in line 110), you can customize IP to DNS Mapping to help you find out anything that is not expected on the internet.
- You need to put your own entries in IP to DNS entries in the dictionary mentioned in line 312


## Feedback & Suggestions
You can reach me out at @Ngrovyer on twitter
I will see if I can make a video tutorial on how to setup this Script and help you monitor your Organization/Target.
