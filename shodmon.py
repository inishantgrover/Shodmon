#! /usr/bin/env python
# coding=UTF-8
# Shodan Monitoring Tool
# By NGrovyer

import time
import datetime
from shodan import Shodan                       #pip install shodan
import sys
import sqlite3
import json
import dateutil.parser as dp
import schedule                                 #pip install schedule
from cStringIO import StringIO
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email import Charset
from email.generator import Generator
import smtplib
import ast

conn = sqlite3.connect('shodan_db.sqlite')

SHODAN_API_KEY = "############" #Your Shodan Key

# Create a connection to the Shodan API
api = Shodan(SHODAN_API_KEY)

#Queries Shodan for a search term and then stores results in a list of dictionaries
def query_Shodan(term, callback):
    print "Runing Shodan Query"
    templist = []
    while True:
        try:
            #Search Shodan and get bunch of IP Addresses (limit 100)
            results = api.search(term,page=1,limit=100)
            counter=1
            
            #Construct a temp dictionary to store details of each of IP Address
            for result in results['matches']:
                temp = {}
                temp["Query"] = term
                time.sleep(1)
                #Fetch details of each  of IP one by one
                host = api.host('%s' %result['ip'])

                ip = '%s' %host.get('ip_str', None)

                #IP Stored as string
                temp["IP"] = ip.encode('ascii', 'replace')

                #Hostname also as string
                hostnames = s = ''.join(host.get('hostnames', None))
                temp["Hostnames"] = hostnames.encode('ascii', 'replace')

                #String as array of ports
                ports = '%s' %host.get('ports', None)
                temp["Ports"] = ports.encode('ascii', 'replace')

                #Last update time as string
                last_update = '%s' %host.get('last_update', None)
                temp["last_update"] = last_update.encode('ascii', 'replace')

                #ASN unique to a company
                asn = '%s' %host.get('asn', None)
                temp["ASN"] = asn.encode('ascii', 'replace')
                
                #Empty dictionary for
                port_dict=dict()
                
                #Convert Ports to array list
                port_list=temp["Ports"].strip("[").strip("]").split(",")
                
                #Get hash data from data row
                hash_data = host.get('data')
                i=0

                #For each port, create dictionary with port=>Hash
                for portname in port_list:
                    port_dict[hash_data[i]['port']]=str(hash_data[i]['hash'])
                    i=i+1

                #Conert that dictonary into string for processing in next function
                temp["hash_data"] = str(port_dict)

                counter=counter+1

                #Create mega list consisting of each of nested list
                templist.append(temp)
                callback(temp)
            break
        except Exception, e:
            #No results found, print no 'matches'
            print 'No %s\r' %e
    #Returns a list of dictionary objects. Each dictionary is a result
    return templist

count_var=0
def print_result(info):
    global count_var
    count_var=count_var+1
    #This function exist for existance purpose, cause I dont want to screw up the code LOL

def run_shodan_query():
    global know_ip_dns_mapping
    #Variable that flips as soon as one change is detected, changes subject line of mail
    is_changed=False
    message_body=""     #Variable which will create mail body of your email
    list = query_Shodan('ASN:\"AS394161\"',print_result) #This is main query, could be done on basis of ASN or anything else, based on shodan format
    print "Processing"

    list_length=len(list)   #Number of results fetched from shodan

    #Code to find out new IPs and revoked IPs
    select_rec = conn.execute("SELECT sno,ip_address,open_ports FROM shodan_db where past_exist=0 order by sno DESC")
    old_ip_address = select_rec.fetchall()

    #How many IPs we saw last time, and how many are there now
    message_body=message_body+"Total IPs Yesterday" + str(len(old_ip_address))+"<br>\r\n"   
    message_body=message_body+"Total IPs Today"+ str(list_length)+"<br>\r\n"

    #Now begins the loop of checking whether any IP is gone from shodan or what?
    for x in old_ip_address:
        is_found=False
        for y in list:
            if x[1]==y['IP']:
                is_found=True
                break
        if is_found==False:
            select_rec = conn.execute("SELECT sno,ip_address,unix_scan_timestamp FROM shodan_db where ip_address='"+x[1]+"' order by sno DESC limit 0,1")
            get_last_date=select_rec.fetchall()
            if len(get_last_date)==0:
                last_scan_date="NONE"
            else:  
                last_scan_date=datetime.datetime.utcfromtimestamp(int(get_last_date[0][2])).strftime('%d-%m-%Y')
            is_changed=True
            message_body=message_body+"Old IP: "+x[1]+" ("+know_ip_dns_mapping.get(x[1],"")+") ::"+x[2]+" is not found today, last appeared on: "+str(last_scan_date)+"<br>\r\n"

    #Now 2nd loop is to check whether a new IP had popped up in Shodan (or what)
    for y in list:
        is_found=False
        for x in old_ip_address:
            if x[1]==y['IP']:
                is_found=True
                break
        if is_found==False:
            select_rec = conn.execute("SELECT sno,ip_address,unix_scan_timestamp FROM shodan_db where ip_address='"+y['IP']+"' order by sno DESC limit 0,1")
            get_last_date=select_rec.fetchall()
            if len(get_last_date)==0:
                last_scan_date="NONE"
            else:            
                last_scan_date=datetime.datetime.utcfromtimestamp(int(get_last_date[0][2])).strftime('%d-%m-%Y')
            is_changed=True
            message_body=message_body+"New IP: "+y['IP']+" ("+know_ip_dns_mapping.get(y['IP'],"<b><u>BLANK</u></b>")+") ::"+y['Ports']+" is found today, last appeared on: "+str(last_scan_date)+"<br>\r\n"

    #Update all past_exist to 1 as we are getting new records
    conn.execute("update shodan_db set past_exist=1")
    
    #Start processing each item in the live list        
    for match in list:
        ip_address=match['IP']
        last_update=match['last_update']
        hostnames=match['Hostnames']
        hash_data=match['hash_data']
        query_term=match['Query']
        asn_num=match['ASN']
        ports=match['Ports']
        
        parsed_t = dp.parse(last_update)
        parsed_date = parsed_t.strftime('%Y-%m-%d')
        unix_timestamp = time.time()
        
        #Code to check change, select query
        select_rec = conn.execute("SELECT sno,hash_data,open_ports FROM shodan_db where ip_address='"+ip_address+"' order by sno DESC limit 0,1")
        q = select_rec.fetchall()
        
        #If IP Already exist in database, check if changes
        if len(q) != 0:

            #Convert ports into a list
            ports_list =ports.strip("[").strip("]").split(",")

            #Convert both strings into dictionaries
            hash_live_dict=ast.literal_eval(hash_data)
            db_hash_dict=ast.literal_eval(q[0][1])
            
            #Check if the length is matching, if not, some new port is there!
            if len(hash_live_dict) == len(db_hash_dict):
                for key in hash_live_dict:
                    
                    #Check if key not in dictionary, means one port got closed, other got opened
                    #below statement means, if key not in dictionary, for some reason below is true
                    if str(key) in db_hash_dict:
                        is_changed=True
                        message_body=message_body+"New Port Found: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"<b><u>BLANK</u></b>")+") "+" | Old:"+str(db_hash_dict) +" AND New: "+str(hash_live_dict) +"<br>\r\n"
                        
                    #If key already exist, check if Hash is same, if hash not equal, something changed, and we need to check
                    else:   
                        if hash_live_dict[key]!=db_hash_dict[key]:
                            is_changed=True
                            message_body=message_body+"HASH CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"<b><u>BLANK</u></b>")+") "+" | Old:"+str(key)+" --> "+ str(db_hash_dict[key]) +" AND New: "+str(key)+" --> "+ str(hash_live_dict[key]) +"<br>\r\n"
            else:
                is_changed=True
                message_body=message_body+"HASH & PORTS CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"<b><u>BLANK</u></b>")+") "+" | Old:"+ str(db_hash_dict) +" AND New:"+ str(hash_live_dict) +"<br>\r\n"
                
	    #Breaking Port string into a list
            db_ports_list=q[0][2].strip("[").strip("]").split(",")
            
            #First check if length is equal, if not clearly port has changed
            if len(ports_list) == len(db_ports_list):
                #Iterate over each live port and see if they are same as what we have in DB
                for port_check in ports_list:
                    if port_check not in db_ports_list:
                        is_changed=True
                        message_body=message_body+"PORT CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"<b><u>BLANK</u></b>")+") "+" | Old:"+ str(db_ports_list) +" AND New:"+ str(ports_list) +"<br>\r\n"

            #If number of ports before and after are not equal, thats definitely a port change!                        
            else:
                is_changed=True
                message_body=message_body+"PORT CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"<b><u>BLANK</u></b>")+") "+" | Old:"+ str(db_ports_list) +" AND New:"+ str(ports_list) +"<br>\r\n"

        else:
	    #if net new IP, append to changes along with comparision
            is_changed=True
            
        #Code to insert the new data into DB
        conn.execute('insert into shodan_db (ip_address,hostname,query_term,ASN_number,hash_data,open_ports,last_update_date,unix_scan_timestamp,past_exist) values (?,?,?,?,?,?,?,?,?)', (ip_address,hostnames,query_term,asn_num,hash_data,ports,parsed_date,unix_timestamp,"0"))

    conn.commit()
    #conn.close()
    message_starter="Total IP Scanned: "+ str(list_length)+" <br>\r\n"

    #If anywhere the change flag is raised
    if is_changed:
        subject="[Changes]Shodan Monitoring"
    else:
        subject="[No Change]Shodan Monitoring"

    #This part of mail body is for record keeping in our mailbox, rather than looking in your Sqlite DB, you can quickly use your mailbox to pin point first appearance of IP
    message_body=message_body+"<br><br><br>Total IPs found today<br>\r\n"
    for match in list:
        message_body=message_body+match['IP']+" ("+know_ip_dns_mapping.get(match['IP'],"<b><u>BLANK</u></b>")+") "+" - Ports - "+match['Ports']+"<br>\r\n"

    print "finished"

    #If you want to see how our mail body will look like, uncomment below line
    #print message_starter+message_body

    #Processing finished, lets mail it!
    mail_status=send_mail(message_starter+message_body,subject)
            
	
#Mailer
def send_mail(msg_body,subject):
    # Addresses to Send on
    print "Drafing Mail body"
    fromaddr = "youremail@gmail.com"        #Your Sender Email Address
    toaddr = "emailaddress@tobe.sent"       #Your Recipent Email Address
    
    #Mail Body starts
    text_body = ""

    top_heading = "<b>Summary is as below:</b><br/>"
    text_body = msg_body                      #Returned from Processing Stage
    text_body = top_heading + text_body

    # Default encoding mode set to Quoted Printable. Acts globally!
    Charset.add_charset('utf-8', Charset.QP, Charset.QP, 'utf-8')

    # 'alternative’ MIME type – HTML and plain text bundled in one e-mail message
    msg = MIMEMultipart('alternative')

    msg['Subject']=subject
    # Only descriptive part of recipient and sender shall be encoded, not the email address
    msg['From'] = fromaddr
    msg['To'] = toaddr
    
    # Attach both parts
    text_body = MIMEText(text_body, 'html', 'UTF-8')
    msg.attach(text_body)

    # Create a generator and flatten message object to 'file’
    str_io = StringIO()
    g = Generator(str_io, False)
    g.flatten(msg)
    # str_io.getvalue() contains ready to sent message
    
    # Optionally - send it – using python's smtplib
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.ehlo()
    s.starttls()

    #This is incase gmail connectivity dont happen at once.
    while True:
        try:
            s.login(fromaddr, "##YOURPASSWORD##")           #YOUR GMAIL PASSWORD, to log into gmail smtp server
            s.sendmail(fromaddr, toaddr, str_io.getvalue())
            break
        except Exception as x:
            print x

    s.quit()

    #Print when the last mail was sent, for debug purpose or to check who failed? the script or the mail ?
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print "Mail Sent @ "+str(st)
    print "\n\n"

#The below is dictionary mapping, for known servers and their domain names. If something unknown Pop up, that either needs to be mapped, or needs to be investigated
know_ip_dns_mapping={
  "209.133.79.81": "sso.tesla.com",
  "209.133.79.66": "sso-dev.tesla.com",
  "209.133.79.38": "Teslamotors.com"
}

#Run the script first time to immediately gather data.
run_shodan_query()

#The scheduler, you can schedule it in mins, or days, or at specific time.
#Read more about it here
#https://github.com/dbader/schedule

#schedule.every(120).minutes.do(run_shodan_query)
schedule.every().day.at("10:30").do(run_shodan_query)

while True:
    schedule.run_pending()
    time.sleep(1)
