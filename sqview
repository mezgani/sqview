#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
sqview is a Python application that analyzes squid log files, and generates nice reports.
sqview  [-t] target [-asvhi][-fz] file
        -t (--target)   target        Find out the total trafic per an ip address
        -a (--address)  Address.      Find out the total bandwidth per ip address.
        -s (--site)     Sites.        Find out the total bandwidth per web site.
        -d (--denied)   Denied Sites. Find out the denied access per ip address.
        -f (--file)     Log file.     Log file to analyze, can be a text file default /var/log/squid/access.log
        -z (--zip)      Log file.     Log file to analyze on a zip format
        -i (--inter)    interact      Interactive analyze (comming soon) 
        -v (--verbose)  Verbose.      Print informative msgs; else no output.
        -h (--help)     Help.         Print this usage information and exit.
Example:
  sqview -f access.log -t 192.168.0.11       : display the myhost trafic
  sqview -a                                   : display the bandwidth per ip address
  sqview --zip /var/log/squid/access.log.1.gz : display the bandwidth per ip address, data extracted from a zip file 
"""

"""sqview support native log file format that logs more and different information than the common log file format:
   the request duration, some timeout information, the next upstream server address, and the content type.
   The format is:
   time elapsed remotehost code/status bytes method URL rfc931 peerstatus/peerhost type
"""


import sys, os, re, time
import gzip, getopt, socket

def getbandwithbyip(dico,ip,mode):
  bandwidth=0
  for key, value in dico.items():
    if str(value[2])==ip:
      bandwidth += int(value[5])
  if mode=="":
    return ("%0.2f") % bandwidth
  elif mode=="k":
    return ("%0.2f") % (float(bandwidth)/1024)
  elif mode=="m":
    return ("%0.2f") % (float(bandwidth)/(1024 * 1024))
  elif mode=="g":
    return ("%0.2f") % (float(bandwidth)/(1024 * 1024 * 1024))

def getbandwithbysite(dico,s,mode):
  bandwidth=0
  for key, value in dico.items():
    if value[7].find('/')>0:
      site=value[7].split('/')[2]
      if str(site)==s:
       bandwidth += int(value[5])
  if mode=="":
    return ("%0.2f") % bandwidth
  elif mode=="k":
    return ("%0.2f") % (float(bandwidth)/1024)
  elif mode=="m":
    return ("%0.2f") % (float(bandwidth)/(1024*1024))
  elif mode=="g":
    return ("%0.2f") % (float(bandwidth)/(1024*1024*1024))


def setdico(fd):
  dico,i={},0
  while 1:
    l=[]
    data=fd.readline() 
    if data =="":
      break
    dd = data.split(" ")
    for item in dd:
      if item != "":
          l.append(item)
    if len(l)==10:
      c,s=l[3].split('/')[0],l[3].split('/')[1]
      ps,ph=l[8].split('/')[0],l[8].split('/')[1]
      l[9]=l[9].strip("\n")
      dico[i]=[l[0],l[1],l[2],c,s,l[4],l[5],l[6],l[7],ps,ph,l[9]]
      i = i + 1
  return dico

def geturls(dico, ip):
  urls=[]
  for key, value in dico.items():
    if str(value[2])==ip:
     if value[7] not in urls:
      urls.append(value[7])
  return urls

def getsitesdenied(dico):
  
  print "\033[1;34m","+"+"="*101+"+","\033[0m"
  print "\033[1;34m | time","\t\t\t Kbytes\t\t   ip address",
  print "\t    web site\t ","\t\t","       |\033[0m"
  print "\033[1;34m","+"+"="*101+"+","\033[0m"
  for key, value in dico.items():
    site=value[3].split('/')[0]
    if str(site)=="TCP_DENIED":
       if value[7].find('/')>0:
        url=value[7].split('/')[2]
       else:  
        url=value[7]
       bd = ("%0.2f") % (float(value[5])/1024)
       print "\033[1;34m |\033[0m\033[1;37m %-15s\t\033[1;34m|\033[0m%-10s\033[1;34m\
       |\033[0m%-15s\033[1;34m |\033[0m%-32s\033[1;34m   |\033[0m" \
       % (str(time.ctime(float(value[0]))),str(bd),str(value[2]),str(url))
  print "\033[1;34m","+"+"="*101+"+""\033[0m"

def getsites(dico, ip):
  i = 0
  print "\033[1;34m","+"+"="*102+"+","\033[0m"
  print "\033[1;34m | time","\t\t\t Kbytes\t\t   method",
  print "\t    web site\t ","\t\t","        |\033[0m"
  print "\033[1;34m","+"+"="*102+"+","\033[0m"
  for key, value in dico.items():
    if str(value[2])==ip:
    
      if value[7].find('/')>0: 
        i   += 1
        url=value[7].split('/')[2]
        bd = ("%0.2f") % (float(value[5])/1024)
        print "\033[1;34m |\033[0m\033[1;37m %-15s\t\033[1;34m|\033[0m%-10s\033[1;34m\
        |\033[0m%-15s\033[1;34m |\033[0m%-33s\033[1;34m  |\033[0m" \
        % (str(time.ctime(float(value[0]))),str(bd),str(value[6]),str(url))
  if i==0:
    print "\033[1;34m | No Data ","\t"*12,"|\033[0m"  
  print "\033[1;34m","+"+"="*102+"+""\033[0m"


def sortdict(dict):
  d=sorted(dict.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
  return d

 
def ipbandwidth(dico, m):
  dict={}
  if m=='':
    s = 'B'
  elif m=='k':
    s = 'K'
  elif m=='m':
    s='M'
  elif m=='g':
    s='G'
  seen=set([])
  for key, value in dico.items():
    ip = value[2]
    if ip not in seen:
        seen.add(ip)
        bd=getbandwithbyip(dico,ip,m)
        bd=bd.strip('\t')
        dict[ip]=float(bd)
  d=sortdict(dict)
  if d!={}:
    print "\033[1;34m","+"+"="*43+"+","\033[0m"
    print "\033[1;34m | address","\t\t\t",
    print "bandwith ",s+"B |","\033[0m"
    print "\033[1;34m","+"+"="*43+"+","\033[0m"
    for i in d:
      print "\033[1;34m |\033[0m\033[1;37m %-15s\t\t\033[1;33m%-12s\033[1;34m |\033[0m" % (str(i[0]),str(i[1]))
    print "\033[1;34m","+"+"="*43+"+""\033[0m"
  else:
    print "\033[1;34m | No Data ","\t"*9,"|\033[0m"  


def sitebandwidth(dico, m):
  dict={}
  if m=='':
    s = 'B'
  elif m=='k':
    s = 'K'
  elif m=='m':
    s='M'
  elif m=='g':
    s='G'
  seen=set([])
  for key, value in dico.items():
    if value[7].find('/')>0:
      site = value[7].split('/')[2]
      if site not in seen:
        seen.add(site)
        bd=getbandwithbysite(dico,site,m)
        bd=bd.strip(' ')
        dict[site]=float(bd)
  d=sortdict(dict)
  if d!={}:
    print "\033[1;34m","+"+"="*59+"+","\033[0m"
    print "\033[1;34m | web site","\t\t\t\t\t",
    print "bandwith ",s+"B |","\033[0m"
    print "\033[1;34m","+"+"="*59+"+","\033[0m"
    for i in d:
      print "\033[1;34m |\033[0m\033[1;37m %-35s\t\t\033[1;33m%-12s\033[1;34m |\033[0m" % (str(i[0]),str(i[1]))
    print "\033[1;34m","+"+"="*59+"+""\033[0m"
  else:
    print "No data"


def main():
  modlist, logfile = [], ''
  lock,start=True,False
  file, dico='',{}

  if len(sys.argv) == 1:
    usage()


  try:
    opts, args = getopt.getopt(sys.argv[1:], "f:z:asdt:vh",
                        ["file", "zip", "address", "site", "denied", "target", "verbose", "help"])
  except getopt.error, msg:
    usage(msg)
    return
  
  for opt, arg in opts:
    if opt in ('-f', '--file'):
      modlist.append('file')
      try:
         file=arg
      except IndexError, e:
         usage(e)
      
    if opt in ('-z', '--zip'):
      modlist.append('zip')
      try:
         zfile=arg
      except IndexError, e:
         usage(e)

    if opt in ('-t', '--target'):
      modlist.append('target')
      lock=False
      start=True
      try:
        target=arg
        ip=socket.gethostbyname(target)
      except Exception, e:
        sys.stderr.write(str(e)+"\n")
        exit(1)

    if opt in ('-a', '--address'):
        modlist.append('address')
    if opt in ('-s', '--site'):
        modlist.append('site')
    if opt in ('-d', '--denied'):
        modlist.append('denied')
    if opt in ('-v', '--verbose'):
        modlist.append('verbose')
    if opt in ('-h', '--help'):
        usage()


  starttime=time.time()
  
  if 'zip' in modlist:
    file=logfile=zfile
    try:
      fd=gzip.open(zfile,'rb')
      dico=setdico(fd)
    except IOError, e:
      sys.stderr.write("Please check  that the file exist and adjust the permission on the log file\n")
      sys.stderr.write("Also you can run sqview as root, or do a sudo on it\n")
      sys.exit(1)

  if not os.path.isfile(file):
      logfile="/var/log/squid/access.log"
 
  if 'file' in modlist:
    print file
    logfile=file
    try:
      fd = open(logfile,'r')
      dico=setdico(fd)
    except IOError, e:
      sys.stderr.write("Please check that the file exist and adjust the permission on the log file\n")
      sys.stderr.write("Also you can run sqview as root, or do a sudo on it\n")
      sys.exit(1)

  if 'file' not in modlist and 'zip' not in modlist:
      logfile="/var/log/squid/access.log"
      try:
        fd=open(logfile,'rb')
        dico=setdico(fd)
      except IOError, e:
        sys.stderr.write("Please check  that the file exist and adjust the permission on the log file\n")
        sys.stderr.write("Also you can run sqview as root, or do a sudo on it\n")
        sys.exit(1)
     

  if 'denied' in modlist and lock: 
     start=True
     getsitesdenied(dico) 
  if 'address' in modlist and lock: 
     start=True
     ipbandwidth(dico,'k')
  if 'site' in modlist and lock:
     start=True
     sitebandwidth(dico,"k")
  if 'target' in modlist: 
      try:
        getsites(dico, ip)
      except Exception, e:
        sys.stderr.write(str(e)+"\n")
        sys.exit(1)

  if start:
    totaltime=time.time()-starttime
    fd.close()
    print "\n"
    print "file: \033[1;34m",logfile,"\033[0m"
    print "size: \033[1;34m",str(os.stat(logfile).st_size)," Bytes","\033[0m"
    print "elapsed time: \033[1;34m%0.3f" % float(totaltime)+"s\033[0m\n"
  else:
    usage()
    return 

def usage(msg=None):
    if msg is not None:
        print >> sys.stderr, msg
    print >> sys.stderr, __doc__
    sys.exit(1)


if __name__=='__main__':
    main()
