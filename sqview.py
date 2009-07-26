#-*- coding:utf-8 -*-

"""
sqview  [-f][-a][-s][-h]
        -f (--file)     Log file.  Log file to analyze, can be a text file or a gzip format, by default /var/log/squid/access.log
        -a (--address)  Address.   Find out the total bandwidth per ip address.
        -s (--site)     Site.      Find out the total bandwidth per web site.
        -v (--verbose)  Verbose.   Print informative msgs; else no output.
        -h (--help)     Help.      Print this usage information and exit.
"""

"""sqview support native log file format that logs more and different information than the common log file format:
   the request duration, some timeout information, the next upstream server address, and the content type.
   The format is:
   time elapsed remotehost code/status bytes method URL rfc931 peerstatus/peerhost type
"""


import sys, os, re, time
import gzip, getopt

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
      dico[i]=[l[0], l[1], l[2], c, s, l[4], l[5], l[6], l[7], ps, ph, l[9]]
      i = i + 1
  return dico

def geturls(dico,ip):
  urls=[]
  for key, value in dico.items():
    if str(value[2])==ip:
     if value[7] not in urls:
      urls.append(value[7])
  return urls

def getsites(dico,ip):
  urls=[]
  for key, value in dico.items():
    if str(value[2])==ip:
      url=value[7].split('/')[2]
      if url not in urls:
        urls.append(url)
  return urls

def opengz(file):
  f = gzip.open(file, 'rb')
  file_content = f.read()
  f.close()
  return file_content

 
def ipbandwidth(dico,m):
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
  d=sorted(dict.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
  print "\033[1;34m","+"+"="*43+"+","\033[0m"
  print "\033[1;34m | address","\t\t\t","bandwith ",s+"B |","\033[0m"
  print "\033[1;34m","+"+"="*43+"+","\033[0m"
  for i in d:
    print "\033[1;34m |\033[0m\033[1;37m %-15s\t\t\033[1;33m%-12s\033[1;34m |\033[0m" % (str(i[0]),str(i[1]))
  print "\033[1;34m","+"+"="*43+"+""\033[0m"


def sitebandwidth(dico,m):
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
  d=sorted(dict.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
  print "\033[1;34m","+"+"="*59+"+","\033[0m"
  print "\033[1;34m | web site","\t\t\t\t\t","bandwith ",s+"B |","\033[0m"
  print "\033[1;34m","+"+"="*59+"+","\033[0m"
  for i in d:
    print "\033[1;34m |\033[0m\033[1;37m %-35s\t\t\033[1;33m%-12s\033[1;34m |\033[0m" % (str(i[0]),str(i[1]))
  print "\033[1;34m","+"+"="*59+"+""\033[0m"



def main():
  global address, site 
  address = site = 0
  modlist, logfile = [], ''
  
  try:
    opts, args = getopt.getopt(sys.argv[1:], "fasvh",
                        ["file", "address", "site", "verbose", "help"])
  except getopt.error, msg:
    usage(msg)
    return
  
  for opt, arg in opts:
    if opt in ('-f', '--file'):
      modlist.append('file')
      try:
        file=args[0]
      except IndexError, e:
        usage(e)
      
    elif opt in ('-a', '--address'):
      modlist.append('address')
    if opt in ('-s', '--site'):
      modlist.append('site')
    if opt in ('-v', '--verbose'):
      modlist.append('verbose')
    if opt in ('-h', '--help'):
      usage()

  if not modlist:
      modlist = ['address']
 
  if 'file' in modlist:
      logfile=file

  if not os.path.exists(logfile):
    if not os.path.isfile(logfile):
        logfile="/var/log/squid/access.log"

  if not modlist:
    modlist = ['address']
  if modlist==['file']:
    modlist=['address']
    
  fd = open(logfile,'r')
  #fd=gzip.open(logfile,'rb')
  starttime=time.time()
  dico=setdico(fd)
  if 'address' in modlist:
     ipbandwidth(dico,'k')
  if 'site' in modlist:
     sitebandwidth(dico,"k")
  totaltime=time.time()-starttime

  print "\n"
  print "file: \033[1;34m",logfile,"\033[0m"
  print "size: \033[1;34m",str(os.stat(logfile).st_size)," Bytes","\033[0m"
  print "elapsed time: \033[1;34m%0.3f" % float(totaltime)," sec\033[0m\n"

def usage(msg=None):
    if msg is not None:
        print >> sys.stderr, msg
    print >> sys.stderr, __doc__
    sys.exit(1)


if __name__=='__main__':
    main()
