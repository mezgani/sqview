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
  print "\033[1;34m","="*45,"\033[0m"
  print "\033[1;34m | address","\t\t\t","bandwith ",s+"B |","\033[0m"
  print "\033[1;34m","="*45,"\033[0m"
  seen=set([])
  for key, value in dico.items():
    ip = value[2]
    if ip not in seen:
        seen.add(ip)
        bd=getbandwithbyip(dico,ip,m)
        bd=bd.strip('\t')
        dict[ip]=float(bd)
  return dict

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
  print "\033[1;34m","="*61,"\033[0m"
  print "\033[1;34m | web site","\t\t\t\t\t","bandwith ",s+"B |","\033[0m"
  print "\033[1;34m","="*61,"\033[0m"
  seen=set([])
  for key, value in dico.items():
    if value[7].find('/')>0:
      site = value[7].split('/')[2]
      if site not in seen:
        seen.add(site)
        bd=getbandwithbysite(dico,site,m)
        bd=bd.strip(' ')
        dict[site]=float(bd)
  return dict







def main():
  logfile="/var/log/squid/access.log"
  fd = open(logfile,'r')
  #fd=gzip.open(logfile,'rb')
  starttime=time.time()
  dico=setdico(fd)
  data=ipbandwidth(dico,"m")
  d=sorted(data.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)

  for i in d:
    print "\033[1;37m %-15s\t\t\t\033[1;33m%6s\033[0m" % (str(i[0]),str(i[1]))

  totaltime=time.time()-starttime

  print "\n"
  print "file: \033[1;34m",logfile,"\033[0m"
  print "size: \033[1;34m",str(os.stat(logfile).st_size)," Bytes","\033[0m"
  print "time elapsed : \033[1;34m%0.3f" % float(totaltime),"\033[0m"


if __name__=='__main__':
    main()
