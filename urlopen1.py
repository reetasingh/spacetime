from urllib import urlopen

r4 = "http://www.ics.uci.edu/about/about_safety.php/ugrad/index.php/grad/about_safety.php/about_safety.php/ugrad/index.php/bren/grad/index.php"

try:
    url2 = urlopen(r4)
except:
    print "failed in urlopen for ", r4
   

