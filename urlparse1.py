import urlparse


main_url = "http://www.ics.uci.edu"
sub_url = "/dept"

r1 = urlparse.urlparse(main_url)
r2 = urlparse.urlparse(sub_url)

r3 = urlparse.urljoin(r1.geturl(),r2.geturl())
print(r3)



