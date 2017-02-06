import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager
from spacetime_local.IApplication import IApplication
from spacetime_local.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time
import lxml.html
import requests
from time import gmtime, strftime

try:
    # For python 2
    from urlparse import urlparse, parse_qs,urljoin
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = 0 if not os.path.exists("successful_urls.txt") else (len(open("successful_urls.txt").readlines()) - 1)
if url_count < 0:
    url_count = 0
MAX_LINKS_TO_DOWNLOAD = 10

@Producer(ProducedLink)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):
# checking push
    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "18164476_74047877"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR W17 Grad 18164476, 74047877"

        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if url_count >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        print len(self.frame.get(OneUnProcessedGroup))
        for g in self.frame.get(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks = process_url_group(g, self.UserAgentString)
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if url_count >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "downloaded ", url_count, " in ", time() - self.starttime, " seconds."
		print "writing data in analytics file"	
		analytics()
        pass

def save_count(urls):
    print "save count"
    global url_count
    url_count += len(urls)
    with open("successful_urls.txt", "a") as surls:
        surls.write("\n".join(urls) + "\n")

def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    save_count(successfull_urls)
    return extract_next_links(rawDatas)
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    outputLinks = list()
    '''
    rawDatas is a list of tuples -> [(url1, raw_content1), (url2, raw_content2), ....]
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''
    for data in rawDatas:
         # print data[0], " main url"
         try:
             parent_url = str(data[0])
             generated = open("generated_urls.txt", "a")
             generated.write("[" + strftime('%X %x %Z') +"]" + parent_url + "\n")
             # check if valid url recieved from frontier
             if (is_valid(parent_url) == True):
                temp_url_list = []
                try:
                        if data[1] != None:
                            if (len(data[1]) > 0):
                                #TODO - what if html is malformed?
                                #TODO - what if links are dynamic scripts?
                                html = lxml.html.fromstring(data[1])
                            else:
                                generated.write("[" + strftime('%X %x %Z') + "]" + " Encountered URL with no page" + "\n")
                                continue
                        else:
                            generated.write("[" + strftime('%X %x %Z') + "]" + " Encountered URL with rawdata null" + "\n")
                            continue
                except Exception as e:
                    generated.write("[" + strftime('%X %x %Z') + "]" + " Encountered exception in parsing URL " + str(e) + "\n")
                    continue

                for link in html.iterlinks():
                     try:
                        sub_url = (link[2])
                        parent_url_parsed= urlparse(parent_url)
                        sub_url_parsed = urlparse(sub_url)
                        new_url = urljoin(parent_url_parsed.geturl(), sub_url_parsed.geturl())
                        generated.write("   " + "original link" + "[" + strftime('%X %x %Z') + "]" + sub_url_parsed.geturl() + "\n")
                        generated.write("   " + "[" + strftime('%X %x %Z') +"]" + new_url + "\n")
                        temp_url_list.append(new_url)
                        print(new_url)
                     except Exception as c:
                         generated.write("[" + strftime('%X %x %Z') + "]" + " Encountered exception in parsing link " + str(c) + "\n")
                         continue

                outputLinks.extend(temp_url_list)
				log_url_count(parent_url, len(temp_url_list))
				
             # else log the invalid url and move ahead
             else:
                 generated.write("[" + strftime('%X %x %Z') + "]" +" Encountered invalid URL" + "\n")
                 log_invalid_url(parent_url)
                 continue
         except Exception as e:
             generated.write("[" + strftime('%X %x %Z') + "]" + " Encountered exception" + str(e) + "\n")
             continue
    return outputLinks

# LOG INVALID URL RECEIVED FROM FRONTIER
def log_invalid_url(url):
        with open("invalid_urls.txt", "a") as invalid_url:
            invalid_url.write("\n".join(url) + "\n")
            invalid_url.close()

# GET THE COUNT OF INVALID URL RECEIVED FROM FRONTIER
def count_invalid_url():
    with open("invalid_urls.txt", "r") as invalidurl:
        s= []
        for i in invalidurl:
            s.append(i)
    invalidurl.close()
    return len(s)

# LOG URL, NUMBER OF LINKS EXTRACTED FOR VALID URL RECIEVED FORM FRONTIER	
def log_url_count(url, count):
    with open("url_count.txt", "a") as url_count:
        url_count.write(url + "," + count + "\n")
        url_count.close()

		
# GET URL HAVING MAXIMUM OUTBOUND LINKS
def get_url_with_max_outbound():
	url_dict = {}
	with open("url_count.txt", "r") as url_count:
		for line in url_count:
			url_list = line.split(',')
			if (url_list[0] in url_dict):
				if (url_dict[url_list[0]] > url_list[1]):
					url_dict[url_list[0]] = url_list[1]
				else:
					continue
			else:
				url_dict[url_list[0]] = url_list[1]
		url_key = None
		url_count = None
		for key, value in sorted(url_dict.items(), key=lambda x:x[1],reverse = True):
			url_key = key
			url_count = value
			break
		return url_key, url_count
	
	
# ANALYTICS METHOD FOR CRAWALER				
def analytics():
	with open("analytics.txt", "w") as analytics_file:
		url_key, url_count = get_url_with_max_outbound()
		analytics_file.write("\nURL with max outbound links: " + url_key + ", Number of outbound links: " + url_count)
		invalid_url_count = count_invalid_url()
		analytics_file.write("\nCount of invalid links recieved: " + invalid_url_count)
		

def is_valid(url):
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''

    # Whether page can be opened on web or not and protocol is valid
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        #TODO - it is possible that website is not up now and url is valid
        #TODO- in that case this method does not help
        request = requests.get(str(url))
        if request.status_code != 200:
            return False
    except:
        return False

    try:
        return ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz|java)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)

