# Import socket module
import getopt
import json

import sys
import urllib2


def main(argv):
    CONTROLLER_IP = '127.0.0.1'
    CONTROLLER_SERVICE_PORT = 6060

    bandwidth = None
    source_ip = None
    destination_ip = None
    option = None
    message = None
    request = {}

    #first get the program commandline params
    try:
	opts, args = getopt.getopt(argv,"s:d:o:m",["sourceip=","destip=","option=","message="])
	for opt,arg in opts:
	    if opt in ("-s","--sourceip"):
		source_ip = arg
	    elif opt in ("-d","--destip"):
		destination_ip = arg
	    elif opt in ("-o","--option"):
		option = arg
	    elif opt in ("-m","--message"):
		message = arg;
	


    except getopt.GetoptError:
	print "usage:  client.py -s <souce_ip> -d <destination_ip> -o <option> -m <message>"


    #send the reservation request to the controller reservation service
	    
    request['source_ip'] = source_ip
    request['dest_ip'] = destination_ip
    request['message'] = message
    request['option'] = option

    request_str = json.dumps(request);
    reservation_endpoint = 'http://'+ CONTROLLER_IP + ":" + str(CONTROLLER_SERVICE_PORT)
    print 'contacting controller server : ' + reservation_endpoint

    req = urllib2.Request(reservation_endpoint)
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req,request_str)
    data = response.read()
    response_dict = json.loads(data)


    if response_dict['result'] == 'BAD_REQUEST':
        print "bad request params.."
        return;
    elif response_dict['result'] == 'FAILED':
        print "reservation failed, try again"
        return;
    elif response_dict['result'] == 'OK':
        print "reservation granted"
        #if reservation granted, go ahead and send the retuest, else abort
        #execute the file download command

        return



if __name__ == '__main__':
    main(sys.argv[1:])


