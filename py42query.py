
import requests
import boto3
import structlog
import json
import math
import itertools
import io
import posixpath
import re
import datetime
import joblib




# Function to request user info, page-by-page
def _getPageOfUsers(authorityURL, 
                    adminuser, 
                    password,
                    pgNum,
                    pgSize,
                    timeoutSeconds = 10):
    """Request a single page of users from the Authority API.
    """
    
    # Hook up the logger
    logger = structlog.get_logger()
    logger.info("Requesting page of users", pgNum = pgNum)
    
    # Build the URL
    requestURL = "{0}/api/v1/User?pgNum={1}&pgSize={2}".format(authorityURL, pgNum, pgSize)
    
    # Make the request
    userPageRequest = requests.get(requestURL, 
                                   auth = (adminuser, password),
                                   timeout = timeoutSeconds)
    
    logger.info("Page of users returned",
                pgNum = pgNum,
                httpStatus = userPageRequest.status_code)
    
    # Decode the JSON and return
    userPageResults = userPageRequest.json()['data']['users']
    return userPageResults
    





def getAllUsers(authorityURL, 
                adminuser,
                password,
                activeOnly = False,
                pgSize = 100,
                timeoutSecondsPerPage = 10):
    """Request all users' details from the Authority (default returns active users only).
    
    Arguments:
     - authorityURL: the URL of the Authority server
     - adminuser: your Code42 admin username
     - password: your Code42 admin password
     - activeOnly: should the function return only active users? Defaults to True
     - pgSize: How many users should be returned in each request? Defaults to 100.
    """
    
    # Hook up the logger
    logger = structlog.get_logger().bind(authorityURL = authorityURL,
                                         adminuser = adminuser)
    
    logger.info("Requesting info for all users", 
                activeOnly = activeOnly)
    
    # First: how many users are there, and how many pages will we need to get them all?
    logger.debug("Requesting total number of users and pages")
    
    # Build the URL
    userCountURL = "{0}/api/v1/User?pgSize=1".format(authorityURL)
    
    # Make the request
    userCountRequest = requests.get(userCountURL, 
                                    auth = (adminuser, password))
    
    # TODO: Add something here to handle failed requests - e.g. 401 Unauthorized
    userCount = userCountRequest.json()['data']['totalCount']
    
    # How many pages are there?
    totalPages = int(math.ceil(userCount / float(pgSize)))
    
    logger.debug("Total number of users and pages returned", 
                 nTotalUsers = userCount, 
                 nTotalPages = totalPages, 
                 pgSize = pgSize)
                       
    
    # Request each page
    userPages = [_getPageOfUsers(authorityURL, 
                                 adminuser, 
                                 password, 
                                 pgNum = x, 
                                 pgSize = pgSize,
                                 timeoutSeconds = timeoutSecondsPerPage) 
                 for x in range(1, totalPages + 1)]
    
    # Collapse into a single list
    allUsers = list(itertools.chain.from_iterable(userPages))
    
    
    # Filter to active users, if requested
    if activeOnly:
        activeUsers = [user for user in allUsers if user['active'] == True]
        logger.info("Active users returned",
                    numActiveUsers = len(activeUsers),
                    numAllUsers = len(allUsers))
        return activeUsers
    
    # Otherwise, return the users (if any)
    elif len(allUsers) > 0:
        logger.info("All users returned",
                    numAllUsers = len(allUsers))
        return allUsers
    
    # If no users, print a warning. (Raise an exception?)
    else:
        logger.warn("No users returned.")
    


def getUser(authorityURL, adminuser, password, 
            userUid = None, 
            userId = None, 
            username = None,
            timeoutSeconds = 10):
    """Request one user's details from the Authority.
    
    Takes the authorityURL and credentials, and exactly one of: userUid 
    (preferred), userId, or username.
    
    Beware: username does fuzzy matching and will cause an error if more than 
    one user is matched. userId is also slated for deprecation, but still
    required for some API calls. If you can, just use userUid.
    """
    
        
    # Hook up the logger
    logger = structlog.get_logger().bind(authorityURL = authorityURL,
                                         adminuser = adminuser)
    
    
    if(all(arg is None for arg in [username, userId, userUid])):
        raise Exception("You have to provide at least one of these: username, userId, or userUid")
    
    # Given one user identifier, return their entire user info set
    if userUid is not None:
        
        logger.info("Requesting user info", userUid = userUid)
        
        requestURL = "{0}/api/v1/User/{1}?idType=uid".format(authorityURL, userUid)
        request = requests.get(requestURL, 
                               auth = (adminuser, password),
                               timeout = timeoutSeconds)
        result = request.json()['data']
        return result
    
    elif userId is not None:
        
        logger.info("Requesting user info", userId = userId)
        
        print "userId is deprecated - switch to userUid if you can."
        requestURL = "{0}/api/v1/User/{1}?idType=id".format(authorityURL, userId)
        request = requests.get(requestURL, 
                               auth = (adminuser, password),
                               timeout = timeoutSeconds)
        result = request.json()['data']
        return result
    
    elif username is not None:
        
        logger.info("Requesting user info", username = username)
        
        requestURL = "{0}/api/v1/User?q={1}".format(authorityURL, username)
        request = requests.get(requestURL, 
                               auth = (adminuser, password),
                               timeout = timeoutSeconds)
        result = request.json()['data']['users']
        
        # Handle multiple or zero matches
        if len(result) > 1:
            raise Exception("More than one user matched your search for '%s' - try a more specific search." % username)
        elif len(result) == 0:
            print "No usernames matched your search for '%s'; try again." % username
        else:
            return result
    





def _getPageOfDevices(authorityURL, 
                      adminuser, 
                      password, 
                      pgNum, 
                      pgSize,
                      timeoutSeconds = 10):
    """Request a single page of devices from the Authority API.
    """
    
    # Hook up the logger
    logger = structlog.get_logger()
    logger.info("Requesting device info", pgNum = pgNum)
    
    # Build the URL
    requestURL = "{0}/api/v1/Computer?pgNum={1}&pgSize={2}".format(authorityURL, pgNum, pgSize)
    
    # Make the request
    deviceRequest = requests.get(requestURL,
                                 auth = (adminuser, password),
                                 timeout = timeoutSeconds)
    
    deviceResults = deviceRequest.json()['data']['computers']
    
    logger.info("Page of devices returned",
                pgNum = pgNum,
                httpStatus = deviceRequest.status_code,
                nDevices = len(deviceResults))
    
    # Decode the JSON and return
    return deviceResults
    





def getAllDevices(authorityURL, 
                  adminuser, 
                  password, 
                  activeOnly = True, 
                  pgSize = 100,
                  timeoutSeconds = 10):
    """Request all device details from the Authority (defaults to active devices only).
    
    Arguments:
     - authorityURL: the URL of the Authority server
     - adminuser: your Code42 admin username
     - password: your Code42 admin password
     - activeOnly: should the function return only active devices? Defaults to True
     - pgSize: How many devices should be returned in each request? Defaults to 100.
    """
    
    # Hook up the logger
    logger = structlog.get_logger().bind(authorityURL = authorityURL,
                                         adminuser = adminuser)
    
    logger.info("Requesting info for all devices", 
                activeOnly = activeOnly)
                           
    
    # Request each page
    # Initialize an empty list to receive each page
    devicePages = []         
    
    # Set up a counter for the page number to request
    pgNum = 1
    
    # Initialize the condition
    nDevicesReturned = pgSize
    
    while nDevicesReturned >= pgSize:
        
        # Get a page of devices
        devicePage = _getPageOfDevices(authorityURL, adminuser, password, 
                                       pgNum = pgNum, 
                                       pgSize = pgSize,
                                       timeoutSeconds = timeoutSeconds)
        
        # Append it to the list of results
        devicePages.append(devicePage)
        
        # How many devices were returned?
        nDevicesReturned = len(devicePage)
        
        # Increment the page count
        pgNum = pgNum + 1
    
       
    # Collapse into a single list
    allDevices = list(itertools.chain.from_iterable(devicePages))
    
    
    # Filter to active devices, if requested
    if activeOnly:
        activeDevices = [device for device in allDevices if device['active'] == True]
        logger.info("Active devices returned",
                    numActiveDevices = len(activeDevices),
                    numAllDevices = len(allDevices))
        return activeDevices
    
    # Otherwise, return the devices (if any)
    elif len(allDevices) > 0:
        logger.info("All devices returned",
                    numAllDevices = len(allDevices))
        return allDevices
    
    # If no devices, print a warning. (Raise an exception?)
    else:
        logger.warn("No devices returned.")











def getSecurityPlans(authorityURL, 
                     adminuser, 
                     password, 
                     userId,
                     timeoutSeconds = 10):
    """Request all security plans for a given user. Requires userId.
    
    Arguments:
     - authorityURL: the URL of the Authority server
     - adminuser: your Code42 admin username
     - password: your Code42 admin password
     - userId: if you only have userUid or username, use the getUser() function
       to retrieve the userId.
    
    See also: getDestinations()
    """
    
    # Hook up the logger
    logger = structlog.get_logger().bind(authorityURL = authorityURL,
                                         adminuser = adminuser,
                                         userId = userId)
    
   
    # Build the request URL
    requestURL = "{0}/api/v1/PlanSummary?userId={1}&planTypes=security&active=true".format(authorityURL, userId)
    
    logger.info("Requesting security plans",
                requestURL = requestURL)
   
    # Make the request
    try:
        request = requests.get(requestURL, 
                               auth = (adminuser, password),
                               timeout = timeoutSeconds)
        
    except requests.exceptions.RequestException as e:
        logger.exception("RequestException in request for security plans")
        return e
    except Exception as e:
        logger.exception("Exception in request for security plans")
        return e
    
    
    # Convert the raw JSON response into a list of plans
    plans = request.json()['data']['plans']
        
    logger.info("Security plans returned",
                httpStatus = request.status_code,
                nPlans = len(plans))
    
    return plans




def getStorageAuthToken(authorityURL, 
                        adminuser, 
                        password, 
                        destinationGuid, 
                        planUid,
                        timeoutSeconds = 10):
    """Request a storage auth token for a given destination.
    
    Arguments:
     - authorityURL: the URL of the Authority server
     - adminuser: your Code42 admin username
     - password: your Code42 admin password
       to retrieve the userId.
     - planUid: the ID of the plan you're interested in
     - destinationGuid: the destination in which the storage node resides
    
    You can get the planUid with the  getSecurityPlans() function in this module,
    and destinationGuid with the getDestinations() function.
    """
    
        
    # Hook up the logger
    logger = structlog.get_logger().bind(authorityURL = authorityURL,
                                         adminuser = adminuser,
                                         destinationGuid = destinationGuid,
                                         planUid = planUid)
    
    logger.info("Requesting storage auth token")
    
    # Build the payload
    payload = {"planUid" :  str(planUid), 
               "destinationGuid" : str(destinationGuid) }
    
    # Build the URL
    requestURL = "{0}/api/v1/StorageAuthToken".format(authorityURL)
    
    # Make the request
    try:
        request = requests.post(requestURL, 
                                json = payload, 
                                auth = (adminuser, password),
                                timeout = timeoutSeconds)
        
        logger.info("Storage auth token returned")
    
        # Extract the token
        token = request.json()['data']
        return token
        
    except requests.exceptions.ConnectionError as e:
        logger.exception("ConnectionError in request for storageAuthToken")
        return e
    except Exception as e:
        logger.exception("Exception in request for storageAuthToken")
        return e

    



def _getEventsFromStorageNode(nodeURL, 
                              loginToken, 
                              planUid, 
                              incFiles,
                              startTime,
                              endTime,
                              timeoutSeconds = 60*5):
    """Retrieve the security events for a specific plan, from a specific node.
    """
    
    # Build the URL
    # TODO: startTime and endTime format checking
    # &minTs=2017-04-10T06:00:00.000Z&maxTs=2017-05-10T05:59:59.999Z
    # SecurityDetectionEvent?userUid=761100348575962712&minTs=2017-05-08T06:00:00.000Z&maxTs=2017-05-10T05:59:59.999Z
    if startTime is not None:
        startTimeParam = '&minTs=' + startTime
    else:
        startTimeParam = ''
        
    if endTime is not None:
        endTimeParam = '&maxTs=' + endTime
    else:
        endTimeParam = ''
        
    
    # Build the URL
    requestURL = "{0}/api/v1/SecurityDetectionEvent/?planUid={1}&incFiles={2}{3}{4}".format(nodeURL, planUid, incFiles, startTimeParam, endTimeParam)
        
    
    
    # Hook up the logger
    logger = structlog.get_logger().bind(nodeURL = nodeURL,
                                         incFiles = incFiles,
                                         startTime = startTime,
                                         endTime = endTime,
                                         requestURL = requestURL)
    
    logger.info("Requesting securityDetectionEvents from node")
    
    try:
        request = requests.get(requestURL,
                               headers = {"Authorization": "login_token {0}".format(loginToken)},
                               timeout = timeoutSeconds)
    except requests.exceptions.ConnectionError as e:
        logger.exception("ConnectionError in request for SecurityDetectionEvents")
        return e
    except Exception as e:
        logger.exception("Error in request for SecurityDetectionEvents")
        return e
    
    
    logger.info("SecurityDetectionEvents returned from node",
                httpStatus = request.status_code)
    
    
    logger.debug("Type of object returned: %s" % type(request) )
    
    return request



def getDestinations(authorityURL, 
                    adminuser, 
                    password, 
                    planUid,
                    timeoutSeconds = 10):
    """Retrieve the destinations in which data for a plan are stored.
    
    See also: getSecurityPlans()
    """
    
    
    
    # Hook up the logger
    logger = structlog.get_logger().bind(authorityURL = authorityURL,
                                         adminuser = adminuser,
                                         planUid = planUid)
    
    logger.info("Requesting destinations for plan")
    
    # Set up the request URL
    destinationRequestURL = "{0}/api/v1/Storage/{1}".format(authorityURL, planUid)
    
    try:
        destinationRequest = requests.get(destinationRequestURL, 
                                          auth = (adminuser, password),
                                          timeout = timeoutSeconds)
    except Exception as e:
        logger.exception("Failed to retrieve destinations")
        return e
    
    # Extract the destinations
    destinations = destinationRequest.json()['data']
    
    if len(destinations) > 0:
        logger.info("Destinations returned",
                    nDestinations = len(destinations))
        return destinations
    else:
        logger.exception("No destinations returned for plan",
                         response = destinationRequest)
        return Exception("No destinations returned for plan")




def getSecurityEvents(authorityURL, 
                      adminuser, 
                      password, 
                      planUid,
                      startTime = None, 
                      endTime = None,
                      incFiles = False,
                      authTimeoutSeconds = 10,
                      eventTimeoutSeconds = 60*5):
    """Query all of the security events associated with one plan.

    Each user stores their security detection events at one or more destinations.
    A plan maps users to destinations. This function takes a planUid, retrieves
    the associated destinations, and then queries the security events for each
    destination. Not really for direct use.
    """
    
    # Terminology note: this function starts out talking about destinations,
    # but ends working with storage nodes. 
    # Destinations = an Authority and its accompanying storage nodes
    # We have to get tokens from the Authority, but use them with the nodes.
    
        
    # Hook up the logger
    logger = structlog.get_logger().bind(adminuser = adminuser,
                                         planUid = planUid)
    
    logger.info("Requesting security events from all destinations",
                startTime = startTime,
                endTime = endTime,
                incFiles = incFiles)
    
    #  Get the destinations for this plan
    destinations = getDestinations(authorityURL, 
                                   adminuser, 
                                   password, 
                                   planUid,
                                   timeoutSeconds = authTimeoutSeconds)
    
    # For each node, get the token
    # Taking them as a generator, so they won't be called until right
    # before they're needed - to prevent expiration
    tokens = (getStorageAuthToken(authorityURL, adminuser, password, 
                                  destinationGuid = destkey,
                                  planUid = planUid,
                                  timeoutSeconds = authTimeoutSeconds)
              for destkey in destinations)
    
    
    # For each token, get the stored events
        
    
    # Make the request for each storage node with the planUid and its token  
    eventList = [_getEventsFromStorageNode(
                     nodeURL = token['serverUrl'], 
                     loginToken = token['loginToken'],
                     planUid = planUid, 
                     incFiles = incFiles,
                     startTime = startTime,
                     endTime = endTime,
                     timeoutSeconds = eventTimeoutSeconds)
                 for token in tokens
                 if type(token) is dict]
    
    # Return the results
    return eventList



def writeSecurityEventsToS3(response, bucketName, outputKey):
    """
    """
    
    # Hook up the logger
    logger = structlog.get_logger().bind(bucketName = bucketName,
                                         outputKey = outputKey)
    
    logger.info("Writing SecurityDetectionEvents to S3")
            
    # Extract the events from the response, if it was successful
    if response.status_code == 200:
        rawResponse = response.json()
    else:
        logger.warning("No SecurityDetectionEvents to write - invalid HTTP response",
                       status_code = response.status_code)
        return Exception("Unsuccessful response (%s) - there's nothing to write to S3." % response.status_code)
    
        
    logger.debug("Converting SecurityDetectionEvents response to JSON file object")
        
    # Extract the events and files from the response
    rawEvents = rawResponse['data']['securityDetectionEvents']
    
    # Write them back to an in-memory JSON file
    eventJSON = io.BytesIO()
    json.dump(rawEvents, eventJSON)  
    eventJSON.seek(0)
    
    
    logger.debug("Setting up S3 object")
        
    # Create a new object on S3
    s3resource = boto3.resource('s3')
    outputObject = s3resource.Object(bucketName, outputKey)
    
    logger.debug("Uploading events to S3",
                 uploadSize = len(eventJSON.getvalue()))
    
    # Upload the file
    try:
        outputObject.upload_fileobj(eventJSON)
    except Exception as e:
        logger.exception("Could not upload events to S3")
        return e
        
    
    # Did it work?
    try:
        logger.debug("Checking to see if file can be loaded from S3")
        outputObject.load()
        logger.info("Successfuly uploaded events to S3")
    except Exception as e:
        logger.exception("Could not upload events to S3")
        return e


def _makeOutputKey(outputDir, userObj, i, timestampStr = None):
    """Create an output key with the appropriate chronological hierarchy.
    """
    
    
    # If no timestamp, use the current time
    # Convert timestamp to datetime
    try:
        timestamp = datetime.datetime.strptime(timestampStr, "%Y-%m-%dT%H:%M:%S.000Z")
    except:
        timestamp = datetime.datetime.now()
    
    # Reformat for inclusion in a filepath
    timestampKey = timestamp.strftime("%Y%m%d_%H%M%S")
    
    outputKey = posixpath.join(
        outputDir,
        "year=" + str(timestamp.year),
        "month=" + str(timestamp.month),
        "day=" + str(timestamp.day),
        userObj['username'] + "_" + timestampKey + "_" + str(i) + ".json")
    
    return outputKey





def loadUserSecurityEventsToS3(authorityURL,
                               adminuser,
                               password,
                               bucketName,
                               outputDir,
                               userUid = None,
                               username = None,
                               userId = None,
                               startTime = None,
                               endTime = None,
                               incFiles = True,
                               timeoutSeconds = 60*5):
    """Query the security events for one user, and write them to S3.

    Takes one of userUid, username, or the (deprecated) userId, as well as
    optional time bounds startTime and endTime (which should be in the format
    '2017-04-10T06:00:00.000Z'.
    """
    
    
   
    # Make a quick dict of authorityURL, adminuser, and password, so they
    # can be passed as one unit (which you'll see as **auth below)
    auth = {"authorityURL" : authorityURL,
            "adminuser" : adminuser,
            "password" : password 
    }
    
    
    # Get the user info - you'll need all of it eventually
    if userUid is not None:
        user = getUser(userUid = userUid, **auth)
    elif username is not None:
        user = getUser(username = username, **auth)
    elif userId is not None:
        user = getUser(userId = userId, **auth)            
    else:
        raise Exception("You have to provide either the userUid or username")
        
    
    logger = structlog.get_logger().bind(userUid = user['userUid'],
                                         username = user['username'])
    
    
    # Get their plans
    userPlans = getSecurityPlans(userId = user['userId'], **auth)
    
    # TODO: If no plans returned, return an exception
    
    
    # Query the events for each plan
    userEventResponses = list(itertools.chain.from_iterable(
        [getSecurityEvents(planUid = plan['planUid'],
                           startTime = startTime,
                           endTime = endTime,
                           incFiles = incFiles,
                           eventTimeoutSeconds = timeoutSeconds,
                           **auth) 
         for plan in userPlans]
    ))
    
    # Write them out to S3
    # Note: users with more than one plan will have more than one item in
    # userEventResponses. In turn, each of those responses is likely to
    # have multiple sets of events - one from each of that plan's destinations.
    # Watch out for all that branching.       
    
    [writeSecurityEventsToS3(
        response, 
        bucketName = bucketName,
        outputKey = _makeOutputKey(outputDir, user, i, datetime.datetime.now()))
     for i, response in enumerate(userEventResponses)
     if type(response) == requests.models.Response] 
     #& response.status_code == 200]
    
    
    # Return a basic summary
    userSummary = {"userUid": user['userUid'],
                   "username": user['username'],
                   "nPlans": len(userPlans),
                   "nDestinations": len(userEventResponses),
                   "nSuccessfulResponses": sum([response.status_code == 200 
                                                for response in userEventResponses
                                                if type(response) == requests.models.Response])
    }
    
    userSummary['nFailedResponses'] = userSummary['nDestinations'] - userSummary['nSuccessfulResponses']
    
    logger.info("Successfully loaded user's SecurityDetectionEvents to S3",
                nPlans = userSummary['nPlans'],
                nDestinations = userSummary['nDestinations'],
                nSuccessfulResponses = userSummary['nSuccessfulResponses'],
                nFailedResponses = userSummary['nFailedResponses'])
    
    return userSummary
         










def loadAllUsersSecurityEventsToS3(authorityURL, 
                                   adminuser, 
                                   password, 
                                   bucketName,
                                   outputDir,
                                   startTime = None, 
                                   endTime = None, 
                                   incFiles = False,
                                   activeOnly = True,
                                   timeoutSecondsPerUser = 60*5):
    """
    """
    
    # Make a quick dict of authorityURL, adminuser, and password, so they
    # can be passed as one unit (which you'll see as **auth below)
    auth = {"authorityURL" : authorityURL,
            "adminuser" : adminuser,
            "password" : password 
    }
    
    # Hook up the logger
    logger = structlog.get_logger().bind(adminuser = adminuser)    
    logger.info("Loading all users' SecurityDetectionEvents to S3")
    
    
    # Request the complete userlist from the Authority
    userList = getAllUsers(activeOnly = activeOnly, **auth)
    
    
    # We want to be able to report on the outcome of every user, so set up
    # a dict with userUids as keys. This way, even if everythin below fails, 
    # there will be some kind of stub for every user.
    userOutcomes = {key: None for key in [user['userUid'] for user in userList] }
    
    # For each user:
    for user in userList:
        
        print "Working on SDE request for %s" % user['username']
        
        userSummary = loadUserSecurityEventsToS3(userUid = user['userUid'],
                                                 bucketName = bucketName,
                                                 outputDir = outputDir,
                                                 startTime = startTime,
                                                 endTime = endTime,
                                                 incFiles = incFiles,
                                                 timeoutSeconds = timeoutSecondsPerUser,
                                                 **auth)
                                                 
        
        # Store the summary in the global list of results
        userOutcomes[user['userUid']] = userSummary
        
        
    return userOutcomes










def checkAllUsersSecurityEventsOnS3(authorityURL,
                                    adminuser,
                                    password,
                                    bucketName, 
                                    outputDir,
                                    activeOnly = True):
    """
    """
    
    
    # Make a quick dict of authorityURL, adminuser, and password, so they
    # can be passed as one unit (which you'll see as **auth below)
    auth = {"authorityURL" : authorityURL,
            "adminuser" : adminuser,
            "password" : password 
    }
    
    # Hook up the logger
    logger = structlog.get_logger().bind(adminuser = adminuser,
                                         bucketName = bucketName,
                                         outputDir = outputDir)
    
    logger.info("Checking for all users' SecurityDetectionEvents on S3")
    
    
    # Request the complete userlist from the Authority
    userList = getAllUsers(activeOnly = activeOnly, **auth)
    
    # List all the objects in the bucket
    s3Bucket = boto3.resource('s3').Bucket(bucketName)
    s3Files = [obj for obj in s3Bucket.objects.filter(Prefix = outputDir)]
    
    if(len(s3Files) == 0):
        logger.warning("No files were found in the specified outputDir; are you sure that's the right outputDir?")
    
    # Parse into a friendlier list of dicts
    filesParsed = [{'bucketName': s3File.bucket_name,
                    'key': s3File.key,
                    'username': re.search(pattern = r".*/([A-Za-z\\.]*).*json",
                                          string = s3File.key).group(1),
                    'size': s3File.size,
                    'lastModified': s3File.last_modified}
                   for s3File in s3Files
                   if s3File.key.endswith("json")]
      
    
    
    # Which users drawn from the Authority aren't present on S3?
    authUsers = set([user['username'] for user in userList])
    s3Users = set([s3File['username'] for s3File in filesParsed])
    usersWithNoS3File = authUsers - s3Users
    
    logger.warn("Users with no files on S3 found",
                nUsers = len(usersWithNoS3File),
                usernames = usersWithNoS3File)
    
        
    # Group the files under username in a new dictionary
    userFiles = {}.fromkeys(authUsers, {})        
    
    for username in userFiles:
        files = [parsedFile for parsedFile in filesParsed 
                 if parsedFile['username'] == username]
        
        try:
            lastModified = max([s3File['lastModified'] for s3File in files])
        except:
            lastModified = None        
        
        userFiles[username]['s3Files'] = files
        
        userFiles[username] = {
            'nS3Files':      len(files),
            'lastModified': lastModified,
            's3Files':       files
        }
    
    
    logger.info("Returning details of SecurityDetectionEvent files on S3 file results",
                nUsersFound =    len([userFiles[username] for username in userFiles if userFiles[username]['nS3Files'] != 0]),
                nUsersNotFound = len(usersWithNoS3File),
                nFilesFound =    len(filesParsed))
    
    return userFiles
    





def loadNewSecurityEventsToS3(outputDir,
                              resultsPath,
                              adminuser,
                              password,
                              bucketName = "com.code42.predictiveintel",
                              authorityURL = "https://sp.code42.com",
                              incFiles = True,
                              timeoutSecondsPerUser = 60*5,
                              n_parallel_tasks = 4,
                              **kwargs):
    """Update an existing directory of events with the latest events for each user.

    ... or create that directory if it doesn't yet exist. This function reads in
    the existing set of events for each user on S3, identifies the latest event
    for each user, and then queries all events after that moment (if any).

    This function is parallelized across its host's cores using Python's joblib
    package. By default, it will run 4 tasks in parallel, which can pull the full
    two-year history of 700+ Code42 employee devices in about 15 minutes.
    Larger organizations may want to increase the parallelism.
    """
    # Set up a dict of authorityURL, adminuser, and password - they get used a lot,
    # and it's easier to pass them via kwargs
    auth = {"authorityURL" : authorityURL,
            "adminuser" : adminuser,
            "password" : password 
    }
    
    
    
    
    # Configure the log
    logger = structlog.get_logger()
    logger = logger.bind(adminuser = adminuser)
    
    
    
    # Get the status for all users to see when SDEs were most recently
    # loaded.
    logger.info("Checking for user events on S3")
    
    userStatus = checkAllUsersSecurityEventsOnS3(
        bucketName = bucketName,
        outputDir = outputDir,
        activeOnly = False,
        **auth)
    
    
    # Update the events for all users
    logger.info("Starting to load users' new SecurityDetectionEvents to S3")
    
    
    
    # Iterate over all users
    outcomesList = joblib.Parallel(n_jobs = n_parallel_tasks)(
        joblib.delayed(_loadOneUserToS3)(
            username = username, 
            lastModified = userStatus[username]['lastModified'],
            authDict = auth,
            bucketName = bucketName,
            outputDir = outputDir,
            incFiles = incFiles,
            timeoutSecondsPerUser = timeoutSecondsPerUser)
        for username in userStatus
    )
    
    logger.info("Finished loading new SecurityDetectionEvents")
    
    
    # Write out the outcomes
    resultsPathFull = posixpath.join(resultsPath, 
        'loadResults_' +
        datetime.datetime.now().strftime("%Y%m%d_%H%M%S") +
        '.json')

    logger.debug("Setting up resultsFile on S3", resultsPath = resultsPathFull)

    
    # Simplify that list into a dict with this incomprehensible comprehension:
    userOutcomes = {username: results 
                    for userOutcome in outcomesList
                    for username, results in userOutcome.iteritems() }


    # Write the output to an in-memory JSON file
    userOutcomesJSON = io.BytesIO()
    json.dump(userOutcomes, userOutcomesJSON)  
    userOutcomesJSON.seek(0)
    
        
    # Create a new object on S3
    s3resource = boto3.resource('s3')
    outputObject = s3resource.Object(bucketName, resultsPathFull)
    
    logger.debug("Uploading resultsFile to S3")
    
    # Upload the file
    try:
        outputObject.upload_fileobj(userOutcomesJSON)
    except Exception as e:
        logger.exception("Could not upload resultsFile to S3")
        return e
        
    
    # Did it work?
    try:
        logger.debug("Checking to see if file can be loaded from S3")
        outputObject.load()
        logger.info("Successfuly uploaded resultsFile to S3")
    except Exception as e:
        logger.exception("Could not upload resultsFile to S3")
        return e
    
    
    # Return the outcomes, too
    return userOutcomes










# This is a helper function for loadNewSecurityEventsToS3 above,
# to allow it parallelize the user queries.
# It can't be defined *within* that function, however, because the function
# has to be pickled for multiprocessing - and functions defined inside a 
# closure can't be pickled. :|
def _loadOneUserToS3(username,
                     lastModified, 
                     authDict,
                     bucketName,
                     outputDir,
                     incFiles,
                     timeoutSecondsPerUser,
                     **kwargs):
    """Query security detection events for one user and load them to S3.

    This is a thin wrapper around getUser and loadUserSecurityEventsToS3 that
    just made adding parallelism to the existing code easier.
    """
    
    # Hook up the logger
    logger = structlog.get_logger()
    logger.info("Loading new SecurityDetectionEvents for user", 
                username = username)
    
    print "Loading new SecurityDetectionEvents for %s..." % username
    
    # Get the userUid
    try:
        userInfo = getUser(username = username, **authDict)[0]
    except:
        logger.warning("Could not retrieve userUid for %s" % username)
        return({username: None})
    
    # Assuming the job is running at 24 hour intervals, and takes 4-5 hours to
    # complete, we've got to bump the query time back a little to make sure there's
    # no gap.
    # This will result in some overlap, but that's taken care of in the 
    # Parquet table-building process.
    # This requires that the raw files stay put, which they may not.
    # Alternatives to this heuristic:
    # - Read the actual last event timestamp out of each user's file
    # - Read actual last event timestamp from the EDW
    # - Switch the job to actual 24-hour pull windows (but then: how do we
    #   backfill on a per-device basis?)
    if lastModified is None:
        startTimeParam = None
    else: 
        startTime = lastModified - datetime.timedelta(hours = 5)
        startTimeParam = startTime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
    
    userSummary = loadUserSecurityEventsToS3(
        userUid = userInfo['userUid'],
        bucketName = bucketName,
        outputDir = outputDir,
        startTime = startTimeParam,
        endTime = None,
        incFiles = incFiles,
        timeoutSeconds = timeoutSecondsPerUser,
        **authDict)
                                             
    
    # Store the summary in the global list of results
    return({username: userSummary})


