

import boto3     
import py42query 

authorityURL = 'https://authority-east-lb.us.code42.com' 
bucketName =  'com.code42.scratch.datascience' 
outputDir =  'sectools_raw' 
resultsPath = outputDir 
incFiles = True 

# Get the SP query credentials 
ssm = boto3.client('ssm', region_name = 'us-east-1') 

adminuser = ssm.get_parameters( 
    Names = ['c42-api-username'], 
    WithDecryption = True)['Parameters'][0]['Value'] 

password = ssm.get_parameters( 
    Names = ['c42-api-password'], 
    WithDecryption = True)['Parameters'][0]['Value'] 


results = py42query.loadNewSecurityEventsToS3( 
    outputDir = outputDir, 
    resultsPath = resultsPath, 
    authorityURL = authorityURL, 
    bucketName = bucketName, 
    adminuser = adminuser, 
    password = password, 
    incFiles = incFiles) 
