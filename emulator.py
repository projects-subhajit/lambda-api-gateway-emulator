from gateway_config import *
from flask import Flask,request,jsonify
import lambda_function
import json
import re
import time
from datetime import datetime

app = Flask(__name__)

paths=list(paths_definition.keys())

def match_path(string, paths):
    string = string.rstrip('/')
    for path in paths:
        pattern = re.sub(r'{[^}]+}', r'[^/]+', path)
        match = re.match(pattern, string)
        if match and path.count('/')==string.count('/'):
            pattern_for_proxy_path = r'{([^}]+)\+}'  # Regex pattern to match '{<variable>+}'
            match_for_proxy_path = re.search(pattern_for_proxy_path, path)
            if match_for_proxy_path:
                variable = match_for_proxy_path.group(1)  # Extract the variable
                index=path.split('/').index("{"+f"{variable}"+"+}")
                value=string.split('/')[index]
                return path, {variable:value}
            else:
                return path, None
    return None, None

class LambdaContext:
    def __init__(self, function_name):
        self.function_name = function_name

    def set_attribute(self, attribute_name, attribute_value):
        setattr(self, attribute_name, attribute_value)

context = LambdaContext(function_name)

@app.route('/',methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
@app.route('/<path:proxy_path>',methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
def endpoint(proxy_path=None):
    proxy_path=proxy_path.rstrip('/')
    matched_path = match_path(f"/{proxy_path}" if proxy_path else '/', paths)

    method=request.method.upper()
    allowed_methods=list(paths_definition.get(matched_path[0]).keys())

    if method in allowed_methods or "ANY" in allowed_methods:
        scheme=request.scheme
        content_type=request.content_type
        headers={header_key: header_value for header_key,header_value in request.headers.items()}
        multivalue_headers={header_key: [h_v.strip() for h_v in header_value.split(',')] if header_key.lower()!="accept-encoding" else [header_value] for header_key,header_value in request.headers.items()}
        arguments={arg_key: arg_value for arg_key,arg_value in request.args.items()}
        

        event={
            "resource": matched_path[0],
            "path": proxy_path,
            "httpMethod": method,
            "headers": headers,
            "multiValueHeaders": multivalue_headers,
            "queryStringParameters": arguments,
            "multiValueQueryStringParameters": None,
            "pathParameters": matched_path[1],
            "stageVariables": stage_variables if stage_variables or len(stage_variables)!=0 else None,
            "requestContext": {
                "resourceId": "uvzdmb",
                "resourcePath": matched_path[0],
                "httpMethod": method,
                "extendedRequestId": "HRPDNGCoiYcFRtA=",
                "requestTime": datetime.utcnow().strftime('%d/%b/%Y:%H:%M:%S +0000'),
                "path": proxy_path,
                "accountId": "666696661271",
                "protocol": "HTTP/1.1",
                "stage": stage_name,
                "domainPrefix": "1s9ggcpx4a",
                "requestTimeEpoch": int(time.time()),
                "requestId": "d811957a-c92a-4435-adfd-e3a4d02d3879",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "esPCbkjp324l6w8dzo6Dh62Q1lmMjP2n9PeyNxhP",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "o4zkwqpyb7",
                    "userAgent": request.headers["User-Agent"],
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "49.37.11.24",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None
                },
                "domainName": "1s9ggcpx4a.execute-api.us-east-2.amazonaws.com",
                "apiId": "1s9ggcpx4a"
            },
            "body": str(request.data.decode('utf-8')),
            "isBase64Encoded": False
        }

        context.set_attribute("aws_request_id","b30b0062-f275-4d79-a19e-0d44a772caef")
        context.set_attribute("log_group_name",f"/aws/lambda/{function_name}")
        context.set_attribute("log_stream_name","2023/06/29/[$LATEST]8b3a58ae2e4747f487321edc453c4b84")
        context.set_attribute("function_name",function_name)
        context.set_attribute("memory_limit_in_mb",128)
        context.set_attribute("function_version","$LATEST")
        context.set_attribute("invoked_function_arn",f"arn:aws:lambda:us-east-2:666696661271:function:{function_name}")
        context.set_attribute("client_context",None)
        context.set_attribute("identity","CognitoIdentity([cognito_identity_id=None,cognito_identity_pool_id=None])")

        fnc_execution=lambda_function.lambda_handler(event,context)

        return fnc_execution if fnc_execution else "Function does not return anything."
    else:
        return "The method is not authorized or supported."

# main driver function
if __name__ == '__main__':
    app.run()



# =================================================
# Sample 

# function_name=""
# paths_definition = {
#     "/abc" : {
#             "ANY":{"integration_type":"aws_proxy"},
#             "POST":{"integration_type":"aws"}
#         },
#     "/abc/{def+}":{
#             "POST":{"integration_type":"aws_proxy"}
#         },
#     "/mno/{xyz+}":{
#             "POST":{"integration_type":"aws_proxy"}
#         }
# }
# stage_variables=[]
# stage_name="sandbox_test"
