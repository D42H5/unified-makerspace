"""
TODO
***
- PUT -> POST
- Split current request body validators into collections of individual checks that can be explicitly called. Should allow for more robust request body validation of any kind (e.g., post and update).
- PATCH actually implemented
***
- Delete actually implemented
- Manually generate timestamp for equipment and qualifications. Visit timestamp should still be given in request body.
"""
import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
import logging
from datetime import datetime

class InvalidQueryParameters(BaseException):
    """
    An exception that should be raised if a query parameter
    -- or combination of query parameters -- is not acceptable.
    """
    def __init__(self, *args):
        """
        Initialize the exception with a custom message. The message
        must be passed as an arg.
        """
        exceptionMsg = "One (or more) query parameters are invalid."
        if not args:
            args = (exceptionMsg,)

        # Initialize exception with args
        super().__init__(*args)

class InvalidRequestBody(BaseException):
    """
    An exception that should be raised if a request body
    does not match requirements.
    """
    def __init__(self, *args):
        """
        Initialize the exception with a custom message. The message
        must be passed as an arg.
        """
        exceptionMsg = "One (or more) required keys are missing."
        if not args:
            args = (exceptionMsg,)

        # Initialize exception with args
        super().__init__(*args)

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize the DynamoDB client using boto3
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

# Table names
user_table_name = 'new-test-user'
visit_table_name = 'new-test-visits'
equipment_table_name = 'new-test-equipment'
qualifications_table_name = 'new-test-qualifications'

# Define path constants
user_endpoint: str = "/{user_id}"
users_path: str = "/users"
users_param_path: str = users_path + user_endpoint
visits_path: str = "/visits"
visits_param_path: str = visits_path + user_endpoint
equipment_path: str = "/equipment"
equipment_param_path: str = equipment_path + user_endpoint
qualifications_path: str = "/qualifications"
qualifications_param_path: str = qualifications_path + user_endpoint

# Other global values
SCAN_LIMIT: int = 1000
TIMESTAMP_FORMAT: str = "%Y-%m-%dT%H:%M:%S"
TIMESTAMP_INDEX: str = "TimestampIndex"

# Main handler function
def handler(event, context):
    try:
        logger.info(f"\nRequest event method: {event.get("httpMethod")}")
        logger.info(f"\nEVENT\n{json.dumps(event, indent=2)}")

        method_requires_body: list = ["POST", "PATCH"]

        response = buildResponse(statusCode = 400, body = {})
        http_method: str = event.get("httpMethod")
        resource_path: str = event.get("resource")

        # Get a user_id if needed
        user_id: str = ""
        if user_endpoint in resource_path:
            user_id = event['pathParameters'].get('user_id')

            # Make sure no '@' is in user_id
            if len(user_id.split("@")) > 1:
                errorMsg: str = "user_id can't be an email."
                body = { 'errorMsg': errorMsg }
                return buildResponse(statusCode = 400, body = body)

        # Get the body data if needed
        data:dict = {}
        if http_method in method_requires_body:
            if 'body' not in event:
                errorMsg: str = "REST method {http_method} requires a request body."
                body = { 'errorMsg': errorMsg }
                return buildResponse(statusCode = 400, body = body)
            data = json.loads(event['body'])

        # Try to get any query parameters
        try:
            query_parameters: dict = event['queryStringParameters']
        except:
            query_parameters: dict = {}

        # FIXME: For debugging purposes right now. Worth keeping?
        logger.info(f"\nLOCAL VARS:\n"
                    +f"http_method: {http_method}\n"
                    +f"resource_path: {resource_path}\n"
                    +f"user_id: {user_id}\n"
                    +f"data: {data}\n"
                    +f"query_parameters: {query_parameters}\n"
        )

        # User information request handling
        if http_method == "GET" and resource_path == users_path:
            response = get_all_user_information()
        elif http_method == "POST" and resource_path == users_path:
            response = create_user_information(data)

        elif http_method == "GET" and resource_path == users_param_path:
            response = get_user_information(user_id)
        elif http_method == "PATCH" and resource_path == users_param_path:
            response = patch_user_information(user_id, data)
        elif http_method == "DELETE" and resource_path == users_param_path:
            response = delete_user_information(user_id)


        # Visit information request handling
        elif http_method == "GET" and resource_path == visits_path:
            response = get_all_visit_information(query_parameters)
        elif http_method == "POST" and resource_path == visits_path:
            response = create_user_visit_information(data)

        elif http_method == "GET" and resource_path == visits_param_path:
            response = get_user_visit_information(user_id, query_parameters)


        # Equipment information request handling
        elif http_method == "GET" and resource_path == equipment_path:
            response = get_all_equipment_usage_information(query_parameters)
        elif http_method == "POST" and resource_path == equipment_path:
            response = create_user_equipment_usage(data)

        elif http_method == "GET" and resource_path == equipment_param_path:
            response = get_user_equipment_usage(user_id, query_parameters)
        elif http_method == "PATCH" and resource_path == equipment_param_path:
            response = patch_user_equipment_usage(user_id, data)


        # Qualifications information request handling
        elif http_method == "GET" and resource_path == qualifications_path:
            response = get_all_qualifications_information(query_parameters)
        elif http_method == "POST" and resource_path == qualifications_path:
            response = create_user_qualifications(data)

        elif http_method == "GET" and resource_path == qualifications_param_path:
            response = get_user_qualifications(user_id)
        elif http_method == "PATCH" and resource_path == qualifications_param_path:
            response = patch_user_qualifications(user_id, data)


        # FIXME: For debugging purposes right now. Worth keeping?
        logger.info(f"\nFINAL RESPONSE:\n{response}")
        return response
    except Exception as e:
        logger.info(e)
        errorMsg: str = f"{str(e)}"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 599, body = body)

####################
# Helper functions #
####################
def buildResponse(statusCode: int, body: dict):
    """
    Returns a valid response to return to API Gateway.

    :params statusCode: The response status code.
    :params body: The content to return in a dictionary.
    """
    return {
        "statusCode": statusCode,
		"headers": {
			"Content-Type": "application/json"
		},
        "body": json.dumps(body)
    }

def buildTimestampKeyExpression(query_parameters: dict, timestamp_attr_name: str):
    """
    Returns a valid Key() expression to use when sorting by timestamp. Use this
    value by &ing it with other KeyConditionExpressions.

    :note: The timestamp attribute MUST be a sort key. Additionally, at least one
           of the following key names must be in query_parameters with a value.
           Given query values must be in ISO 8601 format excluding the local
           offset (e.g., YYYY-MM-DDThh:mm:ss). 

           Valid Query Parameter Keys:
           start_timestamp
           end_timestamp

    :params query_parameters: The dictionary containing on of the keys
                              mention above.
    :params timestamp_attr_name: The name of the data field containing
                                 the ISO 8601 compliant (as described
                                 above in the note) timestamps.
    :raises InvalidQueryParameters: If the start_timestamp occurs after
                                    the end_timestamp
    """

    start_timestamp = None
    end_timestamp = None

    if "end_timestamp" in query_parameters:
        end_timestamp = query_parameters["end_timestamp"]
    if "start_timestamp" in query_parameters:
        start_timestamp = query_parameters["start_timestamp"]

    # Build the FilterExpression to filter by
    if end_timestamp and not start_timestamp:
        expression = Key(timestamp_attr_name).lte(end_timestamp)

    elif start_timestamp and not end_timestamp:
        expression = Key(timestamp_attr_name).gte(start_timestamp)

    else:
        # Can't have the end_timestamp occur before the start_timestamp
        if str(end_timestamp) < str(start_timestamp):
            raise InvalidQueryParameters("When searching with both start and end timestamps, end_timestamp cannot occur before start_timestamp.")

        expression = Key(timestamp_attr_name).between(start_timestamp, end_timestamp)

    return expression

def queryByKeyExpression(table, key_expression, GSI = None) -> list:
    """
    Queries a given table for all entries that match the provided key
    expression. When desiring to search by timestamp, table is required
    to have a secondary global index with a primary key of {"S": "_ignore"}
    and a sort key set to the timestamp attribute name. All entries to be
    queried by timestamp must have an _ignore value of "1". Any other table
    entry with an _ignore value that isn't "1" will be ignored.

    :note: This will return a list of objects containing the values of the
           primary key of the table, the corresponding timestamp, and the
           _ignore value ("1"). Additional queries using this data may be
           needed to get more information from the table. Also, the queried
           table MUST have the timestamp field provided to the key expression
           as a sort key.
    :params table: The dynamodb.Table to scan.
    :params key_expression: A valid Key() expression to filter results by.
                            Common problems result from trying to use a
                            non primary key (primary+sort) in the expression.
    :params GSI: The string name of the global secondary index that has _ignore
                 primary key and timestamp as the sort key. Required if
                 trying to query by timestamps.
    :return: A list containing all entries that pass the timestamp filtering.
    """

    """
    Query at least once, then keep querying until queries
    stop exceeding response limit.
    """

    # TODO: Put params into an args tuple and call *args in .scan()

    # The list that will store all matching query items
    items: list = []
    try:
        if GSI != None:
            response = table.query(
                IndexName=GSI,
                KeyConditionExpression=key_expression,
                ScanIndexForward=False, # Orders results by descending timestamp
            )
        else:
            response = table.query(
                KeyConditionExpression=key_expression,
                ScanIndexForward=False, # Orders results by descending timestamp
            )

        items += response['Items']

        """
        Query until "LastEvaluatedKey" isn't in response (all appropriate keys
        where checked)
        """
        while "LastEvaluatedKey" in response:
            if GSI != None:
                response = table.query(
                    IndexName=GSI,
                    KeyConditionExpression=key_expression,
                    ScanIndexForward=False, # Orders results by descending timestamp
                )
            else:
                response = table.query(
                    KeyConditionExpression=key_expression,
                    ScanIndexForward=False, # Orders results by descending timestamp
                )

            items += response['Items']

    except Exception as e:
        # Don't log since this function's errors should be handled by caller
        raise Exception(e)

    return items

def scanTable(table, filter_expression = None) -> list:
    """
    Scans an entire dynamodb table. Optionally uses a passed in filter expression
    to limit the results returned.

    :params table: The dynamodb.Table to use.
    :params filter_expression: The optional Attr() filter to use.
    :return: A list of all returned items (that optionally match
              filter_expression).
    """

    # List to store returned items
    items: list = []

    # TODO: Put Filter/Limit into an args tuple and call *args in .scan()
    """
    Scan at least once, then keep scanning until either no more
    items are returned or the end of the table is reached.
    """
    try:
        if not filter_expression == None:
            response = table.scan(
                FilterExpression=filter_expression,
                Limit=SCAN_LIMIT
            )

        else:
            response = table.scan(
                Limit=SCAN_LIMIT
            )

        items += (response['Items'])
        logger.info(f"\nTable returned:\n{response}")

        # Keep scanning for more items until no more return
        while 'Items' in response and 'LastEvaluatedKey' in response:
            if not filter_expression == None:
                response = table.scan(
                    FilterExpression=filter_expression,
                    Limit=SCAN_LIMIT,
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )

            else:
                response = table.scan(
                    Limit=SCAN_LIMIT,
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )

            items += (response['Items'])

    except KeyError:
        pass

    except Exception as e:
        logger.info(e)
        raise e

    return items

def allKeysPresent(keys: list[str], data: dict) -> bool:
    """
    Checks if all strings in a list are in a dictionary.

    :params keys: A list of strings to check as keys for the dictionary.
    :params data: The dictionary to check the keys against.
    :returns: True if all keys are present, false if at least one of them isn't.
    """

    for key in keys:
        if key not in data:
            return False
    return True

def validateCreateUserRequestBody(data: dict):
    """
    Valides the request body used when creating a user information entry.
    Will raise an InvalidRequestBody error with the details explaining
    what part of the body is invalid.

    :params data: The request body to validate.
    :raises: InvalidRequestBody
    """

    required_fields: list[str] = ["user_id", "university_status"]
    status_fields: list[str] = ["undergraduate_class"]

    # Ensure all required fields are present
    if not allKeysPresent(required_fields, data):
        errorMsg: str = f"Missing at least one field from {required_fields} in requestBody."
        raise InvalidRequestBody(errorMsg)

    # Ensure all status fields are present if data['university_status'] == "Undergraduate"
    if data['university_status'] == "Undergraduate":
        if not allKeysPresent(status_fields, data):
            errorMsg: str = f"Missing at least one field from {status_fields} in requestBody."
            raise InvalidRequestBody(errorMsg)

def validateCreateVisitRequestBody(data: dict):
    """
    Valides the request body used when adding/updating user information.
    Will raise an InvalidRequestBody error with the details explaining
    what part of the body is invalid.

    :params data: The request body to validate.
    :raises: InvalidRequestBody
    """

    required_fields: list[str] = ["user_id", "timestamp", "location"]

    # Ensure all required fields are present
    if not allKeysPresent(required_fields, data):
        errorMsg: str = f"Missing at least one field from {required_fields} in requestBody."
        raise InvalidRequestBody(errorMsg)

    # Ensure timestamp is in the correct format
    try:
        datetime.strptime(data['timestamp'], TIMESTAMP_FORMAT)
    except ValueError:
        errorMsg: str = f"Timestamp not in the approved format. Approved format is 'YYYY-MM-DDThh:mm:ss'."
        raise InvalidRequestBody(errorMsg)

def validateCreateEquipmentRequestBody(data: dict):
    """
    Valides the request body used when adding/updating user information.
    Will raise an InvalidRequestBody error with the details explaining
    what part of the body is invalid.

    :params data: The request body to validate.
    :raises: InvalidRequestBody
    """

    required_fields: list[str] = ["user_id", "timestamp", "location",
                                  "project_name", "project_type", "equipment_type"]
    
    class_project_fields: list[str] = ["class_number", "faculty_name", "project_sponsor"]
    club_project_fields: list[str] = ["organization_affiliation"]

    equipment_3d_printer_fields: list[str] = ["printer_name", "print_duration",
                                              "print_mass", "print_mass_estimate",
                                              "print_status", "print_notes"]

    # Ensure all required fields are present
    if not allKeysPresent(required_fields, data):
        errorMsg: str = f"Missing at least one field from {required_fields} in requestBody."
        raise InvalidRequestBody(errorMsg)

    # Project Type field assertion
    # Ensure all class project fields are present if data["project_type"] == "Class"
    if data["project_type"] == "Class":
        if not allKeysPresent(class_project_fields, data):
            errorMsg: str = f"Missing at least one field from {class_project_fields} in requestBody."
            raise InvalidRequestBody(errorMsg)

    # Ensure all club project fields are present if data["project_type"] == "Club"
    elif data["project_type"] == "Club":
        if not allKeysPresent(club_project_fields, data):
            errorMsg: str = f"Missing at least one field from {club_project_fields} in requestBody."
            raise InvalidRequestBody(errorMsg)

    # Equipment type field assertion
    # Ensure all 3D Printer fields are present if data["equipment_type"] == "3D Printer"
    if data["equipment_type"] == "3D Printer":
        if '3d_printer_info' not in data:
            errorMsg: str = f"Missing '3d_printer_info' object in requestBody."
            raise InvalidRequestBody(errorMsg)

        if not allKeysPresent(equipment_3d_printer_fields, data['3d_printer_info']):
            errorMsg: str = f"Missing at least one field from {equipment_3d_printer_fields} in requestBody."
            raise InvalidRequestBody(errorMsg)

    # Ensure timestamp is in the correct format
    try:
        datetime.strptime(data['timestamp'], TIMESTAMP_FORMAT)
    except ValueError:
        errorMsg: str = f"Timestamp not in the approved format. Approved format is 'YYYY-MM-DDThh:mm:ss'."
        raise InvalidRequestBody(errorMsg)

def validateCreateQualificationRequestBody(data: dict):
    """
    Valides the request body used when adding/updating user information.
    Will raise an InvalidRequestBody error with the details explaining
    what part of the body is invalid.

    :params user_id: The name of the user.
    :params data: The request body to validate.
    :raises: InvalidRequestBody
    """

    required_fields: list[str] = ["user_id"]

    # Ensure all required fields are present
    if not allKeysPresent(required_fields, data):
        errorMsg: str = f"Missing at least one field from {required_fields} in requestBody."
        raise InvalidRequestBody(errorMsg)


######################################
# User information function handlers #
######################################
def get_all_user_information():
    """
    Returns all user information entries from the user information table.
    """

    table = dynamodb.Table(user_table_name)
    users = scanTable(table)

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nUsers:\n{users}")

    body = { 'users': users }
    return buildResponse(statusCode = 200, body = body)

def create_user_information(data: dict):
    """
    Adds a new user to the user information table.

    :params data: The user information to store.
    """

    table = dynamodb.Table(user_table_name)

    try:
        validateCreateUserRequestBody(data)
    except InvalidRequestBody as irb:
        body = { 'errorMsg': str(irb) }
        return buildResponse(statusCode = 400, body = body)

    # Check to make sure the user doesn't already exist. Return 400 if user does exist.
    user_id: str = data['user_id']
    response = get_user_information(user_id)
    if response['statusCode'] == 200:
        errorMsg: str = f"User {user_id} information already exists. Did you mean to update?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    # Actually try putting the item into the table
    try:
        table.put_item(
            Item=data
        )
    except Exception as e:
        logger.info(e)
        body = { 'errorMsg': "Something went wrong on the server." }
        return buildResponse(statusCode = 500, body = body)

    # If here, put action succeeded. Return 201
    return buildResponse(statusCode = 201, body = {})

def get_user_information(user_id: str):
    """
    Gets all of the information for the specified user.

    :params user_id: The name of the user.
    """

    table = dynamodb.Table(user_table_name)
    response = table.get_item(
            Key={ 'user_id': user_id }
    )

    # user_id doesn't exist if 'Item' not in response
    if 'Item' not in response:
        errorMsg: str = f"No information for the user {user_id} could be found. Is there a typo?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    user = response['Item']

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nUser:\n{user}")

    return buildResponse(statusCode = 200, body = user)

def patch_user_information(user_id: str, data: dict):
    """
    Updates an existing user's information. Fails if the user does not exist.

    :params user_id: The name of the user.
    :params data: The updated user information.
    """

    table = dynamodb.Table(user_table_name)
    status_fields: list[str] = ["undergraduate_class"]

    # Ensure an entry to update actually exists
    response = get_user_information(user_id)
    if response['statusCode'] != 200:
        errorMsg: str = f"User {user_id} could not be found. Did you mean to add the user?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    else:
        user = response['body']

    # Make sure the data contains the same user_id as the path user_id
    if 'user_id' in data and data['user_id'] != user_id:
        errorMsg: str = f"Path parameter user_id and request body user_id don't match."
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    if 'university_status' in data and data['university_status'] == "Undergraduate":
        if not allKeysPresent(status_fields, data):
            errorMsg: str = f"Missing at least one field from {status_fields} in requestBody."
            body = { 'errorMsg': errorMsg }
            return buildResponse(statusCode = 400, body = body)

    # Successfully updated user
    return buildResponse(statusCode = 202, body = {})

def delete_user_information(user_id: str):
    """
    Deletes all of a user's information from the user information table.

    :params user_id: The name of the user.
    """
    return buildResponse(statusCode = 200, body = {})


#######################################
# Visit information function handlers #
#######################################
def get_all_visit_information(query_parameters: dict):
    """
    Returns all visit information entries from the visit information table.

    :params query_parameters: A dictionary of parameter names and values to filter by.
    """

    table = dynamodb.Table(visit_table_name)
    if query_parameters:
        try:
            timestamp_expression = buildTimestampKeyExpression(query_parameters, 'timestamp')

        except InvalidQueryParameters as iqp:
            body = { 'errorMsg': str(iqp) }
            return buildResponse(statusCode = 400, body = body)

        try:
            key_expression = Key('_ignore').eq("1") & timestamp_expression
            items = queryByKeyExpression(table, key_expression, GSI = TIMESTAMP_INDEX)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

        # Do a second lookup for all returned items to get the rest of the data
        visits = []
        for item in items:
            user_id = item['user_id']

            response = table.get_item(
                Key={ 'user_id': user_id }
            )

            visits.append(response['Item'])

    else:
        visits = scanTable(table)

    body = { 'visits': visits }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nVisits:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def create_user_visit_information(data: dict):
    """
    Adds a new visit entry for a user to the visit information table.

    :params data: The visit entry to add.
    """

    table = dynamodb.Table(visit_table_name)

    try:
        validateCreateVisitRequestBody(data)
    except InvalidRequestBody as irb:
        body = { 'errorMsg': str(irb) }
        return buildResponse(statusCode = 400, body = body)

    # Ensure no other entry with same user_id and timestamp already exists
    user_id: str = data['user_id']
    timestamp: str = data['timestamp']
    response = table.get_item(
        Key={
            'user_id': user_id,
            'timestamp': timestamp,
        }
    )
    if 'Item' in response:
        errorMsg: str = f"Visit entry for user {user_id} at timestamp {timestamp} already exists. Did you mean to input a different user or timestamp?"
        body = { 'errorMsg': errorMsg}
        return buildResponse(statusCode = 400, body = body)

    # Always force "_ignore" key to have value of "1"
    data['_ignore'] = "1"

    # Actually try putting the item into the table
    try:
        table.put_item(
            Item=data
        )
    except Exception as e:
        logger.info(e)
        body = { 'errorMsg': "Something went wrong on the server." }
        return buildResponse(statusCode = 500, body = body)

    # If here, put action succeeded. Return 201
    return buildResponse(statusCode = 201, body = {})

def get_user_visit_information(user_id: str, query_parameters: dict):
    """
    Gets all of the visit information entries for a specified user from the visit information table.

    :params user_id: The name of the user.
    :params query_parameters: A dictionary of parameter names and values to filter by.
    """
    table = dynamodb.Table(visit_table_name)
    if query_parameters:
        try:
            timestamp_expression = buildTimestampKeyExpression(query_parameters, 'timestamp')

        except InvalidQueryParameters as iqp:
            body = { 'errorMsg': str(iqp) }
            return buildResponse(statusCode = 400, body = body)

        try:
            key_expression = Key('user_id').eq(user_id) & timestamp_expression
            visits = queryByKeyExpression(table, key_expression)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

    else:
        key_expression = Key('user_id').eq(user_id)
        visits = queryByKeyExpression(table, key_expression)

    body = { 'visits': visits }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nVisits:\n{body}")

    return buildResponse(statusCode = 200, body = body)


#################################################
# Equipment usage information function handlers #
#################################################
def get_all_equipment_usage_information(query_parameters: dict):
    """
    Returns all the equipment usage objects from the equipment usage table.

    :params query_parameters: A dictionary of parameter names and values to filter by.
    """
    table = dynamodb.Table(equipment_table_name)
    if query_parameters:
        try:
            timestamp_expression = buildTimestampKeyExpression(query_parameters, 'timestamp')

        except InvalidQueryParameters as iqp:
            body = { 'errorMsg': str(iqp) }
            return buildResponse(statusCode = 400, body = body)

        try:
            key_expression = Key('_ignore').eq("1") & timestamp_expression
            items = queryByKeyExpression(table, key_expression, GSI = TIMESTAMP_INDEX)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

        # Do a second lookup for all returned items to get the rest of the data
        equipment_logs = []
        for item in items:
            user_id = item['user_id']

            response = table.get_item(
                Key={ 'user_id': user_id }
            )

            equipment_logs.append(response['Item'])

    else:
        equipment_logs = scanTable(table)

    body = { 'equipment_logs': equipment_logs }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nequipment_logs:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def create_user_equipment_usage(data: dict):
    """
    Adds an equipment usage entry for a specified user to the equipment usage table.

    :params user_id: The name of the user.
    :params data: The equipment usage entry to store.
    """

    table = dynamodb.Table(equipment_table_name)

    try:
        validateCreateEquipmentRequestBody(data)
    except InvalidRequestBody as irb:
        body = { 'errorMsg': str(irb) }
        return buildResponse(statusCode = 400, body = body)

    # Ensure no other entry with same user_id and timestamp already exists
    user_id: str = data['user_id']
    timestamp: str = data['timestamp']
    response = table.get_item(
        Key={
            'user_id': user_id,
            'timestamp': timestamp,
        }
    )
    if 'Item' in response:
        errorMsg: str = f"Equipment usage entry for user {user_id} at timestamp {timestamp} already exists. Did you mean to input a different user or timestamp?"
        body = { 'errorMsg': errorMsg}
        return buildResponse(statusCode = 400, body = body)

    # Always force "_ignore" key to have value of "1"
    data['_ignore'] = "1"

    # Actually try putting the item into the table
    try:
        table.put_item(
            Item=data
        )
    except Exception as e:
        logger.info(e)
        body = { 'errorMsg': "Something went wrong on the server." }
        return buildResponse(statusCode = 500, body = body)

    # If here, put action succeeded. Return 201
    return buildResponse(statusCode = 201, body = {})

def get_user_equipment_usage(user_id: str, query_parameters: dict):
    """
    Gets all of the equipment usage objects for a specified user from the equipment usage table.

    :params user_id: The name of the user.
    :params query_parameters: A dictionary of parameter names and values to filter by.
    """
    table = dynamodb.Table(equipment_table_name)
    if query_parameters:
        try:
            timestamp_expression = buildTimestampKeyExpression(query_parameters, 'timestamp')

        except InvalidQueryParameters as iqp:
            body = { 'errorMsg': str(iqp) }
            return buildResponse(statusCode = 400, body = body)

        try:
            key_expression = Key('user_id').eq(user_id) & timestamp_expression
            equipment_logs = queryByKeyExpression(table, key_expression)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

    else:
        key_expression = Key('user_id').eq(user_id)
        equipment_logs = queryByKeyExpression(table, key_expression)

    body = { 'equipment_logs': equipment_logs }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nequipment_logs:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def patch_user_equipment_usage(user_id: str, data: dict):
    """
    Updates an equipment usage entry for a specified user. Fails if no entry with a
    corresponding user_id and timetamp exists.

    :params user_id: The name of the user.
    :params data: The updated equipment usage entry.
    """
    return buildResponse(statusCode = 200, body = {})


################################################
# Qualifications information function handlers #
################################################
def get_all_qualifications_information(query_parameters: dict):
    """
    Returns all the qualifications information entries from the qualifications table.

    :params query_parameters: A dictionary of parameter names and values to filter by.
    """
    table = dynamodb.Table(qualifications_table_name)
    if query_parameters:
        try:
            timestamp_expression = buildTimestampKeyExpression(query_parameters, 'last_updated')

        except InvalidQueryParameters as iqp:
            body = { 'errorMsg': str(iqp) }
            return buildResponse(statusCode = 400, body = body)

        # Query for matching qualifcation entries
        try:
            key_expression = Key('_ignore').eq("1") & timestamp_expression
            items = queryByKeyExpression(table, key_expression, GSI = TIMESTAMP_INDEX)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

        # Do a second lookup for all returned items to get the rest of the data
        qualifications = []
        for item in items:
            user_id = item['user_id']

            response = table.get_item(
                Key={ 'user_id': user_id }
            )

            qualifications.append(response['Item'])

    else:
        qualifications = scanTable(table)

    body = { 'qualifications': qualifications }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nqualifications:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def create_user_qualifications(data: dict):
    """
    Adds a qualifications information entry for a specified user to the qualifications table.

    :params user_id: The name of the user.
    :params data: The qualifications information entry to add.
    """

    table = dynamodb.Table(qualifications_table_name)

    try:
        validateCreateQualificationRequestBody(data)
    except InvalidRequestBody as irb:
        body = { 'errorMsg': str(irb) }
        return buildResponse(statusCode = 400, body = body)

    # Check to make sure the user doesn't already exist. Return 400 if user does exist.
    user_id: str = data['user_id']
    response = get_user_qualifications(user_id)
    if response['statusCode'] == 200:
        errorMsg: str = f"User {user_id} qualifications already exist. Did you mean to update?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    # Store the formatted current time in data['last_updated']
    data['last_updated'] = datetime.now().strftime(TIMESTAMP_FORMAT)

    # If 'trainings' not in data, store an empty list
    if 'trainings' not in data:
        data['trainings'] = []

    # If 'waivers' not in data, store an empty list
    if 'waivers' not in data:
        data['waivers'] = []
    # Always force "_ignore" key to have value of "1"
    data['_ignore'] = "1"

    # Actually try putting the item into the table
    try:
        table.put_item(
            Item=data
        )
    except Exception as e:
        logger.info(e)
        body = { 'errorMsg': "Something went wrong on the server." }
        return buildResponse(statusCode = 500, body = body)

    # If here, put action succeeded. Return 201
    return buildResponse(statusCode = 201, body = {})

def get_user_qualifications(user_id: str):
    """
    Gets the qualifications information entry for a specified user from the qualifications table.

    :params user_id: The name of the user.
    """

    table = dynamodb.Table(qualifications_table_name)

    logger.info(f"\n????\n{user_id}")

    """
    Query the table (because get_item doesn't play nice without specifying sort key).
    Limit the results to 1 since we are enforcing 1 qualifications entry per user.
    If an item already exists, this will return an "array" of 1 item in the 'Items'
    key. For these purposes, ['Items'][0] is equivalent to retrieving the desired
    user's qualifications.
    """
    response = table.query(
            KeyConditionExpression=Key('user_id').eq(user_id),
            Limit=1
    )

    # User qualifications doesn't exist if length of response['Items'] == 0
    if len(response['Items']) == 0:
        errorMsg: str = f"No qualificationsfor the user {user_id} could be found. Is there a typo?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    qualifications = response['Items'][0]

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\n{user_id} Qualifications:\n{qualifications}")

    return buildResponse(statusCode = 200, body = qualifications)

def patch_user_qualifications(user_id: str, data: dict):
    """
    Updates the qualifications information entry for a specified user. Fails if the a
    qualifications entry does not exist for the user.

    :params user_id: The name of the user.
    :params data: The updated qualifications information entry.
    """
    return buildResponse(statusCode = 200, body = {})
