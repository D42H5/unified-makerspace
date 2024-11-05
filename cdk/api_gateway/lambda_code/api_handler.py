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

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize the DynamoDB client using boto3
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

# Table names
user_table_name = 'beta-test-user-information'
#visit_table_name = 'beta-test-visit-information'
visit_table_name = 'test2'
equipment_table_name = 'beta-test-equipment-information'
qualifications_table_name = 'beta-test-training-information'

# Define path constants
user_endpoint: str = "/{username}"
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

# Main handler function
def handler(event, context):
    logger.info(f"\nRequest event method: {event.get("httpMethod")}")
    logger.info(f"\nEVENT\n{json.dumps(event, indent=2)}")

    method_requires_body: list = ["PUT", "PATCH"]

    response = buildResponse(statusCode = 400, body = {})
    http_method: str = event.get("httpMethod")
    resource_path: str = event.get("resource")

    # Get a username if needed
    username: str = ""
    if user_endpoint in resource_path:
        username = event['pathParameters'].get('username')

    # Get the body data if needed
    data: dict = {}
    if http_method in method_requires_body:
        data = event['body']

    # Try to get any query parameters
    try:
        query_parameters: dict = event['queryStringParameters']
    except:
        query_parameters: dict = {}

    # Get a timestamp to use for this request
    timestamp: str = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nLOCAL VARS:\n"
                +f"http_method: {http_method}\n"
                +f"resource_path: {resource_path}\n"
                +f"username: {username}\n"
                +f"data: {data}\n"
                +f"query_parameters: {query_parameters}\n"
                +f"timestamp: {timestamp}\n"
    )

    # User information request handling
    if http_method == "GET" and resource_path == users_path:
        response = get_all_user_information()
    elif http_method == "GET" and resource_path == users_param_path:
        response = get_user_information(username)
    elif http_method == "PUT" and resource_path == users_param_path:
        response = add_user_information(username, data)
    elif http_method == "PATCH" and resource_path == users_param_path:
        response = update_user_information(username, data)
    elif http_method == "DELETE" and resource_path == users_param_path:
        response = delete_user_information(username)

    # Visit information request handling
    elif http_method == "GET" and resource_path == visits_path:
        response = get_all_visit_information(query_parameters)
    elif http_method == "GET" and resource_path == visits_param_path:
        response = get_user_visit_information(username, query_parameters)
    elif http_method == "PUT" and resource_path == visits_param_path:
        response = add_user_visit_information(data)

    # Equipment information request handling
    elif http_method == "GET" and resource_path == equipment_path:
        response = get_all_equipment_usage_information(query_parameters)
    elif http_method == "GET" and resource_path == equipment_param_path:
        response = get_user_equipment_usage(username, query_parameters)
    elif http_method == "PUT" and resource_path == equipment_param_path:
        response = add_user_equipment_usage(username, timestamp, data)
    elif http_method == "PATCH" and resource_path == equipment_param_path:
        response = update_user_equipment_usage(username, timestamp, data)

    # Qualifications information request handling
    elif http_method == "GET" and resource_path == qualifications_path:
        response = get_all_qualifications_information(query_parameters)
    elif http_method == "GET" and resource_path == qualifications_param_path:
        response = get_user_qualifications(username)
    elif http_method == "PUT" and resource_path == qualifications_param_path:
        response = add_user_qualifications(username, data)
    elif http_method == "PATCH" and resource_path == qualifications_param_path:
        response = update_user_qualifications(username, data)

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nFINAL RESPONSE:\n{response}")
    return response


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

def get_user_information(username: str):
    """
    Gets all of the information for the specified user.

    :params username: The name of the user.
    """

    table = dynamodb.Table(user_table_name)
    response = table.get_item(
            Key={ 'username': username }
    )

    # Username doesn't exist if 'Item' not in response
    if 'Item' not in response:
        errorMsg: str = f"No information for the user {username} could be found. Is there a typo?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    user = response['Item']

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nUser:\n{user}")

    return buildResponse(statusCode = 200, body = user)

def add_user_information(username: str, data: dict):
    """
    Adds a new user to the user information table.

    :params username: The name of the user.
    :params data: The user information to store.
    """
    return buildResponse(statusCode = 200, body = {})

def update_user_information(username: str, data: dict):
    """
    Updates an existing user's information. Fails if the user does not exist.

    :params username: The name of the user.
    :params data: The updated user information.
    """
    return buildResponse(statusCode = 200, body = {})

def delete_user_information(username: str):
    """
    Deletes all of a user's information from the user information table.

    :params username: The name of the user.
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
            items = queryByKeyExpression(table, key_expression, GSI = '_ignore-timestamp-index')

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

        # Do a second lookup for all returned items to get the rest of the data
        visits = []
        for item in items:
            username = item['username']

            response = table.get_item(
                Key={ 'username': username }
            )

            visits.append(response['Item'])

    else:
        visits = scanTable(table)

    body = { 'visits': visits }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nVisits:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def get_user_visit_information(username: str, query_parameters: dict):
    """
    Gets all of the visit information entries for a specified user from the visit information table.

    :params username: The name of the user.
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
            key_expression = Key('username').eq(username) & timestamp_expression
            visits = queryByKeyExpression(table, key_expression)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

    else:
        key_expression = Key('username').eq(username)
        visits = queryByKeyExpression(table, key_expression)

    body = { 'visits': visits }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nVisits:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def add_user_visit_information(data: dict):
    """
    Adds a new visit entry for a user to the visit information table.

    :params data: The visit entry to add.
    """
    return buildResponse(statusCode = 200, body = {})


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
            items = queryByKeyExpression(table, key_expression, GSI = 'TimestampIndex')

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

        # Do a second lookup for all returned items to get the rest of the data
        equipment_logs = []
        for item in items:
            username = item['username']

            response = table.get_item(
                Key={ 'username': username }
            )

            equipment_logs.append(response['Item'])

    else:
        equipment_logs = scanTable(table)

    body = { 'equipment_logs': equipment_logs }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nequipment_logs:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def get_user_equipment_usage(username: str, query_parameters: dict):
    """
    Gets all of the equipment usage objects for a specified user from the equipment usage table.

    :params username: The name of the user.
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
            key_expression = Key('username').eq(username) & timestamp_expression
            equipment_logs = queryByKeyExpression(table, key_expression)

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

    else:
        key_expression = Key('username').eq(username)
        equipment_logs = queryByKeyExpression(table, key_expression)

    body = { 'equipment_logs': equipment_logs }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nequipment_logs:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def add_user_equipment_usage(username: str, timestamp, data: dict):
    """
    Adds an equipment usage entry for a specified user to the equipment usage table.

    :params username: The name of the user.
    :params timestamp: The timestamp of the entry.
    :params data: The equipment usage entry to store.
    """
    return buildResponse(statusCode = 200, body = {})

def update_user_equipment_usage(username: str, timestamp, data: dict):
    """
    Updates an equipment usage entry for a specified user. Fails if no entry with a
    corresponding username and timetamp exists.

    :params username: The name of the user.
    :params timestamp: The timestamp in the entry to retrieve.
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
            items = queryByKeyExpression(table, key_expression, GSI = 'TimestampIndex')

        except Exception as e:
            logger.info(e)
            body = { 'errorMsg': "Something went wrong on the server." }
            return buildResponse(statusCode = 500, body = body)

        # Do a second lookup for all returned items to get the rest of the data
        qualifications = []
        for item in items:
            username = item['username']

            response = table.get_item(
                Key={ 'username': username }
            )

            qualifications.append(response['Item'])

    else:
        qualifications = scanTable(table)

    body = { 'qualifications': qualifications }
    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\nqualifications:\n{body}")

    return buildResponse(statusCode = 200, body = body)

def get_user_qualifications(username: str):
    """
    Gets the qualifications information entry for a specified user from the qualifications table.

    :params username: The name of the user.
    """
    table = dynamodb.Table(qualifications_table_name)

    response = table.get_item(
            Key={ 'username': username }
    )

    # User qualifications doesn't exist if 'Item' not in response
    if 'Item' not in response:
        errorMsg: str = f"No qualificationsfor the user {username} could be found. Is there a typo?"
        body = { 'errorMsg': errorMsg }
        return buildResponse(statusCode = 400, body = body)

    qualifications = response['Item']

    # FIXME: For debugging purposes right now. Worth keeping?
    logger.info(f"\n{username} Qualifications:\n{qualifications}")

    return buildResponse(statusCode = 200, body = qualifications)

def add_user_qualifications(username: str, data: dict):
    """
    Adds a qualifications information entry for a specified user to the qualifications table.

    :params username: The name of the user.
    :params data: The qualifications information entry to add.
    """
    return buildResponse(statusCode = 200, body = {})

def update_user_qualifications(username: str, data: dict):
    """
    Updates the qualifications information entry for a specified user. Fails if the a
    qualifications entry does not exist for the user.

    :params username: The name of the user.
    :params data: The updated qualifications information entry.
    """
    return buildResponse(statusCode = 200, body = {})
