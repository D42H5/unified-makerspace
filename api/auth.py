"""
The MakerSpace staff are able to create, delete, and manage users
with varying permissions, such as administrators, managers, and
visitors.
"""

import models


def login(email: str, password: str):
    """
    Logs in an existing user.

    ================   ============
    **Endpoint**        /api/users
    **Request Type**    POST
    **Access**          ALL
    ================   ============

    Parameters
    -----------
    email : str, required
        The email of the user.
    password : str, required
        The password of the user.

    Returns
    --------
    Success
    code: int
        Return Code
    user: models.User
        The existing user.
    auth_token: str
        New authentication token.
    LoginFailure
    code: int
        Return Code
    message: str
        Response Message
    """


def create_user(email: str, password: str, first_name: str, last_name: str, hardware_id: str):
    """
    Creates a new user in the Cognito Pool.

    ================   ============
    **Endpoint**        /api/users
    **Request Type**    PUT
    **Access**          ALL
    ================   ============

    Parameters
    -----------
    last_name : str, required
        The last name of the user.
    first_name : str, required
        The first name of the user.
    hardware_id : str, required
        Unique hardware id of the user's TigerCard.
    email : str, required
        The email of the user.
    password : str, required
        The password of the user.

    Returns
    --------
    Success
    code: int
        Return Code
    user: models.User
        The newly created user.
    auth_token: str
        New authentication token.
    EmailInUse
    code: int
        Return Code
    message: str
        Response Message
    """


def delete_user(auth_token: str, user_id: str):
    """
    Deletes a user specified by their email.

    ================   ============
    **Endpoint**        /api/users
    **Request Type**    DELETE
    **Access**          MAINTAINER
    ================   ============

    Parameters
    -----------
    auth_token : str, required
        Token to verify user credentials.
    user_id : str, required
        The id of the user.

    Returns
    --------
    Success
    code: int
        Return Code
    message: str
        Response Message
    InsufficientPermissions
    code: int
        Return Code
    message: str
        Response Message
    """


def get_users(auth_token: str, user_ids: [str]):
    """
    Gets all the users with their permissions. If called
    by maintainer, only retrieve names, otherwise get
    all information.

    ================   ============
    **Endpoint**        /api/users
    **Request Type**    GET
    **Access**          MAINTAINER
    ================   ============

    Parameters
    -----------
    auth_token : str, required
        Token to verify user credentials.
    user_ids: [str], optional
        If specified, get only data for users
        specified by user_id.

    Returns
    --------
    Success
    code: int
        Return Code
    users: [models.User] | [str]
        List of returned users or names.Must be in same
        order of request.
    """


def update_user(auth_token: str, user_id: str, user: models.User):
    """
    Updates a user's attributes (permissions, card id, name, etc.)

    ================   ============
    **Endpoint**        /api/users
    **Request Type**    PATCH
    **Access**          MAINTAINER
    ================   ============

    Parameters
    -----------
    auth_token : str, required
        Token to verify user credentials.
    user_id: str, required
        The id of the user to update attributes for.
    user:
        The new user object with changed attributes.
    Returns
    --------
    Success
    code: int
        Return Code
    message: str
        Response Message
    InsufficientPermissions
    code: int
        Return Code
    message: str
        Response Message
    """


# todo add change_password
# todo confirmation code lambda