from unicon.utils import to_plaintext

def extract_creds_from_device(device, connection): # noqa C901
    """
    extract the credentials. if the device has credentials, use those as they
    take precedence and have a built-in fallback to default creds.
    if not, get the connection username and password, if that does not work
    fall back to the device tacacs username and passwords.
    """

    try:
        if device.connections[connection].get('credentials'):
            # New-style credentials present (credentials and login_creds).
            login_creds = device.connections[connection].get('login_creds')

            # login_creds can be str or list, if list check only the first credential.
            if isinstance(login_creds, list):
                login_creds = login_creds[0]

            try:
                # Unicon has built-in fallback to default credentials. If the connection credentials
                # are not present, it will fall back to the device default credentials, and if
                # those are not present, it will fall back to the testbed default credentials.
                # Only if no default credentials of any kind are present will it raise AttributeError.
                username = device.connections[connection].credentials.get(login_creds).get('username')
                password = device.connections[connection].credentials.get(login_creds).get('password')
            except AttributeError:
                username = 'root'
                password = 'lab'

        else:
            raise ValueError('Device does not have connection credentials configured.')
    
    except KeyError:
        # This exception is only raised if connection is not present in connections.
        raise KeyError(f'no connection {connection} found on device {device}')

    if username is None or password is None:
        raise ValueError(f'cannot derive username and password from {device}\'s testbed entry')

    return (username, to_plaintext(password))
