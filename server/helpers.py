"""This contains all the helper functions in the application"""

def validate_required(request_data, *args):
    missing = ''
    status = 'success'
    message = 'All parameters provided'
    if request_data:
        for arg in args:
            if arg not in request_data.keys():
                addition = str(arg)
                if missing:
                    addition = ', ' + str(arg)
                missing = missing + addition
            else:
                if not request_data[arg]:
                    addition = str(arg)
                    if missing:
                        addition = ', ' + str(arg)
                    missing = missing + addition
                if arg.lower() == 'email' and request_data[arg]:
                    if not validate_email(request_data[arg]):
                        response = {
                            'status': 'fail',
                            'message': 'Email address is invalid'
                        }
                        return response
                if 'password' in arg.lower() and request_data[arg]:
                    if len(request_data[arg]) < 6:
                        response = {
                            'status': 'fail',
                            'message': 'Password should be at least 6 characters'
                        }
                        return response

    else:
        missing = ', '.join(args)

    if missing:
        status = 'fail'
        value_string = 'value'
        if ', ' in missing:
            value_string = 'values'
        message = 'Please provide the required parameter ' + value_string + ' for'
    response = {
        'status': status,
        'message': message + ' ' + missing
    }
    return response

def validate_token(request):
    auth_token = ''
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    return auth_token

def validate_email(email):
    first_part = email.split('@', 1)[0]
    second_part = email.split('@', 1)[1]
    if '@' in second_part or second_part.count('.') > 1 or '.' not in second_part or len(first_part) == 0:
        return False
    return True
