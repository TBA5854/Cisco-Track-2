import re

def is_password_strong(password):

    if len(password) < 8:
        return False

    if not re.search(r'[A-Z]', password):
        return False
    
    if not re.search(r'[a-z]', password):
        return False
    
    if not re.search(r'[0-9]', password):
        return False
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


passwords = ['password123', 'Password123', 'Password123!', 'password', 'PASSWORD', '12345678', '!@#$%^&*()']
for password in passwords:
    print(f'Password: {password}, Strong: {is_password_strong(password)}')