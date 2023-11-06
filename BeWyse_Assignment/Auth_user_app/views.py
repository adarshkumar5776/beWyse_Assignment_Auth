from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
import json
import pyrebase
from django.contrib import auth
import uuid
from Auth_user_app.mongoDbConnection import MongoDBConnection
import firebase_admin
from firebase_admin import auth, credentials


config2 = {
  "type": "service_account",
  "project_id": "bewyseauth",
  "private_key_id": "4d9dbbdfde4e5ab9837d71386423fc7693c2d038",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCl2q3+y5CD6cXj\nPImVNtdeGuqTVSKWFva8KkO4l2viHsRaBZ1xdvvDBxZhAGPU8mywe4mT1Y8deG0/\nMyC19IB9lg6s8K4mDchquHLgZcZZtflBHSsg8esay7Zx7v83I5+BJJURbm9n5u73\nzCE/6jhx+dZukls+JsewACfMFHYF01SJ9xXYz8NdA0SJSYSEjdAa8ReZZGAJlpwk\ne6FPtDpleg9DdbMsNDnIduX008HOZ5LPB8R6+kDst0sv3pTR0U4OXl9jmqmftSUb\nnzcfCnPHlXhCv19jZMdUT06coUoV/DZfX/SKpvyEZkBRT7WdTew48Y093b8dBhlZ\nR4W0YoQzAgMBAAECggEAAyharY7qm0/MnxjJSx7FPZbB3eMoynq9cfgybRKZNzhZ\n79vCcTZQTuVy2PVmisaNdVQLMBpqpC/t97wyyvc/qOAs5cCsHOvChd0YVPEbGrZo\nwLZ5/IfrXoEZUO5CEFFZTrxlbmwP1ZelkVb8g5q86Og0Qf6qAchiKa9j32E0WLM3\nVdC4P+D+XflbA0BXUMyNWwbrpbq5iyxtgAkS4Zu1nBOFXmCUPGOZN5hTiA0s1DBN\ne71JBrIQlDVkfTsCFjjrQsA/X8alzZAQjxp1GJUyfIFNk1X3R5nvr/xjJWPtQ2/r\nl5HGSixDLk4n9KQwJGiFlUHKScoVT8iHpikwEYbMQQKBgQDOLnenSlAFsUN8ZAYR\nGQDTK7v7mD986S4aQRb5ksVZWzmHGfrCwjPJUS4bxbiknzAxd0Ffhkj/LVMp0vfE\n1LvsuuQFe7+OA6Dw2HAtOroNfSC+hBzbdU0N4EumnMxHb0yyw4GB65seR5aWb7IF\nns92BD5UkJHR/23b66lY39rR6QKBgQDN7buvNqYuQyQWGIni6MKaGbeY46jkwvAO\nZ4sDGtXfK0kLTTDeixUCjL5Fz8LYn5UkjHE2yEnHtb1/NDBudQ2ijnMTfF5eGNLF\nM9jhU/MWObPR5+1tZSvXJpSokJKljSpg+JmQ8VuGf7lQkEic4vJfPp9KN2ycJBxS\ntNiWom1XuwKBgDKZzNvNrR34hyt8ENEZZc5tqVDx6ILrZ1kiKFVP5AcuEExL3/L0\nXmlF9x7xw4MDXnyFXBHpjvixUvusvwobe5N5uoRt/nEICvOQ6tbu1sKAtwyKt9pU\nS3jgVzCowqm1cwlcWehcvlEMGLUK7JHci+XW3MU8Rc1X9spGZ+Vb6wQhAoGBAMNn\nAT/qQFgHl7drw3NP4FBvdLqb1Ah2PWm9sLfaf/TK0v3pWiThnqcTu/zsfvwkuVW7\n+jW8ad4aQtzwPcCiS7TjLKjhy33IWj+LyhFOIo0FZe8Y/z9dz/LRBiDJRo3W3M61\nNqrFi06d5c9fibds1gWwm1/GJcYnscR9HEQbjlu/AoGAYCKEUyx7SXkkrEuc97zM\nkzMbfIenlaM932FMY6SZ+JaoLoHYQm8idIgAD2T15qJmlXjs0g383NsDDAqsQXTv\n6mOqGM203xhGbCWATECVNH9QAFtH+ehZ/2aIS6IRVzzRB2gkmqFumrxt4jIfglng\nWjOVh3rSBohOOsxh405h4v8=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-s9hyu@bewyseauth.iam.gserviceaccount.com",
  "client_id": "102095798061492598886",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-s9hyu%40bewyseauth.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
cred = credentials.Certificate(config2)
firebase_admin.initialize_app(cred)

config={
  'apiKey': "AIzaSyD2JqmIOSF1KUW_XqvapA6A_4rTWrutg8I",
  'authDomain': "bewyseauth.firebaseapp.com",
  'projectId': "bewyseauth",
  'storageBucket': "bewyseauth.appspot.com",
  'messagingSenderId': "486932981115",
  'appId': "1:486932981115:web:cf37de480d14f8556909de",
  'measurementId': "G-ST0RPZLRYK",
  'databaseURL': "https://bewyseauth-default-rtdb.firebaseio.com/"
}


firebase = pyrebase.initialize_app(config)
authe = firebase.auth()
database = firebase.database()

@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username', '')
        password = data.get('password', '')

        if not username or not password:
            return JsonResponse({"message": "username and password are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        mongodb_connection = MongoDBConnection()
        user_collection = mongodb_connection.get_collection("user_details")
        user_data = user_collection.find_one({"username": username})
        if user_data is None:
            return JsonResponse({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        try:
            email = user_data.get('email', '')
            user = authe.sign_in_with_email_and_password(email, password)
            uid = user['localId']
            session_id = user['idToken']
            request.session['uid'] = str(session_id)
            custom_token = auth.create_custom_token(uid)
            print(custom_token)
            user_data = {
                "username": username,
                "email": email,
                "custom_token": custom_token.decode("utf-8")
            }
            return JsonResponse(user_data,status=status.HTTP_200_OK)

        except:
            return JsonResponse({"message": "Username or password is invalid"}, status=status.HTTP_401_UNAUTHORIZED)

    return JsonResponse({"error": "Invalid HTTP method"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@csrf_exempt
def user_logout(request):
    from django.contrib import auth
    auth.logout(request)
    return JsonResponse({"message": "Logged out Successfully"}, status=status.HTTP_200_OK)

def generate_unique_username(email):
    if email:
        username = email.split('@')[0]
    else:
        username = str(uuid.uuid4())[:30]
    user_collection = MongoDBConnection().get_collection("user_details")
    while user_collection.find_one({"username": username}):
        username += str(uuid.uuid4())[:8] 
    return username

@csrf_exempt
def user_register(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username', '')  
        email = data.get('email', '')
        password = str(data.get('password', ''))
        first_name = data.get('first_name', '')  
        last_name = data.get('last_name', '')

        if not email or not password:
            return JsonResponse({"message": "Email and password are required"}, status=status.HTTP_404_NOT_FOUND)            
        if len(password) < 8:
            return JsonResponse({"message": "The password is too short. It must contain at least 8 characters"}, status=status.HTTP_400_BAD_REQUEST)
        if any(len(field) > 100 for field in (email, username, password, first_name, last_name)):
            return JsonResponse({"message": "Only 100 characters are allowed for a field"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not username or username.isspace():
            username = generate_unique_username(email)
            username = username                      
        try:
            user_collection = MongoDBConnection().get_collection("user_details")
            existing_user = user_collection.find_one({"username": username})
            existing_email = user_collection.find_one({"email": email}) 
            if existing_user or existing_email:
              MongoDBConnection().close_connection()
              return JsonResponse({"message": "A user with that username or email already exists"}, status=status.HTTP_400_BAD_REQUEST)
            user_collection.insert_one(data)
            authe.create_user_with_email_and_password(email,password)
            MongoDBConnection().close_connection()
            return JsonResponse({"username": username, "email": email}, status=status.HTTP_200_OK)
        except:
             return JsonResponse({"message": "error occured"}, status = status.HTTP_400_BAD_REQUEST)
    
    return JsonResponse({"error": "Invalid HTTP method"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@csrf_exempt
def user_view(request):
    if 'uid' in request.session:
        decoded_token = auth.verify_id_token(get_custom_token)
        request.uid = decoded_token.get('uid')
        get_custom_token = request.headers.get('Authorization')
        if not get_custom_token:
             return JsonResponse({"message": "Unauthorized Access"}, status=status.HTTP_401_UNAUTHORIZED)
        id_token = request.session['uid']
        a = authe.get_account_info(id_token)
        a = a['users']
        print(a)
        email = a[0]['email']
        print(email)
        mongodb_connection = MongoDBConnection()
        user_collection = mongodb_connection.get_collection("user_details")
        user_data = user_collection.find_one({"email": email})    
        formatted_data = {
            "username": user_data.get("username", ""),
            "email": user_data.get("email", ""),
            "full_name": f"{user_data.get('first_name', '')}-{user_data.get('last_name', '')}"
        }
        return JsonResponse(formatted_data, status=status.HTTP_200_OK)
    return JsonResponse({"message": "Unauthorized Access"}, status=status.HTTP_401_UNAUTHORIZED)


@csrf_exempt
def user_edit(request):
    if 'uid' in request.session:
        id_token = request.session['uid']
        a = authe.get_account_info(id_token)
        print(a)
        a = a['users']
        email = a[0]['email']
        localId = a[0]['localId']
        if request.method == 'POST':
            data = json.loads(request.body.decode('utf-8'))
            first_name = data.get('first_name', '')
            last_name = data.get('last_name', '')
            new_username = data.get('username', '')
            new_email = data.get('email','')
            get_custom_token = request.headers.get('Authorization')
            mongodb_connection = MongoDBConnection()
            user_collection = mongodb_connection.get_collection("user_details")
            existing_user = user_collection.find_one({"email": email})
            if existing_user:
                object_id = existing_user['_id']
            existing_user = user_collection.find_one({"username": new_username,"_id": {"$ne": object_id}})
            if existing_user:
                return JsonResponse({"message": "A user with that username already exists"}, status=status.HTTP_400_BAD_REQUEST)
            existing_user_with_email = user_collection.find_one({"email": new_email, "_id": {"$ne": object_id}})
            if existing_user_with_email:
                return JsonResponse({"message": "A user with that email already exists"}, status=status.HTTP_400_BAD_REQUEST)

            user_collection.update_one(
                    {"_id": object_id},
                    {"$set": {
                        "username": new_username,
                        "email": new_email,
                        "first_name": first_name,
                        "last_name": last_name
                    }}
                )
            decoded_token = auth.verify_id_token(get_custom_token)
            request.uid = decoded_token.get('uid')
            if not get_custom_token:
                return JsonResponse({"message": "Unauthorized Access"}, status=status.HTTP_401_UNAUTHORIZED)

            auth.update_user(
                    localId,
                    email=new_email
                )
        
            formatted_data = {
                    "username": new_username,
                    "email": new_email,
                    "full_name": f"{first_name}-{last_name}"
                }
            return JsonResponse(formatted_data, status=status.HTTP_200_OK)            

        return JsonResponse({"message": "Invalid HTTP method"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    else:
        return JsonResponse({"message": "Unauthorized Access"}, status=status.HTTP_401_UNAUTHORIZED)