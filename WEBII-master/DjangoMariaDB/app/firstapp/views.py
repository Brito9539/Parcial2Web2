# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import render, HttpResponse

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def login(request):

    #VALIDATE METHOD
    if request.method == 'POST':

        #DECLARE RESPONSE
        response_data = {}
        if checkJson().isJson(request.body) == True:

            #CHECK JSON CONTENT
            jsonData = json.loads(request.body)
            if 'user' not in jsonData:
                response_data['result'] = 'error'
                response_data['message'] = 'user is required'
                return JsonResponse(response_data, status=401)
            elif 'password' not in jsonData:
                response_data['result'] = 'error'
                response_data['message'] = 'password is required'
                return JsonResponse(response_data, status=401)

            #CHECK IF USER EXITST
            try:
                objU = ApiUsers.objects.get(user = jsonData['user'])
            except:
                response_data['result'] = 'error'
                response_data['message'] = 'The user does not exist or the password is incorrect'
                return JsonResponse(response_data, status=401)

            #TAKE PASSWORD OF THE USER
            noHashPassword = jsonData['password']
            hashedPassword = objU.password

            #CHECK IF PASSWORD IS CORRECT

            if check_password(noHashPassword, hashedPassword) == False:
                response_data['result'] = 'error'
                response_data['message'] = 'The user does not exist or the password is incorrect'
                return JsonResponse(response_data, status=401)

            #CHECK IF USER HAS API-KEY
            if objU.api_key == None:
                apiKeyU = ApiKey().generate_key_complex()
                objU.api_key = apiKeyU
                objU.save()
                #obj.api_key = newApiKey
                #obj.save()

            #RETURN RESPONSE
            response_data['result'] = 'success'
            response_data['message'] = 'Valid Credentials'
            response_data['userApiKey'] = objU.api_key
            return JsonResponse(response_data, status=200)


        else:
            response_data['result'] = 'error'
            response_data['message'] = 'Invalid Json'
            return JsonResponse(response_data, status=400)

    else:
        responseData = {}
        responseData['result'] = 'error'
        responseData['message'] = 'Invalid Request'
        return JsonResponse(responseData, status=400)


def makepassword(request,password):
    hashPassword = make_password(password)
    response_data = {}
    response_data['password'] = hashPassword
    return JsonResponse(response_data, status=200)

def vista(request):
    return render(request, 'index.html')
