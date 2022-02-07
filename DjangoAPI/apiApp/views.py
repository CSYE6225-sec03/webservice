from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
import json

def testRequest(request):
    return HttpResponse(content_type='application/json; charset=utf-8 ')
