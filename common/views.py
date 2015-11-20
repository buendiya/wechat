import sha
import logging

from django.conf import settings
from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
logger = logging.getLogger('common.logger')


def authentication(request):
    signature = request.GET.get('signature')
    timestamp = request.GET.get('timestamp')
    nonce = request.GET.get('nonce')
    echostr = request.GET.get('echostr')

    token = settings.TOKEN
    temp_array = sorted([token, timestamp, nonce])
    temp_str = ''.join(temp_array)
    hex_str = sha.new(temp_str).hexdigest()
    if hex_str == str(signature):
        return HttpResponse(echostr)
    else:
        logger.warning('signature: %s, timestamp: %s, nonce: %s, echostr: %s, sha_str: %s', signature, timestamp, nonce, echostr, hex_str)
        return HttpResponse('Failed')