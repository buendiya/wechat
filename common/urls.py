from django.conf.urls import patterns, url

from common import views

urlpatterns = patterns('',
    url(r'^$', views.authentication, name='authentication'),
)