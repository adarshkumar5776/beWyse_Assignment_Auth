from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
    path('register/', views.user_register, name="User_Register"),
    path('login/', views.user_login, name="User_Login"),
    path('logout/', views.user_logout, name="User_Logout"),
    path('profile/view/', views.user_view, name="User_view"),
    path('profile/edit/', views.user_edit, name="User_edit")
]