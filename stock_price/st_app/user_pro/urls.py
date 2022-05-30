from django.urls import path
from user_pro import views

urlpatterns = [
    path('register',views.user_register,name='register'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('login',views.user_login,name='login'),
    path('logout',views.user_logout,name='logout'),
    path("profile/<int:user_id>", views.user_profile, name='profile'),
    
]