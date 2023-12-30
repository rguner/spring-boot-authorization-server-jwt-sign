
auth code almak için
http://localhost:8000/oauth2/authorize?response_type=code&client_id=client1&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid%20read

user/password girersen su adrese yönlendirir:
http://127.0.0.1:8080/authorized?code=RVgy8JF8RbFdnHMmuazNxioVFvpiLShRfO7PUiJCBVHuo8jVf_-VpMlmy_dF9yOJL5LHOAqBlec1PilgEiuICwiU9WJ2FyX_9galbN58-41_tmACdkJAgxz_bhQVLbR8

buradan gelen code değeri ile postman'de localhost:8000/oauth2/token isteğine code= olarak form parametresi iletilir.
     
