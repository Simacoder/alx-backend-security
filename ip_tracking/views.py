from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit


@csrf_exempt
@ratelimit(key="ip", rate="5/m", method="POST", block=True)
@ratelimit(key="ip", rate="10/m", method="POST", block=True)
def login_view(request):
    """
    A login view protected by per-IP rate limits:
      - Anonymous users: 5 requests/minute
      - Authenticated users: 10 requests/minute
    """
    if request.user.is_authenticated:
        return HttpResponse("Authenticated login attempt successful.")
    return HttpResponse("Anonymous login attempt received.")
