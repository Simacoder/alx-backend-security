import datetime
from django.utils.timezone import now
from .models import RequestLog


class IPLoggingMiddleware:
    """
    Middleware that logs the IP address, timestamp, and path of every request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract client IP
        ip_address = self.get_client_ip(request)

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path,
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """
        Try to get the real client IP, even behind proxies.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # In case of multiple IPs, take the first one
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or "0.0.0.0"
