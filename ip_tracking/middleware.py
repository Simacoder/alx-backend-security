from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.core.cache import cache
from ipgeolocation import IpGeoLocation
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    """
    Middleware that logs IPs, geolocation, and blocks blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeoLocation()  # django-ipgeolocation helper

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Forbidden: Your IP has been blocked.")

        # Get geolocation (cached for 24h)
        location = cache.get(f"geo:{ip_address}")
        if not location:
            try:
                geo_data = self.geo.lookup(ip_address)
                location = {
                    "country": geo_data.get("country_name"),
                    "city": geo_data.get("city"),
                }
            except Exception:
                location = {"country": None, "city": None}
            cache.set(f"geo:{ip_address}", location, timeout=60 * 60 * 24)  # 24h

        # Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path,
            country=location.get("country"),
            city=location.get("city"),
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        """
        Try to get the real client IP, even behind proxies.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip or "0.0.0.0"
