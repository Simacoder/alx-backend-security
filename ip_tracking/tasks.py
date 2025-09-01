from datetime import timedelta
from django.utils.timezone import now
from celery import shared_task
from django.db.models import Count
from .models import RequestLog, SuspiciousIP


@shared_task
def detect_anomalies():
    """
    Hourly task that flags suspicious IPs:
      - >100 requests in past hour
      - Accessing sensitive paths (/admin, /login)
    """
    one_hour_ago = now() - timedelta(hours=1)

    # Check for high request volume
    high_volume_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(req_count=Count("id"))
        .filter(req_count__gt=100)
    )
    for record in high_volume_ips:
        ip = record["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            reason=f"High traffic: {record['req_count']} requests in the past hour.",
        )

    # Check for access to sensitive paths
    sensitive_paths = ["/admin", "/login"]
    sensitive_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago, path__in=sensitive_paths
    ).values("ip_address", "path")

    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log["ip_address"],
            reason=f"Accessed sensitive path: {log['path']}",
        )

