from django.http import JsonResponse
from .models import Invoice


def invoice_unscoped(request, pk):
    inv = Invoice.objects.get(pk=pk)  # EXPECT: unscoped-tenant-lookup
    return JsonResponse({"total": inv.total})


def invoice_query_param(request):
    inv = Invoice.objects.filter(id=request.GET["id"]).first()  # EXPECT: unscoped-tenant-lookup
    return JsonResponse({"total": inv.total})


def invoice_attacker_tenant(request):
    # Tenant keyword is present, but value is attacker-controlled!
    inv = Invoice.objects.get(
        pk=request.GET["id"],
        tenant_id=request.GET["tenant_id"],  # EXPECT: unscoped-tenant-lookup
    )
    return JsonResponse({"total": inv.total})


def invoice_scoped_kw(request, pk):
    inv = Invoice.objects.get(pk=pk, tenant_id=request.user.tenant_id)  # OK
    return JsonResponse({"total": inv.total})


def invoice_scoped_relation(request, pk):
    inv = request.user.tenant.invoices.get(pk=pk)  # OK
    return JsonResponse({"total": inv.total})


# Additional regression corpus; only positive filter predicates carry scope shape.
def invoice_chained_scope(request, pk):
    return Invoice.objects.filter(tenant_id=request.user.tenant_id).select_related("customer").get(pk=pk)  # OK: unscoped; REVIEW: provenance


def invoice_excluded_scope(request, pk):
    return Invoice.objects.exclude(tenant_id=request.user.tenant_id).get(pk=pk)  # EXPECT: unscoped-tenant-lookup


def invoice_kwargs(request):
    return Invoice.objects.get(**request.GET.dict())  # EXPECT: unscoped-tenant-lookup; REVIEW: kwargs


def invoice_raw(request):
    return Invoice.objects.raw("SELECT * FROM app_invoice WHERE id=%s", [request.GET["id"]])  # REVIEW: raw


def invoice_bulk(request):
    return Invoice.objects.filter(pk=request.GET["id"]).update(total=0)  # EXPECT: unscoped-tenant-lookup; REVIEW: bulk


def invoice_named_auth(request, pk):
    # Attribute names are not sanitizers. This is intentionally request-controlled.
    request.auth = request.GET["tenant_id"]
    return Invoice.objects.get(pk=pk, tenant_id=request.auth)  # EXPECT: unscoped-tenant-lookup


from django.shortcuts import get_object_or_404


def invoice_shortcut(request, pk):
    return get_object_or_404(Invoice, pk=pk)


def invoice_shortcut_attacker_scope(request, pk):
    return get_object_or_404(Invoice, pk=pk, tenant_id=request.GET["tenant"])


def invoice_shortcut_scoped(request, pk):
    return get_object_or_404(Invoice.objects.filter(tenant_id=request.user.tenant_id), pk=pk)
