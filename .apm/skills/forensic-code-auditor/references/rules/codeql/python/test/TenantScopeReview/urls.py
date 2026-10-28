from django.urls import path
import views

urlpatterns = [
    path("shortcut/<int:pk>/", views.invoice_shortcut),
    path("shortcut-attacker/<int:pk>/", views.invoice_shortcut_attacker_scope),
    path("shortcut-scoped/<int:pk>/", views.invoice_shortcut_scoped),
    path("inv-chain/<int:pk>/", views.invoice_chained_scope),
    path("inv-exclude/<int:pk>/", views.invoice_excluded_scope),
    path("inv-kwargs/", views.invoice_kwargs),
    path("inv-raw/", views.invoice_raw),
    path("inv-bulk/", views.invoice_bulk),
    path("inv-auth/<int:pk>/", views.invoice_named_auth),
    path("inv/<int:pk>/", views.invoice_unscoped),
    path("inv/", views.invoice_query_param),
    path("inv-attacker/", views.invoice_attacker_tenant),
    path("inv2/<int:pk>/", views.invoice_scoped_kw),
    path("inv3/<int:pk>/", views.invoice_scoped_relation),
]
