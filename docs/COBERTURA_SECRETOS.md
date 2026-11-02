# Cobertura de secretos

Medición local con gitleaks **8.30.1**, tras garita#2. Regenerar con:

```bash
PYTHONUTF8=1 python3 scripts/cobertura_secretos.py > tabla.md
```

Las muestras se construyen al vuelo; los cuerpos repetitivos son deliberadamente
falsos y nunca se imprimen. Cada forma nueva se compara en un log y asignada
a una variable neutra (`valor`), con un control negativo de longitud o alfabeto.
También se incluyen referencias de cobertura previa (asignadas a `API_KEY`)
y negativos comunes.
Garita muestra los detectores que realmente respondieron; `—` significa que
no hubo hallazgo. No se consulta al proveedor ni se comprueba validez.

Esta tabla mide estas muestras, no exhaustividad ni equivalencia entre motores.
Gitleaks aplica entropía, allowlists y reglas contextuales: puede rechazar cuerpos
repetitivos (incluido ACCA) o formatos que sólo reconoce con una asignación
específica. Azure Storage/Service Bus no tienen aquí una regla dedicada en el
TOML de referencia. Las formas de SendGrid y PyPI siguen las solicitadas en el
issue; el TOML admite una forma más amplia de SendGrid y limita PyPI a 1000
caracteres. Se incluye además el sufijo opcional de Databricks y el runner
rutable de GitLab descritos en ese TOML. Garita no detecta por formato valores
sin firma, como un secreto AWS de 40 caracteres o el auth token hexadecimal
de Twilio; una asignación sospechosa puede producir un aviso en contexto real.

| Proveedor | Tipo | Contexto | gitleaks | Garita |
| --- | --- | --- | --- | --- |
| AWS | ASIA (positivo) | suelta | aws-access-token | llave_proveedor |
| AWS | ASIA (positivo) | asignada | aws-access-token | llave_proveedor |
| AWS | ASIA (negativo) | suelta | — | — |
| AWS | ASIA (negativo) | asignada | — | — |
| AWS | ABIA (positivo) | suelta | aws-access-token | llave_proveedor |
| AWS | ABIA (positivo) | asignada | aws-access-token | llave_proveedor |
| AWS | ABIA (negativo) | suelta | — | — |
| AWS | ABIA (negativo) | asignada | — | — |
| AWS | ACCA (positivo) | suelta | — | llave_proveedor |
| AWS | ACCA (positivo) | asignada | — | llave_proveedor |
| AWS | ACCA (negativo) | suelta | — | — |
| AWS | ACCA (negativo) | asignada | — | — |
| AWS | A3TA (positivo) | suelta | aws-access-token | llave_proveedor |
| AWS | A3TA (positivo) | asignada | aws-access-token | llave_proveedor |
| AWS | A3TA (negativo) | suelta | — | — |
| AWS | A3TA (negativo) | asignada | — | — |
| AWS | A3T9 (positivo) | suelta | aws-access-token | llave_proveedor |
| AWS | A3T9 (positivo) | asignada | aws-access-token | llave_proveedor |
| AWS | A3T9 (negativo) | suelta | — | — |
| AWS | A3T9 (negativo) | asignada | — | — |
| Azure | AD client secret (positivo) | suelta | — | llave_proveedor |
| Azure | AD client secret (positivo) | asignada | — | llave_proveedor |
| Azure | AD client secret (negativo) | suelta | — | — |
| Azure | AD client secret (negativo) | asignada | — | — |
| Azure | Storage AccountKey (positivo) | suelta | — | llave_azure |
| Azure | Storage AccountKey (positivo) | asignada | — | llave_azure |
| Azure | Storage AccountKey (negativo) | suelta | — | — |
| Azure | Storage AccountKey (negativo) | asignada | — | — |
| Azure | Service Bus SharedAccessKey (positivo) | suelta | — | llave_azure |
| Azure | Service Bus SharedAccessKey (positivo) | asignada | — | llave_azure |
| Azure | Service Bus SharedAccessKey (negativo) | suelta | — | — |
| Azure | Service Bus SharedAccessKey (negativo) | asignada | — | — |
| Slack | app token (positivo) | suelta | slack-app-token | llave_proveedor |
| Slack | app token (positivo) | asignada | slack-app-token | llave_proveedor |
| Slack | app token (negativo) | suelta | — | — |
| Slack | app token (negativo) | asignada | — | — |
| Slack | services (positivo) | suelta | slack-webhook-url | webhook_slack |
| Slack | services (positivo) | asignada | slack-webhook-url | webhook_slack |
| Slack | services (negativo) | suelta | — | — |
| Slack | services (negativo) | asignada | — | — |
| Slack | workflows (positivo) | suelta | slack-webhook-url | webhook_slack |
| Slack | workflows (positivo) | asignada | slack-webhook-url | webhook_slack |
| Slack | workflows (negativo) | suelta | — | — |
| Slack | workflows (negativo) | asignada | — | — |
| Slack | triggers (positivo) | suelta | slack-webhook-url | webhook_slack |
| Slack | triggers (positivo) | asignada | slack-webhook-url | webhook_slack |
| Slack | triggers (negativo) | suelta | — | — |
| Slack | triggers (negativo) | asignada | — | — |
| Twilio | API key (positivo) | suelta | twilio-api-key | llave_proveedor |
| Twilio | API key (positivo) | asignada | twilio-api-key | llave_proveedor |
| Twilio | API key (negativo) | suelta | — | — |
| Twilio | API key (negativo) | asignada | — | — |
| SendGrid | API key (positivo) | suelta | sendgrid-api-token | llave_proveedor |
| SendGrid | API key (positivo) | asignada | sendgrid-api-token | llave_proveedor |
| SendGrid | API key (negativo) | suelta | — | — |
| SendGrid | API key (negativo) | asignada | — | — |
| Supabase | access token (positivo) | suelta | — | llave_proveedor |
| Supabase | access token (positivo) | asignada | — | llave_proveedor |
| Supabase | access token (negativo) | suelta | — | — |
| Supabase | access token (negativo) | asignada | — | — |
| DigitalOcean | doo (positivo) | suelta | digitalocean-access-token | llave_proveedor |
| DigitalOcean | doo (positivo) | asignada | digitalocean-access-token | llave_proveedor |
| DigitalOcean | doo (negativo) | suelta | — | — |
| DigitalOcean | doo (negativo) | asignada | — | — |
| DigitalOcean | dop (positivo) | suelta | digitalocean-pat | llave_proveedor |
| DigitalOcean | dop (positivo) | asignada | digitalocean-pat | llave_proveedor |
| DigitalOcean | dop (negativo) | suelta | — | — |
| DigitalOcean | dop (negativo) | asignada | — | — |
| DigitalOcean | dor (positivo) | suelta | digitalocean-refresh-token | llave_proveedor |
| DigitalOcean | dor (positivo) | asignada | digitalocean-refresh-token | llave_proveedor |
| DigitalOcean | dor (negativo) | suelta | — | — |
| DigitalOcean | dor (negativo) | asignada | — | — |
| Shopify | shpat_ (positivo) | suelta | shopify-access-token | llave_proveedor |
| Shopify | shpat_ (positivo) | asignada | shopify-access-token | llave_proveedor |
| Shopify | shpat_ (negativo) | suelta | — | — |
| Shopify | shpat_ (negativo) | asignada | — | — |
| Shopify | shpca_ (positivo) | suelta | shopify-custom-access-token | llave_proveedor |
| Shopify | shpca_ (positivo) | asignada | shopify-custom-access-token | llave_proveedor |
| Shopify | shpca_ (negativo) | suelta | — | — |
| Shopify | shpca_ (negativo) | asignada | — | — |
| Shopify | shppa_ (positivo) | suelta | shopify-private-app-access-token | llave_proveedor |
| Shopify | shppa_ (positivo) | asignada | shopify-private-app-access-token | llave_proveedor |
| Shopify | shppa_ (negativo) | suelta | — | — |
| Shopify | shppa_ (negativo) | asignada | — | — |
| Shopify | shpss_ (positivo) | suelta | shopify-shared-secret | llave_proveedor |
| Shopify | shpss_ (positivo) | asignada | shopify-shared-secret | llave_proveedor |
| Shopify | shpss_ (negativo) | suelta | — | — |
| Shopify | shpss_ (negativo) | asignada | — | — |
| PyPI | upload token (positivo) | suelta | pypi-upload-token | llave_proveedor |
| PyPI | upload token (positivo) | asignada | pypi-upload-token | llave_proveedor |
| PyPI | upload token (negativo) | suelta | — | — |
| PyPI | upload token (negativo) | asignada | — | — |
| Hugging Face | access token (positivo) | suelta | huggingface-access-token | llave_proveedor |
| Hugging Face | access token (positivo) | asignada | huggingface-access-token | llave_proveedor |
| Hugging Face | access token (negativo) | suelta | — | — |
| Hugging Face | access token (negativo) | asignada | — | — |
| Vault | service token (positivo) | suelta | — | llave_proveedor |
| Vault | service token (positivo) | asignada | — | llave_proveedor |
| Vault | service token (negativo) | suelta | — | — |
| Vault | service token (negativo) | asignada | — | — |
| age | private key (positivo) | suelta | age-secret-key | llave_proveedor |
| age | private key (positivo) | asignada | age-secret-key | llave_proveedor |
| age | private key (negativo) | suelta | — | — |
| age | private key (negativo) | asignada | — | — |
| Databricks | API token (positivo) | suelta | databricks-api-token | llave_proveedor |
| Databricks | API token (positivo) | asignada | databricks-api-token | llave_proveedor |
| Databricks | API token (negativo) | suelta | — | — |
| Databricks | API token (negativo) | asignada | — | — |
| Databricks | API token suffix (positivo) | suelta | databricks-api-token | llave_proveedor |
| Databricks | API token suffix (positivo) | asignada | databricks-api-token | llave_proveedor |
| Databricks | API token suffix (negativo) | suelta | — | — |
| Databricks | API token suffix (negativo) | asignada | — | — |
| Doppler | personal token (positivo) | suelta | doppler-api-token | llave_proveedor |
| Doppler | personal token (positivo) | asignada | doppler-api-token | llave_proveedor |
| Doppler | personal token (negativo) | suelta | — | — |
| Doppler | personal token (negativo) | asignada | — | — |
| Linear | API key (positivo) | suelta | linear-api-key | llave_proveedor |
| Linear | API key (positivo) | asignada | linear-api-key | llave_proveedor |
| Linear | API key (negativo) | suelta | — | — |
| Linear | API key (negativo) | asignada | — | — |
| Notion | API token (positivo) | suelta | — | llave_proveedor |
| Notion | API token (positivo) | asignada | — | llave_proveedor |
| Notion | API token (negativo) | suelta | — | — |
| Notion | API token (negativo) | asignada | — | — |
| Postman | API token (positivo) | suelta | postman-api-token | llave_proveedor |
| Postman | API token (positivo) | asignada | postman-api-token | llave_proveedor |
| Postman | API token (negativo) | suelta | — | — |
| Postman | API token (negativo) | asignada | — | — |
| Pulumi | API token (positivo) | suelta | pulumi-api-token | llave_proveedor |
| Pulumi | API token (positivo) | asignada | pulumi-api-token | llave_proveedor |
| Pulumi | API token (negativo) | suelta | — | — |
| Pulumi | API token (negativo) | asignada | — | — |
| Sentry | user token (positivo) | suelta | — | llave_proveedor |
| Sentry | user token (positivo) | asignada | — | llave_proveedor |
| Sentry | user token (negativo) | suelta | — | — |
| Sentry | user token (negativo) | asignada | — | — |
| Grafana | service account (positivo) | suelta | grafana-service-account-token | llave_proveedor |
| Grafana | service account (positivo) | asignada | grafana-service-account-token | llave_proveedor |
| Grafana | service account (negativo) | suelta | — | — |
| Grafana | service account (negativo) | asignada | — | — |
| PlanetScale | tkn (positivo) | suelta | planetscale-api-token | llave_proveedor |
| PlanetScale | tkn (positivo) | asignada | planetscale-api-token | llave_proveedor |
| PlanetScale | tkn (negativo) | suelta | — | — |
| PlanetScale | tkn (negativo) | asignada | — | — |
| PlanetScale | pw (positivo) | suelta | planetscale-password | llave_proveedor |
| PlanetScale | pw (positivo) | asignada | planetscale-password | llave_proveedor |
| PlanetScale | pw (negativo) | suelta | — | — |
| PlanetScale | pw (negativo) | asignada | — | — |
| PlanetScale | oauth (positivo) | suelta | planetscale-oauth-token | llave_proveedor |
| PlanetScale | oauth (positivo) | asignada | planetscale-oauth-token | llave_proveedor |
| PlanetScale | oauth (negativo) | suelta | — | — |
| PlanetScale | oauth (negativo) | asignada | — | — |
| GitLab | gldt- (positivo) | suelta | — | llave_proveedor |
| GitLab | gldt- (positivo) | asignada | — | llave_proveedor |
| GitLab | gldt- (negativo) | suelta | — | — |
| GitLab | gldt- (negativo) | asignada | — | — |
| GitLab | glrt- (positivo) | suelta | — | llave_proveedor |
| GitLab | glrt- (positivo) | asignada | — | llave_proveedor |
| GitLab | glrt- (negativo) | suelta | — | — |
| GitLab | glrt- (negativo) | asignada | — | — |
| GitLab | pipeline trigger (positivo) | suelta | gitlab-ptt | llave_proveedor |
| GitLab | pipeline trigger (positivo) | asignada | gitlab-ptt | llave_proveedor |
| GitLab | pipeline trigger (negativo) | suelta | — | — |
| GitLab | pipeline trigger (negativo) | asignada | — | — |
| GitLab | routable runner (positivo) | suelta | — | llave_proveedor |
| GitLab | routable runner (positivo) | asignada | — | llave_proveedor |
| GitLab | routable runner (negativo) | suelta | — | — |
| GitLab | routable runner (negativo) | asignada | — | — |
| Heroku | API key v2 (positivo) | suelta | — | llave_proveedor |
| Heroku | API key v2 (positivo) | asignada | — | llave_proveedor |
| Heroku | API key v2 (negativo) | suelta | — | — |
| Heroku | API key v2 (negativo) | asignada | — | — |
| AWS | AKIA (referencia) | suelta | aws-access-token | llave_proveedor |
| AWS | AKIA (referencia) | asignada | aws-access-token | asignacion_sospechosa, llave_proveedor |
| Google | AIza (referencia) | suelta | — | llave_proveedor |
| Google | AIza (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| GitHub | ghp_ (referencia) | suelta | — | llave_proveedor |
| GitHub | ghp_ (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| GitHub | gho_ (referencia) | suelta | — | llave_proveedor |
| GitHub | gho_ (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| GitHub | ghs_ (referencia) | suelta | — | llave_proveedor |
| GitHub | ghs_ (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| GitHub | github_pat_ (referencia) | suelta | — | llave_proveedor |
| GitHub | github_pat_ (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| Slack | xoxb- (referencia) | suelta | slack-bot-token | llave_proveedor |
| Slack | xoxb- (referencia) | asignada | slack-bot-token | asignacion_sospechosa, llave_proveedor |
| Slack | xoxp- (referencia) | suelta | — | llave_proveedor |
| Slack | xoxp- (referencia) | asignada | generic-api-key | asignacion_sospechosa, llave_proveedor |
| Stripe | sk_live_ (referencia) | suelta | stripe-access-token | llave_proveedor |
| Stripe | sk_live_ (referencia) | asignada | stripe-access-token | asignacion_sospechosa, llave_proveedor |
| Stripe | rk_live_ (referencia) | suelta | stripe-access-token | llave_proveedor |
| Stripe | rk_live_ (referencia) | asignada | stripe-access-token | asignacion_sospechosa, llave_proveedor |
| OpenAI | sk-proj- (referencia) | suelta | — | llave_proveedor |
| OpenAI | sk-proj- (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| OpenAI | sk- (referencia) | suelta | — | llave_proveedor |
| OpenAI | sk- (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| Anthropic | sk-ant-api03- (referencia) | suelta | — | llave_proveedor |
| Anthropic | sk-ant-api03- (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| Anthropic | sk-ant-admin01- (referencia) | suelta | — | llave_proveedor |
| Anthropic | sk-ant-admin01- (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| Supabase | sb_secret_ (referencia) | suelta | — | llave_proveedor |
| Supabase | sb_secret_ (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| npm | npm_ (referencia) | suelta | — | llave_proveedor |
| npm | npm_ (referencia) | asignada | — | asignacion_sospechosa, llave_proveedor |
| PEM | RSA (referencia) | suelta | — | llave_privada |
| PEM | RSA (referencia) | asignada | — | llave_privada |
| PEM | OPENSSH (referencia) | suelta | — | llave_privada |
| PEM | OPENSSH (referencia) | asignada | — | llave_privada |
| PEM | EC (referencia) | suelta | — | llave_privada |
| PEM | EC (referencia) | asignada | — | llave_privada |
| URL | postgres (referencia) | suelta | — | credencial_en_url |
| URL | postgres (referencia) | asignada | — | credencial_en_url |
| URL | redis (referencia) | suelta | — | credencial_en_url |
| URL | redis (referencia) | asignada | — | credencial_en_url |
| URL | https (referencia) | suelta | — | credencial_en_url |
| URL | https (referencia) | asignada | — | credencial_en_url |
| Supabase | service role JWT (referencia) | suelta | — | jwt |
| Supabase | service role JWT (referencia) | asignada | — | asignacion_sospechosa, jwt |
| AWS | secret sin firma (referencia) | suelta | — | — |
| AWS | secret sin firma (referencia) | asignada | — | asignacion_sospechosa |
| Twilio | auth sin firma (referencia) | suelta | — | — |
| Twilio | auth sin firma (referencia) | asignada | — | asignacion_sospechosa |
| Negativo | hash hex | suelta | — | — |
| Negativo | hash hex | asignada | — | — |
| Negativo | UUID | suelta | — | — |
| Negativo | UUID | asignada | — | — |
| Negativo | base64 | suelta | — | — |
| Negativo | base64 | asignada | — | — |
| Negativo | SKU | suelta | — | — |
| Negativo | SKU | asignada | — | — |
| Negativo | documentación AWS | suelta | — | — |
| Negativo | documentación AWS | asignada | — | — |

## Pruebas nuevas

En `tests/test_garita.py`, clase `CoberturaSecretProtection`: cada par prueba
la forma suelta en un log y asignada a una variable neutra. Las negativas
usan longitudes o alfabetos incorrectos. Se comprueba `buscar` directamente
para que el aviso de asignación sospechosa no oculte un patrón ausente.

- `test_aws_asia_positivo` / `test_aws_asia_negativo`
- `test_aws_abia_positivo` / `test_aws_abia_negativo`
- `test_aws_acca_positivo` / `test_aws_acca_negativo`
- `test_aws_a3ta_positivo` / `test_aws_a3ta_negativo`
- `test_aws_a3t9_positivo` / `test_aws_a3t9_negativo`
- `test_azure_ad_client_secret_positivo` / `test_azure_ad_client_secret_negativo`
- `test_azure_storage_accountkey_positivo` / `test_azure_storage_accountkey_negativo`
- `test_azure_service_bus_sharedaccesskey_positivo` / `test_azure_service_bus_sharedaccesskey_negativo`
- `test_slack_app_token_positivo` / `test_slack_app_token_negativo`
- `test_slack_services_positivo` / `test_slack_services_negativo`
- `test_slack_workflows_positivo` / `test_slack_workflows_negativo`
- `test_slack_triggers_positivo` / `test_slack_triggers_negativo`
- `test_twilio_api_key_positivo` / `test_twilio_api_key_negativo`
- `test_sendgrid_api_key_positivo` / `test_sendgrid_api_key_negativo`
- `test_supabase_access_token_positivo` / `test_supabase_access_token_negativo`
- `test_digitalocean_doo_positivo` / `test_digitalocean_doo_negativo`
- `test_digitalocean_dop_positivo` / `test_digitalocean_dop_negativo`
- `test_digitalocean_dor_positivo` / `test_digitalocean_dor_negativo`
- `test_shopify_shpat_positivo` / `test_shopify_shpat_negativo`
- `test_shopify_shpca_positivo` / `test_shopify_shpca_negativo`
- `test_shopify_shppa_positivo` / `test_shopify_shppa_negativo`
- `test_shopify_shpss_positivo` / `test_shopify_shpss_negativo`
- `test_pypi_upload_token_positivo` / `test_pypi_upload_token_negativo`
- `test_hugging_face_access_token_positivo` / `test_hugging_face_access_token_negativo`
- `test_vault_service_token_positivo` / `test_vault_service_token_negativo`
- `test_age_private_key_positivo` / `test_age_private_key_negativo`
- `test_databricks_api_token_positivo` / `test_databricks_api_token_negativo`
- `test_databricks_api_token_suffix_positivo` / `test_databricks_api_token_suffix_negativo`
- `test_doppler_personal_token_positivo` / `test_doppler_personal_token_negativo`
- `test_linear_api_key_positivo` / `test_linear_api_key_negativo`
- `test_notion_api_token_positivo` / `test_notion_api_token_negativo`
- `test_postman_api_token_positivo` / `test_postman_api_token_negativo`
- `test_pulumi_api_token_positivo` / `test_pulumi_api_token_negativo`
- `test_sentry_user_token_positivo` / `test_sentry_user_token_negativo`
- `test_grafana_service_account_positivo` / `test_grafana_service_account_negativo`
- `test_planetscale_tkn_positivo` / `test_planetscale_tkn_negativo`
- `test_planetscale_pw_positivo` / `test_planetscale_pw_negativo`
- `test_planetscale_oauth_positivo` / `test_planetscale_oauth_negativo`
- `test_gitlab_gldt_positivo` / `test_gitlab_gldt_negativo`
- `test_gitlab_glrt_positivo` / `test_gitlab_glrt_negativo`
- `test_gitlab_pipeline_trigger_positivo` / `test_gitlab_pipeline_trigger_negativo`
- `test_gitlab_routable_runner_positivo` / `test_gitlab_routable_runner_negativo`
- `test_heroku_api_key_v2_positivo` / `test_heroku_api_key_v2_negativo`
- `test_negativos_realistas`: hash hexadecimal, UUID, base64, SKU y ejemplo AWS.
