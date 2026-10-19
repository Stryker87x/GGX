# GGX Cloud Highlights Dashboard

Single-streamer, password-protected dashboard for finding Greekgodx Twitch clips, ranking their view velocity and reviewing them before publishing.

## Deployment
Docker-based Render web service. Set `DASHBOARD_USERNAME` and a strong `DASHBOARD_PASSWORD` in Render (at least 16 characters). By default scanning is disabled; to enable, set Twitch developer credentials (`TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET`) and `SCAN_ENABLED=1`. The built-in scanner checks every 2 hours while the service is running; **Render Free can sleep, so this is not a guaranteed 24/7 worker**. Only use paid always-on hosting if that's necessary and after checking pricing.

## Permission and publishing
Discovery of publicly listed clips is distinct from downloading or reposting them. Before approving external publication, record documented creator permission with `CREATOR_PERMISSION_JSON`, e.g. `{"creator_login":"greekgodx","permission_status":"approved","signed_permission_reference":"REAL_AGREEMENT_REFERENCE","allowed_platforms":["youtube","tiktok"],"allowed_editing":true,"revoked":false,"expires_on":"2027-12-31"}`. This is a template, NOT confirmation of permission. The real agreement should clearly permit you to edit and republish on your own channels and monetise if intended; third-party music and guests may require additional permission. Currently the app only discovers and queues clip links. It does not download Twitch media, edit MP4s, or publish to YouTube/TikTok; those are separate development and authorisation steps.

## Data limitation
On Render Free, `DATA_DIR=/tmp/ggx` is ephemeral: data can disappear after restart or redeploy. Use persistent Postgres/object storage for a production service. Never commit credentials or real contracts to this public repository.

## Security
Basic-auth dashboard and signed action forms; TLS is terminated by Render. Change credentials using Render environment settings. `/health` is public and displays no user data.
