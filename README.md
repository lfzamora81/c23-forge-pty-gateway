### Deployment Steps
1. Create a GitHub repo and push these files.
2. In Render, select "New Web Service" and connect the repository.
3. Render will auto-detect the `render.yaml`. 
4. Navigate to the Service Settings -> Environment and add: E2B_API_KEY, TERMINAL_TOKEN_SECRET, and ALLOWED_ORIGINS.
5. Once deployed, note the URL (e.g., https://c23-forge-e2b-pty-gateway.onrender.com).
6. In Base44, set TERMINAL_GATEWAY_URL to wss://c23-forge-e2b-pty-gateway.onrender.com/terminal (or just the https domain if the frontend handles pathing).
