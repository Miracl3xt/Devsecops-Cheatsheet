# DevSecOps Commands

## Trivy Scans
Use Trivy to scan Docker images for vulnerabilities, secrets, and misconfigurations.

1. Basic scan:
    ```bash
    trivy image <imagename> --scanners vuln,secret,misconfig --format template --template "@html.tpl" -o report.html
    ```

2. Scan with the option to ignore unfixed vulnerabilities:
    ```bash
    trivy image <imagename> --scanners vuln,secret,misconfig --format template --template "@html.tpl" -o report.html --ignore-unfixed
    ```

## CDXgen and Grype
Generate SBOM (Software Bill of Materials) and perform vulnerability scanning with Grype.

1. Generate SBOM for a Docker image:
    ```bash
    cdxgen -r <imagename> -o sbom.json -t docker
    ```

2. Generate SBOM for the current directory:
    ```bash
    cdxgen -r -o sbom.json
    ```

3. Generate SBOM for a specific path:
    ```bash
    cdxgen -r /path -o sbom.json
    ```

4. Scan SBOM with Grype (Windows):
    ```bash
    type sbom.json | grype -o template -t html.tmpl > grype.html
    ```

5. Scan SBOM with Grype (Linux/Unix):
    ```bash
    cat sbom.json | grype -o template -t html.tmpl > grype.html
    ```

## Azure Repository Image Scanning
Use Trivy to scan container images stored in Azure Container Registry (ACR).

1. Login to Azure and ACR:
    ```bash
    az login
    az acr login --name <reposname>
    docker login <reposname>.azurecr.io
    ```

2. Scan Azure container images:
    ```bash
    trivy image <imagerepo>.azurecr.io/alpha.1.1.1 --scanners vuln,secret,misconfig --format template --template "@html.tpl" -o report_pdca_dap.html
    ```
